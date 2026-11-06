# IOSurface `obj+0xf1` 生命周期线 —— 27.0.1 已复现内核 UAF panic

设备：iPhone 17 Pro Max (iPhone18,2)，iOS 27.0.1 (24A446)
对照：27.2 kernelcache（静态），`com.apple.iokit.IOSurface(402.8)`
结论级别：**S2 候选 —— 内核 UAF 已实证（4 次同点 panic），但「种雷序列」尚未归因到本 harness。见 §7 归因更正。**

---

## 0. 一句话结论

在 27.0.1 上，「生产 surface → 多线程 `IOSurfaceLock`/`IOSurfaceUnlock` 打流 → 关闭 root 连接 → 释放 surface」这一循环跑到第 **100** 次时，
`IOSurfaceRoot` 的 `root+0x188` 注册表里残留了一个 `node+0x58` 指向**已释放 surface** 的节点；
下一次遍历该表的 `0xa3462f0` 对每个节点执行 `ldr x0,[node->owner,#0xd8]` 去拿 owner 的锁，
命中已释放（tag 已轮转）的对象 → `Kernel tag check fault` → panic。

27.2 用三处改动堵掉这条路：
1. `#802`（注销）在 `root+0x150` 锁内把 `[self+0xf1]` 置 1（粘滞「已注销」标记）；
2. `#799`（注册）在锁内先测 `[self+0xf1]`，命中直接返回 `0xE00002D8 kIOReturnNotAttached`；
3. `#802` 从 teardown **末尾**提到**最前**（紧跟清 `+0xf0` 之后），把「已注销」窗口收到最短。

27.0.1 三样都没有。

---

## 1. 静态：对象模型与两把守卫

### 1.1 对象布局（证据：反汇编 + `+0xf0`/`+0xf1` 全 cache 访问普查）

| 偏移 | 含义 | 证据 |
|---|---|---|
| `+0xe8` | 共享 `IOSurfaceRoot` | `0xa34ac44 str x0,[x19,#0xe8]`（start 里从全局 `0x837ec10` 取 root 后存） |
| `+0xf0` bit0 | 「本对象当前在 root 注册表内」 | `0xa34b2cc strb w0,[x19,#0xf0]`，`w0` = `0xa3487c8` 返回值；init 时 `0xa33ea40 stp q0,q0,[x0,#0xf0]` 清零 |
| `+0xf1` | **27.2 独有**「已注销」粘滞标记 | 27.0.1 全 cache **0** 处访问；27.2 恰好 2 处 |
| `+0xf8` | PAC 签名指针（`autda`/`xpacd`，失配 `brk #0xc472`） | `0xa34b2dc` teardown 中 `ldr x16,[x21,#0xf8]!` |
| `+0x150` | root 的注册表互斥量 | `#799`/`#802`/`0xa3462f0` 首尾各 lock/unlock 一次 |
| root`+0x188` / `+0x190` | 注册表 list head / tail | `#799` 头插入，`#802` 双向摘链（不一致 `brk #0xbffd`） |
| root`+0x3e8` / `+0x420` / `+0x428` | 另一套向量（`0xa3487c8` 追加，`x19+0x3e8` 是它自己的锁） | `0xa3487c8` 里 `ldr x0,[x0,#0x3e8]` + `+0x420/+0x428` 扩容 |

节点（zone `0x8382170`，`#802` 用 `0x83821f0` 释放，同一 zone 相隔 `0x80`）：

| 偏移 | 含义 |
|---|---|
| `+0x00` | next |
| `+0x08` | prev |
| `+0x10` | 24 字节子对象，由 `init = 0xb379304` 写：`(old&3) | *reference`、`in[0]`、`in[1]` |
| `+0x20` | key（`structureInput[1]`） |
| `+0x50` | `structureInput[2]` |
| `+0x58` | **owner 对象**（注册者 self） |

### 1.2 三处版本差（逐字）

`#799` 注册 —— 27.0.1 `0xfffffe000a3460f0` vs 27.2 `0xfffffe000a3944c0`，锁后插入了 4 条：

```
ldrb w8,[x21,#0xf1]        ; x21 = self
tbz  w8,#0,+0x10
add  w20,w20,#0x1b         ; 0xE00002D8 kIOReturnNotAttached
b    <epilogue>
```

`#802` 注销 —— 27.0.1 `0xfffffe000a346364` vs 27.2 `0xfffffe000a394744`，锁后、走表之前插入：

```
mov w8,#1
strb w8,[x20,#0xf1]        ; x20 = self
```

teardown —— 27.0.1 `0xfffffe000a34b2dc` vs 27.2 `0xfffffe000a3996c4`：

```
27.0.1                             27.2
---------------------------------  ---------------------------------
ldrb w8,[x0,#0xf0]; tbz -> tail    ldrb w8,[x0,#0xf0]; tbz -> tail
sturb wzr,[x21,#-8]  (+0xf0=0)     strb wzr,[x20,#0xf0]
bl 0xa348910  (root,obj,sig)       bl 0xa394744  = #802   << 提到最前
bl 0xa3450b0  (root,sig)           bl 0xa396cf8
bl 0xa346364  = #802  << 最后      bl 0xa393480
```

即：27.0.1 在「清 `+0xf0`」与「摘链」之间夹了**两次函数调用**；27.2 把这个窗口压成零，并额外立了 `+0xf1` 这道不可逆的闸。

### 1.3 `0xa34b2dc` 怎么被调用 —— 不是那个 2 项数组

`0xfffffe000837f650` / `0x837f658` 是 `__const` 里相邻的两个槽，**不是** 2 项数组：

- 派生 vtable 基址 `0xfffffe000837f388` → 槽 `0x2c0` = `0x837f648`，槽 **`0x2c8`** = `0x837f650` → `0xa34b188`，槽 **`0x2d0`** = `0x837f658` → `0xa34b2dc`。
- 全 cache 对 `0x837f000` 页的 `adrp` 站点共 19 处，全部在 IOSurface 内，偏移 `0x198/0x200/0x300/0x330/0x360/0x380`，**没有任何一处**在 `0x650`。
- `0xa34b188`（槽 0x2c8）与 `0xa34b2dc`（槽 0x2d0）是该类仅有的两个覆盖方法；二者都以 `[base+0x2c0]`/`[base+0x2c8]`（基表 `0xfffffe0007ef2f28`，com.apple.kernel）尾调，并调用 `setProperty("IOUserClientEntitlements")`（`0x7a1b62f`）/`setProperty("IOUserClientDefaultLocking")`（`0x7a1b648`）。
- 所以 `0xa34b188` = 建立期（注册 + 置 `+0xf0`），`0xa34b2dc` = 销毁期；`0xa34b2dc` 由 OSMetaClass 虚派发（`ldr xN,[x?,#0x2d0]`，全 cache 454 处该偏移的静态派发点）在 release/terminate 时进来，**用户面用 `IOServiceClose` / 端口最后引用消失 / 进程退出触发**。
- 「`0xa34b2dc` 的静态 `bl` 调用者 = 0」是正确观测：它是虚函数，只经 vtable 槽到达。`0xa3487c8`（置 `+0xf0` 的那个）的静态调用者唯一，就是 `0xa34b2c8`，位于 `0xa34b188` 体内。

### 1.4 selector 17 的入参契约（反汇编解出，非猜测）

```
handler 0xa3498f4:  ldr x1,[args+0x10] ; cbz x1 -> 0xE00002C2 kIOReturnBadArgument
                    ldr x2,[args+0x30]                 ; structureInput，需 >=24B
#799:               ldr x1,[reference]                 ; 解引用
                    ldp x2,x3,[structureInput]
                    ldr x8,[structureInput+0x10]
                    init(node+0x10, *reference, in[0], in[1])
                    node+0x50 = in[2] ; node+0x58 = self
                    头插入 root+0x188 / root+0x190
```

`args+0x10` 是 **reference 数组指针**，只有 `IOConnectCallAsyncMethod` 会填；同步 `IOConnectCallMethod` 恒为 0。
实测（`out/israce/round-*.ndjson` 的 `@calib` 行）：同步 4 种形态全部 `0xE00002C2`；
`IOConnectCallAsyncMethod(c,17,wakePort,&ref,1,...)` → **`KERN_SUCCESS`**。
`init = 0xb379304` 只做 `(old&3)|*ref` / `in[0]` / `in[1]` 三个标量写入，不解引用 `*ref`。

selector 18（按 key 注销，尾部 `0xa3461f4`）实测同步调用返回 `0xE00002C2`，本轮未打通，**未使用**。

---

## 2. 复现矩阵

`N` = 并发面数，`I` = 每变体迭代数。全部用例 begin/end 双行 + 每行 `fsync`。

| tag | v | 说明 | 结果 |
|---|---|---|---|
| baseline | 0 | 同步 sel17（对照） | `0xE00002C2` |
| baseline | 1 | async sel17 + 非零 reference | **`SUCCESS`** |
| double | 1 | async sel17 ×2 | `SUCCESS` → **`0xE00002C9`**（`#799` dup 分支） |
| postclose | 2 | 注册 → `IOServiceClose` → 再注册 | `SUCCESS` / `0xC9` / `MIG_BAD_ARGUMENTS`（端口 kobject 已摘除，再调不过内核） |
| postclose2 | 18 | 同上 ×2 | 同上 |
| addrreuse | 19 | 关 A 留残留节点 + 24 个新客户端复用地址 | `MIG_BAD_ARGUMENTS` |
| lockdeg | 15 | surface + 4 线程 lock/unlock 打流 + `IOServiceClose` + `CFRelease` | 无 panic（单跑 1000 次） |
| surfch | 14 | sel17 打流 + create/lookup/release churn | 未跑到 |
| big | 16 | 64 surface + 8 连接 + 12 打流线程 | 未跑到 |
| race8 | 11 | 8 连接 16 线程 + 交错 close | 未跑到 |
| race1 | 10 | 1 连接 6 线程 + close | 未跑到 |

### 2.1 触发序列（`V_LOCKDEG`，逐字）

一次迭代：

```
1. IOServiceOpen(IOSurfaceRoot, mach_task_self(), 0, &c)
2. IOConnectCallAsyncMethod(c, 17, wakePort, &ref, 1, NULL, 0, in[3]={1,2,3}, 24,
                            NULL, &0, NULL, NULL)          // 注册：node+0x58 = c
3. IOSurfaceCreate({IOSurfaceWidth:64, Height:4, BytesPerElement:4, PixelFormat:'BGRA'})
4. 4 个线程循环：IOSurfaceLock(s,0,&seed) ; IOSurfaceUnlock(s,0,&seed)
5. sleep(200us + (I%40)*25us)
6. IOServiceClose(c)          <-- teardown：清 +0xf0 → 两次调用 → #802 摘链
7. sleep(300us) ; 停线程 ; CFRelease(s)     <-- surface 释放；它自己的 #802 若被第 6 步的窗口跨过，节点就留下来了
```

~~第 100 次迭代的第 6 步触发~~ —— **此说法已作废，见 §7。**
`lockdeg-N1-I0100` 只是设备重启瞬间本进程正在写的位置；崩溃任务从来不是本 App。

---

## 3. panic 记录（4 次独立启动，同一指令）

| # | 时间 | slide | pc(static) | lr(static) | CPU | 类型 |
|---|---|---|---|---|---|---|
| 1 | 12:11:05 | `0x3e48c000` | `0xfffffe000a34ff88` | `0xa346338` | 0 | Kernel tag check fault |
| 2 | 12:12:03 | `0x2eb20000` | `0xfffffe000a34ff88` | `0xa346338` | 3 | Kernel tag check fault |
| 3 | 12:16:22 | `0x4686c000` | `0xfffffe000a34ff88` | `0xa346338` | 1 | Kernel tag check fault |
| 4 | 12:17:54 | `0x2f420000` | `0xfffffe000a34ff88` | `0xa346338` | 0 | Kernel tag check fault |

原始日志：`out/panics/panic-full-2026-11-01-*.ips`，机器可读汇总 `out/israce/panic/summary.json`。
四次 panic 全部落在 `com.apple.iokit.IOSurface(402.8)` 内（slide 由各自日志的
`dependency: com.apple.iokit.IOSurface(402.8)[…]@0x…->0x…` 行反推，静态 `__TEXT` 起点 `0xfffffe000a3257c0`）。

### 3.1 故障指令与调用点

```
0xa34ff4c  bti c ; pacibsp ; …            <-- 被调函数
0xa34ff74  mov  x22, x0                    ; x0 = 被操作对象
0xa34ff78  adrp x8, 0x8383000 ; ldr x8,[x8,#0x8c0]
0xa34ff80  ldr  x8,[x8] ; str x8,[sp,#0x18]      ; stack guard
0xa34ff88  ldr  x0,[x0,#0xd8]              <-- ★ 炸在这里（取对象锁）
0xa34ff8c  bl   0xa359e3c                   ; lck_mtx_lock（解析：auth_got 0x83833c0 -> 0xfffffe000abd3390）
0xa34ff9c  bl   0xa34f8cc
0xa34ffa8  bl   0xa359e5c                   ; unlock（0x83833d0 -> 0xfffffe000abd3f78）
```

调用者（`lr - 4 = 0xa346334`）：

```
0xa3462f0  bti c                       <-- 函数：遍历 root+0x188
0xa346314  ldr x0,[x20,#0x150] ; bl lock
0xa34631c  ldr x22,[x20,#0x188]        ; head
0xa346320  cbz x22 -> exit
0xa346324  ldr x0,[x22,#0x58]          ; ★ node->owner  ← 已释放 surface
0xa346328  ldr w3,[x19,#0x10]
0xa34632c  mov x1,x22 ; mov x2,x21
0xa346334  bl  0xa34ff4c               ; lr = 0xa346338  ✓ 与 4/4 日志一致
```

### 3.2 tag 失配的算术校验（panic #4）

```
x0  = 0xf8_fffe2ea528a120   -> 真实 0xfffffe2ea528a120
far = 0xf6_fffe2ea528a1f8   = x0 + 0xd8   ✓ 与 `ldr x0,[x0,#0xd8]` 一致
期望 tag 0xf6 ≠ 寄存器 tag 0xf8
```

`far − x0 = 0xd8` 精确等于故障指令的立即数偏移，**tag 在 free 时被轮转** —— 这就是内核内存标记对 UAF 的现场判定。
不是空指针、不是类型混淆：是**一个曾经有效、已被释放的对象被继续解引用**。

---

## 4. 27.0.1 vs 27.2 的现象差

| 观测点 | 27.0.1 | 27.2 |
|---|---|---|
| `[obj+0xf1]` 全 cache 访问数 | 0 | 2（`0xa394500 ldrb`、`0xa394774 strb`） |
| `[obj+0xf0]` 访问站点 | 28 | 32（多出 `0xa3996ec strb wzr,[x20,#0xf0]`） |
| 注销后再次注册 | `#799` 照插，返回 `SUCCESS`（dup 时 `0xC9`） | 锁内命中 `+0xf1` → **`0xE00002D8 kIOReturnNotAttached`** |
| teardown 中「清 `+0xf0`」到「摘链」之间的窗口 | 两次函数调用（`0xa348910`、`0xa3450b0`） | 零（`#802` 紧跟其后） |
| `root+0x188` 残留节点的可能性 | 存在 | 被 `+0xf1` + 提前摘链双重排除 |
| 本复现序列 | **4/4 次 panic @ `0xa34ff88`** | 无设备可跑；静态判定路径已封闭 |

---

## 5. 边界（不填空白）

1. **没有 27.2 设备**，27.2 一侧是静态判定，不是实测「同序列不 panic」。要闭环需要 27.2 真机。
2. `0xa3462f0` 的**用户入口**尚未逐条对到 selector 号：已证它是 `root+0x188` 遍历 + 逐节点驱动 `0xa34ff4c`，且 panic 时由 `IOServiceClose` 的 teardown 引出，但 handler→`0xa3462f0` 的那一跳没有 xref 到具体 selector。
3. `select 18`（按 key 注销）同步调用恒 `0xE00002C2`，其异步形态未测；27.2 **没有**给 `0xa3461f4` 加 `+0xf1` 检查，这条支路是开放的，但本轮的 panic 不来自它。
4. `destroy(node+0x10)` = stub `0xa35a09c` → `__auth_got 0x83834f0` → `0xfffffe000b37acf0`（com.apple.kernel）。其内部分支（UAF / 泄漏 / 断言）未读。
5. `+0xf0`/`+0xf1` 究竟是「本对象在 `root+0x188` 里」还是「本对象在 `root+0x420` 向量里」，两套容器的分工未完全对上：`0xa3487c8` 操作的是 `+0x3e8/+0x420/+0x428` 向量，而 `#799`/`#802` 操作 `+0x188/+0x190` 链表。已证的是 panic 落在**链表**这条路上。

---

## 6. 重跑

```bash
# 整轮持锁（/tmp/ios27-device.lock），单次等待 <= 35s
./harness/israce/run.sh
python3 harness/israce/merge.py --report out/israce.ndjson
```

产物：
- `out/israce.ndjson` —— 全量原始记录（begin/end 双行，每行 fsync）
- `out/israce/round-*.ndjson` —— 每回合快照
- `out/israce/last.log` —— 人读日志
- `out/panics/panic-full-2026-11-01-*.ips` —— 4 份原始 panic
- `out/israce/panic/summary.json` —— pc/lr/slide 机器可读汇总

判定口径：`begin` 无 `end` 的 key = panic 指纹。当前唯一指纹 `lockdeg-N1-I0100`。


---

## 7. 归因更正（12:26 实测；覆盖 §0/§2.1 的原始判断）

### 7.1 我原先的说法是错的

| 原说法 | 实测 |
|---|---|
| 「崩在 `lockdeg` 第 100 次迭代的第 6 步 `IOServiceClose`」 | **错**。4 份 panic 的 `Panicked task` 分别是 `pid 878: avconferenced` 与 3 次 `pid 0: kernel_task` |
| 「`lockdeg-N1-I0100` 是 panic 指纹」 | **错**。它只表示设备重启那一刻本进程正在写这一行，等于「被重启杀掉的孤儿」，不是崩溃点 |
| 「本 App 在自己进程里撞到崩溃点」 | **错**。4 次 panic 的 `processByPid`（413/593/663/751 条快照）中**均无本 App** |

### 7.2 二分结果（每项单独跑，跑后观察 45–93s）

| 变体 | 迭代 | 结果 |
|---|---|---|
| `min-reg-close-rel`（create→reg→close→release） | 8 | 无 panic |
| `min-close-rel`（不注册） | 8 | 无 panic |
| `min-reg-rel-close`（先 release 后 close） | 8 | 无 panic |
| `min-rel-close`（不注册、先 release） | 8 | 无 panic |
| `min-reg-close`（不 release） | 8 | 无 panic |
| `spray32`（32 surface 喷射） | 8 | 无 panic |
| `locklite`（1 线程、零 sleep） | 60 | 无 panic |
| `lockdeg`（4 线程 + 抖动） | 200 + 800 | 无 panic（共 1000 次） |
| `postclose`（额外 uref + `IOServiceClose` + 再注册） | 40 | 无 panic（观察 93s） |
| `big`（64 surface + 8 连接 + 12 线程） | 12 | 无 panic（观察 45s） |

即：**单变体一律不种雷**。所以 §2.1 那张「lockdeg 是触发点」的表不成立，`IOServiceClose` / `CFRelease` 的增删都不是枢轴。

### 7.3 仍未排除的两个解释

1. **组合效应**：4 次 panic 的运行都同时含 `surfch` + `race8`/`race1`（narrow 计划）或再加 `dereg18` + `forkcl`/`forkexit`（wide 计划）。这三项是仅存的、未单独测过的嫌疑。
2. **另一套 harness**：12:11–12:17 期间设备上同时有第二套 fuzz harness，且与本 harness **共用 bundle id `com.example.ios27poc`**、互相 `--terminate-existing` 杀进程。它在 12:20 前被停掉；此后本 harness 的 6 次运行（约 1600 用例）**零 panic**。时间线与该解释完全一致，**无法排除**。

### 7.4 仍然成立的部分（与归因无关）

- 故障指令 `0xa34ff88 ldr x0,[x0,#0xd8]`，调用者 `0xa346338`（`0xa3462f0` 的注册表遍历），4 次 panic、4 个 slide、4 个 CPU 全部一致。
- `far = x0 + 0xd8` 精确对应指令立即数，tag 由 `0xf8/0xf6/0xf4/0xfc` 等变为另一值 —— 内核内存标记判定的 UAF。
- 27.0.1 对 `+0xf1` 的字节访问 0 处，27.2 恰好 2 处（`0xa394500 ldrb`、`0xa394774 strb`）。
- 故障函数下游 `0xa34f8cc` 用 `+0x108`(base) / `+0x110`(count) 做 `base + count*8` 寻址，index 来自调用者 —— 回收后是可用的读写原语候选。


---

## 8. `#802` 拔全部（推翻「只摘一个」假设）+ `+0xf0` 的真实身份

### 8.1 `#802` 是完整遍历，不是摘一个

```
0xa346390  ldr  x21,[x19,#0x188]      ; cur = head
0xa346394  cbz  x21 -> exit
0xa3463a0  ldr  x23,[x21]             ; next = cur->next（先存，摘链安全）
0xa3463a4  ldr  x8,[x21,#0x58]
0xa3463a8  cmp  x8,x20
0xa3463ac  b.ne 0xa346408             ; 不匹配 -> 前进一步
0xa3463b0..0xa3463f0  摘链 / destroy(node+0x10) / free(node)
0xa346408  mov  x21,x23 ; cbnz x23 -> 0xa3463a0   ; ★ 继续走到底
0xa346410  unlock ; tail call unlock
```

结论：**`#802` 会摘掉所有 `node+0x58 == self` 的节点。** 「一个 self 以多个 key 注册会留残节点」的假设不成立。

### 8.2 `+0xf0` 是计数器低字节，`+0xf1` 是同字的高字节标志

三个 `+0xf0` 清零点全部是构造/析构，不是运营态：

```
0xa3415b0  bl zone_alloc
0xa3415d4  str xzr,[x0,#0xd0]      ; +0xd0 = 数组指针
0xa3415d8  str wzr,[x0,#0xd8]      ; +0xd8 = 锁（0xa34ff4c 锁的就是它）
0xa3415dc  str xzr,[x0,#0xe8]      ; +0xe8 = root
0xa3415e0  str wzr,[x0,#0xf0]      ; +0xf0 = 32 位计数（低字节）+ 标志字节(+0xf1)
0xa3415e4  str xzr,[x0,#0x108]     ; +0x108 = 另一套数组 base
0xa3415e8  str wzr,[x0,#0x110]     ; +0x110 = 那套数组 count
```

析构路径 `0xa343760` 把 `+0xf0` **当计数用**：

```
0xa343760  ldr x20,[x0,#0xe8]      ; root
0xa343764  ldr w21,[x0,#0xf0]      ; count  ← 计数，不是布尔
0xa343768  lsl x2,x8,#3
0xa34376c  bl  0xa359e0c           ; 释放前处理
0xa343778  lsl x1,x21,#3           ; size = count*8
0xa343780  bl  0xa359dec           ; 释放 count*8 字节
0xa343790  str wzr,[x19,#0xf0]     ; 计数清零
```

因此：
- `strb w0,[x19,#0xf0]`（`0xa34b2cc`）= **注册计数置 1**；
- teardown 的 `ldrb w8,[x0,#0xf0]; tbz w8,#0` = 判 `count & 1`，在 count ∈ {0,1} 时等价于「已注册」；
- 27.2 的 `strb w8,[x20,#0xf1]` = **同一个 32 位字的第二个字节**，即该字的高位标志，与计数互不干扰。

### 8.3 由此得到的确定性种雷条件（无需竞态）

teardown 第一句是 `ldrb w8,[x0,#0xf0]; tbz -> tail`。**只要计数被清零而节点仍在链表里，teardown 就整段跳过，`#802` 不会执行，节点变成 `+0x58` 悬空的孤儿。**

候选清零点就是析构路径 `0xa343760`（它先释放 `count*8` 字节再把计数清零）。若能找到一条用户态可达、在 teardown 之前走到的 `0xa343760`，种雷就是**确定性**的：`create → register → 触发该析构 → release`，一次即成。

这条尚未验证：`0xa343760` 所在函数的入口地址与调用者未取。**下一步就是把它 xref 出来，再对 selector 表。**


---

## 9. 归因定案：种雷 = `postclose`，引爆 = `lockdeg`（组合，5/5 一致）

### 9.1 决定性实验（12:30:01 启动，单跑 panic 时刻的完整计划，全新 tag 强制重跑）

**第 5 次 panic：12:30:30.11，`pid 0: kernel_task`，slide `0x4c2e4000`**

| 项 | 值 |
|---|---|
| pc (static) | `0xfffffe000a34ff88` |
| lr (static) | `0xa346338` |
| far | `0xfbfffe240c0b66f8` |
| `processByPid` | 631 条，**无本 App** |

与 12:11:05 / 12:12:03 / 12:16:22 / 12:17:54 四次**同点**。5 次 panic、5 个 slide，pc/lr 完全一致。

### 9.2 崩溃前进程卡死在第 183 次迭代

本次运行的 ndjson 只推进到：

```
baselineC 4 / doubleC 4 / postcloseC 6 / lockdegC 183（begin 无 end）
DANGLING: lockdegC-N1-I0183
```

`surfchC` / `bigC` / `race8C` / `race1C` **一条都没开始**。计划里 `lockdegC` 之后还有 4 个阶段，说明进程在第 183 次迭代内**卡死在某个内核调用里**，主线程阻塞导致 watchdog 也没能写出 `@summary`。

### 9.3 由此得到的因果配对

| 运行 | 含 postclose | 含 lockdeg | panic |
|---|---|---|---|
| 12:10:35 wide | ✔ | ✔ | ✔ 12:11:05 |
| 12:11:34 wide | ✔ | ✔ | ✔ 12:12:03 |
| 12:15:54 narrow | ✔ | ✔ | ✔ 12:16:22 |
| 12:17:29 narrow | ✔ | ✔ | ✔ 12:17:54 |
| 12:30:01 narrow（tag C） | ✔ | ✔ | ✔ 12:30:30 |
| 12:20 mini | ✘ | ✔ | 无 |
| 12:23 lockdeg 单跑 ×1000 | ✘ | ✔ | 无 |
| 12:24 postclose 单跑 ×40 | ✔ | ✘ | 无 |
| 12:26 big 单跑 ×12 | ✘ | ✘ | 无 |

**5/5 命中，4/4 未命中。** 单跑任一者都不炸 ⇒ 必须两者相邻共存。

机械解释：
1. **种雷**：`postclose` = `mach_port_mod_refs(SEND,+1)` → `IOServiceClose(c)` → 在该端口名上再调 selector 17 → `mach_port_deallocate`。额外 uref 让端口名活过 `IOServiceClose`，user client 已被 close 但端口仍指向已释放的 kobject。
2. **引爆**：`lockdeg` 的 4 线程 `IOSurfaceLock`/`IOSurfaceUnlock` 打流 + `IOServiceClose`，在第 N 次迭代让主线程**卡死**在内核里。
3. 约 3 s 后 GPU workloop 走到注册表遍历（`0xa3338cc` → `0xa3462f0`）→ `0xa346338` → `ldr x0,[owner+0xd8]` → tag 失配 → panic。

### 9.4 字段布局按类分开（修正 §8）

| 类 | `+0xd0` | `+0xd8` | `+0xe8` | `+0xf0` | `+0x108` | `+0x110` |
|---|---|---|---|---|---|---|
| surface 对象 | base1 | count1（32 位） | base2 | count2（低字节）+ `+0xf1` 标志字节 | base | count |
| 注册表节点 owner | — | **锁指针** | — | — | — | — |

故障点 `ldr x0,[x0,#0xd8]` 取的是**节点 owner 的锁**，不是 surface 的 count —— 两个类的 `+0xd8` 语义不同，不可混用。

### 9.5 仍成立的静态结论

- `#802` 摘全部匹配节点（`0xa346408 mov x21,x23; cbnz x23 -> loop`），「只摘一个」假设作废。
- 虚 `free()`（`0xa343448` → `0xa34368c` → `0xa34373c`）把 `+0xd0/+0xd8/+0xe8/+0xf0` 全部清零；teardown 的门 `ldrb w8,[x0,#0xf0]; tbz -> tail` 读的正是被清零的那个字节。
- 27.2 的 `+0xf1` 与该字**共存**：`+0xf0` 会被析构清零，标志放在 `+0xf1` 才能活过清零。这是 Apple 选这个位置的直接理由。
- `0xa34f8cc` 是带边界检查（`cmp w9,w1; b.ls`）+ 范围/tag 校验（`eor/tst #-0x40000000000000`）的访问器，定性为 **UAF 读**，不是干净任意地址。


---

## 10. 回收控制：未取得样本（负结果）

### 10.1 实验

```
plan = seedR(V_SEQ1817 ×20) → sprayR(V_SPRAY ×10，每次 48 个同尺寸 surface) → lockR(V_LOCKDEG ×400)
```

结果：**430 用例全部完成，无 panic、无卡死**（`lockR` 400/400 有 end）。

随后 `lockR2 = V_LOCKDEG ×900`（无喷射）再跑一轮：**900/900 完成，无 panic**。

### 10.2 判据与实测

| 判据 | 结果 |
|---|---|
| `far − x0` 不再是 `0xd8` ⇒ 回收成功 | **未观测到**。5 次 panic 全部 `far − x0 = 0xd8` |
| `far` tag 变但偏移仍 `0xd8` ⇒ 部分回收 | 无法区分：任何 free 都会轮转 tag，5 次 panic 的 tag 各不相同，这本身不构成回收证据 |
| 完全不变 ⇒ 未打中 | 与观测一致 |

**结论：没有证据表明已释放对象被重新占住。** 喷射 48 个 surface 那一组本轮未崩溃，因此没有可比对样本 —— 这是样本不足，不是否定。

### 10.3 引爆的可靠性

| 运行 | 阶段 A | 阶段 B 迭代 | panic |
|---|---|---|---|
| 12:11 / 12:12 / 12:16 / 12:17 / 12:30 | ✔ | 200 | **5/5 崩** |
| 12:33（含 48 喷射） | ✔ | 400 | 不崩 |
| 12:35 | ✘（无新种子） | 900 | 不崩 |

即：A+B 相邻命中率 5/5，但**不是每次必中**；12:30 之后的 1300 次引爆迭代全部干净。**引爆概率随设备状态漂移，未量化。**

### 10.4 卡死点定位：未取得

逐步 mark（open/reg/create/spam/close/release，每条 fsync）已加入 `V_LOCKDEG`。但 12:30 之后未再复现卡死，因此**卡在哪个内核调用仍然未知**。

已知的唯一硬事实：两次卡死都发生在 `IOServiceClose(c)` 之前的打流窗口内（第 100 / 183 次迭代），且主线程阻塞到 watchdog 无法写入 `@summary`。

### 10.5 交付

复现器已冻结为 `out/POC-isurface-uaf.md`：完整参数、selector 17 入参契约、字段布局按类分开、失败模式表、未验证项清单、以及「确定性内核挂死」这条独立结论。


---

## 11. 冷启动实验：1 个有效样本，阴性；另 2 轮因工程缺陷作废

### 11.1 协议与结果

每轮：`devicectl device reboot` → 等设备回归（~25 s）→ 只跑 A(`V_SEQ1817`×20) + B(`V_LOCKDEG`×250) → 观察 35 s。

| 轮 | 执行情况 | panic | 有效性 |
|---|---|---|---|
| R1 | `seedR1` 20/20、`lockR1` 250/250 **确实执行** | 无（设备仍 5 份） | **有效** |
| R2 | `lockR2` 这个 tag **与 12:35 那次 900 迭代的运行撞名**，断点续跑把用例全跳过 | 无 | **作废** |
| R3 | 设备在启动时刻不可达（`CoreDeviceError 1011`），App 未运行 | 无 | **作废** |

### 11.2 结论

**冷启动假设没有被支持，但样本只有 1 个，不足以否定。**

一次有效的「重启 → A+B 一次」是阴性。要判定「冷启动 + A+B = 可复现协议」，需要 3/3 有效样本；现在 1/3。

已确认的是：**命中率漂移不是靠冷启动就能消掉的**（R1 就是冷启动，仍不中）。PoC 文档按「重试直到命中」写，不做确定性承诺。

### 11.3 顺带修掉的工程缺陷（`@abort: no IOSurface service`）

复核合并库：`@abort` 共 **4** 条（`no IOSurface service` 2 条、`calibration failed` 2 条），不是每轮 5 条 —— 但方向是对的：

- 原实现**扫一遍**候选名就 abort，冷启动后 `IOSurfaceRoot` 尚未发布时必然空转。
- 已改为**轮询扫描**：最多 40 轮 × 100 ms（~4 s），命中即停，并在 `@abort` 里带上 `scanTries` 计数。
- R1 的 `seedR1`/`lockR1` 计数证明：即使有 abort，那一轮的用例**确实执行了**，冷态窗口没被吃掉。

### 11.4 回收判据升级（由外部静态分析给出，本项目采信为待验证）

`0xa34f8cc` 的完整语义是「取数组第 idx 项，并校验其 `+0x10` 等于 `self+0x118`」，两次解引用：

```
0xa34f954  ldr  x16,[x17]          ; ptr = base(陈旧) + idx*8
0xa34f95c  autda x16,#0xf69b       ; PAC 认证
0xa34f97c  ldr  x8,[x16,#0x10]     ; 第二次解引用
```

因此判据改为三档：**`brk #0xc472` = 回收成功且 base 受控**（优于 `far−x0` 观察）；`far−x0 = 0xd8` = 未回收；其它 pc = 新路径。

**该语义与判据尚未在本项目实测中验证**（本项目只观测到 5 次 `far−x0 = 0xd8`）。


---

## 12. 四段配方冷启动复跑：阴性 → 引爆需要「别的任务」

### 12.1 实验（tag E，mark 关闭，与 12:30 那轮同构）

冷启动后跑 `baseline×4 → double×4 → postclose×6 → lockdeg×250`（参数取 12:30 实测值）。

自查（时间戳全新，确认不是跳过记录）：

```
baselineE   begin=4   end=4    t=0.025..0.026
doubleE     begin=4   end=4    t=0.026..0.027
postcloseE  begin=6   end=6    t=0.027..0.029
lockdegE    begin=250 end=250  t=0.029..0.446
E 系列 dangling: []          panic 数 = 5（基线 5，无新增）
```

**四段全跑通、250 次引爆迭代全成对、无 panic。**

### 12.2 与 12:30 那轮的差异只剩一项

| 项 | 12:30（崩） | 现在（不崩） |
|---|---|---|
| 段序与参数 | baseline4/double4/postclose6/lockdeg | **相同** |
| 每迭代耗时 | 1.54 ms | 1.64 ms（实测，几乎一致） |
| 死亡位置 | `lockdegC-N1-I0183` | 250 次全部正常结束 |
| **设备已开机时长** | **约 12 分钟** | **约 1 分钟** |

「执行速度」已被排除（外部逐条时序证明 1.54 vs 1.64 ms）。剩下的唯一差异是**设备 uptime 与后台活动**。

### 12.3 由此收紧的假设：雷种下了，但没人去踩

5 次 panic 的踩雷者全部是**别的任务**：
- 1 次 `avconferenced`（用户 syscall 入口 `0xa34d5c8`）
- 4 次 `kernel_task` GPU workloop（入口 `0xa337204` → `0xa351bc4` → AGXG18P）

两次卡死（I0100 / I0183）是本进程踩到，表现为**主线程阻塞**、不 panic。

冷启动后 1 分钟内，`avconferenced` 与 GPU workloop 都不活跃 ⇒ **雷即使种下也没有触发者**。这解释了为什么同样的四段配方在冷启动下连续两次阴性，而 12:30 那次（设备已跑 12 分钟、前一小时连续 4 次 panic 的后台活动）会中。

**这不是「配方坏了」，是「观测窗口里没有踩雷者」。**

### 12.4 下一步（未执行）

在种雷之后**主动制造踩雷者**，二选一：
- **GPU 路径**：`MTLCreateSystemDefaultDevice` + 渲染循环若干帧（走 `0xa351bc4` → AGXG18P workloop）
- **syscall 路径**：在多进程/多接口上制造 IOSurface 活动，逼 `0xa34d5c8`

判据不变：`brk #0xc472` = 回收成功；`far−x0 = 0xd8` = 未回收；`begin` 无 `end` = 卡死。

### 12.5 `lockdeg` 完整实现（此前未公开）

```c
// 4 个线程，每个都是：
static void *spamLock(void *arg) {
    IOSurfaceRef s = (IOSurfaceRef)arg;
    uint32_t seed = 0;
    while (gSpamRun) { IOSurfaceLock(s, 0, &seed); IOSurfaceUnlock(s, 0, &seed); }
    return NULL;
}

// 主线程：
IOServiceOpen → sel17(async) 注册 → IOSurfaceCreate(64x4x4 BGRA)
gSpamRun = 1; 起 4 个 spamLock(s)
usleep(200 + (iter % 40) * 25)          // 200..1175 µs 抖动
IOServiceClose(c)                        // 打流中拆连接
usleep(400)
gSpamRun = 0; join 4 线程
CFRelease(s)
```


---

## 13. 双引用倒序释放：阴性 —— 并推翻本项目自己的「种雷」叙事

### 13.1 实验（`V_DUALREF`，tag `dualF`，60 次）

```c
open → sel17(async) 注册 → s = IOSurfaceCreate(64x4x4 BGRA)
gid = IOSurfaceGetID(s)
s2  = IOSurfaceLookup(gid)          // 第二个引用
IOServiceClose(c)                   // teardown 先走完
usleep(20ms)
CFRelease(s)                        // 减一，不归零
usleep(200ms)
CFRelease(s2)                       // ★ 归零 → 释放链遍历 0xa3338cc → 0xa3462f0
```

结果：`begin=60 end=60`，`IOSurfaceLookup` **60/60 返回非 NULL**，`gid = 424`（稳定复用），**无 panic，无卡死，无 dangling**。

### 13.2 这个结果推翻了什么

`postclose` 的三次调用返回码是 `SUCCESS → 0xE00002C9 → MIG_BAD_ARGUMENTS → MIG_BAD_ARGUMENTS`。

**`MIG_BAD_ARGUMENTS` 是 MIG 层拒绝**，意味着第三次、第四次调用**根本没进到 `#799`**。而 `#799` 才是插入注册表节点（`node+0x58 = self`）的唯一路径。

**所以 `postclose` 从来就没有种下任何东西** —— 没有插入过节点，也就没有「`+0x58` 悬空的孤儿节点」。此前把 `postclose` 认定为「种雷」是错的：额外 uref 让**端口名**活过 `IOServiceClose`，但 **kobject 已死**，调用在 MIG 层就被挡回，`#799` 不会执行。

### 13.3 修正后的整体判断

| 实验 | 是否触碰了「插入节点 → owner 被释放」这条链 | 结果 |
|---|---|---|
| `postclose` ×40 | 否（`#799` 从未执行） | 无 |
| `lockdeg` ×1900 | 每轮插入 1 个节点，owner = 活着的 client | 无 |
| `min` 5 种顺序 | 插入 1 个节点后正常 close（`#802` 摘净） | 无 |
| `big` ×12 | 插入多个节点，全部正常 close | 无 |
| `four-phase`（baseline/double/postclose/lockdeg）×250 | 同上 | 无 |
| `dualF` ×60（双引用倒序释放，真走到释放链遍历） | 否 | 无 |

**本项目至今没有任何一个单进程序列被证明种下过雷。** 因此 12:11–12:30 那 5 次命中**不能归因于本 harness 的配方** —— 那个时段唯一在场且此后消失的第三方，是共用 bundle id `com.example.ios27poc` 的另一套 harness（12:11–12:17 活跃，与本进程互相 `--terminate-existing`）。它创建的 surface 在本进程之外持引用，它自己释放时会在**它的上下文**里跑释放链遍历 —— 与 5 次 panic 的「崩溃任务从来不是本进程」完全一致。

**§9 的「归因定案」据此撤回。** 现在的证据状态是：故障点、故障指令、27.2 修复指纹、字段布局这些静态结论全部成立；但**触发序列未定**。

### 13.4 仍然成立的部分

- 故障链 `0xa3338cc → 0xa3462f0 → 0xa346338 → 0xa34ff88 ldr x0,[x0,#0xd8]`，5/5 panic 一致，5 个 slide 反推后 pc/lr 完全相同。
- `far − x0 = 0xd8` 全部一致。
- 27.2 的 `+0xf1` 两处字节访问（27.0.1 零处）。
- 字段布局按类分开（surface 的 `+0xd8` 是 count1；节点 owner 的 `+0xd8` 是锁）。
- `0xa34f8cc` 是带边界检查与 PAC 校验的访问器（外部静态分析，未实测验证）。
- `IOSurfaceLookup(gid)` 在同进程内可取到第二个引用（60/60 非 NULL）。


---

## 14. 三步重注册实验：**没能测到假设** —— 因为第 2 步（注销）本身就失败

### 14.1 实测返回码（tag `replantG`，60/60 全执行）

| 步 | 调用 | 返回码 | 名称 |
|---|---|---|---|
| 1 | `sel17` 注册 | `0` | `SUCCESS` |
| 2 | `sel18` 注销 | **`0xE00002C2`** | **`kIOReturnBadArgument`** |
| 3 | `sel17` 再注册 | `0xE00002C9` | `kIOReturnInternalError`（dup 分支） |

### 14.2 这个结果的含义与「假设被否」不同

第 3 步返回 `0xC9`，看起来像「重注册被拒 ⇒ 路径不通」。**但真正的原因是第 2 步根本没执行成功**：

注销返回 `kIOReturnBadArgument`，说明**节点的状态从未改变**，于是第 3 步撞上的是「同 key + 同 self 已存在」的 dup 检查（`0xC9`），**没有测到「已注销对象再注册」这个动作**。

**假设（27.0.1 允许注销后再注册、27.2 用 `+0xf1` 挡）至今未被测试。**

### 14.3 顺带暴露的旧漏洞

`sel18` 在本 harness 里**从未成功过一次**。所有用过 `SEL_DEREG` 的变体（`V_DEREG18`、`V_SEQ1817` 的第 2 步）拿到的都是这个 `0xE00002C2`。

即：**「注销」这条路径本项目从未真正跑通过**，此前把它当作已工作的动作是错的（`dualF` 之前的所有「注销」相关结论都要按未执行重读）。

### 14.4 下一步需要的静态输入

`sel18` 的 handler 是 `0xa34991c → 0xa3461f4`。需要它的**参数前置检查**：

- 是否也要求 `args+0x10`（reference）非空？若与 `sel17` 同为 async-only，则 `callSel` 必须带 `referenceCnt=1` 且非 NULL 指针 —— 但 `sel17` 用同一路径返回 `SUCCESS`，说明 `callSel` 已满足这一点，故 `sel18` 拒绝的是别的东西。
- `structureInput` 需要多少字节？是否要求 `structureOutput`？
- 是否要求 `scalarInputCount` / `scalarInput` 的特定取值？

在第 2 步跑通之前，三步实验无法判定假设。


---

## 15. ★ 重注册路径成立：27.0.1 允许「注销后再注册」（tag `seq4I`，20/20 全一致）

### 15.1 四步返回码

| 步 | 调用形态 | 返回码 | 名称 |
|---|---|---|---|
| 1 | `sel17` **async**（referenceCnt=1，in={1,2,3}） | **`0x0`** | SUCCESS |
| 2 | `sel17` async 再注册 | **`0xE00002C9`** | kIOReturnInternalError（dup，证明节点在） |
| 3 | `sel18` **同步**（`scalarInput=NULL,count=0`；`structureInput` **精确 24 字节**；无输出） | **`0x0`** | **SUCCESS —— 注销成功** |
| 4 | `sel17` async 再注册（同一连接、同一 client） | **`0x0`** | **SUCCESS —— 27.0.1 允许注销后重注册** |

无 panic、无卡死（本轮只验证可达性，未接踩雷动作）。

### 15.2 此前 `sel18` 恒失败的原因（本项目自身的错）

`sel18` 是**同步方法**，派发表里没有 `asyncWakeTarget` 槽（`scalarIn=0, structIn=24, scalarOut=0, structOut=0`）。
此前一律用 `IOConnectCallAsyncMethod` 打 `sel18`，IOKit 前置校验直接拒（`0xE00002C2`），**handler 从未被执行**。
改正为同步调用后一次通过。

**连带更正 §14**：§14 说的「注销从未跑通」是**调用形态**错误，不是路径不存在。注销本身可用。

### 15.3 意义

`sel17 → sel18 → sel17` 这条序列在 27.0.1 上**完全可达且全部返回成功**，与 27.2 的补丁语义精确对应（27.2 在注销时置 `+0xf1=1`，注册时检查并返回 `0xE00002D8`）。

**这是本会话首个被实测证实的、与官方修复一一对应的可触发状态机路径。** 与 27.0.1 的 `+0xf1` 零字节访问互为印证。

### 15.4 尚未做的最后一步

本轮只到第 4 步（重注册成功），**没有接「关闭连接 + 触发释放链遍历」**，因此尚未产生 panic。下一步：
`sell17 → sel18 → sel17 → IOServiceClose(c) → 双引用倒序释放（触发 0xa3338cc → 0xa3462f0）`，判据 `far−x0=0xd8` 或 `brk #0xc472`。


### 15.5 主实验（变体 1）：`sel17 → sel18 → sel17 → IOServiceClose → 双引用倒序释放` = 阴性

tag `replant2J`，40 次全执行：

```
rc0(注册)=0×40   rc1(注销)=0×40   rc2(再注册)=0×40
begin=40 end=40  dangling=[]      panic 数仍为 5（无新增）
```

**三步全成功、client 已 close、释放链遍历已触发，仍未崩。** 无卡死。

**未记录的缺口**：本轮没有把 `IOSurfaceLookup(gid)` 的返回写进 `rcs`，因此**无法确认倒序释放的第二个引用确实非空**（`dualF` 里该值 60/60 非 NULL，但那是另一个变体）。下一轮必须把 `lookup非空` 与 `gid` 一并落盘。

### 15.6 待做（变体 2，对照）

`sel17 → sel18 → sel17 → 双引用倒序释放`（**不 close**）。若变体 2 也炸 ⇒ 重注册本身即可造坏节点；若只有变体 1 炸 ⇒ 必须「重注册 + 释放 client」组合。两者结论方向不同，必须分开跑，变体间重启。


---

## 16. 轮 3（Metal 真实 GPU 提交）：**有效阴性**

### 16.1 取证齐全（40/40，无一项为 0）

| 取证 | 值 | 判定 |
|---|---|---|
| `MTLCreateSystemDefaultDevice()` 非空 | `1 ×40` | 不是「无 GPU 权限」的无效轮 |
| `newTextureWithDescriptor:iosurface:plane:` 非空 | `1 ×40` | surface 已交给 GPU |
| 第二张 texture 非空 | `1 ×40` | blit 目标就绪 |
| `MTLCommandBuffer.status` | **`4`（Completed）×40** | **真实 GPU 工作已提交并完成** |
| `gid` | `382/5/381/251`（真实 ID） | 非 0 |
| 种雷三步 | `0/0/0` 各 ×40 | 注册→注销→再注册全成功 |

`begin=40 end=40`，`dangling=[]`，**panic 仍为 5（零新增）**。

### 16.2 这排除了什么

- 排除「`dev` 为 NULL 导致无效轮」—— 四个值全齐。
- 排除「只建 texture 未提交」—— `blit + commit + waitUntilCompleted` 全部执行，`status=4`。
- 排除「GPU 侧没碰这块 surface」—— `newTextureWithDescriptor:iosurface:` 就是 IOGPUFamily 持有 surface 的标准路径，拆除时必经 GPU 侧 KPI。

**即：种雷动作真做了、GPU 真实工作真跑了、surface 拆除真发生了、归零释放真执行了 —— 依然不崩。**

### 16.3 累计工作量与结论

12:30 之后，本项目在 6 类互不相同的机制家族上跑了 **2000 次以上用例**（postclose、lockdeg、min 顺序、spray、big、四段、dualF、replant、replant+close、Metal），**零 panic、零卡死**。

**结论（本项目能负责的表述）**：在 iOS 27.0.1 / iPhone18,2 上，**用纯用户态手段，以下所有序列均不能稳定触发该 UAF**：注册/注销/重注册状态机、连接关闭时序、surface 引用计数归零、真实 GPU 工作与 texture 拆除。

12:11–12:30 的 5 次 panic 与环境条件（同时在场且共用 bundle id 的另一套 harness、约 12 分钟 uptime、后台高频 IOSurface 活动）相关性成立，但**无法重建该环境，因此不能归因，也不能作为可复现 PoC**。

### 16.4 仍然成立并可交付的成果

1. **故障指纹**：`0xa34ff88 ldr x0,[x0,#0xd8]`、调用者 `0xa346338`、`far = x0 + 0xd8`，5 次 panic / 5 个 slide / 4 个 CPU 完全一致。
2. **27.2 修复点**：`+0xf1` 字节访问 27.0.1 为 **0**、27.2 为 **2**（注册侧检查返回 `0xE00002D8`、注销侧打粘滞标记）。
3. **实测正例**：27.0.1 上 `sel17=SUCCESS → sel18(同步)=SUCCESS → sel17 再注册=SUCCESS`，即**允许对已注销的 userClient 再注册**；27.2 用 `+0xf1` 封堵。**这是与官方补丁一一对应的实测路径。**
4. **选择子调用契约**：`sel17` 必须 async（`referenceCnt≥1`、非零 ref、`args+0x10` 非空）；`sel18` 必须**同步**（`scalarIn=0`、`structureInput` 精确 24 字节、无输出），混用会被 IOKit 前置校验拒为 `0xE00002C2`。
5. **字段布局按类分开**：surface 的 `+0xd8` 是 count1；注册表节点 owner（userClient）的 `+0xd8` 是锁。


---

## 17. 原版二进制重建：热机协议阴性；冷启动仅 1 个有效样本，阴性

### 17.1 原版重建（`main-repro.m` = `main.m.bak` 12:09 版，27803 字节，11 变体，无 Metal）

保留当前 20 变体版为 `main-cur.m`，**未覆盖任何现有文件**。原版计划 11 阶段：

```
baseline 8 / double 8 / seq1817 8 / dereg18 200 / race1 300 / race8 120
/ forkcl 200 / forkexit 200 / surfch 200 / lockdeg 200 / big 60
```

### 17.2 热机协议（后经外部证据证伪，但已跑完）

装 A(`leo4920`) + B(`leo4921`) → 交替 launch/terminate churn ×25（约 10 分钟）→ 8 阶段计划 ×3 轮，每轮观察 50 s：

```
churn 后基线 panic = 5
轮 1 = 5   轮 2 = 5   轮 3 = 5        全阴性
```

### 17.3 冷启动协议（重启 → 尽快启动 → 8 阶段 → 观察 40 s）

| 轮 | 设备可用 | 启动 | panic | 有效性 |
|---|---|---|---|---|
| 1 | ~14 s | **未启动**（5 次尝试均失败，无成功行） | 5 | **作废** |
| 2 | ~11 s | **未启动**（同上） | 5 | **作废** |
| 3 | ~11 s | **第 4 次尝试成功（约开机 26 s）** | 5 | **有效，阴性** |

**有效样本只有 1 个，阴性。** 前两轮 `devicectl process launch` 在 DDI 就绪前全部失败，属工程失败，与结论无关。

### 17.4 待补

要在「冷启动 + 立刻跑 + 原版 8 阶段」上得到 3 个有效样本，需把启动重试拉长到开机后 ~40 s 并确认 `A 已启动` 行出现，每轮之间重启。目前只有 1 个有效阴性。


---

# 18. 最终状态（封口）

> 本节自包含，不依赖其他章节或文档。

## 18.1 已确证（不依赖是否可复现）

### (a) 故障指纹 —— 【实测】5 次 panic / 5 个不同 KASLR slide / 4 个不同 CPU，逐字段一致

```
pc   0xfffffe000a34ff88   ldr x0,[x0,#0xd8]
lr   0xfffffe000a346338   (0xa3462f0 +0x44)
调用链 0xa3338cc → 0xa3462f0 → 0xa34ff48 → 0xa34ff88
far − x0 = 0xd8           5/5 成立
x0 = 已释放的 IOSurface user client（其 +0xd8 是对象内部锁）
```
slide 取值：`0x3e48c000 / 0x2eb20000 / 0x4686c000 / 0x2f420000 / 0x4c2e4000`。
崩溃任务：`avconferenced` ×1、`kernel_task` ×4 —— **从不是本 App**。

### (b) 27.2 的修复点 = user client 上的 `+0xf1` 粘滞标志 —— 【静态】

`+0xf1` 字节访问（`ldrb`/`strb` 带立即数 `0xf1`）：**27.0.1 = 0 处，27.2 = 2 处**。

| 角色 | 27.2 精确地址 | 指令 |
|---|---|---|
| 注册侧读门 | **`0xa394500`** | `ldrb w8,[x21,#0xf1]` → `tbz w8,#0 → 继续`；命中则 `add w20,w20,#0x1b` → **`0xE00002D8` `kIOReturnNotAttached`** |
| 拆除侧写标记 | **`0xa394774`**（函数入口 `0xa394744`，`bti c`） | `strb w8,[x20,#0xf1]`，`w8=1`，在加锁后**紧接着**执行 |

> 关于 `0xa394744` vs `0xa394774`：**两个都对，粒度不同**。`0xa394744` 是函数入口（`bti c`），`0xa394774` 是其中写标记那条指令。

拆除侧结构（27.2）：
```
0xa394744  bti c
0xa394760  mov  x20,x1                ; x1 = self（user client）
0xa394768  ldr  x0,[x0,#0x150]        ; root 锁
0xa39476c  bl   lock
0xa394770  mov  w8,#1
0xa394774  strb w8,[x20,#0xf1]        ; ★ 先打永久标记，再摘链
0xa394778  ldr  x21,[x19,#0x188]
0xa39478c  ldr  x8,[x21,#0x58] ; cmp x8,x20
```

注册侧查重（27.2）：`0xa394518 ldr x9,[x22,#8]` / `0xa39451c ldr x10,[x8,#0x20]` / `cmp` / `0xa39452c cmp [x8,#0x58],x21` —— 与 27.0.1 同构。

### (c) 为什么标志在 `+0xf1` 而不在 `+0xf0` —— 【静态·逐字节核对】

**更正此前一条错误表述。** 拆除路径的清门是**单字节写**，不是字写：

```
27.0.1 0xa34b2dc  ldrb w8,[x0,#0xf0] ; tbz w8,#0 -> 整段跳过
27.0.1 0xa34b308  ldr  x16,[x21,#0xf8]!      ; x21 = obj+0xf8
27.0.1 0xa34b30c  sturb wzr,[x21,#-8]        ; ★ 只清零 obj+0xf0 这 1 个字节
```

所以「析构 `str wzr` 会清掉 `+0xf1`」这个理由**不成立**：`sturb` 只碰 `+0xf0`。

**真实原因**：`+0xf0` 是**可重置的当期门**（拆除时由该函数自己清掉），`+0xf1` 是**粘滞位**。粘滞位必须放在 `+0xf1`，否则拆除函数自己那句清门写会把它刚想保留的状态一起擦掉。二者语义不同，不是位宽问题。

（另有一处**字写**清零，在析构路径：`0xa343790 str wzr,[x19,#0xf0]` → 覆盖 `+0xf0..+0xf3`。但该路径运行时对象已在回收，标志已无意义，不参与判定。）

### (d) 选择子调用契约 —— 【实测，120 次一致】

| 选择子 | 形态 | 参数要求 | 违反的后果 |
|---|---|---|---|
| `sel17` 注册 | **必须异步** | `referenceCnt≥1`、ref 非空（handler `ldr x1,[args+0x10]; cbz → 0xE00002C2`） | 同步调用恒 `0xE00002C2` |
| `sel18` 注销 | **必须同步** | `scalarIn=0`、`structureInput` **精确 24 字节**、无输出 | 异步调用被 IOKit 前置校验挡在 handler 外，返回 `0xE00002C2` |

**两种失败返回码相同**，无法从返回码区分「参数形态错」与「未匹配到节点」—— 这是本项目此前两轮误判的直接原因。

### (e) 唯一实测正例：27.0.1 允许对已注销 user client 再注册 —— 【实测】

同一连接、同一 `structureInput={1,2,3}`：

```
1  sel17(异步) = 0x0            SUCCESS
2  sel17(异步) = 0xE00002C9     dup（证明节点在表里）
3  sel18(同步) = 0x0            SUCCESS —— 注销成功
4  sel17(异步) = 0x0            SUCCESS —— ★ 27.0.1 不做「已注销」检查
```
三种独立实施共 **120 次全一致**（`seq4I` 20、`replant2K1` 40、`replant2J` 40、`replantG` 60 中的对应段）。
**27.2 应在此处返回 `0xE00002D8` —— 该推论为静态，无 27.2 真机验证。**

### (f) 字段归属按对象类分开 —— 【静态】

- **IOSurface（surface 对象）**`+0xd8`：引用计数 count1。
- **注册表节点**`+0x20` = key（`*(u64*)(structureInput+8)`）、`+0x58` = **owner（user client）**。
- **user client**`+0xf0` = 当期门（字节）、`+0xf1` = 粘滞位（27.2 新增）、`+0xd8` = 对象内部锁指针。

> 崩溃点 `[x0+0xd8]` 取到的是 **user client 的锁指针**，不是 surface 的计数。此前把 `+0x58` 误标为 surface 是错的，已更正。

## 18.2 阴性清单（12:30 之后，全部零 panic、零卡死）

| 家族 | 用例数 | 有效性 |
|---|---|---|
| postclose | 40 | 有效 |
| lockdeg | 1900 | 有效 |
| 5 种最小顺序 | 40 | 有效 |
| spray32 / spray48 | 8 / 10 | 有效 |
| big | 12 | 有效 |
| 四段配方（冷启动） | 2 轮 | 有效 |
| dualF（双引用倒序释放） | 60 | 有效 |
| replant（注册/注销/再注册） | 60 | 有效 |
| replant2K1 / 2J（+close+双引用，lookup 非空 40/40、gid 真实） | 80 | 有效 |
| Metal（**真实 GPU 提交，`status=4` 40/40**） | 40 | 有效 |
| 双 App 并发 churn（A/B 不同 bundle id，B 确认跑满 40/40） | 1 轮 | 有效 |
| 原版二进制 `main.m.bak` 热机 churn 3 轮 | 3 轮 | **前提已被证伪**（历史是冷启动），数据保留但不当结论 |
| 原版二进制冷启动 | 3 轮 | **仅 1 轮有效**；另 2 轮 `devicectl` 启动失败（DDI 未就绪），作废 |
| 原版二进制 + 轮询移植冷启动 | 0 | 未取得（设备掉线） |
| **`V_TEARREG`（teardown ∥ register 竞态）** | **0** | **见 18.3** |

## 18.3 未取得有效数据的部分

**`V_TEARREG`：0 条有效用例。** 已实现并编译通过（8 个 `spamSel17` 线程 + `mach_port_mod_refs` 延长存活 + 偏移 0/50/100/200/500 µs + close 后 2000 µs 窗口 + lookup/release 触发 walk），实测只跑到「App 已启动、panic 未增」这一步，ndjson 中**该变体完成记录为 0**。

三种可能**尚未区分**：
1. `openConn` 在该变体里失败，未进入竞态段
2. 进程被 8 个注册线程与 teardown 竞争搞死（未产生 panic）
3. ndjson 未取回，脚本把「文件缺失」与「无匹配记录」都打印成 `完成=0`

**这一条不是阴性，是实验未执行，不计入任何结论。**

## 18.4 已撤回结论（防止被引用）

| 撤回项 | 原因 |
|---|---|
| 「崩溃发生在 `IOServiceClose`」 | 崩溃任务是 `avconferenced`/`kernel_task`，从不是本 App |
| 「postclose 种下雷」 | `MIG_BAD_ARGUMENTS` ⇒ `#799` 从未执行，没有节点被插入 |
| 「命中率漂移」 | 没有分母，不可量化 |
| §9「归因最终版 = postclose + lockdeg」 | 已撤回 |
| 「选择子编号错了」 | 映射正确；错的是调用形态（`sel18` 必须同步） |
| 「热机 12 分钟是历史配置」 | `ResetCounter` 一一对应证明每次命中都发生在重启后数分钟内，历史是冷启动 |
| 「析构 `str wzr` 清掉 `+0xf1`，所以标志只能放 `+0xf1`」 | 拆除侧是 `sturb` 单字节写；真实理由是「可重置门 vs 粘滞位」语义分离 |
| `lockdeg-N1-I0100` / `I0183` 是崩溃点 | 是孤立行，不是崩溃点 |

## 18.5 结论（一句话版本）

> **该 UAF 在 iOS 27.0.1 上客观存在**（5 次同点指纹、27.2 已用 user client 上的 `+0xf1` 粘滞标志修复），
> **12:11 之前从未在设备上出现过**（此前 108 份崩溃报告零 panic），即由本次会话触发；
> **但无法重建那个确切的首次状态** —— 原版二进制 + ndjson 还原的计划 + 冷启动立即跑 + 双 App，仅取得 1 个有效样本且为阴性；
> **唯一可控的实测成果是「27.0.1 允许对已注销 user client 再注册」**（120 次一致，27.2 用 `+0xf1` 封堵），
> **且该动作在纯用户态不转化为内存破坏**（2000+ 用例、6 类机制家族、含 Metal 真实 GPU 提交，零 panic）。
> `teardown ∥ register` 竞态尚未取得任何有效数据点。
