# AUDIT-DCP-DUALPIPE — AppleMobileDispH18P-DCP 双管状态机审计（27.0.1 → 27.2）

```
样本 : out/v2701|v272/driver_AppleMobileDispH18P-DCP.macho  (705,568 B → 713,792 B)
边界 : LC_FUNCTION_STARTS，基址 __TEXT.vmaddr，自证 A[0]==__TEXT_EXEC.vmaddr（两版均 True）
函数 : 27.0.1 = 1460，27.2 = 1484（+24）
配对 : 字符串引用多重集签名 → 唯一配对 117，仅 27.2 新增 10，仅 27.0.1 独有 4
结论 : 新双管状态机 4 个函数全部定位；27.0.1 的 swap_start 缺 secondary 合法性闸（逐指令给出）；
       竞态候选在 modeset 路径（跨管无同步）；但 AppleCLCD2 → 本条代码的 selector 路径未建立。
未证 : 内核侧是否经 shim 虚表 0x598/0x5d8 调进来（kernelcache 无符号表，留白）
```

---

## 0. 方法自证与不可越界的留白

| 项 | 值 |
|---|---|
| 27.0.1 `__TEXT` | `0xfffffe0007651180` vmsize `0x8e3c` |
| 27.0.1 `__TEXT_EXEC` | `0xfffffe00091fe310` vmsize `0x25ed0` |
| 27.2 `__TEXT` | `0xfffffe000765c350` vmsize `0x98eb` |
| 27.2 `__TEXT_EXEC` | `0xfffffe0009245aa0` vmsize `0x27138` |
| `LC_FUNCTION_STARTS` | 27.0.1 `off 0x57bf8 size 0x6e0`；27.2 `off 0x59b60 size 0x700` |
| 首项 == `__TEXT_EXEC`.vmaddr | 27.0.1 `0xfffffe00091fe310` ✔；27.2 `0xfffffe0009245aa0` ✔ |
| 指针解码 | `va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)`，**未**按 bit63 过滤 |
| `LC_SYMTAB` | 两版 `nsyms = 0`（全剥符号） |
| `LC_DYLD_INFO` / exports trie | **不存在** → 无导出符号，外部 kext 无法按名调用 |

`strings(1)` 对这两个文件会报 `section 0 offset extends past the end of the file`：
文件是按段表重组的，节头偏移非法但段 `fileoff/filesize` 有效，故所有字符串扫描均走
原始字节 + 段表映射，不走 `strings`。

**留白项（不猜）**：`0xac2475c / 0xac25344 / 0xb32b338 / 0xb32b404` 四个外部桩在
`out/stubs-named.json` 里查不到 VA，`out/kernelcache.27.2` 亦无符号表，故只按行为命名，
不给符号名。

---

## 1. 新函数定位结果

全部以 `__PRETTY_FUNCTION__` 风格字符串的**代码引用点**定位（不是就近猜测）。

| 27.2 VA | 长度 | 身份 | 判定依据 |
|---|---|---|---|
| `0xfffffe00092674b0` | `0x23c` | `establish_dual_pipe_pairing` | 引用自身名字串 `0x76655ff`（作 `%s`）+ `AED grow`(0x7665675) + `peer pipe index`(0x76655b7) + `paired primary fb`(0x76656ff) |
| `0xfffffe00092676ec` | `0x11c` | `teardown_dual_pipe_pairing` | 引用 `0x76657bd` + `AED teardown-pairing: …`(0x7665731/0x766575d/0x766578d) |
| `0xfffffe0009259620` | `0x268` | `establish_dual_pipe_shim_state` | 引用 `0x7661faa` + `null secondary`/`no tiling manager`/`not plugged, refusing to pair`/`VFTG merge, skipping re-pair` |
| `0xfffffe0009259920` | `0x1a0` | `teardown_dual_pipe_shim_state` | 引用 `AED tore down dual-pipe shim state`(0x766210f / fmt 0x76620d8)；由 `teardown_dual_pipe_pairing` 尾跳进入 |
| `0xfffffe0009267808` | `0xec` | tiling-mgr 配对原语（被 shim_state 调用） | `0x92597e0 bl` |
| `0xfffffe00092678f4` | `0xdc` | tiling-mgr 解配原语 | `0x9259a2c bl` |
| `0xfffffe0009259888` | `0x98` | 锁作用域计时（`%s: lock held %llu us`） | 唯一引用该串 |
| `0xfffffe000925b0e0` | `0x1c0` | **swap 路径**（含 `rejected swap_start`） | 引用 `0x76627d5` |
| `0xfffffe000925e4dc` | `0x21b0` | `set_digital_out_mode` | 引用 `Aborting set_digital_out_mode after dual pipe teardown on %d…`(0x766348a) |

### 1.1 关键字符串引用点（直接回答"引用点在哪"）

```
dual pipe: rejected swap_start on secondary fb %u (client %p)   0x76627d5 → 0x925b0e0 @ 0x925b268
AED grow: primary fb %u -> secondary fb %u …                    0x7665675 → 0x92674b0 @ 0x9267638
Aborting set_digital_out_mode after dual pipe teardown on %d …  0x766348a → 0x925e4dc @ 0x925ec4c
```
（地址取 `add x0, x0, #imm` 那条指令，即真正拼出字符串地址的位置。）

### 1.2 为什么这两个函数"没有调用者"——必须先说清

`establish_dual_pipe_pairing` / `teardown_dual_pipe_pairing` 在本 kext 内：

* `bl`/`b` 调用者 = **0**（全 1484 个函数扫过）
* 唯一引用是 `__DATA_CONST` 的函数指针表，且**相邻两个槽**：
  `0xfffffe000813b6f0 → 0x92674b0`、`0xfffffe000813b6f8 → 0x92676ec`
* 该表基址 `0xfffffe000813b590`（由 3 个构造函数写入对象 `+0`，见 `0x92647d8` /
  `0x9264838` / `0x92649b8` 三个构造函数里的 `str x16,[x0]`：`0x926480c` / `0x926486c` /
  `0x92649f8`）
* 故槽位：`0x813b6f0-0x813b590 = 0x160`，`0x813b6f8-0x813b590 = 0x168`
* **全 binary 内不存在任何 `mov x17,#0x160` / `#0x168`**（operand 扫描，两版均 0 条）。
  `#0x160]` 形式的指令在两版各 6 条，全部是字段读或栈存取，无一是虚表派发：
  `0x925b3c0 ldr x0,[x21,#0x160]`、`0x925b63c`/`0x925b654 ldr x0,[x20,#0x160]`、
  其余三条是 `[sp,#0x160]` 的 stp/ldp/stp。`#0x168]` 形式：**0 条**。
  （判据 #4/#5 复核：带 `!` 的前索引如 `ldr x8,[x16,#0xd8]!` 才是虚表槽，此处均无 `!`。）

同理 `establish_dual_pipe_shim_state` 的唯一调用者就是 `establish_dual_pipe_pairing`
（`0x926768c bl`），`teardown_shim_state` 的唯一入口是 `teardown_dual_pipe_pairing`
的尾跳（`0x92677ac b`）。

⇒ **这条状态机在本 kext 里只能经虚表进入，而槽位 0x160/0x168 在本 kext 内无派发点。**
结论只能写到"由外部（内核 IOMobileFramebuffer 框架）驱动"，再往前一步缺证据。

### 1.3 数据结构（由 1.1 的代码反推，全部有指令支撑）

`IOMobileFramebufferTilingMgr`（vptr `0x813b590`）：

```
+0x00  vptr
+0x0c  u8
+0x10  u32
+0x18  ptr
+0x20  record[16]         ; 构造时 memset 0x600 = 16*0x60，与 cmp w1,#0x10 吻合
        每项 96 B:
        +0x00 u32  secondary fb 索引
        +0x08 ptr  peer shim（带 PAC，disc 0xc8a2）
        +0x10 u8   flags，bit4 = "已配对"
vtable:  slot 0x160 = establish_dual_pipe_pairing
         slot 0x168 = teardown_dual_pipe_pairing
```

`IOMobileFramebufferShim`（vptr 由构造写入，disc `0xcda1`；偏移两版相差 +8，见 §2.1）：

```
+0x58e8  log 通道
+0x61b8  fTilingMgr        (27.0.1: +0x61b0)
+0x61c0  peer shim         (27.0.1: +0x61b8)
+0x61c8  extra pipe[]      (27.0.1: +0x61c0)
+0x61e8  extra pipe 计数 u8 (27.0.1: +0x61e0)
+0x65ac  u8                (27.0.1: +0x65a4)
+0x65ae  u8  bit0          (27.0.1: +0x65a6)
+0x65bc  u8  bit0          (27.0.1: +0x65b4)
+0x65bd  u8  bit0          (27.0.1: +0x65b5)
+0x65d1  u8  "已配对/已并入 VFTG"  (27.0.1: +0x65c9)
+0x65d4  u32 状态字 = 3 当双管建立  (27.0.1: +0x65cc)
+0x65e0  每-shim 锁对象   (27.0.1: +0x65d8)
+0x5df1  u8  bit0 = "我是 secondary"   ← 两版**相同**（不在 +8 位移区内）
```

`+0x5df1` 的语义由写入方确认：`0x9259ac0 @0x925a15c str x0,[x19,#0x61c0]` 建立 peer 后，
`x9 = peer + 0x5df1; strb #1, [x9]`（0x925f758 一处）——即**往对端写"你是 secondary"**；
拆除侧 `strb wzr,[x9]`（0x92591a0 / 0x9259d00 / 0x9259e60 / 0x9259ffc）成对清除。

### 1.4 锁的真实身份（有串支撑，不靠猜）

| 桩 | GOT 槽 | 目标 | 判据 |
|---|---|---|---|
| `0x926bdc8` | `0x813c948` → `0xac2475c` | 全局锁 | 与 `0x926bdd8`(`0xac25344`) 在 18 个函数里严格成对，`teardown_dual_pipe_pairing` 里只夹住 `ldr w22,[x21]; ldrb w21,[x21,#0x10]` 两条读 |
| `0x926bdd8` | `0x813c950` → `0xac25344` | 全局解锁 | 同上，18/18 平衡 |
| `0x926be58` | `0x813c990` → `0xb32b338` | **每-shim 锁** | 参数恒为 `[shim+0x65e0]`；配对的 `0x9259888` 打印 `%s: lock held %llu us` |
| `0x926be68` | `0x813c998` → `0xb32b404` | 每-shim 解锁 | 同上 |

两把锁**互不相干**：`swap_start` 只拿每-shim 锁（`0x65e0`），从不碰全局锁；全局锁只保护
tiling-mgr 的 `record[16]`。

---

## 2. 27.0.1 的无保护路径（逐指令 + 数据流）

### 2.1 先钉死"这是重排不是改逻辑"

配对（字符串签名唯一）给出 4 个发生增长的函数，其余 117 个唯一配对签名完全一致：

| 27.0.1 | 长度 | 27.2 | 长度 | Δ |
|---|---|---|---|---|
| `0x9213314` swap 路径 | `0x168` | `0x925b0e0` | `0x1c0` | `+0x58` |
| `0x92165bc` `set_config_requires_dual_pipe` | `0xe0` | `0x925e3c0` | `0x11c` | `+0x3c` |
| `0x921669c` `set_digital_out_mode` | `0x1b44` | `0x925e4dc` | `0x21b0` | `+0x66c` |
| `0x921ee94` display-wall 配置 | `0xfc` | `0x9267330` | `0xfc` | `0`（仅共享串被并入，非改动） |

**锚点**：`set_config_requires_dual_pipe` 两版是同一个函数、同一条消息
（`%s: fTilingMgr is NULL`），只有偏移变了：

```
27.0.1  0x92165d4  ldr x19,[x0,#0x61b0]    ; fTilingMgr
27.2    0x925e3d8  ldr x20,[x0,#0x61b8]    ; fTilingMgr   ← +8
```

同一函数里 `swap` 侧：
```
27.0.1  0x9213368  ldr x0,[x19,#0x61b8]    ; peer shim
27.2    0x925b124  ldr x8,[x19,#0x61c0]    ; peer shim    ← +8
```
⇒ `(fTilingMgr, peerShim)` 这对相邻字段整体 `(0x61b0,0x61b8) → (0x61b8,0x61c0)`。
左侧所有 0x65xx 偏移同样 +8（`0x65d8→0x65e0`、`0x65b5→0x65bd`、`0x65a6→0x65ae`、
`0x61e0→0x61e8`）。`0x5df1` **未**位移 ⇒ 插入点在 `(0x5df1, 0x61b0)` 区间内新增 8 B。

**这条锚点很重要**：不先钉死重排，就会把 `0x61b8→0x61c0` 误读成"换成另一个对象"，
从而编出一个 27.0.1 把 swap 提交给 tiling manager 的假结论。判据 #3。

### 2.2 27.2 新增的那一段（原文）

```
0x925b110  mov  x19, x0              ; x19 = shim
0x925b114  mov  w8, #0x5df1
0x925b118  add  x25, x0, x8          ; x25 = &shim[0x5df1] = &"我是 secondary"
0x925b11c  ldrb w8, [x25]            ; (1) 读自身 secondary 标记
0x925b120  tbz  w8, #0, 0x925b12c    ; 不是 secondary → 正常路径
0x925b124  ldr  x8, [x19, #0x61c0]   ; (2) 读自身下游 peer
0x925b128  cbz  x8, 0x925b238        ; peer 为空 → 拒绝
```

拒绝分支：
```
0x925b238  ldr  x16,[x19]                       ; vptr
0x925b240  movk x17,#0xcda1,lsl#48 ; autda      ; disc 0xcda1 = shim 类
0x925b248  mov  x17,#0x848 ; add x16,x16,x17
0x925b250  ldr  x8,[x16]
0x925b25c  blraa x8, x16                        ; vtable[0x848] = 取 fb 号
0x925b260  stp  x0, x20, [sp]                   ; 参数 fb, client
0x925b268  x0 = 0x76627d5                       ; "dual pipe: rejected swap_start on secondary fb %u (client %p)"
0x925b270  mov  w0,#0x2e2 ; movk w0,#0xe000     ; 返回 0xe00002e2
```

### 2.3 27.0.1 对应位置什么都没有，直接进 submit

27.0.1 同函数（`0x9213314`）从函数入口一路到 submit，**没有**上面 6 条：

```
0x921333c  mov  x22, x2
0x9213340  mov  x21, x1
0x9213344  mov  x19, x0                    ; shim
0x9213348  ldr  x0, [x0, #0x65d8]          ; 每-shim 锁对象（27.2: 0x65e0）
0x921334c  bl   0x9223460                  ; LOCK
0x9213350  mov  x0, x19
0x9213354  mov  x1, x21
0x9213358  mov  x2, x22
0x921335c  bl   0x9223690                  ; ★ submit(shim, args) —— 无任何 secondary 合法性检查
0x9213360  mov  x20, x0                    ; 主状态
0x9213364  ldr  w25, [x21]                 ; swapID 快照
0x9213368  ldr  x0, [x19, #0x61b8]         ; peer shim（27.2: 0x61c0）
0x9213370  cbz  x0, 0x92133ac              ; 无 peer → 跳过扇出
0x9213374  mov  w8, #0x5df1
0x9213378  add  x8, x0, x8                 ; peer + 0x5df1  ← 注意是 peer 的标记
0x921337c  ldrb w8, [x8]
0x9213384  tbz  w8, #0, 0x92133ac
0x921338c  cbnz w20, 0x92133ac             ; 主提交失败则不扇出
0x9213390  mov  x1, x21
0x9213394  mov  x2, x22
0x9213398  bl   0x9223690                  ; ★ 同一次 submit 再打到 peer
0x921339c  ldr  w8, [x21]
0x92133a0  cmp  w8, w25
0x92133a4  b.ne 0x9213458                  ; swapID 变了 → "mismatched swapID's %d vs %d"
...
0x9213428  ldr  x0, [x19, #0x65d8]
0x921342c  bl   0x9223470                  ; UNLOCK
```

**数据流**：
1. `args`（x1）里带 swapID；`[x1]` 是 swapID 字（`ldr w25,[x21]`，`ldr w8,[x21]` 前后比对）。
2. `submit` 被调用 1 + N 次：自己、peer（若 `peer[0x5df1]` bit0 置位）、以及
   `shim[0x61e0]` 个 extra pipe（循环 `0x92133e0..0x9213424`，每项
   `ldr x0,[x28, x27, lsl #3]` 后再 submit）。
3. 每次扇出后 `[x1]` 必须仍是同一个 swapID，否则记 `mismatched swapID's %d vs %d`
   （这是 27.0.1 **已有**的一致性检查，不是新增）。
4. 返回值取第一个非零（`cmp w23,#0 / ccmp w0,#0,#4,eq / csel w23,w0,w23,ne`）。

**27.2 里"紧跟新增调用之后的操作"**（= 27.0.1 缺少保护的路径）：
新增拒绝块之后的落点 `0x925b12c` 就是
```
0x925b12c  ldr  x0,[x19,#0x65e0]      ; LOCK
0x925b140  bl   0x926c088             ; ← 就是 27.0.1 的 0x9223690（submit）
0x925b14c  ldr  x0,[x19,#0x61c0]      ; peer
0x925b178  bl   0x926c088             ; peer 扇出
```
即：**27.0.1 缺的那道闸，保护的正是 `submit` 本身。** 一个被标成 secondary 且没有下游
peer 的 shim，在 27.0.1 里会毫无阻力地执行 `submit`（把自己当一个正常 framebuffer 提交
swap），并且继续走完 extra-pipe 扇出循环。

### 2.4 `set_config_requires_dual_pipe` 的差异：**只有一条诊断，逻辑完全没变**

这条要特别说清，因为很容易误判成"加保护"。两版是同一个函数，`Δ = 0x3c`：

**27.0.1（完整 0xe0 B，可控）**
```
0x92165d4  ldr   x19, [x0, #0x61b0]      ; fTilingMgr
0x92165d8  cbz   x19, 0x9216670          ; NULL → log "%s: fTilingMgr is NULL"
0x92165dc  mov   w8, #0xaa ; strb w8,[sp,#0x13]   ; out 参置哨兵 0xaa
0x92165e4  mov   w8, #-0x55555556 ; stur  w8,[sp,#0x14]   ; 其余 out 区填 0xaa
0x92165f4  ... shim->vtable[0x848] → x1 = fb id
0x921661c  mov   x17, x19 ; ldr x16,[x19] ; movk x17,#0xcda1,lsl#48 ; autda
0x921662c  xpacd x17 ; cmp x16,x17 ; b.eq ; brk #0xc472      ; arm64e 完整性校验
0x9216640  add   x8, x16, #0x158
0x9216644  ldr   x9, [x16, #0x158]       ; tiling_mgr->vtable[0x158]
0x9216648  add   x2, sp, #0x13           ; x2 = &out
0x9216650  mov   x17, x8 ; movk x17,#0xaac0,lsl#48
0x9216658  blraa x9, x17                 ; (tiling_mgr, fb_id, &out) → w0 = status
0x921665c  cmp   w0, #0
0x9216660  cset  w8, eq                  ; status==0
0x9216664  ldrb  w9, [sp, #0x13]         ; out.bit0
0x9216668  and   w0, w8, w9              ; 返回 (status==0) && out.bit0
```

**27.2（0x11c B）** 把 `cset/and` 换成显式分支，只多了一条日志：
```
0x925e460  blraa x9, x17                 ; 同一个 vtable[0x158]
0x925e464  cbz   w0, 0x925e4c4           ; status==0 → 0x925e4c4: ldrb w8,[sp,#0x13]; and w0,w8,#1
0x925e468  mov   x20, x0                 ; 失败：保存状态
0x925e46c  ... shim->vtable[0x848] → fb id
0x925e498  adrp  x0, 0x7663000
0x925e49c  add   x0, x0, #0x3f           ; "AED: fb %u could not read ADM pipe-count intent (0x%x); modesetting as single pipe"
0x925e4b8  bl    0x926bde8               ; log
0x925e4bc  mov   w8, #0                  ; → and w0,w8,#1 = 0
```

**判定：语义等价，`false` 的两种来源（status≠0 / out.bit0=0）两版都是 `false`。**
27.2 唯一新增的是 `0x925e468..0x925e4b8` 这段日志（正好 0x3c 字节）。
`Δ` 与字符串差集（该函数只多 1 条串、少 0 条）完全对得上。

⇒ 这条不能算"保护"，也**不能**算"放宽"。此前若把它当成 27.2 的加固点，属误判。

### 2.5 `set_digital_out_mode` 的差异（真正的竞态面）

27.2 该函数新增 18 条消息、删除 4 条。删除的正是 27.0.1 的**纯计时**日志：

```
- %s: Merge Config: Primary VFTG enable time %dms
- %s: Primary modeset time %dms
```
新增的是一整套**跨管同步 + 状态闸**：

```
+ Dual pipe: fb %u waiting for primary VFTG link check, timeout %u ms        (0x925fe30)
+ Dual pipe: fb %u primary VFTG link check done in %u ms, localStatus %u     (0x925ffac)
+ Dual pipe: fb %u issuing secondary modeset on fb %u (timing %u color %u)   (0x9260338)
+ Dual pipe: fb %u waiting for primary modeset thread, timeout %u ms         (0x92603c4)
+ Dual pipe: fb %u primary modeset thread finished in %u ms, status 0x%x     (0x9260504)
+ Aborting set_digital_out_mode after dual pipe teardown on %d. HPD dropped during teardown, dual pipe timing cannot run on one pipe.   (0x925ec4c)
+ Skipping redundant modeset (timing=%u, color=%u)                            (0x925f284)
+ modeset: fb %u is_dual=%d adm_forced=%d vftg_cfg=%d paired=%d hpd_dual_ok=%d timing=%u color=%u (%ux%u@%uHz)   (0x925e9e8)
```

两版**同类位置**的对照（证明"等"这件事原来就有，但只等硬件，不等对端）：

```
27.0.1  0x9217bfc  cmp  w8, w23
        0x9217c00  b.ne 0x9217c28
        0x9217c04  cmp  w28, #0x65          ; 100 ms 预算
        0x9217c08  b.lo 0x9217dfc
        0x9217c10  lsl  w8, w28, #1         ; ms*2
        0x9217c20  "Merge Config: Primary VFTG enable time %dms"
```
```
27.2    0x925ff60  cmp  w8, w28
        0x925ff64  b.ne 0x925ffb4
        0x925ff94  lsl  w8, w20, #1
        0x925ff9c  cbz  x21, ...
        0x925ffac  "primary VFTG link check done in %u ms, localStatus %u"
```
同形状、同 `lsl #1`、同预算常量 —— 27.2 只是把 `localStatus` 加进了消息。**所以"轮询
VFTG 使能"不是 27.2 新加的**。27.2 真正新加的是另外两处：

```
0x925fe30  "waiting for primary VFTG link check, timeout %u ms"   ; secondary 侧等 primary
0x92603c4  "waiting for primary modeset thread, timeout %u ms"    ; secondary 侧等一个线程
0x9260504  "primary modeset thread finished in %u ms, status 0x%x"
```
⇒ **27.0.1 里 primary 与 secondary 的 modeset 都在调用者线程里内联跑完，二者之间没有任何
等待、也没有 `paired` / `hpd_dual_ok` 这道状态闸。** 27.2 把 primary modeset 挪到线程里，
并让 secondary 侧带超时地等它。

`Aborting … HPD dropped during teardown` 的闸是一条栈上字节（`ldrb w8,[sp,#0xcf]; tbz
w8,#0,0x925ef9c`，`0x925ec14`），命中就整段中止、不打 VFTG/merge 时序。

---

## 3. 竞态窗口的具体形态

### 3.1 形态 A —— 跨管 modeset 竞态（与公告 "race condition" 对得上）

| 项 | 内容 |
|---|---|
| 执行流 1 | 线程 T1：对 **primary fb** 调 `set_digital_out_mode`（27.0.1 `0x921669c`，27.2 `0x925e4dc`），跑到 VFTG 使能 + merge config 编程 |
| 执行流 2 | 线程 T2：对 **secondary fb** 调同一函数，跑到自己那份 VFTG 使能轮询 |
| 共享状态 | ① VFTG/merge 硬件寄存器组（两管共用一套 merge 配置）<br>② `shim[0x5df1]`（谁是 secondary）<br>③ `shim[0x61b8]/[0x61c0]` peer 链<br>④ tiling-mgr `record[16]`（`+0` sec_fb / `+8` shim / `+0x10` bit4 paired）<br>⑤ `shim[0x65c9..0x65cc]`（27.2: `0x65d1..0x65d4`）配对标志与状态字 |
| 27.0.1 缺的校验 | ① 没有 `paired` / `hpd_dual_ok` / `vftg_cfg` / `adm_forced` 这组输入闸（27.2 才在 `0x925e9e8` 一次性快照并据此分流）<br>② 没有"secondary 侧等 primary 的 VFTG link check / modeset 线程"（27.2 `0x925fe30` / `0x92603c4`）<br>③ 没有"teardown 期间 HPD 掉了就不许跑双管时序"（27.2 `0x925ec4c`）<br>④ 没有 redundant modeset 去重（27.2 `0x925f284`） |
| 27.0.1 缺的锁 | 两管路径之间**没有**任何互斥：全局锁只护 tiling-mgr 数组；每-shim 锁（`0x65e0`/`0x65d8`）是 per-object，T1 拿 A 的锁、T2 拿 B 的锁，互不阻塞 |
| 后果方向 | 两管同时编程同一套 merge/VFTG 状态 → 谁后写谁赢；secondary 可能以自己那份（未与 primary 对齐的）时序完成 link check，从而在 merge 尚未成立时被当作已配对 |

### 3.2 形态 B —— 27.2 的 establish 侧读记录不持全局锁（残留在"已修复"版本里）

`teardown_dual_pipe_pairing` 读 `record[fb]` 时**持**全局锁：
```
0x926775c  adrp x23, 0xb951000
0x9267760  ldr  x0, [x23, #0xe90]   ; 全局锁对象 = __DATA+0xe90
0x9267764  bl   0x926bdc8           ; LOCK
0x9267768  ldr  w22, [x21]          ; record+0x00  sec_fb
0x926776c  ldrb w21, [x21, #0x10]   ; record+0x10  flags
0x9267770  ldr  x0, [x23, #0xe90]
0x9267774  bl   0x926bdd8           ; UNLOCK
0x9267778  tbz  w21, #4, 0x92677d0  ; bit4 = 已配对
```
`establish_dual_pipe_pairing` 读同一份记录**完全不持锁**（它的 `bl` 目标里没有
`0x926bdc8 / 0x926bdd8` 任一），随后把读到的 shim 指针交给
`establish_dual_pipe_shim_state`。真正改数组的 `0x9267808 / 0x92678f4` 倒是**都**持该
全局锁的。

⇒ 记录数组的"读"在 establish 侧是无锁的，`fb` 索引与 `record[fb].shim` 之间可被
`0x92678f4` 改掉。这是 27.2 内部的残余 TOCTOU，与公告所指的 27.0.1 缺陷是两件事，
但值得记一笔。

### 3.3 形态 C —— 27.2 的 swap 闸在锁外求值

`swap_start` 的新闸（`0x925b114..0x925b128`）在 `0x925b12c` 取每-shim 锁**之前**求值，
而闸门保护的 `submit` 在锁内、且锁内会**重新读** `shim[0x61c0]` 再判一次。
所以并发 teardown 清 `0x61c0` 时不会走到 UAF（扇出侧会看到 NULL 跳过），
最坏是**偶发假拒绝**（`0xe00002e2`）。27.0.1 侧因为整段都在锁内，反而不存在这个假拒绝，
但它也就没有那道闸 —— 两版在这里是"一个拿锁换保护、一个拿保护换锁外求值"的取舍。

---

## 4. 可达性

### 4.1 已核实的硬障碍

```
com.apple.driver.AppleMobileDispH18P-DCP :  funcs 1460  tables 0  sels 0
```
（`out/census.json` 的 `kexts` 行，原文照抄）

`tables = 0, sels = 0` ⇒ **这个 kext 自身没有 IOExternalMethod 分发表**。
`out/census.json` 的 2266 条 `rows` 里也没有一条 `kext` 等于本 kext。

### 4.2 swap / modeset 两个入口的槽位

shim 类 vptr（disc `0xcda1`）由构造函数写入；`swap_start` 与 `set_digital_out_mode`
在 `__DATA_CONST` 里各只有一个槽：

```
swap_start            0x925b0e0 → 槽 0xfffffe000813ac90
set_digital_out_mode  0x925e4dc → 槽 0xfffffe000813acd0
set_matrix            0x925db54 → 槽 0xfffffe000813ad60
```
（27.0.1 对应 `0x8124958 / 0x8124998`）

在这两个槽偏移上，本 kext 内**没有**任何派发点：

* `mov x17,#0x598` 命中 5 处（`0x9248c1c / 0x9248f28 / 0x92523ac / 0x9252708 / 0x926a8b0`），
  但全部是 **disc `0x8bc0`** 的另一个类（接收者是 `[shim+0x5e90]`，见
  `0x9253fd4 ldr x0,[x0,#0x5e90]`）——不是 shim。判据 #5：靠 disc 区分，不靠偏移撞车。
* `0x5d8` 偏移在本 kext 只有一条 `strb wzr,[x22,#0x5d8]`（字段写）。

### 4.3 因此可达性只能这样写

* `AppleCLCD2` 实测可 `open`（type 0/1/2/3）是事实，但它给你的是 **IOKit 服务句柄**；
  本 kext `sels=0`，**没有任何 selector 能落在本 kext 的 swap / modeset / pairing 代码里**。
* `swap_start`（槽 `0x598`）与 `set_digital_out_mode`（槽 `0x5d8`）都是
  `IOMobileFramebufferShim` 的虚函数，本 kext 内无调用者 ⇒ 只能由**内核里的
  IOMobileFramebuffer 框架**通过虚表调进来。那条链的 selector 活在
  `com.apple.kernel`（census：`tables 58, sels 210`），不在 DCP kext。
* **卡点**：`out/kernelcache.27.2` / `27.0.1` 均无符号表，我无法把内核侧
  "`mov x17,#0x598` / `#0x160` / `#0x168` + `add x16,x16,x17`" 的命中定位到具体函数，
  因为这些偏移在内核里分别出现 471 / 242 / 432 次（`0xcb0`/`0xcb8` 只有 4/5 次但不足以
  单独定案）。按判据 #6 不做频率推断，故这一步**留白**。

---

## 5. 直答

### 27.0.1 的 DCP 双管状态机有没有可被 app 触发的竞态？

**有竞态候选，但"可被 app 触发"这一环没有建立。**

**有的部分（有逐指令证据）：**

1. 27.0.1 **不存在** `establish_dual_pipe_pairing` / `teardown_dual_pipe_pairing` /
   `establish_dual_pipe_shim_state` / `teardown_shim_state` 这一整套配对状态机
   —— 两版字节计数 0→1，且字符串签名配对把它们判为"仅 27.2 存在"。
2. 27.0.1 的双管是**隐式**的：peer 链 `shim[0x61b8]` + 对端 `peer[0x5df1]` 一个 bit
   就是全部状态，没有 `paired` 状态字（27.2 的 `shim[0x65d4]=3`）、没有 `plugged` 校验
   （27.2 的 `not plugged, refusing to pair`）、没有 `VFTG merge` 去重
   （27.2 的 `fb already in VFTG merge, skipping re-pair`）。
3. swap 路径的无保护路径是确定的，在 `0x921335c`：一个"被标成 secondary、且没有下游
   peer"的 shim 会直接执行 `submit`，没有 27.2 在 `0x925b114..0x925b128` 的那道闸。
4. modeset 路径的竞态形态是确定的：27.0.1 里 primary / secondary 两个 modeset 都在调用者
   线程内联执行，彼此无等待、无 `paired`/`hpd_dual_ok` 闸、且两管不共用任何锁；27.2 改成
   primary 线程化 + secondary 带超时等待（`0x925fe30` / `0x92603c4` / `0x9260504`）。

**卡住的部分（说清读了哪些、卡在哪）：**

* 读了：两版 macho 的段表、`LC_FUNCTION_STARTS`（自证通过）、全 1484 个函数的
  `adrp+add` 常量与 `bl/b` 目标、`__DATA_CONST/__DATA` 全部 8 字节 fixup 槽、
  两版全部 282/308 条 `__TEXT` cstring 及其引用点、117 组唯一签名配对。
* 卡在：`establish/teardown_dual_pipe_pairing` 是 tiling-mgr 虚表 `0x813b590` 的
  slot `0x160`/`0x168`，`swap_start` 是 shim 虚表 slot `0x598`，`set_digital_out_mode`
  是 slot `0x5d8` —— **这 4 个槽在本 kext 内都没有派发点**，而本 kext `sels=0`、
  无导出符号、无 `LC_DYLD_INFO`。要接上"哪个 selector"必须解析内核侧
  `com.apple.kernel` 里 IOMobileFramebuffer 框架的调用点，而
  `out/kernelcache.27.0.1` / `27.2` 都是 `nsyms=0` 的剥符号镜像，现有资产不够。
  槽位偏移频率扫描（0x160 命中 242 次等）**不可用作证据**，已主动排除。

**给上层的一句话建议**：把"AppleCLCD2 可 open"当成"能打 DCP 双管"是跨了一层的推断。
下一步应当去 `com.apple.kernel` 里定位调用 shim 槽 `0x598`/`0x5d8` 的函数（镇定点：
`IOMobileFramebuffer` 的 modeset / swap 入口），或者换一个 `sels > 0` 且直接持有 shim
的服务（census 里 `IODisplayPortFamily` sels=33、`dual=true`）。
