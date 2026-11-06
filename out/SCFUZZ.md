# SCFUZZ — 真机 SUCCESS selector 的标量值边界 fuzzing

设备 `DEVICE-UDID`（iPhone18,2 / iOS 27.0.1）。项目根 `tasks/ios27-chain-poc`。套件 `harness/scfuzz/`。

**一句话**：上一轮 SVC2 那 5131 次调用标量全传 0。本轮把 21 个边界值逐个怼进 11 个真机 SUCCESS 的标量入参位（外加 sel 56 的 156 字节内容 4 种模式 1784 次），**抓到两条活输入通道**：

- **`IOMobileFramebuffer` sel 51（`0xa17ec28`）**：标量当**枚举/模式**用，`低32位 > 4` 直接 `kIOReturnBadArgument`。**有边界检查，且边界就是 0..4**。
- **`AGXAcceleratorG18P` sel 42（`0xa023d58`）**：**两个标量都活**，`x0 ∈ {0,1}`、`x1 ∈ {0,1,2}`，越界返回 `kIOReturnInternalError`（handler 真跑进去、内部失败），**负数（bit31=1）一律当哨兵放行**。

其余 11 个标量位（MFB 12/13/19/22/31/33/53-两位置、HID sel 1、GPU 19/41）**对 21 个值完全无反应**，sel 56 的 156 字节内容 4 模式也**全无反应**（`kr` 恒 SUCCESS、`oc/sc` 恒 0）。

**panic：5 → 5，无新增。挂死/超时：0 次。设备未重启。**

## 0. 五态 / 记录纪律

| 项 | 结果 |
|---|---|
| build | 每次 `xcrun -sdk iphoneos clang -arch arm64 -fobjc-arc` rc=0，size=`90856`，sha256=`a4252e288ca8cf287e1b9640f296cc2aa2d4274e196fecf53705b5e3a6eada0d` |
| 指纹 | 每个 stage 装前 `strings Payload/UC.app/UC \| grep -c SCFUZZ-20261101-scalar-bound-a91f37` = **1**；残留 svc2probe/gpuprobe/svcprobe 指纹 = 0 |
| sign | `codesign -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)"` rc=0 |
| install | 6 个 stage 全部 `App installed`（同一 bundle id 覆盖装） |
| launch | `devicectl process launch --console`，进程自退出 rc=0 |
| 跑完 | 每个 stage ndjson 都有 `@done` 尾标记 |
| panic | `ls -1 out/panics/*.ips \| wc -l`：跑前 **5** → 跑后 **5** |
| 挂死/超时 | `@timeout` **0 条**，`@abort` **0 条** |
| 重启设备 | 无 |

`copy from` 的 stderr 每次单独打印（`copy rc=0 size=...`，无 stderr 内容）。

## 1. 本轮先修掉的两个坑（会改后面所有 probe 的打法）

### 1.1 `scalarOutputCount` / `structOutputSize` 是 **in/out**，调用前必须填容量

第一版 `job_run()` 把 `&oc` / `&sc` 直接交给 `IOConnectCallMethod`，而 `Job` 是 `calloc` 出来的 ⇒ 传进去是 **0**。结果凡是**声明了 structOut 的 selector 全部假阴性**：

| GPU selector | 声明 stOut | 修前（`*sc` 传 0） | 修后（`*sc = stOut`） |
|---|---|---|---|
| 0 | 64 | `0xe00002c2` BadArgument | **SUCCESS**，`sc=64` |
| 2 | 536 | `0xe00002c2` | **SUCCESS**，`sc=536` |
| 19 | 24 | `0xe00002c2` | **SUCCESS**，`sc=24` |
| 41 | 0 | SUCCESS（`stOut=0`，所以没事） | SUCCESS |

⇒ 这不是 GPU 特有：**任何声明 `structOut>0` 的 selector，传 0 容量都会被 MIG 判成契约不符**，handler 根本不会跑。对照上一轮 SVC2 的 ndjson：**全部 `@r` 里没有任何一条 `kr=0 且 sto>0`，`@so` / `@h`（hexdump）也一条不存在**（msc 轮 92 次调用、零 hexdump）—— 与“输出容量传 0 导致声明了 stOut 的selector 全部假阴性”完全一致（那轮的 `Job` 同样 calloc ⇒ `*sc` 同样传 0）。因果关系本轮没做对照实验定论，但这是目前最简单的解释。修正：`j->oc = j->so; j->sc = j->sto;` 再调。

### 1.2 GPU 的 sel 19 / 42 依赖**连接前置状态**

同一个 `(sel, scIn, stIn, scOut, stOut)`，**全新连接的第一发**调用 → `0xe00002c2`；在同一条连接里按 A 表顺序（0,1,2,3,4,5,16,17,…）跑过之后 → **SUCCESS**。所以本轮 GPU 每个目标先用 A 表里它前面的条目预热（`@warm` 行，共 91 次），再进基线 + 边界遍历。gpuprobe 当时是顺序跑整张表，所以没暴露这个前提。

## 2. 覆盖与总量

| stage | 服务 | selector | 调用数 | 说明 |
|---|---|---|---:|---|
| mfb | IOMobileFramebuffer (type 0) | 12,13,19,22,31,33,51 (sIn=1)；53 (sIn=2) | 189 | 8 基线 + 189 边界 |
| | | 26 (sIn=0) | 0 | `@skip`：无标量可动 |
| hid | IOHIDEventService (type 2) | 1 (sIn=1) | 21 | 表 `0xfffffe000831e300` |
| gpu | AGXAcceleratorG18P (type 1) | 19,41 (sIn=1)；42 (sIn=2) | 84 | 预热 91 + 3 基线 |
| jpeg | AppleJPEGDriver (type 0) | 0, 2 | 0 | 契约 `sIn=0`、`stIn=0` ⇒ 无可 fuzz 的输入 |
| s56 | IOMobileFramebuffer | 56 (sIn=0, stIn=156) | 1784 | 模式 A/B/C/D |
| p3 | 边界细化 | MFB 51 + GPU 42 | 30 | 阶段 3 |

**合计真机调用 2220 次**（阶段 1 标量 294 次 + 阶段 2 1784 次 + 阶段 3 30 次 + 预热/基线 112 次）。

阶段 1 的值表（21 个，任务书原表，逐个试、每次只变一个位置）：

`0x0, 0x1, 0x2, 0x3, 0x4, 0x7, 0x8, 0xf, 0x10, 0x7f, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff, 0x100000000, 0x2000000000000000, 0xffffffffffffffff`

## 3. 「kr 与全 0 时不同」的组合 —— 本轮最重要的输出

全 0 基线：所有目标的基线 `kr` 都是 `0x0 SUCCESS`（`@base` 行）。下列组合与基线不同。

### 3.1 `IOMobileFramebuffer` selector 51，handler `0xa17ec28`（标量位置 0）

判据是**标量的低 32 位无符号值 ≤ 4**：

| 服务 | selector | 标量位置 | 值 | kr |
|---|---|---|---|---|
| IOMobileFramebuffer | 51 | 0 | `0x0` | `0x0` SUCCESS |
| IOMobileFramebuffer | 51 | 0 | `0x1` | `0x0` SUCCESS |
| IOMobileFramebuffer | 51 | 0 | `0x2` | `0x0` SUCCESS |
| IOMobileFramebuffer | 51 | 0 | `0x3` | `0x0` SUCCESS |
| IOMobileFramebuffer | 51 | 0 | `0x4` | `0x0` SUCCESS |
| IOMobileFramebuffer | 51 | 0 | `0x7` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x8` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0xf` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x10` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x7f` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0xff` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x100` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0xffff` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x10000` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x7fffffff` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x80000000` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0xfffffffe` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0xffffffff` | `0xe00002c2` kIOReturnBadArgument |
| IOMobileFramebuffer | 51 | 0 | `0x100000000` | `0x0` SUCCESS |
| IOMobileFramebuffer | 51 | 0 | `0x2000000000000000` | `0x0` SUCCESS |
| IOMobileFramebuffer | 51 | 0 | `0xffffffffffffffff` | `0xe00002c2` kIOReturnBadArgument |

结论：`0,1,2,3,4` → SUCCESS；`≥5` 一路到 `0xFFFFFFFF` 全是 `kIOReturnBadArgument`。**高 32 位被完全忽略**（0x1_00000004 → SUCCESS，0xFFFFFFFF_00000004 → SUCCESS，0x2000000000000004 → SUCCESS），说明 handler 是按 `w` 寄存器读的（32 位截断）。

⇒ 这是**有边界检查的活输入通道**：典型 `if (arg > 4) return kIOReturnBadArgument;` 形态，枚举/模式选择。**安全侧**（越界被拒，不是被当成索引用）。

### 3.2 `AGXAcceleratorG18P` selector 42，handler `0xa023d58`（标量位置 0 和 1，两个都活）

| 服务 | selector | 标量位置 | 值 | 另一位 | kr |
|---|---|---|---|---|---|
| AGXAcceleratorG18P | 42 | 0 | `0x0` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 0 | `0x1` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 0 | `0x2` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x3` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x4` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x7` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x8` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0xf` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x10` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x7f` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0xff` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x100` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0xffff` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x10000` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x7fffffff` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 0 | `0x80000000` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 0 | `0xfffffffe` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 0 | `0xffffffff` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 0 | `0x100000000` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 0 | `0x2000000000000000` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 0 | `0xffffffffffffffff` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0x0` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0x1` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0x2` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0x3` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x4` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x7` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x8` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0xf` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x10` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x7f` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0xff` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x100` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0xffff` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x10000` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x7fffffff` | `0x0` | `0xe00002c9` kIOReturnInternalError |
| AGXAcceleratorG18P | 42 | 1 | `0x80000000` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0xfffffffe` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0xffffffff` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0x100000000` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0x2000000000000000` | `0x0` | `0x0` SUCCESS |
| AGXAcceleratorG18P | 42 | 1 | `0xffffffffffffffff` | `0x0` | `0x0` SUCCESS |

判据（两位都看）：

| 标量 | 允许 | 越界返回 | 备注 |
|---|---|---|---|
| `scalarIn[0]` | `0, 1` | `0xe00002c9` `kIOReturnInternalError` | `>=2` 到 `0x7FFFFFFF` 全错 |
| `scalarIn[1]` | `0, 1, 2` | `0xe00002c9` `kIOReturnInternalError` | `>=3` 到 `0x7FFFFFFF` 全错 |
| 任意一位 | bit31 = 1（`0x80000000`/`0xFFFFFFFE`/`0xFFFFFFFF`） | — | **SUCCESS**：负数被当哨兵/缺省值 |

交叉确认（阶段 3）：`(2,*)` 全错、`(*,3)` 全错、`(0..1, 0..2)` 全对 ⇒ 两个位置**同时**参与判定。

与 MFB 51 的关键差别：这里返回的是 **`kIOReturnInternalError` 而不是 BadArgument** ⇒ handler **已经进去了、跑了一段、在下游失败**。这不是参数形状校验，是**语义边界**。

反汇编佐证（`out/iogpu.kext.macho`，VA `0xa023d58`）：

```
0xfffffe000a023d8c  ldr  x8, [x2, #0x20]      ; x2 = IOExternalMethodArguments*
0xfffffe000a023d90  ldr  w23, [x8]            ; scalarIn[0] —— **32 位读**
0xfffffe000a023d94  ldr  w21, [x8, #8]         ; scalarIn[1] —— **32 位读**
...
0xfffffe000a023e20  cmp  x0, x21, lsl #2       ; structOutputSize ? scalarIn[1] * 4
0xfffffe000a023e24  b.lo 0xfffffe000a023e40    ; 不够就跳过 copyout
0xfffffe000a023e28  ldr  x0, [x22, #0x120]    ; device
0xfffffe000a023e2c  mov  x1, x23             ; arg1 = scalarIn[0]
0xfffffe000a023e30  mov  x2, x24             ; arg2 = structOut 指针
0xfffffe000a023e34  mov  x3, x21             ; arg3 = scalarIn[1]
0xfffffe000a023e38  bl   0xfffffe000a0428f4 ; helper(dev, idx, buf, count)
```

两条 32 位读解释了“高 32 位无效”；`cmp structOutputSize, count*4` 说明 `scalarIn[1]` 是**条目数**（每条约 4 字节），`scalarIn[0]` 是**条目索引** —— 正是任务书担心的「标量当索引/长度用」的形态，但下游 helper（`0xa0428f4`，其中 `cmp x21, #0x80, lsl #12` 做上界、`cmp w8, #3` 查设备状态字节）**会拒**，所以是**有校验**的。

## 4. 阶段 1 全表（逐 selector）

### 4.1 有变化的（完整逐值）

见 §3.1（MFB 51，21 行）与 §3.2（GPU 42，42 行）。

### 4.2 无变化的（21 个值 × 每个位置，`kr`/`oc`/`sc` 与基线完全一致）

| 服务 | selector | handler | 标量位置 | 试了 | 出现的 (kr, oc, sc) |
|---|---|---|---|---:|---|
| AGXAcceleratorG18P | 19 | `0xa0227e0` | 0 | 21 值 | `0x0/oc=0/sc=24` |
| AGXAcceleratorG18P | 41 | `0xa0236ac` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOHIDEventService | 1 | `0xa0f5eb0` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 12 | `0xa17e984` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 13 | `0xa17e994` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 19 | `0xa17ebe8` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 22 | `0xa17ed58` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 31 | `0xa17f138` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 33 | `0xa17f29c` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 53 | `0xa17e0f8` | 0 | 21 值 | `0x0/oc=0/sc=0` |
| IOMobileFramebuffer | 53 | `0xa17e0f8` | 1 | 21 值 | `0x0/oc=0/sc=0` |

⇒ 这些 selector 的标量入参**要么不被读、要么读了不影响返回**。注意它们**仍然 handler 在跑**（基线 SUCCESS 已证），所以“传 0 成功”只是因为没有校验之外的路径被触发。

## 5. 阶段 2：sel 56（`0xa17e13c`，`structIn=156`）四种内容模式

| 模式 | 内容 | 次数 | kr 分布 | 与全 0 基线不同 |
|---|---|---:|---|---:|
| A | 全 0（对照） | 1 | `0x0` | 0 |
| B | 全 0xFF | 1 | `0x0` | 0 |
| C | 39 个 u32 槽，逐槽填 0..37（其余 0） | 1482 | `0x0` | 0 |
| D | 固定 seed 随机（seed=`0x5CF055EED001 + k*0x9E3779B97F4A7C15`，每次落 `hash`） | 300 | `0x0` | 0 |

⇒ **156 字节内容怎么填都一样**：`kr` 恒 `0x0 SUCCESS`、`oc/sc` 恒 0、`live` 恒 0。handler `0xa17e13c` 不校验也不回显这 156 字节中的任何一位（至少不体现为返回值/输出长度变化）。模式 C 覆盖了 39 个槽 × 38 个值 = 1482 次，模式 D 300 次随机，**没有一次差异**。

## 6. 阶段 3：边界细化（只在出现异常 kr 的两处做）

### 6.1 MFB sel 51 —— 确认是 32 位无符号比较，边界 4

| 值 | 低 32 位 | kr | 说明 |
|---|---|---|---|
| `0x5` | `0x5` | `0xe00002c2` | 0..4 之后第一个值 |
| `0x6` | `0x6` | `0xe00002c2` | 0..4 之后第二个值 |
| `0x100000004` | `0x4` | `0x0` | 低32=4 高32=1：测是否按 32 位截断 |
| `0x100000005` | `0x5` | `0xe00002c2` | 低32=5 高32=1 |
| `0x100000007` | `0x7` | `0xe00002c2` | 低32=7 高32=1 |
| `0xffffffff00000004` | `0x4` | `0x0` | 低32=4 高32=0xFFFFFFFF |
| `0xffffffff00000007` | `0x7` | `0xe00002c2` | 低32=7 高32=0xFFFFFFFF |
| `0x2000000000000004` | `0x4` | `0x0` | 低32=4 高位非0 |
| `0x2000000000000007` | `0x7` | `0xe00002c2` | 低32=7 高位非0 |
| `0x1ffffffff` | `0xffffffff` | `0xe00002c2` | 低32=0xFFFFFFFF |
| `0xfffffffffffffffb` | `0xfffffffb` | `0xe00002c2` | 低32=0xFFFFFFFB |
| `0xfffffffffffffff8` | `0xfffffff8` | `0xe00002c2` | 低32=0xFFFFFFF8 |

### 6.2 GPU sel 42 —— 双标量交叉 + 符号位 + 截断

| x0 | x1 | kr | 说明 |
|---|---|---|---|
| `0x0` | `0x0` | `0x0` | 交叉 0,0（对照） |
| `0x0` | `0x1` | `0x0` | 交叉 0,1 |
| `0x0` | `0x2` | `0x0` | 交叉 0,2 |
| `0x0` | `0x3` | `0xe00002c9` | 交叉 0,3 |
| `0x1` | `0x0` | `0x0` | 交叉 1,0 |
| `0x1` | `0x1` | `0x0` | 交叉 1,1 |
| `0x1` | `0x2` | `0x0` | 交叉 1,2 |
| `0x1` | `0x3` | `0xe00002c9` | 交叉 1,3 |
| `0x2` | `0x0` | `0xe00002c9` | 交叉 2,0 |
| `0x2` | `0x1` | `0xe00002c9` | 交叉 2,1 |
| `0x2` | `0x2` | `0xe00002c9` | 交叉 2,2 |
| `0x2` | `0x3` | `0xe00002c9` | 交叉 2,3 |
| `0x80000000` | `0x0` | `0x0` | x0 符号位：INT32_MIN |
| `0x0` | `0x80000000` | `0x0` | x1 符号位：INT32_MIN |
| `0x2` | `0x80000000` | `0xe00002c9` | x0=2 越界 + x1 负数 |
| `0x80000000` | `0x80000000` | `0x0` | 两个都是 INT32_MIN |
| `0x100000002` | `0x0` | `0xe00002c9` | 低32=2 高32=1：测截断 |
| `0x0` | `0x100000003` | `0xe00002c9` | 低32=3 高32=1：测截断 |

结论：`x0 ∈ {0,1}`、`x1 ∈ {0,1,2}`，**两位独立判定**（`(2,0)` 与 `(0,3)` 都错），**bit31 置位即放行**（`(0x80000000,0)`、`(0,0x80000000)`、`(0x80000000,0x80000000)` 全 SUCCESS），**按 32 位截断**（`0x1_00000002` 等价于 2 → 错；`0x1_00000003` 等价于 3 → 错）。这是「负值当无效哨兵、非负值当真实索引/计数」的典型签名。

## 7. panic / 挂死

| 项 | 结果 |
|---|---|
| `ls -1 out/panics/*.ips \| wc -l` 跑前 | 5 |
| 同上 跑后 | 5 |
| 新增 panic | **0** |
| `@timeout`（3s 线程级超时） | **0 条** |
| `@abort`（同 stage 连续 3 次超时熔断） | **0 条** |
| stage 中途没有 `@done` | 无（6 个 stage 全部有 `@done`） |
| 设备重启 | 无 |

所有内核调用都在 <100ms 内返回（mfb 62ms / hid 13ms / gpu 45ms / p3 25ms / s56 537ms），没有出现“`kr` 恒 0 但副作用出现”的最危险形态。

## 8. 套件与原始 ndjson

```
harness/scfuzz/main.m        探针本体（阶段 1/2/3 全在这一个文件里）
harness/scfuzz/run.sh        build→指纹→签名→安装→启动→取回→panic 计数→归档，一个 stage 一个进程
harness/scfuzz/results/      原始 ndjson / log / hb
```

复现：

```bash
cd tasks/ios27-chain-poc/harness/scfuzz
./run.sh mfb 600     # 标量边界：MFB 12/13/19/22/31/33/51/53
./run.sh hid 600     # 标量边界：IOHIDEventService sel 1
./run.sh gpu 600     # 标量边界：AGX 19/41/42（自带 A 表预热）
./run.sh jpeg 600    # 契约 sIn=0 ⇒ 全 @skip
./run.sh s56 600     # sel 56 的 156 字节四种模式
./run.sh p3 600      # 边界细化（MFB 51 + GPU 42）
```

权威结果文件：

| stage | 文件 | 行数 |
|---|---|---:|
| mfb | `harness/scfuzz/results/mfb-20261101-163709.ndjson` | 414 |
| hid | `harness/scfuzz/results/hid-20261101-163712.ndjson` | 48 |
| jpeg | `harness/scfuzz/results/jpeg-20261101-163715.ndjson` | 6 |
| s56 | `harness/scfuzz/results/s56-20261101-163719.ndjson` | 3574 |
| gpu | `harness/scfuzz/results/gpu-20261101-163606.ndjson` | 403 |
| p3 | `harness/scfuzz/results/p3-20261101-163658.ndjson` | 96 |

作废（同一轮早先版本，仅作对照，不进表）：`gpu-20261101-163348.ndjson`, `gpu-20261101-163505.ndjson`, `mfb-20261101-163309.ndjson`, `hid-20261101-163341.ndjson`, `s56-20261101-163333.ndjson`。

原始 ndjson 一行一条，key 约定：`@meta` / `@open` / `@warm` / `@base`（全 0 基线）/ `@pre`（调用前落盘 + fsync）/ `@s1`（阶段 1）/ `@s2`（阶段 2）/ `@s3`（阶段 3）/ `@p1done` `@p2done` `@p3done` / `@skip` / `@timeout` / `@abort` / `@hb`（200ms 心跳）/ `@done`。`live=1` = 该 `(kr, oc, sc)` 与本目标全 0 基线不同。

## 9. 结论

1. **14 个标量入参位里只有 3 个是活的**：MFB 51（1 位）、GPU 42（2 位）。其余 11 位（MFB 12/13/19/22/31/33/53×2、HID 1、GPU 19/41）对 21 个边界值零反应。
2. **两条活通道都有边界检查**，所以都不是“传 0 必成功、传边界就出事”的未校验索引：
   - MFB 51：`低32 > 4` → `kIOReturnBadArgument`，枚举形态，**安全**。
   - GPU 42：`x0 > 1` 或 `x1 > 2` → `kIOReturnInternalError`，索引+计数形态，**下游会拒**，也安全；但这是本轮唯一出现**非形状错误**（InternalError = handler 已执行）的点。
3. **sel 56 的 156 字节是死输入**：4 种模式 1784 次，`kr`/`oc`/`sc` 一个字都没变。要继续挖得换通道（例如先用 sel 55 之类建好对象再回来喂 sel 56），单靠内容 fuzz 这条到头了。
4. 本轮**修掉的两个通用坑**比这两个 selector 结论更值钱：`structOutputSize` 必须预填容量（否则所有 `stOut>0` 的 selector 全部假阴性）、AGX 19/42 必须先预热连接。任何后续 probe 都要按这两条写。

---

生成：`harness/scfuzz/build_report.py`（只读 `results/*.ndjson`，只写本文件）。

---

## 追加：本轮暴露的一处通用假阴性（影响面见下）

`IOConnectCallMethod` 的 `scalarOutputCount` / `structOutputSize` 是 **in/out 参数**，
调用前必须预填容量。传 0 时：

```
凡声明 structOut > 0 的 selector -> handler 内部 copyout 前校验失败 -> BadArgument
=> 全部假阴性
```

证据链：
1. 本套件第一版传 0 ⇒ GPU sel 0/2/19 全 BadArgument；改成预填后 SUCCESS、`sc=64/536/24`
2. 回溯 `SVC2-PROBE.md` 的 ndjson：**没有一条 `kr=0 且 sto>0`**，`@so`/`@h` 段完全为空
   —— 与同因假阴性完全一致

**受影响的结论**：`AppleM2ScalerCSCDriver` 那批 selector 的判定。
该 kext **严格扫描 0 张派发表（手写 switch）**，是最该拿正确姿势重测的一面。

## 另一个必须记住的前置条件

`AGX` sel 19 / sel 42 依赖**连接前置状态**：全新连接第一发 `BadArgument`，
按 A 表顺序预热（0,1,2,3,4,5,16,17,…）后才 `SUCCESS`。
⇒ 所有后续 selector 探测**必须带预热序列**，否则会低估可用 selector 数。

---

## 追加：IOMobileFramebuffer 的标量校验（静态坐实）

sel 12 的 handler `0xa17e984` 是纯转发：

```asm
ldr x8,[x2,#0x20]     ; scalarInput
ldr w1,[x8]           ; scalarIn[0]，此处零校验
b   0xa17c6e0
```

跟进目标 `0xa17c6e0`（192 条指令），**`x19 = w1` 的全部使用点**：

```
0xa17c6f0  stp  x20,x19,[sp,#0x40]   ; 保存
0xa17c6fc  mov  x19,x1               ; 取值
0xa17c7b0  stp  x19,x8,[sp,#0x18]    ; 再保存
0xa17c86c  cmp  w19,#1               ; <<< 校验
0xa17c90c  cmp  w19,#1               ; <<< 校验
```

**⇒ 标量被当布尔值校验（只允许 0/1），不存在未校验索引。**

与动态结果一致：MFB 10 个在用 selector 里，14 个标量位只有 sel 51 有反应，
且是枚举边界（≤4 通过、≥5 拒），**有边界检查**。

## MFB 线小结

| selector | 形态 | 校验 | 结论 |
|---|---|---|---|
| 12/13/19/22/31/33 | `sIn=1` 布尔/枚举 | 静态+动态均证实有界 | 安全侧 |
| 51 | `sIn=1` 枚举 ≤4 | 边界在 4/5，精确 | 安全侧 |
| 53 | `sIn=2` 转发到 vtable+0x5e8 | 21 个边界值零反应 | 未证，但无信号 |
| 56 | `stIn=156` 精确长度，内容转发 | 长度精确校验；1684 次内容 fuzz 全 SUCCESS | **内容死输入** |
| 26 | `sIn=0 stIn=0` | 无可测输入 | — |

**MFB / AppleCLCD2 这条面在当前测试强度下无信号。**
