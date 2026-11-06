# 直接审计：AppleJPEGDriver / AppleProResHW / AppleH16CameraInterface（iOS 27.0.1）

**README（10 行）**
1. 本文件是**直接审计**，不做 27.0.1↔27.2 差分。判据只有一句：*在 27.0.1 里，这段代码能不能越界*。
2. 靶子：`com.apple.driver.AppleJPEGDriver`、`com.apple.driver.AppleProResHW`、`com.apple.driver.AppleH16CameraInterface`。
3. 数据：`out/kc.27.0.1.full`（78,135,296 B，arm64e fileset，301 个 kext）。
4. **附带解决了一个卡了两轮的问题**：`__DATA_CONST` 里的指针不是不可解——`va = 0xfffffe0007004000 + (w & 0xFFFFFFFF)`，于 `USERCLIENT-TARGETS.md` §1.3「selector 数取不到」**作废**。
5. 三个 kext 的 `IOExternalMethodDispatch` 表已全部取出：JPEG 10 个 selector、ProRes 5 个、H16Cam 117 个，共 **132** 个。
6. 逐条人工读过的入口/被调函数：**19 个**（占 132 的 14.4%），明细见各节与 §5。
7. 找到 **2 个形态命中但证据链断掉的候选**，0 个可确认的内存破坏；两个候选的断点位置都写明了。
8. ProRes 需要 `com.apple.private.proreshw`，在我们能力位下**打不开**（可达性先于漏洞出局）。
9. 所有结论都给了 VA，可用 `kc.dis(va, n)` 复现；工具在 `tools/kva.py`、`tools/ktriage.py`。
10. 最后一节是直答。

---

## 0. 先把指针解出来（这一步决定了后面全部工作）

### 0.1 结论

`USERCLIENT-TARGETS.md` §1.3 断言「这个 cache 里 kext 的 `__DATA_CONST` 不含绝对内核指针，派发表被 chained-fixup 编码过，解不出来」。**半对半错**：确实不是裸指针，但编码是可解的。

```python
# kc = 整个 kernelcache 文件
BASE = 0xfffffe0007004000          # 外层 __TEXT 的 vmaddr
va   = BASE + (word & 0xFFFFFFFF)  # 36 位 target 或 32 位 target 都适用（镜像 < 4 GiB）
```

验证方式（自证，不靠猜）：对 `AppleJPEGDriver` 的 `__DATA_CONST` 逐 8 字节解码——2635 个非零字里，**2365 个的落点恰好是 `bti c` / `pacibsp` 函数序言**（89.8%）。随机数据命中一次的概率约 2⁻³²，命中 2365 次只可能是解码本身对。

| kext | `__DATA_CONST` 非零字 | 落点是函数序言 | 命中率 |
|---|---|---|---|
| AppleJPEGDriver | 2635 | **2365** | 89.8% |
| AppleH16CameraInterface | 5791 | **2517** | 43.5% |
| AppleProResHW | 6153 | **482** | 7.8% |

（命中率差异来自各 kext `__DATA_CONST` 里「非代码指针」的占比不同——比如 ProRes 的绝大多数字是缓冲区描述符和常量表。这不是解码不可靠的信号：三张派发表里的每一条 `function` 字段都 100% 命中序言。）

第二个独立验证：H16Cam 的 `externalMethod` 里 `adrp x9,#0xfffffe0008086000; add x9,x9,#0xae0` 得到的表地址 `0xfffffe0008086ae0`，与我**仅靠指针扫描**找到的表基址完全一致。代码与数据两条路互为印证。

### 0.2 为什么之前三次尝试都失败

| §1.3 的做法 | 失败原因 |
|---|---|
| 按「首字段是 `0xfffffe00_xxxxxxxx`」扫 `IOExternalMethodDispatch` | 表里存的是编码值，不是 VA |
| 统计 `0xfffffe00_xxxxxxxx` 形状的字，命中 0 | 同上，形状根本不存在 |
| 假设 `adrp+add x2,&table; mov w3,#count` | count 不总在 `w3`；JPEG 用 `w4`，H16Cam 干脆内联 `umull` |

### 0.3 三个 kext 的派发表

| kext | 表地址 | selector 数 | 记录步长 | 取到方式 |
|---|---|---|---|---|
| `AppleJPEGDriver` | `0xfffffe00080dd990` | **10** | `0x28` | 代码 `mov w4,#0xa` |
| `AppleProResHW` | `0xfffffe000b905ce0` | **5** | `0x28` | 代码 `mov w4,#5` |
| `AppleH16CameraInterface` | `0xfffffe0008086ae0` | **117** | `0x18` | 代码 `mov w8,#0x18; umull` + `cmp w1,#0x75` |

**步长不一样，这是实测事实，不是笔误。** 前两个 kext 的 `externalMethod` 是裸尾调用（`b <veneer>` → `IOUserClientDefaultLockingSingleThreadExternalMethod`，该字符串在两者的 `__TEXT` 里都有），索引由内核侧做，记录 40 字节；H16Cam 自己 `umull` 出 `&table[selector]` 再传给 `IOUserClient::externalMethod`，记录 24 字节。

两种记录**前 24 字节布局相同**（`function / checkScalarInputCount / checkStructureInputSize / checkScalarOutputCount / checkStructureOutputSize`），40 字节版多出的 16 字节在全部 15 条记录里都是 0。步长不是猜的：按 0x28 走，10 条指针全部落在 `bti c` 序言上，且 `10×0x28 = 0x190` 恰好顶到 `0xfffffe00080ddb20` 的下一对象；按 0x18 走会踩到全零字段。

### 0.4 `IOExternalMethodArguments` 的实际字段偏移（实测）

从三个 kext 的方法体反推（`ldr` 的位移），全部一致：

| args 偏移 | 字段 | 证据 |
|---|---|---|
| `0x10` | `asyncWakeTarget` | H16Cam sel6 `ldr x4,[x2,#0x10]` |
| `0x18` | `scalarInput`（打包值） | ProRes sel1 `ldr w9,[x2,#0x18]` |
| `0x20` | `scalarInput64`（指针） | H16Cam sel0 `ldr x8,[x2,#0x20]; ldr w1,[x8]` |
| `0x30` | `structureInput` | 全部 |
| `0x38` | `structureInputSize` | H16Cam sel6 |
| `0x58` | `structureOutput` | 全部 |
| `0x60` | `structureOutputSize` | 未直接观测（推断自 `0x38`/`0x58` 的对称位置） |
| `0x68` | `structureOutputDescriptor` | H16Cam sel114 `ldr x0,[x2,#0x68]` 后 `autda` + `vtable+0xe8` |
| `0x78` | `structureVariableOutputData` | H16Cam sel94 `ldr x8,[x19,#0x78]; str x0,[x8]` |

（`0x60` 一栏我标了「推断」，因为没有任何一处直接读到它，不冒充实测。）

---

## 1. AppleJPEGDriver

- `__TEXT_EXEC`：`0xfffffe0009002170` + `0x2e008`
- 441 条**去重后的 NUL 结尾可打印串**（任务单里的「617 字符串命中」是原始字节出现次数，口径不同），含 `AppleJPEGDriverUserClient`、`IOUserClientDefaultLockingSingleThreadExternalMethod`、三个结构体型名 `AppleJPEGDriverIOStruct` / `…Ext` / `…2024`
- 无 `com.apple.private.*` 字样；只有基类的 `IOUserClientEntitlements` 串

### 1.1 selector 表（10 个，全取到）

| sel | 方法 VA | stIn | stOut | 语义（按尾调用目标推断） |
|---|---|---|---|---|
| 0 | `0x900a73c` | 0 | 0 | 无结构体，取状态 |
| 1 | `0x900bdf0` | `0x58` | `0x58` | `startDecoder`（`IOStruct`） |
| 2 | `0x900a748` | 0 | 0 | 无结构体 |
| 3 | `0x900d090` | `0x58` | `0x58` | `startEncoder` |
| 4 | `0x900d4a4` | `0x1000` | `0x1000` | `*Ext` |
| 5 | `0x900c8f4` | `0x1000` | `0x1000` | `*Ext` |
| 6 | `0x900dfa8` | `0xda0` | `0xda0` | `*2024` |
| 7 | `0x900d908` | `0xda0` | `0xda0` | `*2024` |
| 8 | `0x9009ba4` | `4` | 0 | 4 字节标量结构 |
| 9 | `0x9009c3c` | 0 | 0 | 无参 |

注意 `stIn` 与三个结构体名字对应得很干净：`0x58` = `IOStruct`，`0xda0` = `IOStruct2024`，`0x1000` = `IOStructExt`。

这条对应关系有**符号级旁证**——`__TEXT` 里留着六个方法的完整签名串：

```
0x752e3b7  IOReturn AppleJPEGDriver::startDecoder(AppleJPEGDriverIOStruct *, AppleJPEGDriverIOStruct *, mach_port_t, IOUserClient *, task_t)
0x752e439  IOReturn AppleJPEGDriver::startDecoderExt(AppleJPEGDriverIOStructExt *, ...)
0x752e4c4  IOReturn AppleJPEGDriver::startEncoder(AppleJPEGDriverIOStruct *, ...)
0x752e546  IOReturn AppleJPEGDriver::startEncoderExt(AppleJPEGDriverIOStructExt *, ...)
0x752e5d1  IOReturn AppleJPEGDriver::startDecoder2024(AppleJPEGDriverIOStruct2024 *, ...)
0x752e65f  IOReturn AppleJPEGDriver::startEncoder2024(AppleJPEGDriverIOStruct2024 *, ...)
```

五个参数正好对应 §1.2 里 thunk 塞的五个寄存器（`x1`=in、`x2`=out、`x3`=port、`x4`=UserClient、`x5`=task）。**所以「指针解码 → 派发表 → selector → 方法」这条链在 JPEG 上是被符号独立验证过的，不是纯算术推断。**

### 1.2 入口体（全部 10 个都读了）

sel1/3/4/5/6/7 是同一模板：

```
mov  x4, x0                     ; 保留 self
ldr  x0, [x0, #0xe0]            ; self->fDriver
cbz  x0, fail                   ; 空指针闸门
ldr  x8, [x2, #0x58]            ; args->structureOutput
ldr  x1, [x2, #0x30]            ; args->structureInput
ldr  x3, [x4, #0xf0]            ; self->fPort
ldr  x5, [x4, #0x100]           ; self->fTask
mov  x2, x8
b    <driver method>
```

**关键观察：入口只传两个指针，一个长度都没传。** 长度信息全部留在结构体字段里由 driver 侧自己取。所以风险点必然在 driver 方法内部，不在入口。

### 1.3 sel1 `startDecoder`（`0x900bdf0`，已完整读完 ~150 条）

进函数后：
```
ldr  w2,  [x19, #0x48]      ; 结构体字段
ldr  x8,  [x19, #0x30]      ; 结构体里的指针字段，只判非空
cmp  x8, #0
cset w3, ne
ldr  w8,  [x19, #0x14]
ldrh w9,  [x19, #0x18]
orr  w4, w9, w8, lsl #16
bl   <log>                  ; 0x9030098 = 日志
...
bl   0x902fb48              ; 按名取类（参数是 __TEXT 里的串地址）
cbz  x0, fail_alloc
mov  x21, x0                ; 分配出的请求对象
ldr  q0, [x19, #0x30]       ; 拷 16 字节
str  q0, [x21, #0x10]
ldr  x8, [x19, #0x40]       ; 拷 8 字节
str  x8, [x21, #0x20]
...
```

**全部是固定位移的定长拷贝**（`q0`=16B、`x8`=8B、`d0`=8B），目标偏移写死（`+0x10`、`+0x20`、`+0x2ac`、`+0x310`、`+0x420`、`+0x450`、`+0x538`）。没有任何一个偏移或长度来自结构体。

唯一带分支的字段是 `struct[0x2c]`：
```
ldr  w8, [x19, #0x2c]
cmp  w8, #1 ; b.le  ...
cmp  w8, #4 ; b.eq  ...
cmp  w8, #3 ; b.eq  ...
cmp  w8, #2 ; b.ne  fail
```
枚举白名单，4 值分支，无落空路径落到数组下标。**此处无越界可能。**

### 1.4 sel5/7 `*Ext` 路径（函数体 `0x900c8f4`，读了含 `mul` 的核心段）

`ktriage` 在 `0x900cae8` 报了一处 `mul`：

```
0x900cadc  and  w9, w25, #0xffff
0x900cae0  mov  w10, #0xaaab
0x900cae4  movk w10, #0xaaaa, lsl #16
0x900cae8  mul  w9, w9, w10
0x900caec  ror  w9, w9, #2
0x900caf0  mov  w10, #0x5556
0x900caf4  movk w10, #0x1555, lsl #16
0x900caf8  cmp  w9, w10
0x900cafc  b.lo ok
```

**判读：这不是索引缩放，是除 3 的魔数（`0xAAAAAAAB` + `ror #2`）。** 按 `METHOD-FUNCTION-BOUNDARY.md` §11 的纪律（乘法常数 + 移位 + 掩码 = 哈希/算术，不是边界检查），这里反过来也成立：它也不是**越界**，只是一条整除性检查。

同一函数前面还有两条真·上界检查：
```
0x900ca6c  cmp  w25, #1, lsl #12     ; w25 <= 0x1000
0x900ca70  b.ls ...
0x900cb2c  cmp  w25, #0xf7f          ; w25 <= 0xf7f
0x900cb30  b.ls ...
```
`w25` 来自结构体字段，两条 `b.ls` 把它夹在 `0x1000` 以下。**有上界。**

### 1.5 sel6 `*2024` 路径（`0x900dfa8`）

```
ldr  w8, [x19, #0x1c]
and  w9, w8, #0xfffe
cmp  w9, #0xa
b.lo cont                 ; 枚举检查：0x1c ∈ {0,1,...,0xb 的偶数值}
...
0x900e09c  ldr  w8, [x19, #4]
0x900e0a0  ldr  w9, [x19, #0xc]
0x900e0a4  cmp  w8, #0xff
0x900e0a8  b.hi fail      ; 上界检查：字段 [0x4] <= 0xff
```
两个用户可控字段都带显式上界。**未发现无界使用。**

### 1.6 sel8（`stIn=4`）

```
ldr  x8, [x2, #0x30]      ; structureInput (4 字节)
ldr  w2, [x8]             ; 读出一个 u32 当参数
b    0x9009ba4
```
正好读 4 字节，与 `checkStructureInputSize = 4` 一致。**规模匹配。**

### 1.7 AppleJPEGDriver 结论

10 个 selector 的入口全部读完，5 个 driver 方法的实体读到了关键分支。**没有找到「长度/索引取自用户结构体且不校验」的路径**：所有结构体驱动的长度都有 `cmp + b.ls/b.hi` 夹住，所有拷贝都是固定位移定长。

---

## 2. AppleProResHW

- `__TEXT_EXEC`：`0xfffffe00093b8880` + `0x56080`
- 287 条去重串，含 **`com.apple.private.proreshw`**

> ### ⚠️ 可达性先出局
> `com.apple.private.proreshw` 是 Apple 私有 entitlement，dev-signed app 拿不到（不在任何可申请的 provisioning profile 里）。即使下面找到洞，**当前能力位打不开这个 UserClient**。这一节的价值是方法示范与「此处确实干净」的排除证据，不是可利用目标。

### 2.1 selector 表（5 个）

| sel | 方法 VA | stIn | stOut | 判读 |
|---|---|---|---|---|
| 0 | `0x93d5c6c` | `0x14` | `0x18` | 状态/版本查询 |
| 1 | `0x93d5484` | `0x10` | 0 | 写共享参数块 |
| 2 | `0x93d6474` | `0xa8` | 0 | 固件/命令入口 |
| 3 | `0x93d612c` | `0x200` | 0 | 缓冲区注册 |
| 4 | `0x93d5fd0` | 0 | 0 | 无参 |

> 上表「判读」一列**全部是根据尾调用目标推断的，ProRes 没有像 JPEG 那样留下方法签名串**。不当作事实用。

`externalMethod` 本体在 `0x93d5508`：`cmp w1,#5; b.lo 0x93d5570`，`b.lo` 分支里 `adrp x3,#0xb905000; add x3,x3,#0xce0` + `mov w4,#5`。

### 2.2 sel1 —— 一个**正确**的钳位样本（值得记录）

```
0x93d549c  ldr  x8, [x2, #0x30]      ; structureInput（16 字节，与 stIn=0x10 一致）
0x93d54a0  ldp  x20, x1, [x2, #8]
0x93d54a4  ldr  w9, [x2, #0x18]      ; args->scalarInput（低 32 位）
0x93d54a8  ldr  q0, [x8]             ; 恰好读 16 字节
...
0x93d54bc  cmp  w9, #8
0x93d54c0  mov  w10, #8
0x93d54c4  csel w8, w9, w10, lo      ; ★ w8 = min(w9, 8)
0x93d54c8  lsl  w2, w8, #3           ; len = w8*8 ≤ 64
0x93d54cc  add  x0, x0, #0x100
0x93d54d0  bl   0x940e840            ; veneer → kernel memcpy
```

数据流：`args->scalarInput` → `w9` → `min(·,8)` → `×8` → `memcpy(self+0x100, …, ≤64)`。

前面 `stp q0,q1,[x0,#0xf0]` / `stp q1,q1,[x0,#0x110]` / `str q1,[x0,#0x130]` 把 `0xf0..0x13f` 清零，目标区 0x100 起还有 0x40 字节可用，`≤64` 正好卡住。**这是教科书写法：钳位在乘法之前。** 记录它是为了给后面的判读立一个对照基准。

### 2.3 sel3（`stIn=0x200`）——用户尺寸直接进分配器

```
0x93d6164  ldr  w1, [x19, #0x60]     ; ← 用户结构体字段
0x93d6168  ldp  x0, x2, [x21, #0xd8]
0x93d616c  ldr  w3, [x21, #0x144]
0x93d6170  bl   0x93c6d34
0x93d6174  str  x0, [x19, #0x68]     ; 结果写回结构体

0x93d6178  ldr  w1, [x19, #0x70]     ; ← 用户结构体字段
0x93d6184  bl   0x93c6d34
0x93d6188  str  x0, [x19, #0x78]

0x93d618c  ldr  w8, [x19, #0x94]
0x93d6190  cbz  w8, skip
0x93d6194  ldr  w1, [x19, #0x98]     ; ← 用户结构体字段
0x93d61a0  bl   0x93c6d34
0x93d61a4  str  x0, [x19, #0xa0]
```

`0x93c6d34` 展开：`ldr x0,[x0,#0x580]` → 一个 mapper 对象 → veneer 调用，`x1` 原样保留。也就是 **`alloc(userSize)`**，`userSize` 是完完整整的 32 位用户值，调用点**没有任何 `cmp`**。

数据流：`structIn[+0x60/+0x70/+0x98]` → `w1` → 分配器 → 返回指针存回 `structIn[+0x68/+0x78/+0xa0]`。

**为什么不判它是洞**：分配器收到多大就分配多大，不涉及「按 A 分配、按 B 写入」的错配。此路径缺的是「分配后谁来写、写多少」的配对证据 —— 我没有追到写入侧。**留白，不升级。**

### 2.4 候选 A：`0x93c6bfc` —— 用户索引 × 4，只有溢出保护没有容量检查

这个函数是全工程最像「索引无上界」的一段：

```
0x93c6bfc  pacibsp                    ; 注意：无前置 bti c，是只被 bl 调用的函数
...
0x93c6c0c  add   x8, x0, #0x180
0x93c6c10  ubfiz x9, x1, #2, #0x20    ; ★ idx*4，32 位零扩展
0x93c6c14  cmp   x9, w9, sxtw         ; ★ 只比 32→64 符号一致，不是容量比较
0x93c6c18  add   x10, x8, w9, sxtw
0x93c6c1c  add   x16, x8, x9
0x93c6c20  movk  x16, #0x2bad, lsl #48 ; 溢出时换成毒指针
0x93c6c24  csel  x10, x10, x16, eq
0x93c6c28  add   x8, x0, #0x190
0x93c6c2c  cmp   x9, w9, sxtw
0x93c6c30  add   x11, x8, w9, sxtw
0x93c6c3c  csel  x11, x11, x16, eq
0x93c6c44  ldr   w10, [x10]           ; ★ obj+0x180 + idx*4   【读】
0x93c6c48  ldr   w9,  [x11]           ; ★ obj+0x190 + idx*4   【读】
```

`x1` 是调用者给的索引。**`cmp x9, w9, sxtw` + `csel 毒指针` 是 `-fsanitize` 风格的乘法溢出检测，不是 `idx < capacity` 检查**——没有任何地方加载容量字段。若 `x1` 用户可控，`obj+0x180+idx*4` 可以越界读最多 16 GiB。

数据流（若能接上）：

```
用户 scalar/结构体字段 → x1 → ubfiz x9,x1,#2 → add x10,obj+0x180,x9 → ldr w10,[x10]  （越界读 4 字节，距离无上界）
```

### 2.5 候选 A 为什么**不能**当发现报

我做了三重引用搜索，全部为空：

1. 全 cache 所有可执行段（`__TEXT_EXEC` / `__TEXT_BOOT_EXEC` / `__PRELINK_TEXT`）逐条解码 `bl`/`b` imm26 → **0 条**跳向 `0x93c6bfc`。
2. 全 cache 逐 8 字节解码重定位指针（`BASE + (w & 0xFFFFFFFF)`）→ **0 条**指向它。
3. 全 cache 原始字节搜 `w & 0xFFFFFFFF == 0x023C2BFC`（覆盖 PAC 签名态、36 位态、32 位态）→ **0 条**。

按工程纪律「『调用者 = 0』只读作『无直接 `bl`/`b`』」，理论上运行期算出来的指针仍可能到达它。但「算出来的指针恰好等于这个偶地址」需要额外的间接表，而这个函数不在任何可解的表里。**所以：形态完全命中第 1 类（索引直取、无上界），但可达性为 0 引用 —— 不列为发现，列入 §5 待定。**

### 2.6 AppleProResHW 结论

5 个 selector 全部读完入口，sel0/1/2/3 的实体读到关键分支。**可达性先出局（`com.apple.private.proreshw`）**；代码侧一个正确钳位（sel1）、一个用户尺寸直进分配器（sel3，无写入侧证据）、一个无容量检查的数组索引（`0x93c6bfc`，零引用）。

---

## 3. AppleH16CameraInterface

- `__TEXT_EXEC`：`0xfffffe0008d59f50` + `0x9ed2c`（三个里最大）
- 1581 条去重串；两个 UserClient 类：`AppleH16CamInUserClient`、`AppleH16PearlCamUserClient`
- **只找到一张派发表**（117 项）；Pearl 那个类的派发没找到 —— 列入 §5
- 无 `com.apple.private.*` 串；可达性由 `IOServiceOpen` 的 sandbox profile 决定，**未实测**

### 3.1 全表统计

| 项 | 数 |
|---|---|
| selector 总数 | 117 |
| 带结构体输入或输出的 | 31 |
| `stIn` / `stOut` = `kIOUCVariableStructureSize`（`0xffffffff`） | **2**（sel6 输入、sel94 输出） |
| 最大固定 `stIn` | `0x628`（sel113） |
| 最大固定 `stOut` | `0x211c`（sel95） |
| 用 `args+0x68`（`structureOutputDescriptor`）的 | 5（sel95/111/112/113/114） |

完整逐条表：`out/iv/selectors.txt`。

### 3.2 派发代码（`0x8dd68c4`，内联，与另两个 kext 不同）

```
mov  w8, #0x18
umull x8, w1, w8             ; selector * 24
adrp x9, #0xfffffe0008086000
add  x9, x9, #0xae0          ; &table
cmp  x8, w8, sxtw            ; 32→64 溢出检测
b.ne fail
add  x10, x9, w8, sxtw
csel x10, x10, x16, eq       ; 溢出则毒指针
cmp  x4, #0
mov  w8, #0x75               ; 117
ccmp w1, w8, #2, eq
b.lo ok
```

selector 上界 `0x75` 是硬的，`umull` 前有 32 位溢出检测。**派发本身干净。**

### 3.3 候选 B：sel6 —— `kIOUCVariableStructureSize` + 只有整除性检查的记录数

这是三个 kext 里唯一一处「用户给的字节数直接变成循环次数」的地方。

**入口 `0x8dd5408`（全文）：**

```
0x8dd540c  ldr  w9, [x2, #0x38]     ; ★ args->structureInputSize（用户可控）
0x8dd5410  lsr  w8, w9, #3
0x8dd5414  mov  w10, #0x4925
0x8dd5418  movk w10, #0x2492, lsl #16
0x8dd541c  umull x8, w8, w10
0x8dd5420  lsr  x8, x8, #0x20        ; x8 = size / 56（魔数除法）
0x8dd5424  lsl  x10, x8, #6
0x8dd5428  sub  x10, x10, x8, lsl #3 ; x10 = x8*56
0x8dd542c  cmp  x10, x9
0x8dd5430  b.ne fail                 ; ★ 唯一的检查：size 必须是 56 的整数倍
0x8dd5434  mov  x3, x0
0x8dd5438  ldr  x4, [x2, #0x10]      ; args->asyncWakeTarget
0x8dd543c  ldr  x1, [x2, #0x30]      ; args->structureInput
0x8dd5440  ldr  x0, [x0, #0xd8]
0x8dd5444  mov  x2, x8               ; ★ count = size/56，无上界
0x8dd5448  b    0x8d9deb8
```

派发表给 sel6 的 `checkStructureInputSize = 0xffffffff`（`kIOUCVariableStructureSize`），意味着**通用派发层不做任何静态尺寸比较**。所以：

```
用户 mach OOL 缓冲区（想给多少给多少）
   → args->structureInputSize
   → /56（只验整除）
   → count
   → 0x8d9deb8 的第 4 参数（w3/w2）
```

**下一跳 `0x8d9deb8`（全文）：**

```
mov  x5, x4                  ; wakeTarget
mov  x4, x3                  ; self
mov  x8, x1                  ; structIn
add  x9, x0, #0x83, lsl #12
add  x9, x9, #0x920
ldr  x0, [x9]                ; 子对象
autda x16, x17               ; 取 ISA
ldr  x9, [x16, #0xe8]!       ; vtable+0xe8
x1 = pacia(0x8d9df18)        ; ★ 把这个回调地址打包成参数
mov  x2, x8                  ; structIn
w3   = count
braa x16, x17                ; 虚调用：m(subobj, cb, structIn, count, self, wakeTarget)
```

**再下一跳 `0x8d9df18`（回调本体，读到头）：**

```
0x8d9dfa0  cmp  x3, #0
0x8d9dfa4  ccmp x4, #0, #0, ne
0x8d9dfa8  cset w8, eq
0x8d9dfac  sub  w9, w2, #0x81
0x8d9dfb0  cmn  w9, #0x80
0x8d9dfb4  b.lo ok              ; ★ 等价于 1 ≤ w2 ≤ 0x80
0x8d9dfb8  tbnz w8, #0, fail
...
0x8d9dfbc  mov  w8, #0x10
0x8d9dfc0  orr  w8, w8, w22, lsl #6
0x8d9dfc4  cmp  w22, #0xa
0x8d9dfc8  mov  w9, #0x280
0x8d9dfcc  csel w25, w9, w8, lo  ; w25 = (w22<10) ? 0x280 : 0x10|w22<<6
0x8d9dfd4  mov  x1, x25
0x8d9dfd8  bl   0x8df0e50        ; alloc(w25)，w25 ≤ 0x2010
```

`b.lo` 的条件算一下：`w9 = w2-0x81`，`cmn w9,#0x80` 即 `w2-1`，无符号 `b.lo` ⇒ `w2-1 < 0x80` ⇒ **`1 ≤ w2 ≤ 0x80`**。随后用 `w22`（= `w2`）算分配大小，上界 `0x10 | 0x80<<6 = 0x2010`。

### 3.4 候选 B 的判定：**不成立，但是推断，不是证明**

如果回调的 `w2` 就是那个 `count`，那么 `count` 在 `[1,0x80]` 被夹住，`0x80×56 = 7168 B`，与 `alloc(0x2010)` 同量级 —— **有界，不是洞**。

**我没有证明 `w2` 就是 `count`。** 依据只是寄存器顺序（`braa` 传 `x2=structIn`、`w3=count`，而回调里被判的是 `w2`）。中间隔着一层虚调用 `vtable+0xe8`，它的调用约定我没有解开。所以这一条的正确写法是：

> 入口处无上界（已证）；下游回调处出现 `[1,0x80]` 钳位（已证）；两者的寄存器对应关系**未证**。

按纪律，**不列为发现**。

### 3.5 sel94 —— 变长输出，但长度是内核自己的常量

```
0x8dd5cf4  mov  w9, #0x1320
0x8dd5cf8  adrp x17, #0xfffffe000808b000
0x8dd5cfc  add  x17, x17, #0x1c0
0x8dd5d00  ldr  x16, [x17]
0x8dd5d04  blraa x16, x17            ; stack_chk_guard 读取
0x8dd5d08  sub  sp, sp, #1, lsl #12
0x8dd5d0c  sub  sp, sp, #0x320        ; ★ 栈上 0x1320 字节缓冲
...
0x8dd5d18  add  x0, sp, #8
0x8dd5d1c  mov  w1, #0x1318
0x8dd5d20  bl   0x8df882c            ; memset(sp+8, 0x1318)
0x8dd5d24  ldr  x8, [x19, #0x20]      ; args->scalarInput64
0x8dd5d28  ldr  w1, [x8]              ; 用户标量
0x8dd5d2c  ldr  x0, [x20, #0xd8]
0x8dd5d30  add  x2, sp, #8            ; 输出指向栈缓冲
0x8dd5d34  bl   0x8dbdfc8             ; ★ 被调方没有长度参数
0x8dd5d38  mov  x20, x0
0x8dd5d40  mov  w1, #0x1318
0x8dd5d44  bl   0x8df82cc            ; 栈保护校验
0x8dd5d48  ldr  x8, [x19, #0x78]      ; structureVariableOutputData
0x8dd5d4c  str  x0, [x8]              ; 把结果指针写回用户可见槽
```

`stOut = 0xffffffff`（变长），但**实际写入长度是写死的 `0x1318`**，被调方 `0x8dbdfc8` 只拿到 `(obj, scalar, buf)`，**没有长度参数可被污染**。栈上有 `stack_chk_guard`（`0xfffffe000808b1c0`）且返回前做 `0x8df82cc` 校验，溢出会被 `brk`。

**这一条反而是「变长声明 + 定长实现」的正确写法**，与 sel6 的「变长声明 + 用户定长」正相反。

### 3.6 AppleH16CameraInterface 结论

117 个 selector 的**入口全部扫过**（每个读了 26 条指令，记录它碰了哪些 args 字段和尾调用目标，见 `out/iv/selectors.txt`），**深读 6 个**（sel0/1/2/4/6/94）+ 3 个被调函数。两个变长 selector 都追到了下游钳位或定长写入。**未发现可确认的内核内存破坏。**

---

## 4. 五类问题的逐类判定

| 类别 | JPEG | ProRes | H16Cam |
|---|---|---|---|
| ① 索引/长度直取 scalar/struct，无上界 | 未命中（所有结构体长度有 `cmp+b.ls/b.hi`） | **形态命中**：`0x93c6bfc` idx×4 无容量检查；**但零引用** | **形态命中**：sel6 count=size/56；下游有 `[1,0x80]` 钳位 |
| ② 尺寸计算整数溢出（mul/lsl 后直接分配/拷贝） | 未命中（`0x900cae8` 的 `mul` 是除 3 魔数） | 未命中（`0x93c6d34` 收到多大分配多大） | 未命中（`umull`+`csel 毒指针` 在派发处；`0x8d9dfc0` 的 `lsl #6` 有 `≤0x80` 前置） |
| ③ `copyin` 长度与实际使用不一致 | 未命中（入口不传长度，全固定位移） | 未命中（sel1 钳位在乘法之前） | 未审计（117 个里只深读 6 个） |
| ④ selector 派发类型混淆 / 越界跳转 | 未命中（`b.lo` + `mov w4,#0xa`） | 未命中（`b.lo` + `mov w4,#5`） | 未命中（`umull` + 溢出检测 + `cmp w1,#0x75`） |
| ⑤ 结构体字段当指针/数组下标 | 未命中（`struct[0x30]` 只判非空，未解引用） | 候选 A 即此类（`x1` 当数组索引），零引用 | 未命中（`args+0x68` 是内核给的 IOMemoryDescriptor，`autda` 后走 vtable） |

---

## 5. 未审计清单（明确留白，不冒充）

### 5.1 完全没碰
| 项 | 规模 | 缺什么 |
|---|---|---|
| H16Cam 其余 111 个 selector 的**函数体** | 111/117 | 只做了入口级扫描（读哪些 args 字段、尾调用去哪），没读方法体 |
| `AppleH16PearlCamUserClient` 的派发表 | 1 张 | 只找到 CamIn 的一张；Pearl 的 117 项之外可能还有一套 |
| ProRes sel2（`stIn=0xa8`）实体 | 1 个 | 入口读了，方法体 `0x93d6474` 未读 |
| JPEG sel0/sel2 实体（`0x900a73c`/`0x900a748`） | 2 个 | 只看了含 `mul w24,w0,w24` 的 `0x900a7c0` 片段，判断为硬件能力查询 |
| `0x8d9deb8` 的虚调用目标（`vtable+0xe8`） | 1 个 | 定义未知，无法确认 `w2` = count |
| `0x93c6d34` 分配后的**写入侧** | 1 条链 | 只确认了「按用户尺寸分配」，没追「谁写、写多少」 |

### 5.2 方法本身的残留风险
1. **40 字节 vs 24 字节派发记录**：JPEG/ProRes 是 `0x28`，H16Cam 是 `0x18`。前 24 字节布局一致、后 16 字节全 0。这两个 kext 走的是 `IOUserClientDefaultLockingSingleThreadExternalMethod`，H16Cam 自己算 `&table[i]` 再传给 `IOUserClient::externalMethod` —— 这个解释与字符串证据吻合，但**我没有解开这两个内核入口去验证步长**。
2. **`args+0x60`（`structureOutputSize`）没有一处直接观测**，位置是推断的。
3. **`ktriage.py` 的 `IDX` 信号噪声大**（JPEG 52 / ProRes 162 / H16Cam 174 条），它只做「值来自内存 + 被缩放 + 本函数内没出现对该寄存器的 `cmp`」，不建完整 def-use 链。真正可信的只有我手工读过的那些。**不要把这三个数字当发现数。**
4. **可达性全部未实测**：三个 kext 都没在真机上跑过 `IOServiceOpen`。ProRes 因 `com.apple.private.proreshw` 可直接判定打不开；JPEG 和 H16Cam 取决于 sandbox profile，**不知道**。

### 5.3 关于 §1.3 的更正建议
`USERCLIENT-TARGETS.md` §1.3 与 §4.1 里「selector 数 301 kext 全部未取」应改为「已解，方法见 `AUDIT-IMAGE-VIDEO.md` §0」。普查表那张 40 行的 `selector 数` 列可以直接填了。

---

## 6. 直答

**这三个 kext 里，有没有用户可控输入导致的内核内存破坏？**

**没有可确认的。**

逐条说清楚边界：

- **AppleJPEGDriver**：10 个 selector 入口全读，5 个方法实体读到关键分支。所有结构体驱动的长度都有显式上界（`cmp w25,#0x1000` / `cmp w8,#0xff` / 枚举白名单），所有拷贝都是固定位移定长，入口根本不传长度。**这一段是干净的。**
- **AppleProResHW**：可达性先出局（`com.apple.private.proreshw`，dev-signed app 拿不到）。代码侧有一个**正确**的钳位样本（sel1，`min(·,8)` 在乘法之前）；有一个用户尺寸直进分配器的路径（sel3 → `0x93c6d34`），分配本身不错配，**写入侧未追，留白**；有一个形态完全命中第 1 类的数组索引（`0x93c6bfc`，`idx*4` 加在 `obj+0x180`/`0x190` 上，只有乘法溢出保护没有容量检查），**但三重引用搜索（全 cache 分支、全 cache 重定位指针、全 cache 原始低 32 位）结果都是 0，够不着**。
- **AppleH16CameraInterface**：117 个 selector 入口全扫、6 个深读。两处 `kIOUCVariableStructureSize` 都追到了下游：sel6 的记录数 `size/56` 在入口无上界，但下游回调 `0x8d9df18` 有 `1 ≤ n ≤ 0x80` 的钳位（**寄存器对应关系未证**）；sel94 声明变长但实现是写死的 `0x1318` 字节栈缓冲 + `stack_chk_guard`。**都没接上「越界写」的证据链。**

下面两句话是这次审计最该被记住的：

1. **「差分看不见的 bug」确实存在，但不在这次的位置。** 这三处的共同特征是「长度已经被夹住」，而不是「27.2 才补上夹子」——也就是说，就算做差分，它们也不会被报成修补点，因为**本来就没修**，本来也不缺。
2. **真正值得继续追的只有一条**：ProRes `0x93c6bfc` 的用户索引路径。它的形态是本次唯一一个「索引直取 + 无容量检查」且**代码完整可读**的，唯一缺的是可达性。如果哪天找到算出来的入口（比如某个 vtable 用 `base + k*4` 索引函数指针数组），它立刻就是一个上界 16 GiB 的越界读。追它的成本比现在低得多——地址已经在手上了。
