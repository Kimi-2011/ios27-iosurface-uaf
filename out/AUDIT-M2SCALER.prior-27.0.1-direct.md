# AppleM2ScalerCSCDriver 直接审计（27.0.1，静态，无设备）

1. 靶子：`com.apple.driver.AppleM2ScalerCSCDriver`，从 `out/kc.27.0.1.full` 抠出，`out/m2s.27.0.1.macho`（3,094,040 B，`__TEXT`/`__TEXT_EXEC`/`__DATA`/`__DATA_CONST`/`__LINKEDIT` 五段）。
2. 这是**审计**，不是差分。全篇只问「这段代码在 27.0.1 里能不能越界」，不问「27.2 修没修」。
3. 类是 `IOSurfaceAcceleratorClient`（`IOSurfaceAcceleratorClient.cpp` 的断言串在本 kext 里），源码树路径 `.../Sources/IOSurfaceAccelerator/AppleM2ScalerCSCDriver/...`。
4. 先修了一个工具 bug（`adrp` 操作数带 `#` 前缀导致字符串/交叉引用解析一直空转），修完后本 kext 的字符串引用从「0 处」变成 28 处。**这个 bug 让此前 USERCLIENT-TARGETS 里「代码形状扫描命中 0」的结论失效**，已在 §1 更正。
5. 顺手把 chained-fixup 指针编码解开了：`va = 存储低 36/32 位 + 0xfffffe0007004000`，4 个手验样本全部落在 `bti c; pacibsp` 上，全 kext 解出 30,884 个指针、其中 5,079 个精确落在函数起点。
6. 方法表**找到了位置**：7 张 5 槽表在 `__DATA_CONST`（`0xfffffe00080e9078` 等，§3.3）。但它的形状不是 24 字节 `IOExternalMethodDispatch`，槽位下标 ↔ selector 编号的对应没解出来。
7. 因此 `selector 11` 的派发路径**未证**；我不能说它是哪个函数，也不能说它可达。
8. 中途纠正了一个大坑：我的函数边界比真表晚 4 字节（真起点是 `bti c; pacibsp` 的 `bti c`），先前「7 个 handler 引用数全 0」和「91% 函数无调用者」都是这个错位造成的假象（§1.4）。
9. 逐条读了 7 处可疑点 / 12 个函数：5 处确认有边界（`sub+cmp+b.hi` + 位掩码双重限制），1 处所有循环定长、实际安全但安全性不来自 `0x2bad`，1 处长度与指针来源断在表派发上（§4）。
10. 一个重要发现：本 kext 里遍布 `cmp x8, w8, sxtw` + `movk x16,#0x2bad,lsl #48` + `csel` 这组指令（700+ 个函数里都有）。它是**索引位移溢出检查**，不是数组长度检查——两者差别是本轮审计最关键的判据（§1.3）。
11. 最后一句是直答：我读到的地方没有找到用户可控输入导致的内核内存破坏；但 selector 编号映射缺失意味着「可达性未证」，所以结论是「未发现」，不是「不存在」。

---

## 1. 工具与三个判据级发现

### 1.1 `adrp` 操作数解析 bug（影响此前结论）

`capstone` 输出 `adrp x8, #0xfffffe0007610000`，操作数带 `#`。我此前的代码写的是 `int(p[1], 16)`，抛 `ValueError` 后被 `except: pass` 吞掉，于是：

- `adrp` 算出的页地址**从来没被记录**，`add xN, xN, #imm` 的字符串/地址解析**全部空转**；
- 所有「按代码形状找派发表命中 0」的结论都只是解析失败，不是「不存在」。

修法：`int(p[1].lstrip('#'), 16)`。修完立刻能在本 kext 解出 28 处 `IOSurfaceAcceleratorClient` 引用、1 处 `asynchronousUserClientCompletionCallback`、1 处 `setLockedInScaler`。

**更正**：`out/USERCLIENT-TARGETS.md` §1.3 第 3 条（「代码形状扫描命中 0 ⇒ 参数位置不是我假设的那套」）建立在同一 bug 上，这条证据作废。其余结论不受影响——guard-signature 判据不含任何字符串或 adrp 解析。

### 1.2 chained-fixup 指针编码（新解出）

`__DATA_CONST` 里的 8 字节字不是裸指针。按 `DYLD_CHAINED_PTR_ARM64E` 位域拆：

```
auth  = bit63      ; 1 = 带 diversity 的签名条目（target 用低 32 位）
bind  = bit62      ; 1 = 符号绑定，跳过
next  = bits 51..61; 链步长 = next*4 字节
key   = bits 49..50
target= 低 36 位（auth 条目取低 32 位）
```

`va = target + 0xfffffe0007004000`。

手验 4 个样本（`0x20454e8 / 0x2046630 / 0x204a340 / 0x204af30`）解出的 VA 全部是 `bti c; pacibsp; stp x29,x30` —— 函数起点。全 kext 解出 30,884 个指针，5,079 个精确落在我的函数起点集合里。

**这条对后续所有 kext 都通用**（`__TEXT_EXEC` 的 `fileoff + 0xfffffe0007004000 == vmaddr`，本 kext 实测 0x20417b0 → 0xfffffe00090457b0 完全吻合）。

### 1.3 `0x2bad` 不是毒化边界检查，是位移溢出检查

本 kext 里 700+ 个函数含这组指令：

```
ubfiz x8, x8, #3, #0x20      ; x8 = (u32)idx << 3，零扩展到 35 位
cmp   x8, w8, sxtw           ; 和「低 32 位符号扩展」比
add   x10, x9, w8, sxtw      ; 正常地址（符号扩展）
add   x16, x9, x8            ; 另一条（零扩展）
movk  x16, #0x2bad, lsl #48  ; 把零扩展那条毒化
csel  x10, x10, x16, eq      ; 相等用正常的，不等用毒化指针 → 访问即崩
```

语义：`idx*8` 一旦越过 bit31，就用故障指针。**它检查的是乘法溢出，不是 `idx < count`。** 一个 4 元素表配 `idx = 1000` 完全通不过这组指令的拦截——1000*8 不溢出，照读。

这正好符合既定的「乘法常数 + 移位 + 掩码 ≠ 边界检查」纪律，只是换了个形态（这次是编译器插的，不是手写哈希）。**读这个 kext 的任何 `table[idx]` 都要先扣掉这层，别把它当上界。**

### 1.4 函数边界：真表解出来了，我的判据差 4 字节

`LC_FUNCTION_STARTS`（dataoff `0x29b170`，size `0x2f00`，ULEB128 增量）解码基准是**镜像第一个段的 vmaddr** `0xfffffe0007543170`（`__TEXT`），不是 `__TEXT_EXEC`：

- 解出 **10,262** 个函数起点，第一个 = `0xfffffe00090457b0`（正好是 `__TEXT_EXEC` 起点），最后一个 `0xfffffe0009185f44`，**全部落在 `__TEXT_EXEC` 内**。

我的边界判据（`pacibsp ∪ (bti c 且下条≠pacibsp)`）给出 10,354 个，数量对得上，但**每个都晚 4 字节**：真函数是 `bti c; pacibsp`，我的规则在「`bti c` 后紧跟 `pacibsp`」时把它判成同一个起点并取了后一条，于是所有 `bl` 目标（指向 `bti c`）全都不匹配。

后果：先前算出的「91% 的函数没有直接调用者」是**假象**。用真表重算：

| 项 | 值 |
|---|---|
| 真函数数 | 10,262 |
| `bl`/`b` 调用边 | 28,286 |
| 不同调用目标 | 7,126 |
| 无直接调用边的函数 | 7,254（70%） |

70% 仍然很高，但这次是真实的：本 kext 是 C++ 重负载（`IOSurfaceAcceleratorClient` + 十几个 `M2Scaler*MSR*` 控制类），虚调用占大头。

**纪律结论修正**：`调用者=0` 只能读作「没有直接 `bl`/`b`」，这一点不变；但**地址必须用真表的起点**，否则会把「函数中段」当成函数头——我先前 7 个所谓 handler 全部踩了这个坑（见 §3.2）。

---

## 2. kext 结构

### 2.1 段与规模

| 段 | vmaddr | 文件大小 |
|---|---|---|
| `__TEXT` | `0xfffffe0007543170` | 0xe890b |
| `__TEXT_EXEC` | `0xfffffe00090457b0` | 0x1413b8 |
| `__DATA` | `0xfffffe000b8d1d08` | 0x24000 |
| `__DATA_CONST` | `0xfffffe00080e3760` | 0x32248 |
| `__LINKEDIT` | `0xfffffe000ba10000` | 0x73029 |

`LC_SYMTAB` 的 `nsyms = 0`，没有 `LC_DYLD_EXPORTS_TRIE`。**没有任何符号**，函数名只能靠断言串锚定。

### 2.2 字符串能锚出什么

从 `__TEXT`/`__DATA` 抽到的关键串（全部实证）：

- 类：`IOSurfaceAcceleratorClient`、`IOSurfaceAcceleratorClientProperty`（后者只在报错格式串里出现）、`kModuleCSC`。
- 方法名：`setLockedInScaler`、`getLockedInScaler`（各 1 处引用）、`asynchronousUserClientCompletionCallback`（1 处引用）、`getIOSurfaceFilmGrainAttachment`、`getCSCMatrix_gatedContext`、`directionalScalingDimCheck`。
- 来源文件：`IOSurfaceAcceleratorClient.cpp`、`AppleM2ScalerCSCHalMSR9/10j/18/21/22.cpp`、`M2ScalerSrcDestCfgControlMSR2/7/9/13/14/23.cpp`、`M2ScalerScalingASEControlMSR10/20.cpp`、`M2ScalerCSCColorConversionControlMSR23.cpp`、`AppleM2ScalerCSCDriverFilters.h`。
- bundle id 串：`com.apple.driver.AppleM2ScalerCSC`（截断）与 `com.apple.driver.AppleM2ScalerCSCDriver`。

### 2.3 comm-API 请求结构（0x1090 字节）

`fn 0xfffffe0009082c8c` 的头三条就有决定性信息：

```
str w8, [x2, #0x1088]   ; w8 = 0xe00002bc (kIOReturnUnsupported)  ⇒ 预置返回码
...
str wzr, [x19, #0x1088] ; 函数尾声清零返回码
```

即：**存在一个 ≥ 0x108c+4 字节的请求结构，最后 4 字节是返回码**。这函数从该结构里读 `+0x20 / +0x2c / +0x28 / +0x30 / +0x68 / +0x70 / +0x74 / +0x88 / +0x1d4 / +0x1d5 / +0x1d8 / +0x1dc`，写 `+0x1088`；中途调一次内部虚方法（vtable 偏移 `0xf8`，`w1 = 0x11`）。

请求结构规模 0x1090 说明它是 `structureInput` 一类的大 blob，而不是 `IOExternalMethodArguments` 的标量数组——`IOExternalMethodArguments` 本身只有 ~0x70 字节。

### 2.4 13 个「读 args 结构偏移」的函数（候选 handler）

扫描全 kext 里对 `[x2 + {0x18,0x20,0x28,0x30,0x38,0x40}]` 的读取：

| 函数 | 指令数 | 读到的字段 | 备注 |
|---|---|---|---|
| `0xfffffe0009175858` | 22 | `[x2+0x18]` | 纯断言 thunk（`w5=0x2aeb`）；**有 1 个直接调用者** `0x90c959c` |
| `0xfffffe0009171250` | 21 | `[x2+0x40]` | 纯断言 thunk（`w5=0x30b`）；**有 1 个直接调用者** `0x90af39c` |
| `0xfffffe00090daa7c` | 97 | `[x2+0x18]` | 断言 + 链表摘除；0 直接调用者 |
| `0xfffffe000910d11c` | 56 | `[x2+0x20]` | 待读；0 直接调用者 |
| `0xfffffe000916a330` | 129 | `[x2+0x40]` | 见 §4.1；**被 2 处表项引用** |
| `0xfffffe0009082c8c` | 337 | `0x20/0x30/0x28` | 见 §2.3、§4.3；**被 1 处表项引用** |
| `0xfffffe00090f1ac8` | 359 | `0x20/0x30/0x28` | 同模板；**被 1 处表项引用** |
| `0xfffffe0009100b1c` | 358 | `0x20/0x30/0x28` | 同模板；**被 1 处表项引用** |
| `0xfffffe0009045b84` | 1971 | `[x2+0x18]` | 数值例程（4 参数），不是 handler；4 个直接调用者 |

**注意**：这 13 个里有 4 个是纯断言 thunk。真正的候选 handler 只有 3 个同模板函数（336/358/358 条）+ 2 个读 `[x2+0x40]` 的。

**没有任何函数读 `[x2+0x38]`（`structureInputSize`）。** 这是一个需要在报告里留白的观察：要么本 kext 的 handler 不直接校验尺寸（靠 IOKit 的 `checkStructureInputSize`），要么 `IOExternalMethodArguments` 的字段序和我用的不同。

---

## 3. selector 派发表：位置找到了，编号没解出来

### 3.1 结论

派发表（更准确说：方法表）**找到了**，就在本 kext 自己的 `__DATA_CONST` 里。但**表记录不是 `IOExternalMethodDispatch`（24 字节 / 4×u32）形状**，所以没法直接把槽位下标读成 selector 编号；`selector 11` 仍未定位。

### 3.2 怎么找到的（以及先前为什么找不到）

两步都必须：

1. **用真函数起点**（§1.4）。先前 7 个「handler」的地址全部比真起点晚 4 字节；`bl` 和表项都指向 `bti c`，因此按错位地址搜什么都搜不到。这是先前 §3 旧版本「13 个 handler 引用数全 0」的真正原因——**不是派发机制特殊，是我地址错了**。
2. **用 §1.2 的 chained-fixup 解码**（`va = 存储低 32 位（auth 条目）或低 36 位 + 0xfffffe0007004000`），再反过来对整个 78 MB cache 做「这个 VA 出现在哪个数据字里」的反查。

反查结果（外层文件偏移 → 段内偏移 → VM）：

| 命中文件偏移 | `__DATA_CONST` 内偏移 | VM 地址 | 该槽位指向 |
|---|---|---|---|
| 0x10e9078 | +0x9918 | `0xfffffe00080e9078` | `0xfffffe0009082c8c` |
| 0x10fc5b8 | +0x1ce58 | `0xfffffe00080fc5b8` | `0xfffffe00090f1ac8` |
| 0x10fd2d8 | +0x1db78 | `0xfffffe00080fd2d8` | `0xfffffe0009100b1c` |
| 0x10e9f08 | +0xa7a8 | `0xfffffe00080e9f08` | `0xfffffe000916a330` |
| 0x10eefd8 | +0xf878 | `0xfffffe00080eefd8` | `0xfffffe000916a330` |
| 0x10fb158 | +0x1b9f8 | `0xfffffe00080fb158` | `0xfffffe00090daa7c` |
| 0x10ff268 | +0x1fb08 | `0xfffffe00080ff268` | `0xfffffe000910d11c` |

（`__DATA_CONST` 外层起点 `0x10df760`，VM 起点 `0xfffffe00080e3760`，长度 `0x32248`，全部对得上。）

### 3.3 表记录的实际形状

以 `0xfffffe00080fc5b8` 为中心解码（`auth=1, next=2` ⇒ 8 字节步长）：

```
-1  0xfffffe000910b184
 0  0xfffffe00090f1ac8   ← 候选 handler
 1  0xfffffe000910b3b8   ← 三张表里都一样
 2  0xfffffe0009057bfc
 3  0xfffffe000910b1a0   ← 三张表里都一样
 4  0xfffffe00090f2074   ← next=8（链跳 32 字节）
 5  0x0
 6  0x0
```

`0xfffffe00080e9078` 那张是 `[0x9082c8c, 0x910b3b8, 0x9083214, 0x910b1a0, 0x9083788]`，`0xfffffe00080fd2d8` 那张是 `[0x9100b1c, 0x910b3b8, 0x91010b4, 0x910b1a0, 0x9101298]`。

共同点：**槽 0 = 一个候选 handler，槽 1 恒 `0x910b3b8`，槽 3 恒 `0x910b1a0`，槽 2 和槽 4 是各自的东西，槽 4 之后跟 32 字节非指针数据。**

所以这不是 `IOExternalMethodDispatch`（那需要「函数指针 + 4 个小整数」，24 字节），而是某种**方法表/描述符数组**：每张 5 槽 + 32 字节填充。我没有证据说明槽 0 对应 select 0、槽 2 对应 selector 1……

`0xfffffe000916a330` 同时出现在**两张**表里（`0x80e9f08` 和 `0x80eefd8`），说明它是被两个描述符共用的实现，不是「一个 selector 一个函数」。

### 3.4 还差什么

- 没找到**把用户 `selector` 与这张表连起来**的代码。要么它在另一个 kext（`com.apple.iokit.IOSurfaceAccelerator` 之类）里，要么走的是我还没识别的 `IOUserClient` 覆写形式。
- 因此 `selector 11` 是谁、参数怎么取、是否可达——**全部未证**。任何「selector 11 读某字段」的说法都是猜的，本文不写。

## 4. 逐点审计

### 4.1 `0xfffffe000916a330`（129 条指令）——结构体拷贝，长度来源未证

签名看：`x0 = self`、`x1 = 某配置对象`、`x2 = 参数结构`（`x19`）。

```
ldr x8, [x2, #0x40]        ; 用户侧位图（bitmask）
cbz x8, skip
rbit x8, x8 / clz x22, x8  ; x22 = 最低置位位的下标（0..63）
...
loop:
  ldr x16, [x21]           ; self->vtable（PAC 签名）
  autda x16, x23
  add x16, x16, #0x138
  ldr x8, [x16]            ; 虚方法
  mov x0, x21 / mov x1, x20 / mov x2, x22
  blraa x8, x16            ; 调 (self, cfg, bit_index)
  ...
  cmp x22, #0x1e           ; ← 位下标上限 30
  b.hi skip
  ldr x8, [x19, #0x40]
  lsl x9, x25, x22         ; x25 = -2
  ands x8, x8, x9
  rbit/clz → 下一个置位位
  b.ne loop
```

关键片段（重复 3 次，分别在 `+0x140 / +0x40c / +0x4f0` 一带）：

```
cmp  x2, #0x10            ; x2 = [x21, #0x80]（self 里的长度字段）
b.lo skip
ldr  x8, [x19, #0xa0]     ; 源（用户结构的字段）
lsr  x9, x2, #4
ldr  q0, [x8], #0x10
str  q0, [x0], #0x10      ; 目标 = [x21, #0xa0]
subs x9, x9, #1
b.ne loop
```

判定：

- 循环次数 = `x2 >> 4`，`x2` 来自 `[self+0x80]`（**内核对象字段**，不是本次 user 结构），源指针来自 `[param+0xa0]`。
- 位图循环有 `cmp x22, #0x1e / b.hi` 上限，`x22` 由 `clz` 保证 ≤ 63，实际上限 30 是显式的。**这一路是有界的**。
- 拷贝那一支的 `x2` 和 `[param+0xa0]` 的**来源未证**：`param` 是 `x1` 还是 `x2` 视调用者而定，而我拿不到调用者（§3）。

**判定：未定性。** 有界的地方确认有界；拷贝支路的长度/指针来源追不到，按纪律留白。

### 4.2 表查找 + 范围检查（5 处，全部确认有界）

`0xfffffe00090b57c8`、`0x90c50d4`、`0x90c5480`、`0x90c563c`、`0x9102ef4`、`0x9129834`、`0x912fa50` 是同一个形状：先对一个「枚举值」做范围 + 位掩码双重限制，再查表。

以 `0x90c50d4` 为例：

```
ldr w19, [x8]              ; 全局枚举
sub w8, w19, #1
cmp w8, #0x1d              ; ← 上界 29
b.hi  fail
mov w9, #0xfff7 / movk w9, #0x3fff, lsl #16
lsr w9, w9, w8
tbz w9, #0            , fail   ; ← 位掩码再筛掉非法值
ubfiz x8, x8, #3, #0x20
adrp x9, ...  / add x9, x9, #0xfa0   ; 表基址
cmp x8, w8, sxtw               ; ← §1.3 的溢出检查（冗余，上面已限死 <29）
... csel 毒化 ...
ldr x8, [x10]
```

判定：**有界**。`sub+cmp+b.hi` 把索引限死在 0..29，位掩码是白名单，表至少 30 项。§1.3 的 `0x2bad` 在这里纯冗余。

同类 `0x9102ef4 / 0x9129834 / 0x912fa50`：`ldr w8,[xN,#0x4c]; sub w8,w8,#0x17; cmp w8,#7; b.hi` → 索引 0..7，表 8 项。**有界。**

### 4.3 `0xfffffe0009082c8c`（336 条指令）——大结构读写，无自校验

- 开头 `str w8,[x2,#0x1088] = 0xe00002bc`，结尾 `str wzr,[x19,#0x1088]`。整个函数**没有出现任何对 `[x2+0x38]`（尺寸字段）的读取**，也没有任何 `cmp` 针对「结构大小」。
- 它读 `[x2+0x20]` 后 `cmp w8,#1; b.ne`（模式开关），读 `[x2+0x2c]/[x2+0x28]/[x2+0x30]` 直接拷进 self，读 `[x2+0x68]/[x2+0x70]` 拷进 self，读 `[x2+0x1d4/#0x1d5/#0x1d8/#0x1dc]` 拷进 self。
- 所有循环都是**定长**（3、4、4 次），没有以用户字段为次数的循环。
- 三段 `0x2bad` 处的索引是 `x23`（0..2 的循环计数器）和 `0x90c2e5c(x23)` 的返回值，见下：

```
mov x0, x23
bl  #0xfffffe00090c2e5c      ; 返回一个枚举
ubfiz x8, x0, #3, #0x20
cmp x8, w8, sxtw             ; §1.3 溢出检查
add x9, x21, w8, sxtw        ; self + 返回值*8
add x16, x21, x8
csel x9, x9, x16, eq
ldr x8, [x9]                 ; ← self[返回值]
```

这里 `0x90c2e5c` 的返回值只过 `0x2bad` 溢出检查，**没有范围检查**就当作 `self + ret*8` 的索引。`0x90c2e5c` 本体是：

```
cmp w0, #2 / b.hi → 返回 0 ...  （0x90c2dec / 0x90c2e5c 都是这个形状）
```

即 `x0`（= `x23`，0..2）被自己限制到 ≤2，返回 0/1/2 之一。所以 **实际是安全的**，但安全性来自 `x23` 的循环上界，不是来自 `0x2bad`。

判定：**这一路有界**（定长循环 + 被调函数自带上界）。但要注意模式：**`0x2bad` 让代码看起来有保护，实际保护来自别处**——这正是 §1.3 那条判据的用处。

### 4.4 断言密集度

`bl 0xfffffe000905c248`（断言打印机）被调用 1,677 次，`0x905c20c` 1,843 次，另有 3 个变体各 700–1,050 次。加上 §1.3 的 700+ 处 `0x2bad`，说明本 kext 是**带断言 + 索引检查编译**的。

对审计的意义：**「看起来没检查」的地方，先确认是不是被这两层（断言 / 位移溢出检查）遮住了实际逻辑**；同时记住这两层都**不**提供 `idx < count` 语义。

### 4.5 `directionalScalingDimCheck`（`0x917dab4` / `0x9180748`）

断言串：`Source dimensions outside ASE range: Src width = %s%d.%s%u, ... Min = ..., Max width ...`。同一个函数名在 27.0.1 里出现两次断言点（不同调用点）。

这是**尺寸范围校验**，方向正确（先查后算）。没有用户可控索引参与，不进候选。但它是「本 kext 有尺寸校验文化」的证据，值得记下。

---

## 5. 未审计清单

| 项 | 规模 | 为什么没做 |
|---|---|---|
| selector 编号 → 表槽位的映射 | 全部 | §3.3：表找到了，形状不是 24 字节 `IOExternalMethodDispatch`，槽位下标与 selector 的对应关系未证 |
| `selector 11` 参数取法 | 1 | 依赖上一项 |
| 「谁拿 selector 当索引读 §3.3 那 7 张表」 | — | 在 `__TEXT_EXEC` 里没找到指向这些表基址的 `adrp+add`；`__DATA_CONST` 里对这些基址的反向查表也还没做 |
| 三份同模板 handler 的**调用者** | 3 | 地址更正为 `0x9082c8c / 0x90f1ac8 / 0x9100b1c`；`bl` 调用者为 0，但已被 §3.3 的表项引用（先前「无数据引用」是地址错位导致的误判） |
| `0x9045b84`（1971 条，最大函数） | 1 | 只读了头部 44 条，判定是数值例程，未细审 |
| `0x910d11c`（56 条） | 1 | 待读 |
| `__TEXT_EXEC` 其余 ~10,250 个真函数 | 全部 | 70% 没有直接调用边（§1.4），虚调用为主，无法做可达性驱动的裁剪；只人工读了 12 个 |
| `__DATA_CONST` 里 5,079 个「指向函数起点」的指针语义（vtable / 派发表 / 回调） | 5,079 | 解码器有了（§1.2），但没做分类 |
| `__DATA` 的 `__kmod` / OSMetaClass 结构 | — | 未尝试；解出 metaclass 才能定位 `externalMethod` 本体 |
| 27.2 侧的同一份审计 | — | 本轮按要求不做差分 |

### 5.1 下一步最有价值的两件事

1. **解 `__DATA` 里的 OSMetaClass**。`IOSurfaceAcceleratorClient` 的 metaclass 里必然有 `getMetaClass` 指针，从那儿能反推 vtable 基址，再顺到 `externalMethod` 本体。这是把「用户 selector」和「我读过的代码」接起来的唯一通道。
2. **找 `selector` 与 §3.3 那张表的连接点**。表位置已有（`0xfffffe00080e9078` / `0x80fc5b8` / `0x80fd2d8` / `0x80fb158` / `0x80ff268` / `0x80e9f08` / `0x80eefd8`），缺的是「谁拿 selector 当索引读这些 5 槽记录」。在 `__DATA_CONST` 里对这些表基址再做一次反向查表（我在 `__TEXT_EXEC` 里没找到 adrp+add 指向它们的代码），或去 `com.apple.iokit.IOSurfaceAccelerator` 找 `IOSurfaceAcceleratorCommApi`。

---

## 6. 直答

**在我逐条读过的代码里，没有找到用户可控输入导致的内核内存破坏。**

具体地：7 处可疑点，5 处（`0x90b57c8 / 0x90c50d0 / 0x9102ef0 / 0x9129830 / 0x912fa4c` 这一族查表）确认有 `sub+cmp+b.hi` 的显式范围限制，表容量至少等于上界+1；1 处（`0x9082c8c`）所有循环定长（3/4 次），索引被循环上界和被调函数 `0x90c2e5c` 自己的 `cmp w0,#2` 双重限制，只是安全性**不来自**那层 `0x2bad` 保护；1 处（`0x916a330` 的 16 字节拷贝支路）源指针与长度都来自对象字段，调用者链断在表派发上，按纪律记为**未定性**而不是「有洞」。

但必须同时说清：**这不等于「这个 kext 里没有洞」。**

- 方法表虽然找到了位置（§3.3，7 张 5 槽表），但**槽位下标 ↔ selector 编号的对应关系没解出来**，所以「用户给 selector 11 时进哪个函数」这一步断了。可达性未证，任何「没有洞」的表述都超出证据。
- 只人工读了 12 个函数 / 10,262 个；70% 的函数没有直接调用边，我无法用调用图做可达性裁剪。
- `__DATA` 的 OSMetaClass 没解，`externalMethod` 本体没找到。

准确的结论是：**未发现，不是不存在。** 下一刀切在 `__DATA` 的 OSMetaClass → vtable → `externalMethod` 这条链上，那是唯一能把「用户参数」和「我读过的代码」接起来的地方；本文顺带交付的 chained-fixup 解码器（§1.2）和 `LC_FUNCTION_STARTS` 基准（§1.4）让这条链变得可走。
