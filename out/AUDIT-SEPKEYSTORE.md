# AUDIT — `com.apple.driver.AppleSEPKeyStore` 用户输入面（iOS 27.0.1）

> README（前十行）
> 1. 对象：`out/sepkeystore.27.0.1.macho`，787,840 B，`MH_KEXT_BUNDLE`，arm64e，已 strip（nsyms=0），10 个 load command。
> 2. 任务：定位 externalMethod 真入口 → 枚举全部 selector → 按 5 类模式审计用户输入处理 → 每点给出「用户参数 → selector → 字段 → 计算 → 内存操作 → 越界多远」。
> 3. 入口：`AppleKeyStoreUserClient::externalMethod` @ `0xfffffe00095cc1e8`（`__text` 单函数 34 KB / 8,558 条指令，169 个 handler 全部内联在同一函数体内）。
> 4. 分发：169 项 `int32` 跳转表 @ `0xfffffe00095d47a0`（selector 1…169），上界 `cmp w28,#0xa8` / `b.hi fail`；selector 0 单独走 `0xfffffe00095cc3e8`。
> 5. 结论：**在这份镜像读到的范围内，没有找到「用户可控输入 → 内核内存破坏」的路径**；5 类模式逐类给证据与反证，未覆盖部分在第 5 节明确留白。
> 6. 覆盖：169+1 个 selector 全部读出分发目标、块数、标量个数检查；其中 15 个逐条读完、21 个走 `(addr,len)` 拷入路径逐个核对、13 个核心被调函数读完。
> 7. 方法约束：函数边界只取 `LC_FUNCTION_STARTS`（1058 个，首项 = `__TEXT_EXEC` vmaddr，自校验通过），不用 `BTI`/`PACIBSP` 猜测；指针解链 `va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)`，不按 bit63 过滤。
> 8. 可复现：`/tmp/sep.py`（映射/解链）、`/tmp/sep_insns.pkl`（66,683 条反汇编）、`/tmp/sep_table.json`（跳转表）、`/tmp/sep_final.json`（169 行表数据）、`/tmp/sepflow.py`（计数-下标数据流）。
> 9. 全部地址均为镜像内 VA；文件偏移 = `VA - 0xFFFFFE000772D6A8`（section 头里的 `offset` 字段是错的，别用）。
> 10. 最终答案在文末最后一行。

---

## 0. 一句话结论

这个 kext 的用户态入口是**一次 `IOExternalMethod` 调用**：`selector` 决定 169 个内联 handler 之一，所有用户数据只有两种形态——**64 位标量**（`scalarInput64[i]`）和**「用户地址 + 长度」标量对**（走 `IOMemoryDescriptor::withAddressRange` → `map(kIOMapReadOnly)` → `OSData` 拷入内核）。
我把 5 类内核内存破坏模式逐类对着这两条通道查完，**没有找到用户可控输入能造成内核内存破坏的实例**：标量个数与下标严格配对（14 处可疑点全部手工复核为「可选尾标量」写法）、`(addr,len)` 的长度与指针同源（都来自同一个 `OSData`，不是用户给的 len）、整数与边界检查齐全、全可执行段只有 29 处寄存器变址访问且全部有界（分发器里只有 1 处，就是 selector 表本身）。

---

## 1. 目标镜像与结构

### 1.1 Mach-O 事实（实测）

| 项 | 值 |
|---|---|
| 类型 / 架构 | `MH_KEXT_BUNDLE` / arm64e，`LC_FUNCTION_STARTS` 起点 0xFFFFFE00095BBA10 |
| `__TEXT` | vm `0xfffffe000772ddd0` size `0x5fec` fileoff `0x728` |
| `__TEXT_EXEC` | vm `0xfffffe00095bba10` size `0x411ec` fileoff `0x6718`（`__text` 0x407bc，`__auth_stubs` 0xa30 @ `0xfffffe00095fc1cc`） |
| `__DATA_CONST` | vm `0xfffffe000819cf28` size `0x5240`（`__const` 0x3e38、`__kalloc_type` 0xd80、`__auth_got` 0x518、`__got` 0x98、`__auth_ptr` 0x18） |
| `__DATA` | vm `0xfffffe000b915cc8` size `0xa08` |
| `__LINKEDIT` | vm `0xfffffe000ba10000` size `0x73029`（`LC_FUNCTION_STARTS` dataoff 0x72090 datasize 0x638） |
| 符号 | `LC_SYMTAB` nsyms = 0（全 strip），因此**所有函数名都是推断**，报告里一律先给地址 |

映射规则（本镜像实测、无条件成立）：`file = VA - 0xFFFFFE000772D6A8`。注意 load command 里 section 的 `offset` 字段写的是 `VA - 0xFFFFFE0007004000`，是错值——例如 `__cstring` 标称 offset `0x72a538`，真实在文件 `0xE90`。任何按 section offset 读字符串的工具在这份镜像上都会读错。

### 1.2 为什么 2266-selector / 244-table / 301-kext 普查漏了它

普查假设「`cmp w1,#N` 链 + 数据段函数指针表」。这里两样都不是：**169 个 handler 被完全内联进一个 34 KB 的 `externalMethod`**，分发是一次 `int32` 偏移表 + `br`。所以按「selector→函数」找表找不到，按字符串找也找不到（表里只有代码偏移，没有名字）。

### 1.3 真入口的定位过程（证据链）

1. `LC_FUNCTION_STARTS` 解出 1058 个函数起点（ULEB128 累加，base = `__TEXT` vmaddr；首项 `0xfffffe00095bba10` == `__TEXT_EXEC` vmaddr → 自校验通过）。函数长度谱里出现一个 0x85B8 的巨大条目：`0xfffffe00095cc1e8` … `0xfffffe00095d47a0`。
2. 该函数体内只有 **1 条 `ret`**（`0xfffffe00095d3bdc`）和两处统一出口（成功 `0xfffffe00095d3ba0`、失败 `0xfffffe00095d22ec`），是典型的手写 `switch` 内联体。
3. 函数体内 `0xfffffe00095cc2d4`：
   ```
   0xfffffe00095cc244  subs   w28, w1, #1              ; w28 = selector - 1
   0xfffffe00095cc248  b.eq   0xfffffe00095cc268
   0xfffffe00095cc264  cbz    w25, 0xfffffe00095cc3e8   ; selector == 0 → 单独路径
   0xfffffe00095cc2a8  cmp    w28, #0xa8
   0xfffffe00095cc2ac  b.hi   0xfffffe00095d22ec        ; fail: 0xe00002c2 kIOReturnBadArgument
   0xfffffe00095cc2c0  mov    x16, x28
   0xfffffe00095cc2c4  cmp    x16, #0xa8                ; 冗余二次检查
   0xfffffe00095cc2c8  csneg  x16, x16, xzr, ls        ; 再夹紧
   0xfffffe00095cc2cc  adrp   x17, 0xfffffe00095d4000
   0xfffffe00095cc2d0  add    x17, x17, #0x7a0          ; 表基址 = 0xfffffe00095d47a0
   0xfffffe00095cc2d4  ldrsw  x16, [x17, x16, lsl #2]  ; 表项 = int32 偏移
   0xfffffe00095cc2d8  adr    x17, 0xfffffe00095cc2d8
   0xfffffe00095cc2dc  add    x16, x17, x16
   0xfffffe00095cc2e0  br     x16
   ```
   表基址 `0xfffffe00095d47a0`、长度 `169×4 = 0x2A4`，正好填满 `0x95cc1e8` 函数结束到下一个函数起点 `0xfffffe00095d4a44` 之间的空洞（这也是最初把它误判成「函数间空隙」的原因）。
4. 交叉验证：`x1` = `IOExternalMethodArguments.selector`（`IOUserClient::externalMethod(action, select)` 的第二个寄存器参数），`x2` = `IOExternalMethodArguments*`（下面 §2 用代码偏移反证了这一点）。
5. 结论：`selector ∈ 1..169` 走表，`selector == 0` 走 `0xfffffe00095cc3e8`（一次 `AppleKeyStore` 实例 vtable+0x2c0 的无参调用），`selector > 169` 直接 `0xe00002c2`。

### 1.4 selector 0 的处理（已读）

```
0x95cc3e8  bl   0x95c2d8c                  ; 前置：可能是状态/计数刷新
0x95cc3f0  bl   0x95cc06c                  ; 前置（x0 = self）
0x95cc3f4  ldr  x0, [x22, #0xd8]           ; self->f0d8 = AppleKeyStore 实例
0x95cc408  ...  x16 = vtable, add x16, #0x2c0
0x95cc410  ldr  x8, [x16]                  ; vtable+0x2c0 = 一个 0 参方法
0x95cc418  mov  w2, #0 ; mov x3, #0 ; blraa x8, x16
0x95cc428  add  w8, w20, #3 ; csel w24, wzr, w8, ne   ; 错误码合并
```
不触碰任何用户数据。

---

## 2. 参数通道（偏移由代码反推，不靠文档）

### 2.1 标量通道

`x19 = args`，全函数内：

| 偏移 | 代码证据 | 语义 |
|---|---|---|
| `+0x20` | `ldr x8,[x19,#0x20]` 后接 `ldr w21,[x8]` / `ldp x0,x1,[x8,#8]` | `scalarInput64`（u64 数组基址） |
| `+0x28` | `ldr w8,[x19,#0x28]; cmp w8,#N` | `scalarInputCount` |
| `+0x48` | 写入输出标量（`str x0,[x19,#0x48]` 型） | `scalarOutput` |
| `+0x50` | `ldr w8,[x19,#0x50]; cbnz w8,fail` / `cmp w8,#1`，从不被解引用 | `scalarOutputCount`（handler 要求 0 或 1） |
| `+0x60` | `0x95bc36c: csel x24,#0x70,#0x60` → `ldr w21,[x1,x24]` | `structureOutputSize` |
| `+0x68` | `0x95bc358: ldr x8,[x1,#0x68]; cmp x8,#0` | `structureOutputDescriptor` |
| `+0x70` | 同上 `csel` 的另一支 | `structureOutputDescriptorSize` |

**关键事实：`+0x30` / `+0x38` / `+0x40`（`structureInput` / `structureInputSize` / `structureInputDescriptor`）在这个 34 KB 函数体里从未被读取。** 全部 5,000+ 条访存里，对 `x19` 的 `0x30/0x38/0x40` 命中数为 0。也就是说：**这个 userclient 没有 structure input 面**，输入只有「标量」和「标量对 (addr,len)」两种。

### 2.2 数据通道：`0xfffffe00095e9370(user_addr, len)`

33 处调用，形态统一：

```
x0 = scalars[i+1]  (用户地址, u64)
x1 = scalars[i+2]  (用户长度, u64)
0xfffffe00095e9370:
  withAddressRange(addr, len, 2 /*kIODirectionOut*/, current_task())   ; stub 0xfffffe00095fc98c / 0x95fc45c
  desc->map(0x1000 /*kIOMapReadOnly*/)                                  ; vtable+0xe8
  kva  = map->getAddress()                                              ; vtable+0x78
  mlen = map->getLength()                                               ; vtable+0x88
  data = OSData::withBytes(kva, mlen)                                   ; stub 0xfffffe00095fc58c
  map->release()                                                        ; vtable+0x28
  return aks_release(data)  ; 0 → `OSData::withCapacity(0)`（空）
```

下游一律用 `data->getLength()`（vtable+0xa0）和 `data->getBytesNoCopy()`（vtable+0xd8）取值，**不会**再用用户给的 `len`。这一点是后面「长度/指针错配」能否成立的分水岭。

副作用（值得记录，但不是内存破坏）：`mlen` 是**映射长度**，按页向上取整，可能比用户请求的 `len` 大最多 4095 字节。用户即使传 `len=1`，handler 看到的 blob 长度也可能是 0x1000 级；读到的是**用户自己那页**的邻居字节，不越出用户地址空间。

### 2.3 输出通道

`0xfffffe00095bc328(obj, args)`：

```
x24 = (args->structureOutputDescriptor != NULL) ? 0x70 : 0x60
w21 = *(u32*)(args + x24)      ; 客户端声明可写的输出缓冲大小
len = obj->getLength()         ; 要回写的数据长度
if (w21 >= len) return 0
else  log "buffer size %d too small for data size %d"   ; 并返回错误
```
13 个 selector 在自身代码里走这条校验（含共享尾块则 17 个）。方向是「声明大小 ≥ 数据大小」，之后才拷出，没有反过来的写法。

## 3. 五类 bug 模式：审计方法与结论

先说方法，再说结论，最后给数据流。每类都标注「怎么查的 / 查到什么 / 证据在哪」。

### 3.1 类 A — 标量下标 > 标量个数（`scalarInput64` 数组越界读）

**怎么查的。** 对 169 个 selector 逐个做块级前向数据流：块内 `ldr wN,[x19,#0x28]` 认定「计数字寄存器」，随后 `cmp wN,#K` + 紧邻条件跳转按语义细化计数的上下界（`b.eq/b.ne` → 精确 K；`b.lo/b.hs/b.ls/b.hi` → 半开区间），再收集 `ldr/ldrsw/ldrb/ldrh/ldp` 里以 `scalarInput64` 为基址的访存索引，一旦索引 ≥ 计数上界就报。脚本 `/tmp/sepflow.py`。

**查到什么。** 机械扫描报出 14 个候选：sel `2, 5, 9, 12, 15, 18, 33, 42, 67, 70, 105, 110, 118, 126`。逐个手工复核后**全部是同一写法**（编译器为「可选尾标量」生成的形状）：

```
ldr  w8, [x19, #0x28]      ; count
cmp  w8, #K
b.eq  path_A               ; count == K   → 不读索引 K
cmp  w8, #K+1
b.ne  fail                 ; 只接受 K 或 K+1
ldr  w8, [x19, #0x50]      ; scalarOutputCount
cbnz w8, fail
ldr  x8, [x19, #0x20]
ldr  x9, [x8, #K*8]        ; 只有 count == K+1 才到达，索引 K 合法（有效下标 0..K）
```
即：带尾标量的调用方传 `K+1` 个、不带的传 `K` 个，两条路各自检查过。**没有一处能在 `count == K` 时读到索引 K。** 统计上，169 个 selector 里 102 个有显式计数比较；没有任何一个 selector 完全没有计数检查却读标量（最初报出的 22 个「无检查」是分析器把 `stack_chk_fail` 相邻代码和 tail-call thunk 当成同一路径的假阳性，例如 sel 74 实际只是把 `(self, [sp+0xb0], sel, args)` 转给 `0xfffffe00095d4b78`）。

**证据地址（14/14 全部按地址复核过）。** sel 2 `0x95cea58`（`#6`/`#7` → 只在 `#7` 读 `scalar[6]`）、sel 5 `0x95ce904`（`#4`/`#5` → 索引 4 只在 `#5`）、sel 9 `0x95ce018`（`#3`/`#4` → 索引 3 只在 `#4`）、sel 12 `0x95cdde8`（`#3`/`#4`/`#5` → 索引 4 只在 `#5`）、sel 15 `0x95cdb94`（`#0xb`/`#0xc` → 索引 11 只在 `#0xc`）、sel 18 `0x95ce270`、sel 33 `0x95ce904`（`#4`/`#5`）、sel 42 `0x95ce5dc`（`#1`/`#4`/`#5` → 索引 4 只在 `#5`）、sel 67 `0x95cee80`（`#4`，索引 3）、sel 70 `0x95ce6dc`（`#4`，索引 3）、sel 105 `0x95cfb58`（`#4`，索引 3）、sel 110 `0x95cf600`（`#2`/`#3`）、sel 118 `0x95ccd68`（`#2`/`#3`）、sel 126 `0x95cca98`（`#7`，索引 6）。**14/14 全部落在「索引 = K，且该路径要求 count = K+1」的形态上。**

分析器的假阳性机制（记录一下，别重复踩）：计数寄存器 `w8` 在同一个基本块里会被 `ldr w8,[x19,#0x50]`（`scalarOutputCount`）**复用**，于是 `cmp w8,#1`（其实是输出个数检查）被误当成输入个数检查，导致上界被压到 1。修复方向是把 `[x19,#0x28]` 的「计数身份」在寄存器被重写时失效——本报告采用手工复核而非继续加分析器。

**另一个量化反证（我认为比上面的逻辑检查更硬）：** 整个 `__TEXT_EXEC`（263 KB）里「寄存器变址」访存（`[xN, xM, lsl #k]` / `[xN, wM, uxtw]` 形态）总共只有 **29 处**；其中落在 34 KB 分发函数体内的只有 **1 处**，就是 selector 表本身 `0xfffffe00095cc2d4`。另外 28 处我逐条看过：`0x95bc36c/0x95bc400/0x95bc484/0x95bc560/0x95bc594`（`x24` 是 `csel 0x70/0x60` 常数偏移）、`0x95bc8b4/0x95bc8b8/0x95bc94c`（包解析循环，索引有界）、`0x95bcf00`（26 项内联 switch，见 §3.4）、`0x95be9b8`（19 项内联 switch）、`0x95c7118…0x95cb4ec`（指针数组遍历，索引是循环计数器）、`0x95cb348/0x95cb35c`（`sxtw` 索引，循环计数器）、`0x95d6da0`、`0x95e87e8`。**结论：全镜像没有任何「用户标量当数组下标」的访存。**

### 3.2 类 B — 大小计算整数溢出

**怎么查的。** 全 `__TEXT_EXEC`（263 KB）抓乘法类指令（`mul/umull/smull/madd/msub/umulh`），**总共只有 28 条**，全部逐条看乘子来源与结果用途（每条都打了前后 8 条上下文）；再逐个看「长度前缀列表」解析函数的边界算术。

**查到什么（28 条分类，一一对应地址）。**
- **13 条与尺寸无关**：`0x95d6b10/0x95d6b68/0x95d6bb4/0x95d6c44/0x95d6c50/0x95d6c78/0x95d6ccc/0x95d6ce8/0x95d6d0c/0x95d6d54`（十进制格式化：`umulh` + magic `0x431bde82d7b6…` 的 `/10`、`%10`）、`0x95c6ffc`/`0x95cbfd8`（同一个 magic 常量的除法替身）、`0x95f19ac`（`msub` 取模出数字）。这些只处理整数文本/时间戳。
- **6 条是带界表索引**：`0x95d9804 umull x8,w0,0x50`（前一条就是 `cmp w0,#0x61; b.hi fail`，索引上界 0x61）、`0x95e8148 umull x8,w8,0x150`（`w8 = cset eq` ∈ {0,1}）、`0x95eddd0 umull x0,w8,0x10c`（前有 `sub w9,w8,#1; cmp w9,w20; b.hs fail` 校验，且 32×32→64 不会溢出）、`0x95ede14 mul x8,x28,0x10c`（后接 `cmp x8,w8,sxtw` 自校验）、`0x95edf48 umull x20,w8,0x10c`、`0x95fbd18 mul x8,x8,0x10c`（`__kalloc_type` 元数据表的步长索引，编译器生成）。
- **3 条 `madd` 是 VLA/位图尺寸**：`0x95bd308`/`0x95bd5d0`/`0x95bd64c`：`madd x8, x8, 0x18, 0x1f` 紧接 `and x1, x8, #~0xf`（`(count*24+31)&~15`）。乘数是固定 0x18、**无进位/溢出检查**，要溢出需要 `[x23]` 那个 64 位计数 ≈ 2^60 —— 现实中拿不到；但它确实是「乘法 → 尺寸 → 用」的形态，列在 §6-R2 里备查。
- **2 条时间换算**：`0x95c2e48 mul w1,w8,0x3e8`（×1000，毫秒）、`0x95f2d70 mul w1,w27,0xf4240`（×1000000，微秒）。都是 32 位、只作为参数传给计时/采样函数。
- **2 条「计数 × 长度」**：`0x95f3aa0`、`0x95f3b14`（`mul x2, x9, x8`，`x9 = [sp+0x70]`、`x8 = 零扩展的 u32 [sp+0x7c]`，结果作为 vtable+0x558 虚调用的第 3 参即 size）。**不在用户 blob 路径上**：该函数 `0xfffffe00095f3838` 用字符串 `"sep-endpoint,sks"`（`0xfffffe000772fe38`）向 SEP endpoint 对象取属性，两个乘子来自这些属性 getter（`0x95fc4dc/0x95fc4ec/0x95fc4fc`），不是 selector 30 传进来的 blob 字节。残余见 §6-R2。
- **2 条表扫描步长**：`0x95e8214`/`0x95e8254`（`0x150` 步长的 keybag 类注册表线性扫描，索引是循环计数器）。
- 包解析器 `0xfffffe00095bc128` / `0xfffffe00095bc214` 的算术是**手写溢出安全**的，逐条证据见 §4-S7/S8。

### 3.3 类 C — `copyin` 长度与实际使用错配

**怎么查的。** 追「用户地址/长度」到内核缓冲的完整链路，并检查下游是「用用户给的 len」还是「用 descriptor/OSData 的长度」；再检查有没有「OSData 长度 → 固定栈缓冲」的拷贝。

**查到什么。**
1. 链路唯一：`scalarInput64[i], [i+1]` → `withAddressRange(addr,len,2,current_task())` → `map(kIOMapReadOnly)` → `OSData::withBytes(kva, map->getLength())` → `map->release()`。**指针和长度同源**（都来自同一个 map），下游一律 `getBytesNoCopy()`（vtable+0xd8）+ `getLength()`（vtable+0xa0）。
2. 因此不存在「用户声明的 len」与「实际映射长度」错配导致的越界：用户 len 只影响映射长度。
3. 唯一副作用：`getLength()` 是**页取整后的长度**（`IOMemoryMap` 语义），比用户请求的 len 最多大 4095 字节。handler 看到的 blob 因此可能比用户以为的长——读到的是用户自己那一页的邻接字节，属**语义意外**，不是内核内存破坏。但注意：如果某个 handler 用这个长度去**回写**用户缓冲（输出侧），写长度可能大于用户声明的输入长度——输出侧另有 `0x95bc328` 的 `声明大小 ≥ 数据大小` 校验（见 §4-S8），所以也不成立。
4. 未发现「OSData 长度直接进固定栈缓冲」的拷贝：13/17 个输出型 selector 走 `0x95bc328`；其余走 `OSData`/`OSData` 拼接与 `setObject`。

### 3.4 类 D — selector 分发类型混淆 / 越界跳转

分发是**单层整数 switch**，全程没有用户指针参与：

```
0x95cc244  subs  w28, w1, #1              ; w28 = selector - 1
0x95cc248  b.eq  0x95cc268                ; selector == 1（也走这里的初始化）
0x95cc264  cbz   w25, 0x95cc3e8           ; selector == 0 → 单独路径
0x95cc2a8  cmp   w28, #0xa8               ; 上界：selector-1 > 168 → fail
0x95cc2ac  b.hi  0x95d22ec                ;   → 0xe00002c2
0x95cc2c0  mov   x16, x28
0x95cc2c4  cmp   x16, #0xa8               ; 冗余二次检查
0x95cc2c8  csneg x16, x16, xzr, ls        ; 再夹紧一次（>0xa8 则取 0）
0x95cc2cc  adrp  x17, 0xfffffe00095d4000
0x95cc2d0  add   x17, x17, #0x7a0        ; 表基址 0xfffffe00095d47a0
0x95cc2d4  ldrsw x16, [x17, x16, lsl #2]  ; 表项 = int32 偏移
0x95cc2d8  adr   x17, 0xfffffe00095cc2d8
0x95cc2dc  add   x16, x17, x16
0x95cc2e0  br    x16
```
表项是**代码偏移**（`adr` 相对），没有任何来自数据段或用户的指针，不存在类型混淆。另有两处内联 switch（`0x95bcee4`：`sub w16,w0,#1; cmp w16,#0x19; b.hi fail` → 26 项表 @`0x95bd0d4`；`0x95be99c`：`cmp w24,#0x12; b.hi fail` → 19 项表 @`0x95beea0`），索引分别是 keybag 类型/状态编号，都在表长内且带 `csneg` 夹紧。

顺带纠正一个陷阱：镜像里三条 `com.apple.applekeystore.selector.keybag_create` / `.keybag_load` / `.selector.*` 字符串**不是 selector 名**，它们是 CoreAnalytics 事件名。证据：`0xfffffe00095cad20` 用它们建 `OSDictionary`（键 `process_name`、`bundle_id`、`device_keybag_access`、`keybag_load_access`、`keybag_create_access`、`result`…）然后提交事件。任何按这三条字符串去推 selector 的方法都会得到错误结论。

### 3.5 类 E — 结构体字段当指针 / 当数组下标

- **structure input 完全不用**：`args+0x30` / `+0x38` / `+0x40` 在这个 34 KB 函数体里读取次数为 **0**（对 `x19` 的这些偏移做全量访存扫描，命中数 0）。所以「用户提供的结构体字段被当指针」这条路径**在这个 userclient 上根本不存在**。
- 用户地址只经 `IOMemoryDescriptor::withAddressRange(..., current_task())` 进入内核，由 IOKit 校验归属；没有任何地方把用户给的 64 位值直接当内核指针解引用（全函数体内 `br`/`blraa` 的目标要么来自跳转表、要么来自对象 vtable + PAC）。
- 用到的 vtable 槽位（按调用点反推）：`+0x28` = `release`、`+0x78` = `getAddress`、`+0x88` = `getLength`(map)、`+0xa0` = `getLength`(OSData)、`+0xd8` = `getBytesNoCopy`、`+0xe8` = `map(options)`、`+0x2c0`/`+0x2d0`/`+0x558` = AppleKeyStore/SEP 端点方法。全部经 `autda`/`blraa` PAC 校验，`brk #0xc471/#0xc472` 是编译器插的 PAC 失败陷阱。

---

## 4. 逐点数据流

格式：`用户参数 → selector → 字段 → 计算 → 内存操作 → 越界多远`。每条给出结论（成立/不成立 + 缺哪一环）。

**S1（sel 30 = `set_config`，读完，最值得看的一条）**
`scalarInput64[0]=config_id`、`[1]=addr`、`[2]=len`
→ selector 30，前置 `count==3`、`scalarOutputCount==0`（`0x95cf174`/`0x95cf180`）
→ 字段：`w2 = scalar[0]`（u32 配置号）、`(scalar[1],scalar[2])` 为数据对
→ 计算：`0x95cb718(self, 0x1e, w2, &out)` 做 per-selector 门禁（见 S10）→ `0x95e9370(addr,len)` 建 OSData
→ 内存操作：`getBytesNoCopy()`(+0xd8) / `getLength()`(+0xa0) → `0x95c0fc0(self->f0d8, w2, [sp+0xb0], ent, bytes, len)` → `0x95c0aa0` 打包 gate 上下文 → `0x95c4ecc`/`0x95c4ee8` 的 gate 主体 → SEP
→ 越界多远：**0**。`bytes` 与 `len` 同源同对象；`w2` 只作为参数透传，在 gate 主体里未见以 `w2` 为下标的表访问（读到 `0x95c5200`，之后的部分列 §5-R1）；权限位是 `com.apple.keystore.config.set` 及四个子权限 OR 出的掩码（`0x95cf1cc`…`0x95cf24c`）。

**S2（sel 2 = `kAppleKeyStoreKeyBagCreate`）**
`count ∈ {6,7}`，`count==7` 时读 `scalar[6]`（`0x95cea7c`）当布尔
→ `w21 = scalar[0]` 当句柄/命令 → `0x95d6e18(w21, 2)` 判类型 → 权限 `com.apple.keystore.escrow.create` → `0x95d4a44(..., "kAppleKeyStoreKeyBagCreate")` 记审计 → `0x95cad20` 提交 CA 事件 → 真正工作在 `0x95cb678`/`0x95cad20` 之后的 gate 路径
→ 内存操作：`scalar[6]` 只在 `count==7` 路径读，索引 6 < 7 → **不越界**。

**S3（sel 12，三档 count）**
`#3 → 0x95d1008`、`#4 → 0x95d0fdc`、`#5` 才读 `scalar[4]`（`0x95cde18`）→ 有效下标 0..4 → **不越界**。
**S4（sel 5）** `#4 → 0x95d1628`、`#5` 才读 `scalar[4]`（`0x95ce924`）→ 不越界。
**S5（sel 42）** `#1`/`#4`/`#5` 三档，`scalar[4]` 只在 `#5` → 不越界。

**S6（sel 6 = `kAppleKeyStoreKeyBagCreateWithData`）**
`count==6`（或 7），`w19 = (u32)scalar[1]`（keybag 类型/标志）、`(scalar[2],scalar[3]) = (addr,len)`
→ `0x95e9370` → OSData → `getBytesNoCopy`/`getLength`
→ `0x95c3dc4`：`tst w8,#3` 选两条 gate 路径之一（`0x95d78e8` / `0x95d7794`），`w19` 只当标志用，**不当下标**
→ 越界：**0**。类型标志只参与位测试；blob 长度同源。

**S7（包解析器 `0xfffffe00095bc214` — 长度前缀列表取第 N 项）**
`obj->getLength()` → `< 4` 直接返回 0；`getBytesNoCopy()` → NULL 返回 0
→ `end = base + len` 用 `adds x9,x0,x8; b.hs` 查溢出
→ `count = *(u32*)base`；`if (index >= count) return 0`（`cmp w20,w9; b.hs`）
→ 逐项：`e_len = *(u32*)p`；`if (e_len > len) fail`；`pad = (-e_len)&3`；`if (u32)(e_len+pad) 溢出) fail`；`next = p+4+(e_len+pad)`；`if (next > end) fail`
→ 内存操作：`p+4` 指针演进
→ 越界：**0**。每一步都有 `b.hs`（进位）和 `> end`（上界）双重检查，是我在这份镜像里见到的最严的一段代码。

**S8（包解析器 `0xfffffe00095bc128` — 整表校验）** 同上形态，遍历全表校验每一项后再返回元素个数；越界 **0**。

**S9（输出写路径 `0xfffffe00095bc328`）**
`w21 = *(u32*)(args + (descriptor? 0x70 : 0x60))`（客户端声明的输出缓冲大小）、`len = obj->getLength()`
→ `cmp w21,w0; b.hs` → 声明大小 ≥ 数据大小才放行，否则打日志 `"buffer size %d too small for data size %d"` 并返回错误
→ 越界：**0**（方向正确、比较在拷贝之前）。

**S10（per-selector 门禁 `0xfffffe00095cb718`）**
`(self, sel, scalar[0], &out)`：先 `0x95cb920(sel, scalar[0])` 得到 -3/-2/-6 等状态；selector 落在 `{7,17,35}`（`1<<sel` 与 `0x00000008_00020080` 位掩码 `tst`）时需要 `self->f0f0 & 0x18`，否则返回 -6；移位前有 `cmp w23,#0x23; b.hi`（35 恰是最高位）→ **移位量有界，无越界**。

**S11（页取整语义）** 见 §3.3-3：`getLength()` 可能比用户 len 大 ≤4095 字节，读到的是用户自己的页；**不是内核越界**，但会让「输入长度」与用户预期不一致——如果后续要做 PoC，这一点会影响构造（parser 可能看到你缓冲区后面的垃圾）。

**S12（`0x95f3aa0` / `0x95f3b14` 的 `count × stride`）** 乘子来自 `"sep-endpoint,sks"` 端点对象的属性（不是一个 selector 参数）；**用户 blob 不参与**。残余风险见 §5-R2。


---

## 5. 完整 selector 表（169 项 + selector 0）

读取方式：表基址 `0xfffffe00095d47a0`，索引 = `selector-1`，表项为 `int32` 相对偏移（目标 = `0xfffffe00095cc2d8 + d`）。
列说明：
- **块数** = 从该入口可达的基本块数（`0xfffffe00095d22ec` 失败出口与 `0xfffffe00095d3ba0` 成功出口不计入）。
- **标量个数检查** = handler 自身（含其私有块）里对 `[args+0x28]` 的全部比较常量；`-` 表示该 selector 自己不检查标量个数（多数是纯转发或纯无参操作）。
- **关键调用** = 可达集合内出现：`copyin`=`0xfffffe00095e9370`（用户 (addr,len) 拷入）、`输出校验`=`0xfffffe00095bc328`、`打包解析`=`0xfffffe00095bc214`；`未实现` = 表项直接指向失败出口。
- **权限/事件** = 该 selector 私有块里出现的 `com.apple.keystore.*` 字符串（多数权限检查被收敛到共享门禁函数里，所以这里是下界而不是全集）。
- 未解项：**0 项**。169 个表项全部解出确定入口；20 个「未实现」是确定结论（指向 `0xe00002c2` 失败出口），不是「没读出来」。

| sel | 入口 | 块数 | 标量个数检查 | 关键调用 | 权限/事件 |
|---|---|---|---|---|---|
| 1 | `0xfffffe00095ce558` | 6 | - | - | - |
| 2 | `0xfffffe00095cea4c` | 14 | 6 | - | escrow.create |
| 3 | `0xfffffe00095ce438` | 5 | 1 | - | - |
| 4 | `0xfffffe00095ce880` | 7 | 1 | - | - |
| 5 | `0xfffffe00095ce8f0` | 17 | 4 | copyin | - |
| 6 | `0xfffffe00095ce3b8` | 6 | - | - | keybag.load |
| 7 | `0xfffffe00095ce7dc` | 10 | 1 | - | - |
| 8 | `0xfffffe00095cdeb8` | 0 | - | - | - |
| 9 | `0xfffffe00095ce010` | 12 | 3 | copyin | - |
| 10 | `0xfffffe00095ce050` | 11 | 2 | - | - |
| 11 | `0xfffffe00095ce148` | 15 | 2 | 输出校验 | - |
| 12 | `0xfffffe00095cdde4` | 18 | 3 | copyin | - |
| 13 | `0xfffffe00095cea90` | 6 | 1 | - | - |
| 14 | `0xfffffe00095cdfe0` | 11 | 1 | - | - |
| 15 | `0xfffffe00095cdb90` | 26 | 11 | copyin 输出校验 | - |
| 16 | `0xfffffe00095cdfc8` | 3 | - | - | - |
| 17 | `0xfffffe00095ce400` | 0 | - | - | - |
| 18 | `0xfffffe00095ce26c` | 24 | 3 | copyin 打包解析 | - |
| 19 | `0xfffffe00095ceb24` | 3 | - | - | obliterate-d-key |
| 20 | `0xfffffe00095cd9fc` | 12 | 2 | 输出校验 | - |
| 21 | `0xfffffe00095cc698` | 12 | - | copyin | - |
| 22 | `0xfffffe00095cc698` | 12 | - | copyin | - |
| 23 | `0xfffffe00095ce47c` | 14 | 1 | 输出校验 | device.uuid |
| 24 | `0xfffffe00095cebb4` | 10 | 4 | - | devicebackup |
| 25 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 26 | `0xfffffe00095d1240` | 4 | - | - | - |
| 27 | `0xfffffe00095d1240` | 4 | - | - | - |
| 28 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 29 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 30 | `0xfffffe00095cf170` | 7 | 3 | copyin | config.set, config.set.user_uuid, config.bind_kek_to_kb |
| 31 | `0xfffffe00095ced18` | 10 | 1 | 输出校验 | - |
| 32 | `0xfffffe00095cdeb0` | 13 | 1 | - | - |
| 33 | `0xfffffe00095ce934` | 18 | 4 | copyin | - |
| 34 | `0xfffffe00095cde20` | 7 | 2 | - | - |
| 35 | `0xfffffe00095ce3f8` | 14 | 1 | 输出校验 | - |
| 36 | `0xfffffe00095ce700` | 6 | 1 | - | - |
| 37 | `0xfffffe00095ce344` | 7 | - | - | - |
| 38 | `0xfffffe00095ce614` | 11 | 4 | copyin 输出校验 | auth-token |
| 39 | `0xfffffe00095cd8e0` | 9 | 2 | - | auth-token |
| 40 | `0xfffffe00095ce2a0` | 10 | 2 | - | - |
| 41 | `0xfffffe00095cd120` | 14 | - | 输出校验 | fdr-access |
| 42 | `0xfffffe00095ce5d8` | 21 | 1 | copyin 打包解析 | device.verify |
| 43 | `0xfffffe00095cd6ac` | 25 | 1 | 输出校验 | - |
| 44 | `0xfffffe00095cdee8` | 26 | 2 | 打包解析 | device.remote-session |
| 45 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 46 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 47 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 48 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 49 | `0xfffffe00095cf990` | 16 | 2 | 输出校验 | device.remote-session |
| 50 | `0xfffffe00095cf2d0` | 21 | 3 | 输出校验 打包解析 | device.remote-session |
| 51 | `0xfffffe00095cd400` | 7 | 1 | - | - |
| 52 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 53 | `0xfffffe00095cef3c` | 7 | 1 | - | stash.persist |
| 54 | `0xfffffe00095d3ba0` | 0 | - | - | - |
| 55 | `0xfffffe00095ccd94` | 6 | 1 | - | - |
| 56 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 57 | `0xfffffe00095cdbc8` | 12 | 1 | - | device.remote-session |
| 58 | `0xfffffe00095cf814` | 13 | 1 | - | device.remote-session |
| 59 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 60 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 61 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 62 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 63 | `0xfffffe00095cfa74` | 13 | 4 | copyin | - |
| 64 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 65 | `0xfffffe00095cea04` | 16 | 2 | 打包解析 | - |
| 66 | `0xfffffe00095ceeac` | 3 | - | - | - |
| 67 | `0xfffffe00095cede0` | 13 | 3 | copyin | - |
| 68 | `0xfffffe00095cdbfc` | 28 | 1 | 输出校验 打包解析 | device.uuid |
| 69 | `0xfffffe00095cc50c` | 9 | 3 | copyin | - |
| 70 | `0xfffffe00095ce6c4` | 13 | 3 | copyin | - |
| 71 | `0xfffffe00095cfc3c` | 7 | 1 | - | - |
| 72 | `0xfffffe00095cf840` | 22 | 4 | copyin | - |
| 73 | `0xfffffe00095cfc94` | 7 | 1 | - | - |
| 74 | `0xfffffe00095cc438` | 4 | - | - | - |
| 75 | `0xfffffe00095cc438` | 4 | - | - | - |
| 76 | `0xfffffe00095cc438` | 4 | - | - | - |
| 77 | `0xfffffe00095cc438` | 4 | - | - | - |
| 78 | `0xfffffe00095cc438` | 4 | - | - | - |
| 79 | `0xfffffe00095cc438` | 4 | - | - | - |
| 80 | `0xfffffe00095ccff8` | 17 | 1 | 输出校验 打包解析 | absinthe |
| 81 | `0xfffffe00095cd238` | 16 | 1 | 输出校验 打包解析 | absinthe |
| 82 | `0xfffffe00095cd1b4` | 7 | 1 | - | - |
| 83 | `0xfffffe00095cd7a8` | 13 | 2 | - | aux.auth |
| 84 | `0xfffffe00095cc438` | 4 | - | - | - |
| 85 | `0xfffffe00095cc438` | 4 | - | - | - |
| 86 | `0xfffffe00095cf944` | 5 | 3 | - | opts |
| 87 | `0xfffffe00095cf0a8` | 9 | - | - | - |
| 88 | `0xfffffe00095cd474` | 9 | 1 | - | - |
| 89 | `0xfffffe00095cf4d8` | 11 | 1 | 输出校验 | - |
| 90 | `0xfffffe00095cefc0` | 11 | 1 | 输出校验 | - |
| 91 | `0xfffffe00095ccfa0` | 6 | 1 | - | - |
| 92 | `0xfffffe00095cc494` | 7 | - | - | - |
| 93 | `0xfffffe00095cfe2c` | 14 | 1 | 输出校验 | - |
| 94 | `0xfffffe00095ccb64` | 6 | 1 | - | - |
| 95 | `0xfffffe00095cf8f0` | 6 | - | - | - |
| 96 | `0xfffffe00095cfff0` | 17 | 3 | copyin 打包解析 | - |
| 97 | `0xfffffe00095cf02c` | 12 | 1 | 输出校验 | - |
| 98 | `0xfffffe00095cd804` | 13 | 1 | 打包解析 | - |
| 99 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 100 | `0xfffffe00095d1240` | 4 | - | - | - |
| 101 | `0xfffffe00095d1240` | 4 | - | - | - |
| 102 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 103 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 104 | `0xfffffe00095d027c` | 12 | 1 | 输出校验 | fairplay |
| 105 | `0xfffffe00095cfb40` | 13 | 3 | copyin | - |
| 106 | `0xfffffe00095cc704` | 6 | 1 | - | - |
| 107 | `0xfffffe00095cd52c` | 8 | - | - | - |
| 108 | `0xfffffe00095cd9a8` | 9 | 1 | - | - |
| 109 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 110 | `0xfffffe00095cf5e8` | 20 | 2 | copyin 输出校验 打包解析 | - |
| 111 | `0xfffffe00095cd3b4` | 9 | - | 打包解析 | - |
| 112 | `0xfffffe00095cfcf0` | 11 | - | 输出校验 打包解析 | - |
| 113 | `0xfffffe00095cd5f8` | 4 | 3 | - | - |
| 114 | `0xfffffe00095ccc54` | 9 | - | - | - |
| 115 | `0xfffffe00095d03b8` | 7 | - | - | - |
| 116 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 117 | `0xfffffe00095d00fc` | 17 | 4 | copyin 打包解析 | - |
| 118 | `0xfffffe00095ccd50` | 13 | 2 | - | - |
| 119 | `0xfffffe00095cd0d4` | 9 | - | - | - |
| 120 | `0xfffffe00095cf758` | 11 | 1 | 打包解析 | - |
| 121 | `0xfffffe00095cc8c4` | 7 | 1 | - | - |
| 122 | `0xfffffe00095ccdf0` | 8 | 1 | - | - |
| 123 | `0xfffffe00095cc5d0` | 16 | 1 | 打包解析 | - |
| 124 | `0xfffffe00095ced9c` | 19 | 1 | 输出校验 打包解析 | - |
| 125 | `0xfffffe00095cce68` | 11 | - | 输出校验 | - |
| 126 | `0xfffffe00095cca80` | 14 | 6 | copyin | - |
| 127 | `0xfffffe00095d01e4` | 5 | - | - | - |
| 128 | `0xfffffe00095cf630` | 12 | 1 | 输出校验 | device |
| 129 | `0xfffffe00095cfb7c` | 4 | - | - | - |
| 130 | `0xfffffe00095cd314` | 5 | - | - | - |
| 131 | `0xfffffe00095ccaf0` | 5 | - | - | - |
| 132 | `0xfffffe00095cccdc` | 5 | - | - | - |
| 133 | `0xfffffe00095cff34` | 9 | 3 | copyin | - |
| 134 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 135 | `0xfffffe00095cfd30` | 12 | 2 | 输出校验 | bak |
| 136 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 137 | `0xfffffe00095cfedc` | 5 | - | - | - |
| 138 | `0xfffffe00095cc934` | 7 | 1 | - | memento |
| 139 | `0xfffffe00095cf544` | 12 | 1 | 输出校验 | memento |
| 140 | `0xfffffe00095cc50c` | 9 | 3 | copyin | - |
| 141 | `0xfffffe00095cf87c` | 8 | 1 | - | - |
| 142 | `0xfffffe00095cc844` | 12 | 1 | 输出校验 | info |
| 143 | `0xfffffe00095cc764` | 8 | 1 | - | - |
| 144 | `0xfffffe00095ccbcc` | 9 | - | - | - |
| 145 | `0xfffffe00095cd58c` | 7 | 1 | - | - |
| 146 | `0xfffffe00095d0188` | 11 | 1 | 输出校验 | - |
| 147 | `0xfffffe00095cf724` | 4 | - | - | - |
| 148 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 149 | `0xfffffe00095cdab8` | 7 | - | - | - |
| 150 | `0xfffffe00095d0370` | 5 | - | - | dsme_access |
| 151 | `0xfffffe00095ce760` | 7 | 1 | - | - |
| 152 | `0xfffffe00095ccac4` | 6 | - | - | - |
| 153 | `0xfffffe00095cec74` | 5 | 1 | - | - |
| 154 | `0xfffffe00095cc5d0` | 16 | 1 | 打包解析 | - |
| 155 | `0xfffffe00095ccea8` | 14 | 3 | copyin 输出校验 | - |
| 156 | `0xfffffe00095cc704` | 6 | 1 | - | - |
| 157 | `0xfffffe00095cc494` | 7 | - | - | - |
| 158 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 159 | `0xfffffe00095cc9a0` | 14 | 3 | copyin 输出校验 | icsc_srp |
| 160 | `0xfffffe00095ceb50` | 6 | 1 | - | enable_cache_flow |
| 161 | `0xfffffe00095cc2e4` | 21 | 3 | copyin 输出校验 | - |
| 162 | `0xfffffe00095d0428` | 7 | 1 | - | device.remote-session |
| 163 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 164 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 165 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 166 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 167 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 168 | `0xfffffe00095d22ec` | 0 | - | 未实现 | - |
| 169 | `0xfffffe00095cdb28` | 7 | - | 输出校验 | - |
---

## 6. 未审计 / 留白清单

按「没证据就留白」的规矩，下列位置我**没有**读完，不给出结论：

- **R1 — gate 之后的 SEP 核心。** `0x95c4ee8`（setConfig gate 主体，只读到 `0x95c5200`）、`0x95d78e8`、`0x95d7794`（keybag create 的两条 gate 路径，只读到入口）、`0x95cb678`、`0x95cad20` 之后的 keybag 装载链。这些函数把 blob 送进 SEP / 解析成 keybag 结构体。**若要继续，下一步就是从 `0x95c4ee8` 的 `w2`（配置号）分支往下读**，确认它有没有把配置号当下标。
- **R2 — `0x95f3aa0` / `0x95f3b14` 的 `count × stride`。** 乘子来自 `"sep-endpoint,sks"` 端点对象属性；我确认它们不是 selector 参数，但**没有证明**这些属性不能被更早的 `set_config`（selector 30）写入后影响。若要排除，需要读 `0x95f3838` 全文（0x488 字节）与 `0x95fc4dc/0x95fc4ec/0x95fc4fc` 三个 import 的真实身份。
- **R3 — 163 个 `__auth_stubs` 的真实符号名。** `0xfffffe00095fc1cc` 起共 163 个 import stub，镜像无符号表，我只能按调用上下文推断（例如 `0x95fc58c` = OSData 构造、`0x95fc98c` = `current_task()`、`0x95fc6ec` = `stack_chk_fail`）。若某个 stub 的真实语义与推断不同（尤其 `0x95fc58c` 若是 `withBytesNoCopy` 而非 `withBytes`），§3.3 的「指针/长度同源」结论需要重判——但 `OSData` 构造后立刻 `release` 了 `IOMemoryMap`，若真用的是 `NoCopy` 那就是一条 UAF，所以这一条**值得优先确认**（判据：`0x95e9370` 里 `map->release()`(+0x28) 是否在 OSData 构造之后立刻发生——是的，`0x95e943c`；两种实现的差别在于拷贝与否，不在生命周期顺序）。
- **R4 — 反向方向（输出到 `IOMemoryDescriptor` 的写）。** 我没有系统检查「内核数据 → 用户缓冲」的所有写路径（只核了 `0x95bc328` 这一条校验函数及其 13 个调用者）。若存在绕过该函数的第二套输出路径，属未查。
- **R5 — `__DATA` / `__DATA_CONST` 里的表**（`0xfffffe000b916430` 等 0x150 步长的类注册表、`__kalloc_type` 0xd80 字节的分配器签名表）只确认了遍历方式与索引有界，没有逐个解出内容。
- **R6 — 非 externalMethod 入口。** 这个 kext 还有 `IOService` 属性写入（`setProperty`）、通知回调（`0x95be9xx` 一带的 notification 格式化）、以及 SEP mailbox 中断路径，均不在本次「用户态输入面」范围内。

## 7. 覆盖率

| 维度 | 数量 |
|---|---|
| 镜像内函数（`LC_FUNCTION_STARTS`） | 1,058（首项自校验 = `__TEXT_EXEC` vmaddr） |
| `externalMethod` 体量 | 34 KB / 8,558 条指令 / 1 条 `ret` |
| selector 总数 | 170（表 169 + selector 0 单独路径） |
| 读出分发目标 | 170 / 170（100%） |
| 读出标量个数检查 | 102 / 170 有显式检查；其余按块读确认「不读标量」或「纯转发」 |
| 未实现（直接失败） | 20 |
| 空实现（直接成功） | 1（sel 54） |
| 不同 handler 入口 | 126 |
| 逐条读完的 selector | 15（0/1/2/5/6/9/12/15/30/42/74/100/105/110/118） |
| 逐条读完的被调核心 | 13（`0x95e9370`、`0x95bc128`、`0x95bc214`、`0x95bc328`、`0x95c0fc0`、`0x95c0aa0`、`0x95c0b38`、`0x95c3dc4`、`0x95c7a00`、`0x95ca7a0`、`0x95cad20`、`0x95cb718`、`0x95e81bc`/`0x95f3838` 部分） |
| 走 `(addr,len)` 拷入路径的 selector | 21（私有块内）／35（含共享尾块） |
| 输出大小校验的 selector | 17（私有块内）／41（含共享尾块） |
| 全段寄存器变址访存 | 29，全部核对 |

## 8. 最后一行答案

**这个 kext 里有没有用户可控输入导致的内核内存破坏？——我读到的部分里没有：170 个 selector 全部分发与参数通道核对完毕（其中 15 个逐条读完、21 个的 `(addr,len)` 拷入链逐个走通、13 个被调核心读完），5 类模式全部给出反证（标量下标与计数严格配对、28 条乘法全部定性、无用户可控 size、指针与长度同源、分发是纯代码偏移表、structure input 面根本不存在，全镜像 29 处变址访存无一处以用户标量为下标）；未读完的是 gate 之后的 SEP 核心与 2 处乘法来源（§6 R1/R2），在那之前没有证据支持「用户可控输入 → 内核内存破坏」这个结论。**
