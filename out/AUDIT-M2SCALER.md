# AUDIT-M2SCALER — `AppleM2ScalerCSCDriver` 的 32 张 int32 派发表审计（27.0.1 vs 27.2）

1. **结论先行**：32 张表**全部复现成功**，且**全部不是** selector 派发表 —— 它们是编译器为 C++ `switch` 生成的跳转表（946 个表项，100% 落在 `bti j` 分支块、且全部在**同一个函数体内**）。
2. 因此「每张 bound 66~70」这个前提只对 32 张里的 **6 张**成立；实际 bound 分布是 9/10/11/13/14/15/16/24/33/65/69/121 共 12 种。
3. 本 kext 的 `__DATA_CONST` 里**没有** `IOExternalMethodDispatch` 记录数组；该段是 9,774 个 chained 函数指针组成的约 300 字节一块的 vtable 海。先前「7 张 5 槽表」的读法不成立（详见 §4）。
4. `IOExternalMethodArguments` 的 selector 面确实存在，但形态是 **`switch (w1)`**：32 张表里 **12 张**按 `w1` 分派。`w1` 正是 `externalMethod(selector, args, dispatch, target)` 的 selector 位。
5. 但这 12 张的 case body 里，**没有一处读 `args->structureInputSize (+0x38)`**；全 kext 唯一被扫到读 `+0x38` 的地方（`0x90af39c`）经手读证伪：那是一个自定义大结构体的字段，不是 `IOExternalMethodArguments`。
6. 3 个同模板大 handler（`0x9082c8c` / `0x90f1ac8` / `0x9100b1c`）接收约 **0x1090 字节**的请求结构，并**无条件**写 `[x2+0x1088]`；结构体来源与尺寸校验**均未证**。这是本次唯一值得继续的候选，不是已成立的漏洞。
7. **跨版本差分**：长度重同步对齐后 99.6%（10219/10262）配对成功；上述 3 个 handler 在 27.2 里**指令序列完全一致**（无修复）。
8. 27.2 新增 57 个函数，新增字符串全部集中在 `0x7614b00–0x7614e00`，且全是**生命周期/回收**语义（PIODMA command 回收、arena 延迟释放、MSR power ref）——**27.2 加固的是资源生命周期，不是边界**。
9. `Histogram bin count (%d)` → `(%ld)` 是 printf 宽度更正，不是安全修复；该边界检查（`cmp w0,#8` / `b.ls`,**无符号**）在 27.0.1 就已存在且正确。
10. **直答**：**没有找到**用户可控输入导致的内核内存破坏。阻断点有两个且都在可达性上：selector → handler 的映射未解、0x1090 结构的来源未证（§8）。

> 资产更正：任务给的 `out/v2701/driver_AppleM2ScalerCSCDriver.macho` 与 `out/v272/` 同名文件**都不存在**。实际可用的是 `out/m2s.27.0.1.macho`（3,094,040 B）与 `out/m2s.27.2.macho`（3,097,168 B）。本报告另存了同路径下的旧审计为 `out/AUDIT-M2SCALER.prior-27.0.1-direct.md`（它审的是另 7 个位置，未触及这 32 张表，两者不重叠）。

---

## 0. 方法与自证

| 项 | 27.0.1 | 27.2 |
|---|---|---|
| `LC_FUNCTION_STARTS` 命令值 | `0x26` | `0x26` |
| 函数数 | 10,262 | 10,276 |
| 首项 | `0xfffffe00090457b0` | `0xfffffe000908c900` |
| `__TEXT_EXEC` vmaddr | `0xfffffe00090457b0` | `0xfffffe000908c900` |
| **自证：首项 == `__TEXT_EXEC` vmaddr** | **True** | **True** |

- 工具坑 1：`LC_FUNCTION_STARTS` 是 **`0x26`**；`0x80000034` 是 `LC_DYLD_CHAINED_FIXUPS`。用错会得到 0 个函数。
- 工具坑 2：`adrp` 的 capstone 操作数带 `#`，取立即数必须 `lstrip('#')`。
- 工具坑 3（本轮新发现）：**kext 镜像与内核 cache 的 `__DATA_CONST` 内容不一致**。镜像里 `0xfffffe00080e9078` 一带是零，cache 里同一 VA 有数据。故**代码段用镜像、数据段必须用 `out/kc.27.0.1.full`**，混用会得出「表全零」的假结论。
- 指针解码：`va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)`。本法在镜像 `__DATA_CONST` 上解出 **9,774** 个落在函数起点的指针，可用。
- 未使用 `if v >> 63: continue`。

---

## 1. 复现：32 张表，与 `DISPATCH-SWEEP.md` 完全一致

签名 `(w & 0xFFE0EC00) == 0xB8A06800`（`ldrsw xT,[xB,xI,lsl #2]`），前向 8 条内 `adr`+`add`+`br`。

- `__TEXT_EXEC` 原始 `ldrsw` 变址命中：**32**
- 确认 `ldrsw`+`adr`+`br`：**32**（与 `DISPATCH-SWEEP.md` 的 M2Scaler 计数一致）
- `bound ≥ 60` 的 7 张，其（派发点, 表基址, 条目数）与 `DISPATCH-SWEEP.md` §4 **逐字段相同**

派发点真实形态（以 `0xfffffe0009051a0c` 为例，`adr` 基准 = `0xfffffe0009051a10`）：

```asm
cmp  w0, #0x41              ; ← 上界闸
b.hi 0xfffffe0009051d38     ; 越界 → default
mov  w16, w0
cmp  x16, #0x41
csneg x16, x16, xzr, ls     ; ← 索引夹取（不是容量检查）
adrp x17, 0xfffffe0009051000
add  x17, x17, #0xd70       ; 表基址 = 0xfffffe0009051d70
ldrsw x16, [x17, x16, lsl #2]
adr  x17, 0xfffffe0009051a10 ; 相对基准
add  x16, x17, x16
br   x16                    ; → bti j 分支块
```

---

## 2. 第 1 步：32 张表逐张真伪判定

判据（任务给定）三条 + 一条我加的结构判据：

- **A 上界闸**：派发前有 `cmp wN,#imm` + `b.hi`
- **B 目标形态**：目标读 `[x2+0x18/0x20/0x28/0x30/0x38]`（`IOExternalMethodArguments`）
- **C selector 位**：索引寄存器是 `w1`
- **D（新增）目标性质**：目标是 `bti j`（跳转表分支）还是 `bti c`（函数入口）

判 D 的理由：`IOExternalMethodDispatch` 表项指向的是**函数入口**（`bti c`）。全部 946 个目标都是 `bti j`，且**每一个都落在派发点所在函数体内部**（容器尺寸见下表），这是 `switch` 被 lower 成跳转表的定义性特征。

| # | 派发点 | 表基址 | 条目 | bound | 索引寄存器 | 容器函数 | 容器指令数 | A 上界闸 | B args 形态 | C=w1 | D 目标 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `0x9051a0c` | `0x9051d70` | 66 | 0x41 | w0 | `0x90519e8` | 226 | ✓ | ✗ | ✗ | `bti j` ×66 |
| 2 | `0x906afac` | `0x906b0dc` | 15 | 0x0e | **w1** | `0x906af88` | 85 | ✓ | ✗ | ✓ | `bti j` ×15 |
| 3 | `0x906d694` | `0x906e650` | 66 | 0x41 | **w1** | `0x906d5fc` | 1045 | ✓ | ✗ | ✓ | `bti j` ×66 |
| 4 | `0x9071dd8` | `0x9071f04` | 10 | 0x09 | w8 | `0x9071db0` | 85 | ✓ | ✗ | ✗ | `bti j` ×10 |
| 5 | `0x9078364` | `0x90791fc` | 66 | 0x41 | **w1** | `0x90782d0` | 971 | ✓ | ✗ | ✓ | `bti j` ×66 |
| 6 | `0x9095160` | `0x9096790` | 14 | 0x0d | w16 | `0x9094f04` | 1571 | ✓ | ✗ | ✗ | `bti j` ×14 |
| 7 | `0x909d598` | `0x909d710` | 11 | 0x0a | w16 | `0x909d4dc` | 141 | ✓ | ✗ | ✗ | `bti j` ×11 |
| 8 | `0x909d968` | `0x909dbb0` | 17 | 0x10 | w25 | `0x909d8c8` | 186 | ✓ | ✗ | ✗ | `bti j` ×17 |
| 9 | `0x909e0c0` | `0x909f97c` | 11 | 0x0a | w22 | `0x909df50` | 1675 | ✓ | ✗ | ✗ | `bti j` ×11 |
| 10 | `0x90a3f5c` | `0x90a4104` | 34 | 0x21 | **w1** | `0x90a3f3c` | 114 | ✓ | ✗ | ✓ | `bti j` ×34 |
| 11 | `0x90a9424` | `0x90a9554` | 15 | 0x0e | **w1** | `0x90a9400` | 85 | ✓ | ✗ | ✓ | `bti j` ×15 |
| 12 | `0x90ab5e0` | `0x90ac1d4` | 14 | 0x0d | w22 | `0x90ab14c` | 1058 | ✓ | ✗ | ✗ | `bti j` ×14 |
| 13 | `0x90ab6f8` | `0x90ac20c` | 14 | 0x0d | w22 | `0x90ab14c` | 1058 | ✓ | ✗ | ✗ | `bti j` ×14 |
| 14 | `0x90b67ac` | `0x90b68dc` | 15 | 0x0e | **w1** | `0x90b6788` | 85 | ✓ | ✗ | ✓ | `bti j` ×15 |
| 15 | `0x90ce7e4` | `0x90d0068` | 34 | 0x21 | w16 | `0x90ce5fc` | 1691 | ✓ | ✗ | ✗ | `bti j` ×34 |
| 16 | `0x90cf0c4` | `0x90d00f0` | **122** | 0x79 | w25 | `0x90ce5fc` | 1691 | ✓ | ✗ | ✗ | `bti j` ×122 |
| 17 | `0x90d1ffc` | `0x90d212c` | 15 | 0x0e | **w1** | `0x90d1fd8` | 85 | ✓ | ✗ | ✓ | `bti j` ×15 |
| 18 | `0x90f067c` | `0x90f1350` | 70 | 0x45 | **w1** | `0x90f05f0` | 856 | ✓ | ✗ | ✓ | `bti j` ×70 |
| 19 | `0x90f3814` | `0x90f3c8c` | 16 | 0x0f | w16 | `0x90f3720` | 347 | ✓ | ✗* | ✗ | `bti j` ×16 |
| 20 | `0x90fc40c` | `0x90fcc4c` | 12 | 0x0b | w16 | `0x90fb14c` | 1728 | ✓ | ✗* | ✗ | `bti j` ×12 |
| 21 | `0x90ff828` | `0x91004fc` | 70 | 0x45 | **w1** | `0x90ff79c` | 856 | ✓ | ✗ | ✓ | `bti j` ×70 |
| 22 | `0x9101c98` | `0x9102b04` | 66 | 0x41 | **w1** | `0x9101c04` | 960 | ✓ | ✗ | ✓ | `bti j` ×66 |
| 23 | `0x910f28c` | `0x910f404` | 17 | 0x10 | w8 | `0x910f264` | 104 | ✓ | ✗ | ✗ | `bti j` ×17 |
| 24 | `0x9110358` | `0x91104e8` | 15 | 0x0e | w20 | `0x91102e0` | 130 | ✓ | ✗ | ✗ | `bti j` ×15 |
| 25 | `0x9110918` | `0x9112818` | 12 | 0x0b | w16 | `0x9110524` | 2237 | ✓ | ✗ | ✗ | `bti j` ×12 |
| 26 | `0x9136e70` | `0x9136fa0` | 15 | 0x0e | **w1** | `0x9136e4c` | 85 | ✓ | ✗ | ✓ | `bti j` ×15 |
| 27 | `0x913a708` | `0x913a8c8` | 17 | 0x10 | w8 | `0x913a6e0` | 122 | ✓ | ✗ | ✗ | `bti j` ×17 |
| 28 | `0x9143bcc` | `0x9143f4c` | 25 | 0x18 | w16 | `0x9143b58` | 253 | ✓ | ✗ | ✗ | `bti j` ×25 |
| 29 | `0x91444bc` | `0x9144884` | 25 | 0x18 | w16 | `0x9144448` | 271 | ✓ | ✗* | ✗ | `bti j` ×25 |
| 30 | `0x914a410` | `0x914a5a0` | 17 | 0x10 | w8 | `0x914a3e8` | 110 | ✓ | ✗ | ✗ | `bti j` ×17 |
| 31 | `0x914b410` | `0x914b4e0` | 15 | 0x0e | **w1** | `0x914b3ec` | 61 | ✓ | ✗ | ✓ | `bti j` ×15 |
| 32 | `0x915c454` | `0x915e8dc` | 15 | 0x0e | w16 | `0x915b8b4` | 3082 | ✓ | ✗ | ✗ | `bti j` ×15 |

`✗*` = 自动扫描曾报「case body 触到 args 偏移」，**手读后证伪**：`0x90f3814` 的 7 处与 `0x91444bc` 的 1 处，基址寄存器是恰好从 `x2` 派生出来的局部量，偏移落进 `{0x18..0x60}` 纯属数值巧合，不是 `IOExternalMethodArguments`。这是本轮必须记下的一类假阳性。

### 2.1 判定汇总

| 判据 | 结果 |
|---|---|
| A 上界闸 | **32/32 有**（`cmp wN,#imm` + `b.hi`，且紧随 `csneg` 夹取） |
| B 目标读 args 字段 | **0/32 成立**（2 处曾命中，手读证伪） |
| C 索引 = `w1` | **12/32** |
| D 目标是 `bti j` 且同在函数内 | **32/32** |

⇒ **32 张全部是编译器 `switch` 跳转表，不是 `IOExternalMethodDispatch` 派发表。** 其中 12 张的 `switch` 作用在 `w1` 上，语义上**可能**就是 `externalMethod` 的 selector 分派（§3）。

### 2.2 这 32 张表的 case body 在做什么（抽样手读）

340 字节 / 85 指令的 5 张表（#2、#11、#14、#17、#26）是同一个模板，全部尾调到各自 4 个共享 helper，例如 `0x906af88`：

```asm
bti c
mov  x0, x8
cmp  w1, #0xe / b.hi default
...
br   x16                       ; → bti j
; 每个 case:
adrp x2, <__TEXT 常量>          ; 常量源指针
add  x2, x2, #imm
mov  w1, #0x1b                 ; 常量元素个数（编译期常量！）
b    0x906b118                 ; 共享 helper
```

共享 helper `0x906b118` 是一个**向量追加**循环：

```asm
ldr  x8, [x20]          ; 计数
lsl  x8, x8, #4         ; idx*16
cmp  x8, w8, sxtw / movk x16,#0x2bad,lsl#48 / csel   ; 位移溢出检查
ldr  q0, [x9]           ; 源
str  q0, [x11]          ; 目标
cmp  x8, x21 / b.lo loop ; 次数 = x21 = 入参 x1
```

**关键判据**：进入 helper 时 `x1`（次数）与 `x2`（源）**都由 case body 赋成编译期常量**，不是用户输入。⇒ 这一族没有用户可控长度。

其余表另有 `ret`-型（#1、#10 的 34 个 case 直接 `ret`，是 getter）与 mixed 型。

---

## 3. 第 2 步：真正的 selector 面

### 3.1 没有 `IOExternalMethodDispatch` 数组

在镜像 `__DATA_CONST`（`0xfffffe00080e3760`，`0x32248` B = 25,673 个 8 字节槽）里：

- 解出 **9,774** 个落在函数起点的 chained 指针
- 按 24 字节 `IOExternalMethodDispatch`（fn + 4×u32）扫，**没有任何 ≥3 条的连续记录**；263 个「首字段是函数指针 + 后 4 字段是小整数」的候选，间隔 296–1384 字节不齐，实际是 **vtable 首槽**（每个 vtable 以函数指针开头，后接 0）

⇒ 本 kext **不使用** 表驱动的 `IOExternalMethodDispatch`。这也解释了 `census.json` 只给它 2 个 selector：census 扫的是数据段记录数组，而这里根本没有。

### 3.2 selector 面 = `switch (w1)`

`IOUserClient::externalMethod` 的 ABI 是 `x0=self, w1=selector, x2=args, x3=dispatch, x4=target`。§2 里 **12 张按 `w1` 分派**的表，与这个 ABI 完全吻合：

| 表 # | 容器函数 | selector 范围 | 条目 | 容器是否在 vtable 里 |
|---|---|---|---|---|
| 2 | `0x906af88` | 0..14 | 15 | 是（1 处） |
| 3 | `0x906d5fc` | 0..65 | 66 | 是（2 处） |
| 5 | `0x90782d0` | 0..65 | 66 | 是（2 处） |
| 10 | `0x90a3f3c` | 0..33 | 34 | 否 |
| 11 | `0x90a9400` | 0..14 | 15 | 是（1 处） |
| 14 | `0x90b6788` | 0..14 | 15 | 是（3 处） |
| 17 | `0x90d1fd8` | 0..14 | 15 | 是（1 处） |
| 18 | `0x90f05f0` | 0..69 | 70 | 是（2 处） |
| 21 | `0x90ff79c` | 0..69 | 70 | 是（3 处） |
| 22 | `0x9101c04` | 0..65 | 66 | 是（4 处） |
| 26 | `0x9136e4c` | 0..14 | 15 | 是（1 处） |
| 31 | `0x914b3ec` | 0..14 | 15 | 是（1 处） |

**但必须留白**：这 12 个函数里只有 `0x914b3ec` 有 61 条指令（最小），其余大多 85–1045 条，且它们的 case body 都**不读** `[x2+0x18..0x40]`。所以「用户给 selector=N 就进第 N 个 case」这一步在**结构上成立**，但**没有一条证据把用户态 selector 接到这 12 个函数上**——它们的 vtable 槽属于哪个类、谁通过该槽调用，均未解（§8）。

---

## 4. 证伪记录：先前「7 张 5 槽表」的读法

`out/AUDIT-M2SCALER.prior-27.0.1-direct.md` §3.3 记录 7 个位置（`0x80e9078`、`0x80fc5b8`、`0x80fd2d8`、`0x80e9f08`、`0x80eefd8`、`0x80fb158`、`0x80ff268`）为「5 槽 + 32 字节填充」的表，并因形状不符而放弃 selector 映射。

本轮按三种步长重解这 7 个位置：

| 步长 | 结果 |
|---|---|
| 24 字节（`IOExternalMethodDispatch`） | 字段是 `(小整数, 0x8011xxxx)` 交替，不是「指针 + 4 小整数」 |
| 40 字节（5×8，先前假设） | 同上，一批值循环出现，无结构 |
| 8 字节 chained 指针 | **成立**：`0x0207ec8c` → `+0xfffffe0007004000` = `0xfffffe0009082c8c`（已知 handler） |

⇒ 这 7 个位置只是 **vtable 海里的任意 8 字节槽**，不是记录数组。「5 槽 + 填充」是把相邻的独立指针/数据误当成一条记录的分组假象。§3.3 的结论（形状不符、放弃映射）方向是对的，但原因是分组错误，不是「表形状特殊」。

---

## 5. 第 3 步：handler 审计

### 5.1 `IOExternalMethodArguments` 字段读取全景（全 10,262 函数）

跟踪 `x2` 及其 `mov` 副本，统计落在标准布局上的读：

| 偏移 | 字段 | 读它的函数数 |
|---|---|---|
| `+0x18` | scalarInput | 15 |
| `+0x20` | scalarInput64 | 12 |
| `+0x28` | scalarInputCount | 10 |
| `+0x30` | structureInput | 5 |
| `+0x38` | **structureInputSize** | **1** |
| `+0x40` | structureInputDescriptor | 8 |
| `+0x48` | scalarOutput | 1 |
| `+0x50` | scalarOutputCount | 6 |
| `+0x58` | structureOutput | 4 |
| `+0x60` | structureOutputSize | 2 |

### 5.2 唯一的 `+0x38` 读者是假阳性（重要）

`0x90af39c` 在 `0x90af668` 处有 `ldr x2,[x22,#0x38]`（`x22 = x2`）。手读整个函数（261 条）后判定：

- 该指针被访问的偏移是 `{0x0, 0x8, 0x30, 0x38, 0x48, 0x50}`，并且 `0x90af44c` 起还出现 `[x19,#0x1fc8]`、`[x19,#0x44]`、`[x21+x21*2]<<4` 等
- 这是一个**自定义结构体**（还带 `[x22+0x30]` 非空检查），不是 `IOExternalMethodArguments`

⇒ **全 kext 没有任何函数可证地读 `structureInputSize`。** 这个「阴性」本身是结论：本 kext 的尺寸把关不可能发生在这里，只能发生在 IOKit 基类（而基类把关依赖 dispatch 表，本 kext 没有该表）。

### 5.3 三个同模板大 handler（唯一候选）

| | 函数 | 指令 | 请求结构偏移（`x19=x2`） |
|---|---|---|---|
| T1 | `0x9082c8c` | 337 | `0x10,0x20,0x24,0x28,0x2c,0x30,0x34,0x68,0x70,0x74,0x88,0xcc,0xd4,0xdc,0x1d4,0x1d5,0x1d8,0x1dc,0x1f9,0x1fb,0x1fd,0x209,0x331,0x344,0x34c,`**`0x1088`** |
| T2 | `0x90f1ac8` | 359 | `0x20,0x28,0x2c,0x30,0x68,0x70,0x74,0x88,0x1d4..0x1dc,`**`0x1088`** |
| T3 | `0x9100b1c` | 358 | 同 T2 |

T1 开头（原文）：

```asm
mov  x19, x2
mov  x21, x0
ldr  x8, [x0, #0x10]
ldp  x20, x8, [x8, #0xf8]
ldr  x23, [x8, #0xc8]
mov  w8, #0x2bc
movk w8, #0xe000, lsl #16      ; w8 = 0xe00002bc = kIOReturnUnsupported
str  w8, [x2, #0x1088]         ; ← 无条件写 +0x1088
```

判定：

- 偏移谱系从 `0x0` 到 `0x1088`，**跨 0x1090**，所以 `x2` 是一个 **≈0x1090 字节的自定义请求结构**，不是 `IOExternalMethodArguments`（后者止于 `0x68`）。§5.1 里 T1/T2/T3 命中 `+0x20/0x28/0x30` 只是与标准布局**数值巧合**——这是本轮的第二个假阳性类别。
- 该结构在**函数入口立刻**被写 `+0x1088`，调用链上**没有任何尺寸比较**（函数内无 `cmp` 针对结构大小，也没有 `+0x38` 读）。
- ⇒ **候选链**：`selector → 请求结构指针 x2 → 入口无条件写 [x2+0x1088]`。若 `x2` 指向的是按用户给的 `structureInputSize` 分配的 kernel buffer 且该 size < 0x108c，则越界写 4 字节。
- **但这三步全都未证**：`x2` 的来源、是否按用户 size 分配、是否有上游统一校验。T1/T2/T3 的 `bl` 调用者为 **0**（纯虚调用），vtable 槽各只有 1 处，谁经该槽调用未解。

### 5.4 `Histogram bin count` 边界检查（正确）

`0x90a1a14`（3928 B）唯一调用断言 thunk `0x916d528`：

```asm
blraa x8, x16            ; 取回 width
mov  w23, w0
cmp  w0, #8
b.ls 0x90a1f5c           ; 无符号 ≤8 → 正常路径
...                      ; 否则断言 "Histogram bin count exceeds maximum"
```

`b.ls` 是**无符号**比较：负数（`0xFFFFFFFF`）会被判成 >8 而走断言，**不能**绕过。判定：**有效闸**，且 27.0.1 就已存在（§7）。

### 5.5 乘法/索引（任务指定 bug 类）

对全 kext 扫 `mul/madd/smull/umull → 8 条内到内存访问`：624 处，其中我按「`umulh`/`smulh`/条件跳转/`csneg`」弱判据标记 486 处「无保护」。

**这个数字不作为结论。** 抽查后判定该判据噪声过大：绝大多数是 `add x13,x10,x10,lsl#1`（×3）、`lsl x8,x8,#4`（×16）这类**常数缩放寻址**，索引本身被循环上界或 `b.hi` 限死，不构成乘法溢出。我只保留一条可陈述的结论：

> 在我**逐个手读过**的函数里（T1/T2/T3、12 个 `w1` 分派器、§5.1 的 38 个 args 读者、`0x916a330`、`0x90af39c`），**没有** `用户长度 × 元素宽度` 参与地址计算且缺溢出检查的模式。486 条「无保护」里没有一条落在这些函数中。

---

## 6. 跨版本：函数配对的正确做法

任务给的「序号对齐 + 长度校验」在**直接对齐**下对本 kext **失败**：

| 方法 | 结果 |
|---|---|
| 直接序号对齐（`fns[i]` ↔ `fns[i]`） | 10,262 对，长度相等仅 **1,197（11.7%）** ⇒ 不可用 |
| 长度重同步对齐（difflib 对长度序列做 LCS） | **10,219 / 10,262（99.6%）** 长度相等 ⇒ **可用** |

27.2 比 27.0.1 多 14 个函数（10,276 vs 10,262），函数在早期插入会使后续序号整体偏移——这正是直接对齐只有 11.7% 的原因，也让 `IOSurface` 上「1,328/1,330 全等」的经验在这里不成立。**用长度序列做 LCS 重同步**后配对恢复。

7 个关键函数全部配对成功且长度全等：

| 函数 | 27.0.1 | 27.2 | 长度 | 归一化指令序列 |
|---|---|---|---|---|
| T1 | `0x9082c8c` | `0x90ca1cc` | 1348 = 1348 | **完全相同** |
| T2 | `0x90f1ac8` | `0x91391bc` | 1436 = 1436 | **完全相同** |
| T3 | `0x9100b1c` | `0x9148218` | 1432 = 1432 | **完全相同** |
| histogram 检查器 | `0x90a1a14` | `0x90e8fc0` | 3928 = 3928 | 仅 `adrp+add` 立即数变 |
| size 检查函数 | `0x90af39c` | `0x90f696c` | 1044 = 1044 | 仅 `adrp+add` 立即数变 |
| getter | `0x916a330` | `0x91b1aac` | 516 = 516 | 仅 `adrp+add` 立即数变 |
| `0x90daa7c` / `0x910d11c` | — | — | 等长 | 仅立即数变 |

（归一化 = 把 ≥6 位的绝对地址立即数换成 `#IMM`，保留助记符与其余操作数，避免 PC 相对偏移造成伪差异。）

**结论：T1/T2/T3 在 27.2 里没有逻辑改动。** §5.3 的候选如果成立，Apple 到 27.2 也没修——这既可能说明它不是缺陷，也可能说明未被发现。两种都不能从静态证据区分。

---

## 7. 跨版本字符串差分

归一化（UUID、`TemporaryDirectory.*`）后：27.2 新增 **49** 条，消失 **36** 条。

### 7.1 新增（全部集中在 `0x7614b00–0x7614e00`）

| 字符串 | 语义 |
|---|---|
| `reclaiming PIODMA command idx=%u tag=%u transformId=%d powerRefOutstanding=%d release=%d` | command 回收 + power ref |
| `reclaimed %u PIODMA command(s), released %u MSR power ref(s), refCount now %u` | 引用计数 |
| `deferring arena release during flush, queue length %u` | arena 延迟释放 |
| `arenaReturnPage` | 页归还 |
| `command %u in use but has no packet sequence (valid=%u)` | 新不变量 |
| `command %u sequence list spans two requests (%p != %p)` | 新不变量（跨请求越界） |
| `Failed to load MsrCPU firmware ... bootProgress=%s(0x%08x) bootEntries=%u running=... ctrrLock=%u ctrrWrDis=%u` | 固件诊断 |

xref 验证：这些串被 `0x91ad640`、`0x91ad568`、`0x91ad5b4`、`0x90a60c4` 引用，而**这 4 个函数全部在 27.2 的 57 个「未配对/新增」函数名单里**。

⇒ **27.2 对 M2Scaler 的改动是资源生命周期（PIODMA command 回收、MSR power ref 计数、arena 延迟释放）+ 新的序列表不变量检查，没有新增边界检查。**

### 7.2 `Histogram bin count` 不是新检查

| | 字符串 |
|---|---|
| 27.0.1 | `Histogram bin count (%d) exceeds maximum (%d)` |
| 27.2 | `Histogram bin count (%ld) exceeds maximum (%d)` |

差别只有 `%d` → `%ld`（计数变量加宽到 64 位后的 **printf 宽度更正**）。检查逻辑 `cmp w0,#8 / b.ls` 两版一致（§5.4）。**不作为安全修复报告**——这正是「字符串差分容易出假阳性」的又一例。

### 7.3 消失的串

`command %d not valid!` 消失，被 `command %u in use but has no packet sequence (valid=%u)` 取代 ⇒ 那条路径的检查被**改写并加强**（从「有效性布尔」变成「有效性 + 序列归属」双判）。这与 7.1 的生命周期主题一致。

---

## 8. 未审计 / 卡在哪

| 项 | 为什么没做完 |
|---|---|
| selector → handler 的**可达性** | 32 张表已定性；12 个 `w1` 分派器的 vtable 槽各自只有 1 处引用，所属类未知，`bl` 直接调用者为 0。缺「谁经哪个槽用用户 selector 调用」这条边 |
| `0x1090` 请求结构的**来源** | T1/T2/T3 的 `x2` 由调用者给；无直接调用者（纯虚调用），无法回溯它是否为 `structureInput` 拷贝、是否按用户 size 分配 |
| IOKit 基类是否统一校验尺寸 | 本 kext 无 `IOExternalMethodDispatch` 表，基类 `checkStructureInputSize` 不会被驱动；但若走 `externalMethod` 覆写 + 手工检查，检查应在驱动里——没找到 |
| `__DATA` 的 OSMetaClass | 未解；解出才能定位 `IOSurfaceAcceleratorClient` 的 vtable 基址与 `externalMethod` 本体（这是唯一能把「用户 selector」接到「我读过的代码」的通道） |
| 946 个 case body | 只逐个手读了 85 指令模板族（5 张表 ×15）与 `ret` 族；122 条的 `0x90ce5fc`（1691 指令、2 张表）只做了自动分类 |
| 全 kext 其余 ~10,250 函数 | 只做了 args 字段、乘法、字串 xref 三类自动扫描 + 少量手读 |

### 下一步最值钱的一步

解 `__DATA` 的 OSMetaClass → 拿到 `IOSurfaceAcceleratorClient` 的 vtable 基址 → 用「槽序号 × 8」在 `__TEXT_EXEC` 里反查 `ldr x8,[x16,#off]!` / `add x16,#off` → 找到调用 §3.2 那 12 个 `w1` 分派器的唯一入口。**这条边一钉住，§5.3 的候选链就能从「未定性」变成「成立」或「排除」。**

---

## 9. 直答

**`AppleM2ScalerCSCDriver` 里有没有用户可控输入导致的内核内存破坏？**

**没有找到。** 不是「不存在」，是「未发现」，且阻断点是具体的两点：

1. **32 张表不是漏洞面。** 逐张验证后全部是编译器 `switch` 跳转表（946 项，100% 目标是同函数内的 `bti j` 分支块，32/32 有 `cmp+b.hi` 上界闸）。其中 12 张作用在 `w1` 上、形态符合 `externalMethod` 的 selector 分派，但 case body 里 **0 处**读 `IOExternalMethodArguments` 字段，且没有一条证据把用户 selector 接到这些函数上。`census.json` 只记 2 个 selector 不是漏扫，是**本 kext 没有 `IOExternalMethodDispatch` 记录数组**（`__DATA_CONST` 是 9,774 个 chained 函数指针组成的 vtable 海）。
2. **唯一候选卡在可达性上。** T1/T2/T3（`0x9082c8c`/`0x90f1ac8`/`0x9100b1c`）接收 ≈0x1090 字节自定义请求结构，并在入口**无条件**写 `[x2+0x1088]`，全函数无尺寸比较；而全 kext **没有任何函数可证地读 `structureInputSize (+0x38)`**（唯一命中 `0x90af39c` 经手读证伪为自定义结构体字段）。若该结构确实按用户给定 size 分配，这就是一个 4 字节越界写；但「`x2` 来源」「是否按用户 size 分配」「上游有无统一校验」三者全未证，`bl` 调用者为 0（纯虚调用）。

**跨版本没有提供额外信心，反而给出方向性否定：**

- T1/T2/T3 在 27.2 里**指令序列完全相同**（长度 1348/1436/1432 全等，归一化后无差异）。
- 27.2 新增的 49 条字符串全部是**生命周期/回收**语义（PIODMA command 回收、MSR power ref 计数、arena 延迟释放、序列归属不变量），xref 落在 4 个**新增函数**上。
- `Histogram bin count` 的 `%d`→`%ld` 是 printf 宽度更正，检查本身（无符号 `cmp #8 / b.ls`）27.0.1 就有且正确。

⇒ 按现有静态证据，**Apple 在 27.2 对 M2Scaler 的改动主题是资源生命周期，不是边界**。如果这个 kext 有被修的内存破坏，更可能落在 §7.1 那批新增的回收/引用计数逻辑上（UAF/重复释放），而不是任务假设的 AVE 式 OOB write。这条线索本轮**没有审**，是下一轮该切的地方。

---

## 10. 复现

```bash
cd tasks/ios27-chain-poc
python3 out/m2s-work/scan.py out/m2s.27.0.1.macho   # 32 表 + 自证
python3 out/m2s-work/charac.py                      # 容器/目标性质
python3 out/m2s-work/bound.py                       # 真上界闸 + 索引寄存器
python3 out/m2s-work/classify2.py                   # case body 家族分类
python3 out/m2s-work/argread.py                     # vtable 归属 + args 读取
python3 out/m2s-work/global_args.py                 # 全 kext args 字段全景
python3 out/m2s-work/extmethod.py                   # 24B dispatch 数组搜索（阴性）
python3 out/m2s-work/xver.py                        # 跨版本配对 + 指令差分
python3 out/m2s-work/mulscan.py                     # 乘法→寻址扫描（噪声大，仅参考）
```

产物：`dispatch_raw.json`、`dispatch_full.json`、`dispatch_char.json`、`dispatch_bound.json`、
`dispatch_family.json`、`dispatch_args.json`、`argfield_scan.json`、`extmethod_tables.json`（均在 `out/m2s-work/`）。

未改动 `out/` 以外任何既有文件；未 git commit。
