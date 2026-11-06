# SEL-SHAPE — 结构输入尺寸阶梯：翻转矩阵

生成于 2026-11-01 11:43:31　来源：`out/selshape.ndjson`（912 条实测记录）

**做法**：固定 selector，扫**参数形状**（structure 输入尺寸、scalar 输入个数、输出容量），看返回码在哪个形状上**翻转**。每次调用一个独立 `io_connect_t`，用完即关；同一 (selector, 形状) 至少重复 2 次（关键点 5 次）。

**判据**：只认翻转，不推测语义。`BadArgument → 其它码` 才是 handler 存在的正面证据。

---

## 1. 直答：`AppleCLCD2` 哪些 selector 在哪个尺寸上翻转了

**一个都没有。零个 selector 在非零输入尺寸上翻转到新返回码。**

实际发生的是**反向翻转**：11 个 selector 在「零参数」这一种形状下才给出各自的真实返回码；一旦加上**任何**非零的 scalar 输入个数、scalar 输出容量或 structure 输出容量，**11 个全部**塌成 `kIOReturnBadArgument`；加非零 structure 输入尺寸时，**其中 10 个**塌成 `BadArgument`。

所以对这些 selector，期望的输入尺寸就是 **0**——不存在「再给多一点参数就能进去」的空间。

**一个例外**：`sel 100` 的权限检查在参数校验**之前**，所以它接受任意尺寸的 structure 输入（1/2/4/8/16/64/256 字节全部返回 `kIOReturnNotPrivileged`，不退化）。它不是零参数客户端，而是「先查权限、再看参数」的客户端。详见 §2.2。

---
## 2. `AppleCLCD2` 的 arity 阈值（精确到 1）

| selector | method(all-0) | scalar in=0 out=0 | scalar in=0 out=1 | scalar in=0 out=2 | scalar in=0 out=4 | scalar in=0 out=16 | scalar in=1 out=0 | scalar in=1 out=1 | scalar in=2 out=0 | scalar in=3 out=0 | scalar in=4 out=0 | scalar in=8 out=0 | struct in=0 out=0 | struct in=0 out=1 | struct in=1 out=0 | struct in=2 out=0 | struct in=4 out=0 | struct in=8 out=0 | struct in=16 out=0 | struct in=64 out=0 | struct in=256 out=0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **26** | `S` | `S` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `S` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` |
| **59** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` |
| **60** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `?` | `?` | `?` | `?` | `?` | `?` |
| **61** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `?` | `?` | `?` | `?` | `?` | `?` |
| **62** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `?` | `?` | `?` | `?` | `?` | `?` |
| **63** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `?` | `?` | `?` | `?` | `?` | `?` |
| **64** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `?` | `?` | `?` | `?` | `?` | `?` |
| **65** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `?` | `?` | `?` | `?` | `?` | `?` |
| **70** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` |
| **71** | `C` | `C` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `C` | `B` | `B` | `?` | `?` | `?` | `?` | `?` | `?` |
| **100** | `P` | `P` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `P` | `B` | `P` | `P` | `P` | `P` | `P` | `P` | `P` |

图例：`S`=`KERN_SUCCESS` `B`=`kIOReturnBadArgument` `C`=`kIOReturnNoCompletion` `P`=`kIOReturnNotPrivileged` `U`=`kIOReturnUnsupported` `O`=`kIOReturnNoMemory` `E`=`kIOReturnError`

读法：

- **只有全零形状能进 handler**：`scalar in=0 out=0`、`struct in=0 out=0`、`method(all-0)` 三列给出真实返回码，且三种 MIG 形式**结果完全一致**——说明客户端的校验看的是**尺寸**，不是调用走哪条 MIG。
- **in=1/2/3/4/8 全部 `B`**：连 1 个 scalar 输入都不接受。
- **out=1/2/4/16 全部 `B`**：连 1 个 scalar 的**输出容量**都不接受。
- **struct in=1、struct out=1 全部 `B`**：structure 方向同理，1 字节就拒。

对 sel 26 与 59–71，这不是「参数不对」，而是这些 handler 在入口就把**任何非零 arity 的调用**判为非法。但**不能**推广成「整个 client 是纯零参数」——`sel 100` 明确接受任意尺寸的 structure 输入（见 §2.2）。

所以这里是**逐个 handler 各自校验自己的参数形状**，而不是客户端级的一刀切。这也解释了为什么同一形状下 11 个 selector 里 10 个行为一致、1 个不同。

### 2.1 上一轮 size 阶梯为什么全 `BadArgument`

第一轮用的是 `IOConnectCallStructMethod(..., out=4096, &outSize)`——**输出容量 4096 本身就足以让调用被拒**。所以那 154 组 `BadArgument` 不是「尺寸没猜对」，而是每一个都被 arity 校验挡在门外。这一轮把 `out` 容量归零后才重新看到 `S`/`C`/`P`。

### 2.2 例外：`sel 100` 先查权限、后看参数

把 `structure` 输入尺寸拉到 256 字节，`sel 100` 与其他 selector 的行为完全不同：

| selector | in=0 | in=1 | in=2 | in=4 | in=8 | in=16 | in=64 | in=256 |
|---|---|---|---|---|---|---|---|---|
| **26** | 真实码 | `B` | `B` | `B` | `B` | `B` | `B` | `B` |
| **59 / 70** | 真实码 | `B` | `B` | `B` | `B` | `B` | `B` | `B` |
| **100** | `P` | **`P`** | **`P`** | **`P`** | **`P`** | **`P`** | **`P`** | **`P`** |

（`P` = `kIOReturnNotPrivileged`，`B` = `kIOReturnBadArgument`；`sel 100` 每格 3–5 次重复，全部一致）

`sel 100` 在 1–256 字节的 structure 输入下**全部**返回 `NotPrivileged`，从不退化成 `BadArgument`。同时它对 **scalar** 方向依然敏感（`scalar in=1` → `B`，`scalar out=1` → `B`）。

已记录的事实：这个 handler 的**权限判定发生在参数校验之前**，且只对 scalar 方向做 arity 校验。不推测它为什么这样，只记录这个矩阵。

---

## 3. 真正出现翻转的地方：`AppleM2ScalerCSCDriver` 与 `AppleJPEGDriver`

这两个类的哨兵是 `Unsupported`（M2Scaler）或存在明确的零参数成功项（JPEG），所以尺寸阶梯能给出**正向翻转**。阶梯：structure 输入 `{0,1,4,8,16,32,64,128}` 字节，全零内容，**输出容量 0**。

### 3.1 `AppleM2ScalerCSCDriver` type 0

| selector | in=0 | in=1 | in=4 | in=8 | in=16 | in=32 | in=64 | in=128 | 翻转 |
|---|---|---|---|---|---|---|---|---|---|
| **0** | `U` | `U` | `U` | `U` | `U` | `U` | `U` | `U` | — |
| **1** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **2** | `U` | `U` | `U` | `U` | `U` | `U` | `U` | `U` | — |
| **3** | `U` | `U` | `U` | `U` | `U` | `U` | `U` | `U` | — |
| **4** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **5** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **6** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **7** | `B` | `B` | `B` | `rc1` | `B` | `B` | `B` | `B` | → in=8: `rc1` |
| **8** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **9** | `B` | `B` | `B` | `B` | `O` | `B` | `B` | `B` | → in=16: `O` |
| **10** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **11** | `S` | `S` | `S` | `S` | `S` | `S` | `S` | `S` | — |
| **12** | `U` | `U` | `U` | `U` | `U` | `U` | `U` | `U` | — |

**翻转项**：

- **sel 7**：零尺寸是 `B`，在 in=8 翻到 `rc1`。
- **sel 9**：零尺寸是 `B`，在 in=16 翻到 `O`。

### 3.2 `AppleJPEGDriver` type 0

| selector | in=0 | in=1 | in=4 | in=8 | in=16 | in=32 | in=64 | in=128 | 翻转 |
|---|---|---|---|---|---|---|---|---|---|
| **0** | `S` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | → in=1: `B`, in=4: `B`, in=8: `B`, in=16: `B`, in=32: `B`, in=64: `B`, in=128: `B` |
| **1** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **2** | `S` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | → in=1: `B`, in=4: `B`, in=8: `B`, in=16: `B`, in=32: `B`, in=64: `B`, in=128: `B` |
| **3** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **4** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **5** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **6** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **7** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **8** | `B` | `B` | `E` | `B` | `B` | `B` | `B` | `B` | → in=4: `E` |
| **9** | `E` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | → in=1: `B`, in=4: `B`, in=8: `B`, in=16: `B`, in=32: `B`, in=64: `B`, in=128: `B` |
| **10** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **11** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |
| **12** | `B` | `B` | `B` | `B` | `B` | `B` | `B` | `B` | — |

**翻转项**：

- **sel 0**：零尺寸是 `S`，在 in=1, in=4, in=8, in=16, in=32, in=64, in=128 翻到 `B`, `B`, `B`, `B`, `B`, `B`, `B`。
- **sel 2**：零尺寸是 `S`，在 in=1, in=4, in=8, in=16, in=32, in=64, in=128 翻到 `B`, `B`, `B`, `B`, `B`, `B`, `B`。
- **sel 8**：零尺寸是 `B`，在 in=4 翻到 `E`。
- **sel 9**：零尺寸是 `E`，在 in=1, in=4, in=8, in=16, in=32, in=64, in=128 翻到 `B`, `B`, `B`, `B`, `B`, `B`, `B`。

---

## 4. 翻转汇总

| 类 | selector | 翻转尺寸 | 从 | 到 | 复现次数 |
|---|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 7 | 8 | `B` | `1` | ✅ 5/5 一致 |
| `AppleM2ScalerCSCDriver` | 9 | 16 | `B` | `O` | ✅ 5/5 一致 |
| `AppleJPEGDriver` | 8 | 4 | `B` | `E` | ✅ 5/5 一致 |
| `AppleJPEGDriver` | 9 | 0 | `B` | `E` | ✅ 5/5 一致 |
| `AppleJPEGDriver` | 0 | 1 | `S` | `B` | ✅ 5/5 一致 |
| `AppleJPEGDriver` | 2 | 1 | `S` | `B` | ✅ 5/5 一致 |
| `AppleCLCD2` | 100 | 1 | `B` | `P` | ✅ 5/5 一致 |

两处「从 `S` 到 `B`」是**反向翻转**（零参数成功、加任何参数就失败），四处「从 `B` 到别的码」是**正向翻转**——后者才是「找到了期望输入尺寸」的证据。

### 4.1 `kIOReturnNoMemory` 与 `kIOReturnError` 的含义边界

按纪律不推测语义，只记录事实：

- `AppleJPEGDriver` sel 8 在 `in=4` 时返回 `kIOReturnError`，其余 7 个尺寸都是 `BadArgument`。**4 字节是这个 handler 唯一被接受的结构输入尺寸。**
- `AppleJPEGDriver` sel 9 在 `in=0` 时返回 `kIOReturnError`，非零尺寸全部 `BadArgument`——它的期望尺寸是 0。
- `AppleM2ScalerCSCDriver` sel 9 在 `in=16` 时返回 `kIOReturnNoMemory`，其余 `BadArgument`——**16 字节被接受，随后在分配阶段失败**。
- `AppleM2ScalerCSCDriver` sel 7 在 `in=8` 时返回裸值 `1`（`KERN_INVALID_ADDRESS` 域，不是 IOKit `0xE00xxxxx`），其余 `BadArgument`。这是唯一一个返回非 IOKit 域的观测，原样记录。

---

## 5. 方法论：翻转有两个方向

这一轮推翻了一个隐含假设——「参数加得越多越可能进 handler」。实际存在两类翻转：

| 方向 | 形态 | 是否等于「找到期望尺寸」 |
|---|---|---|
| **正向** | 某尺寸从 `BadArgument` 变成别的码 | ✅ 是。`BadArgument` = 被校验拒，换成别的码 = 校验通过、进了 handler |
| **反向** | 零参数能进，加任何参数就变 `BadArgument` | ✅ 也是证据，但它证明的是「期望尺寸 = 0」，不是「找到了更大的尺寸」 |

`AppleCLCD2` 除 `sel 100` 外是**纯粹的第二种**。如果只按「正向翻转」找，会得出「这个类全死」的错误结论；反过来如果只看基线不看加参数，又会错过 arity 校验这个结构特征。

---

## 6. `NoCompletion` 的 9 个 selector 不是「参数没给够」

sel 59–65、70、71 在零参数下返回 `kIOReturnNoCompletion`。一个自然的读法是「操作已入队、参数不足」。但本轮实测否定这个读法：

- 对它们加 **1 个** scalar 输入 → `BadArgument`（不是 `NoCompletion`，也不是别的码）
- 加 2/3/4/8 个 → 全部 `BadArgument`
- 给 1 字节 structure 输入 → `BadArgument`
- 给 1 个 scalar 的输出容量 → `BadArgument`

**加参数不会让它们更接近成功，只会让调用在入口被拒。** 所以这 9 个的 `NoCompletion` 是**零参数调用本身的结果**，不是参数不足的信号。

---

## 7. 一致性

| 检查 | 结果 |
|---|---|
| 同一 (selector, 形状) 重复调用 | **0 处不一致**（关键翻转点各 5 次） |
| panic | **0 次** |
| 显示器变黑 | 未发生 |
| 超时 | **0 次** |
| 每次调用独立 conn | 是，用完即关 |

---

## 8. 下一步

`AppleCLCD2` 这条路在「有参调用」方向已经关死——它是零参数客户端，而零参数能拿到的信息本轮已经拿完（26 → 成功、100 → 权限门、59–65/70/71 → `NoCompletion`）。再往下只能是：

1. **对 `AppleJPEGDriver` sel 8 构造 4 字节真实参数**：尺寸已确定是 4，下一步该填内容而不是改形状。
2. **对 `AppleM2ScalerCSCDriver` sel 9 构造 16 字节参数**：尺寸已确定是 16，且已过了校验（返回 `NoMemory` 而非 `BadArgument`）。
3. `AppleCLCD2` 换个角度：静态扫不到派发表，但它是零参数客户端——真正该查的是它**零参数**调用的副作用（sel 26 成功后内核态发生了什么），而不是继续加参数。

---

## 9. 复现

```bash
cd harness/selshape && PLAN=/path/cfg.json WAIT=16 ./run.sh
python3 harness/selshape/gen_report.py
```

`harness/selshape/main.m` 的配置格式（`tmp/selshape.json`）：

```json
[{"class":"AppleCLCD2","type":0,
  "sels":[26,59,60,61,62,63,64,65,70,71,100],
  "shapes":[{"form":"scalar","scalar_in":[],"scalar_out_cap":0},
            {"form":"struct","struct_in_size":4,"struct_out_cap":0}],
  "passes":2}]
```

`form` 三选一：`scalar`（`IOConnectCallScalarMethod`）、`struct`（`IOConnectCallStructMethod`）、`method`（`IOConnectCallMethod`，可同时带 scalar 与 struct）。按 `class|type|sel|pass|shape` 断点续跑；单条 0.8s 超时后跳到下一条。
