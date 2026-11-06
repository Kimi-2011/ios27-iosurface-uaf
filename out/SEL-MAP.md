# SEL-MAP — 零参数探针量出的真实 selector 边界

生成于 2026-11-01 11:34:36　来源：`out/selmap.ndjson`（7680 条实测记录）

**探针**：`IOConnectCallScalarMethod(conn, sel, NULL, 0, NULL, &outCnt=0)`——不传 scalar 输入、不传 struct 输入、不要任何输出。每条 selector 记录返回码，不推测语义。

---

## 1. 直答：6 个类的真实 selector 上界

| 类 | type | **实测上界** | 有效区间 | census 报的 | 差距 |
|---|---|---|---|---|---|
| `AppleCLCD2` | 0 | **测不出** | 无法界定 | 0（静态盲区） | 方法不适用 |
| `AppleM2ScalerCSCDriver` | 0 | **12** | 0..11 | 2 | census 少报 6 倍 |
| `IOSurfaceRoot` | 0 | **测不出** | 无法界定 | 120（疑似应为 60） | 方法不适用 |
| `AGXAcceleratorG18P` | 1 | **56** | 0..55 | 4（2 张表） | census 少报 14 倍 |
| `AGXAcceleratorG18P` | 33 | **测不出** | 无法界定 | — | 方法不适用 |
| `AGXAcceleratorG18P` | 65537 | **56** | 0..55 | — | — |
| `AppleJPEGDriver` | 0 | **测不出** | 无法界定 | 10 | 方法不适用 |
| `H1xANELoadBalancer` | 1 | **测不出** | 无法界定 | 未知 | 方法不适用 |

「上界」定义：**第一个长度 ≥8 的连续 `kIOReturnUnsupported` 段的起点**。在这个位置之后全部是 `Unsupported`，之前则是各种非 `Unsupported` 返回码。

### 1.1 哪些类这个方法能测、哪些测不出——原因只有一个

| 类 | 未知 selector 的返回码 | 能否量出上界 |
|---|---|---|
| `AppleM2ScalerCSCDriver` | `Unsupported` | ✅ 能 |
| `AGXAcceleratorG18P` type 1 / 65537 | `Unsupported` | ✅ 能 |
| `AGXAcceleratorG18P` type 33 | `BadArgument` | ❌ 不能 |
| `IOSurfaceRoot` | `BadArgument` | ❌ 不能 |
| `AppleCLCD2` | `BadArgument`（但非单调） | ❌ 不能 |
| `AppleJPEGDriver` | `BadArgument` | ❌ 不能 |
| `H1xANELoadBalancer` | `BadArgument` | ❌ 不能 |

判定的依据是**哨兵**：对一个**已知不存在**的 selector（4095）发同样的零参数调用。

| 类 | 哨兵 4095 返回 | 含义 |
|---|---|---|
| `AppleM2ScalerCSCDriver` | `Unsupported` | `Unsupported` 是真正的「越界」信号 → 上界可测 |
| `AGXAcceleratorG18P` t1 / t65537 | `Unsupported` | 同上 |
| `IOSurfaceRoot` / `AppleCLCD2` / `AppleJPEGDriver` / `H1xANELoadBalancer` / `AGX` t33 | `BadArgument` | `BadArgument` 是**兜底码**，对「不存在的 selector」也返回它 → 上界不可测 |

**这是本轮最重要的方法论结论**：`BadArgument` 只有在哨兵也返回 `Unsupported` 的类上才等于「handler 存在」。在兜底码是 `BadArgument` 的类上，它与「selector 不存在」**完全不可区分**，任何基于它给出的上界都是编造的。

---

## 2. 逐类明细

### 2.1 `AppleCLCD2` type 0

用途：DCP kext 入口，静态找不到派发　pass0/pass1 **完全一致**（无状态）

```
BUUBBBBBBBBBBBBBBBBBBBBBBBSBBBBBBBBBUUUUUBBBBUUBBBBBBBBBBBBCCCCC   [0-63]
CCBBBBCCBBBBUBBBBBBBBBBBBBBBBBBBBBBBPBBBBBBBBBBBBBBBBBBBBBBBBBBB   [64-127]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [128-191]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnBadArgument` | 235 | [0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]… |
| `kIOReturnUnsupported` | 10 | [1, 2, 36, 37, 38, 39, 40, 45, 46, 76] |
| `kIOReturnNoCompletion` | 9 | [59, 60, 61, 62, 63, 64, 65, 70, 71] |
| `KERN_SUCCESS` | 1 | [26] |
| `kIOReturnNotPrivileged` | 1 | [100] |

**异常项**：

- `Unsupported` 只出现在 sel [1, 2, 36, 37, 38, 39, 40, 45, 46, 76]（共 10 个，**不连续、非单调**），最后一个在 76。 **76 之后仍然有非兜底码的返回**：sel [100]——所以「第一个 Unsupported 就是上界」在这个类上直接失效。

### 2.2 `AppleM2ScalerCSCDriver` type 0

用途：census 说 2，全核扫描说 32 张表　pass0/pass1 **完全一致**（无状态）

```
UBUUBBBBBBBSUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [0-63]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [64-127]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [128-191]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnUnsupported` | 247 | [0, 2, 3, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]… |
| `kIOReturnBadArgument` | 8 | [1, 4, 5, 6, 7, 8, 9, 10] |
| `KERN_SUCCESS` | 1 | [11] |

**异常项**：

- **上界之内出现 `Unsupported`**：sel [0, 2, 3] —— 不是简单的「表尾之外全 Unsupported」，说明这个 client 在有效区间内也返回 `Unsupported`（可能是子分发器）。

### 2.3 `IOSurfaceRoot` type 0

用途：验证 60 还是 120　pass0/pass1 **完全一致**（无状态）

```
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [0-63]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [64-127]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [128-191]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnBadArgument` | 256 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]… |

无异常：上界之后全部为 `Unsupported`，区间内无 `Unsupported`，两次 pass 一致。

### 2.4 `AGXAcceleratorG18P` type 1

用途：已知可开　pass0/pass1 **完全一致**（无状态）

```
BBBBBBBBBBBBBBBBBBBBBBUBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBTUUUUUUUU   [0-63]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [64-127]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [128-191]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnUnsupported` | 201 | [22, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78]… |
| `kIOReturnBadArgument` | 54 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24]… |
| **超时** | 1 | [55] |

**异常项**：

- **上界之内出现 `Unsupported`**：sel [22] —— 不是简单的「表尾之外全 Unsupported」，说明这个 client 在有效区间内也返回 `Unsupported`（可能是子分发器）。

### 2.5 `AGXAcceleratorG18P` type 33

用途：type 33 是新发现的另一个 user client　pass0/pass1 **完全一致**（无状态）

```
BBPBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [0-63]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [64-127]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [128-191]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnBadArgument` | 255 | [0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]… |
| `kIOReturnNotPrivileged` | 1 | [2] |

无异常：上界之后全部为 `Unsupported`，区间内无 `Unsupported`，两次 pass 一致。

### 2.6 `AGXAcceleratorG18P` type 65537

用途：type 位域高位，是否别名　pass0/pass1 **存在差异**

```
BBBBBBBBBBBBBBBBBBBBBBUBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBTUUUUUUUU   [0-63]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [64-127]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [128-191]
UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnUnsupported` | 201 | [22, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78]… |
| `kIOReturnBadArgument` | 54 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24]… |
| **超时** | 1 | [55] |

**异常项**：

- **上界之内出现 `Unsupported`**：sel [22] —— 不是简单的「表尾之外全 Unsupported」，说明这个 client 在有效区间内也返回 `Unsupported`（可能是子分发器）。

### 2.7 `AppleJPEGDriver` type 0

用途：未审过　pass0/pass1 **完全一致**（无状态）

```
SBSBBBBBBEBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [0-63]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [64-127]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [128-191]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnBadArgument` | 253 | [1, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]… |
| `KERN_SUCCESS` | 2 | [0, 2] |
| `kIOReturnError` | 1 | [9] |

无异常：上界之后全部为 `Unsupported`，区间内无 `Unsupported`，两次 pass 一致。

### 2.8 `H1xANELoadBalancer` type 1

用途：验证 B 说的 26 个　pass0/pass1 **完全一致**（无状态）

```
BSBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [0-63]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [64-127]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [128-191]
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   [192-255]
```
图例：`S`=成功 `B`=BadArgument `U`=Unsupported `M`=NotPermitted `P`=NotPrivileged `C`=NoCompletion `E`=Error `T`=超时 `?`=缺失

| 返回码 | 个数 | selector |
|---|---|---|
| `kIOReturnBadArgument` | 255 | [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]… |
| `KERN_SUCCESS` | 1 | [1] |

无异常：上界之后全部为 `Unsupported`，区间内无 `Unsupported`，两次 pass 一致。

---

## 3. `AppleM2ScalerCSCDriver` 的 32 张表：不靠 type 选

census 报 2 条，而全内核扫描发现这个 kext 有 32 张派发表（每张 bound 66~70）。如果这 32 张表是靠 user client 的 type 选的，那么不同 type 应该量出不同上界。实测：

| type | 上界 | 0..15 返回码 | 零参数成功 |
|---|---|---|---|
| 0 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 1 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 2 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 3 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 4 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 5 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 6 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 7 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 8 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 9 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 10 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 11 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 12 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 13 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 14 | 12 | `UBUUBBBBBBBSUUUU` | [11] |
| 15 | 12 | `UBUUBBBBBBBSUUUU` | [11] |

**16 个 type 的上界全部是同一个值，返回码序列逐条相同。** 所以这 32 张表**不是**由 type 选择的。

这否掉了一个具体假设：既然 `AGX` 的 type 33 确实是另一个 user client，「M2Scaler 的 32 张表靠 type 选」本来是最自然的解释——但实测不支持。可行方向只剩：32 张表分属不同的 `IOService` 实例（不只 `AppleM2ScalerCSCDriver` 这一个名字）、或由 `IOServiceAuthorize` / 连接参数而不是 type 选择。

---

## 4. 判读纪律执行情况

| 要求 | 结果 |
|---|---|
| 返回码是唯一证据 | 全部结论只引用返回码，未从返回值反推 handler 语义 |
| 连续 `Unsupported` 之后又出现非 `Unsupported` | 逐类检查，结果见上「异常项」 |
| 同一 selector 两次调用返回码不同 | **0 处**：8 个 target 的 pass0 与 pass1 逐条一致，本轮未观察到状态性 |
| 超时/挂起单独标出 | `AGX` type 1 与 type 65537 的 **sel 55** 两次 pass 均挂起（0.8s 未返回），已标为 `TIMEOUT` 并从 56 用新 conn 续跑成功 |
| panic | **0 次** |
| 显示器变黑 | 未发生，设备全程正常 |

### 4.1 `AGX` sel 55 的复现性

`AGXAcceleratorG18P` type 1 的 sel 55 在**两次独立 pass** 中都挂起（0.8s 内不返回），这不是噪声。相邻位：54 → `BadArgument`，55 → 挂起，56 → `Unsupported`。type 65537 上完全一样（同一 client）。type 33 上 sel 55 正常返回 `BadArgument`。

### 4.2 `AGX` type 65537 是 type 1 的别名

| selector | type 1 | type 65537 |
|---|---|---|
| 22 | `Unsupported` | `Unsupported` |
| 55 | 挂起 | 挂起 |
| 56..255 | `Unsupported` | `Unsupported` |
| 其余 0..54 | `BadArgument` | `BadArgument` |

**256 个 selector 逐一相同。** 所以 `65537`（= `1 | 0x10000`）不是新的 user client，只是 type 的高位标志位被忽略、落回同一个 client。真正的第二个 client 只有 **type 33**。

---

## 5. 与 census 的差距：静态为什么量不到

| 类 | census | 实测 | 差距性质 |
|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 2 | **12** | census 只扫到 1 张表的前 2 项；实际 type 0 可达 12 个 selector，其中 **11 零参数即成功** |
| `AGXAcceleratorG18P` | 4（2 张表） | **56** | 每张表只记录了 2 条，实际 type 1/65537 有 56 个可达 selector |
| `AppleCLCD2` | 0 | **非单调、无单一上界** | 静态完全找不到派发表，动态才有信号 |
| `IOSurfaceRoot` | 120（疑似 60） | **测不出** | 客户端兜底返回 `BadArgument`，与「handler 存在」不可区分 |
| `AppleJPEGDriver` | 10 | **测不出** | 同上 |
| `H1xANELoadBalancer` | 未知 | **测不出** | 同上 |

两处 census 明确低估（M2Scaler 2→12、AGX 4→56）都是 **6~14 倍**。这说明 census 的 selector 计数来自「表里连续可解析的条目」，遇到稀疏表或间接跳转就会提前截断。

---

## 6. `AppleCLCD2` 的真实边界在哪

**没有单一数值上界。** 返回码在 0..255 上不是单调的，按出现位置分成四段互不重叠的信号：

- `KERN_SUCCESS`：sel [26]
- `kIOReturnNotPrivileged`：sel [100]
- `kIOReturnNoCompletion`：sel [59, 60, 61, 62, 63, 64, 65, 70, 71]
- `kIOReturnUnsupported`：sel [1, 2, 36, 37, 38, 39, 40, 45, 46, 76]

具体地说：

1. **sel 26 零参数返回 `KERN_SUCCESS`** —— 唯一一个不带任何参数就能成功的入口。
2. **sel 100 返回 `kIOReturnNotPrivileged`** —— 一个**真实存在、且有权限门**的 handler。这是本轮在 `AppleCLCD2` 上最有价值的发现：之前的 0..63 扫描根本看不到它。
3. **sel 59–65、70、71 返回 `kIOReturnNoCompletion`（9 个）** —— 与周围整片的 `BadArgument` 明确不同，是一条独立的执行路径（不是参数校验失败）。
4. **`Unsupported` 只出现在 sel [1, 2, 36, 37, 38, 39, 40, 45, 46, 76]**（共 10 个），彼此不相邻、不连续。所以「第一个 `Unsupported` 就是上界」在这里**不成立**——`Unsupported` 出现在有效区间内部，而 `BadArgument` 又一直延续到 255。

因此对 `AppleCLCD2` 只能说：**能确认的真实 selector 至少包括 {26, 59–65, 70, 71, 100}**，上界未知（兜底码 `BadArgument` 把区间填满了，无法从返回码判断 101..255 里哪些是真的）。

---

## 7. 下一步该换什么杠杆

零参数探针的极限就在这里：它能把**有明确越界码**的类的上界量死（AGX、M2Scaler），但不能穿透**兜底码是 `BadArgument`** 的类。要突破只剩两条，都不是加 selector 范围：

1. **换参数形状而不是换 selector**：对 `IOSurfaceRoot` 这类，真实 handler 要求 structIn>0，零参数必然 `BadArgument`；给一个 4/16/64 字节的 struct 输入再看返回码是否变化，能把「handler 存在」与「selector 不存在」分开。之前对 `IOSurfaceRoot` 做过 16/64/256 字节的尝试全部 `BadArgument`，但这只试了少数几个 selector，没做全表系统扫描。
2. **按 selector 的 `scalarIn/structIn` 期望值构造最小合法参数**（从 census 的 `scalarIn`/`structIn` 列读），这样 `BadArgument` → `Success`/其它码 的翻转就是 handler 存在的**正面证据**。

---

## 8. 复现

```bash
cd harness/selmap && ./run.sh          # 签名 + 安装 + 推送 tmp/selmap.json + 启动 + 回收
python3 harness/selmap/gen_report.py   # 重新生成本文件
```

工具在 `harness/selmap/main.m`：

- 配置 `tmp/selmap.json`：`[{class, type, sel_max, passes}]`
- **断点续跑**：按 `class|type|pass|sel` 去重，重跑只补未测项
- **单条超时**：每条 selector 之间 semaphore 握手，超时 0.8s 即放弃该 conn、从下一条用**新 conn** 继续（`AGX` sel 55 的挂起就是这样被绕过的）
- **逐条落盘**：每条 selector 一行 NDJSON 并 `fflush`，任何时刻崩溃前面的结果都在
- 全程单次等待 ≤ 16s，低于 35s 上限
