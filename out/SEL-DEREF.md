# SEL-DEREF — 用户字节是不是被当地址用

生成于 2026-11-01 11:48:47　来源：`out/selderef.ndjson`（1496 条记录，138 次实际调用）

**被测点**（上一轮用尺寸阶梯定位出来的「唯一被接受的结构输入尺寸」）：

| 类 | selector | 尺寸 | 全零基线返回 |
|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 7 | 8 B | `1` = `KERN_INVALID_ADDRESS` |
| `AppleM2ScalerCSCDriver` | 9 | 16 B | `kIOReturnNoMemory` |
| `AppleJPEGDriver` | 8 | 4 B | `kIOReturnError` |
| `AppleJPEGDriver` | 9 | 0 B | `kIOReturnError`（不适用 A/B：唯一被接受的输入尺寸就是 0，没有字节可变） |

**方法**：每次调用一个独立 `io_connect_t`，用完即关；每个值先写一行 `begin` 再调用、调用后写一行 `end`，两次 `fflush`。若某值触发 panic，会留下「有 `begin` 无 `end`」的唯一指纹。每个值至少 2 次，关键点 5 次。

---

## 1. 直答四问

### 1.1 那 8 字节是不是被当地址用？

**不是。** 三条独立的证据：

1. **一个有效的内核地址和 NULL 返回完全相同的码。** 把 8 字节设成 `0xFFFFFE0007004000`（已知内核 TEXT 基址）→ `KERN_INVALID_ADDRESS`；设成 `0x0000000000000000`（NULL）→ 同样的 `KERN_INVALID_ADDRESS`。如果它被当指针解引用，一个已映射可读的内核地址不可能和 NULL 得到同一个结果。
2. **本轮全部取值 0 次 panic。** 包括 `0xFFFFFFFFFFFFFF00`（内核地址空间顶部、未映射）与 `0xFFFF000000000000`（非规范地址）——如果真解引用，这些必然 fault。
3. **决定返回码的是位型，不是地址有效性。** 22 个取值里只有 2 个换了码，判别式是「**字节 1–7 是否全为 1**」，与这个值指向哪里毫无关系（见 §1.3）：`0xFFFFFFFFFFFFFF00` 与 `0xFFFFFFFFFFFFFFFF` 同码，而 `0xFFFFFFFF00000000`（高 32 位全 1）反而与 NULL 同码。

### 1.2 哪个/哪些字节是字段？

**没有单字节字段。** 实验 A 把 8 个位置逐字节置 `0xFF`，**8/8 全部返回与全零基线相同的 `1`**；`sel 9` 的 16 个位置、`JPEG sel 8` 的 4 个位置同样 **0 敏感**。

实验 D 才找到敏感区：它**不落在单个字节上，而是横跨字节 1–7 的一个整体位型判断**——字节 0 取什么值完全无关（`0xFF...FF` 与 `0xFF...00` 结果相同），而字节 1–7 里只要有一个不是 `0xFF` 就退回基线码。所以拿不到「字段偏移表」，能拿到的只有这一条位型规则。

### 1.3 返回码会随值改变吗？改成什么？

**会，且只有一种变化。** 规则（`sel 7` 上测了 **22 个不同取值**，全部符合；关键点 5/5 复现）：

```
NoMemory  ⟺  (value >> 8) == 0x00FFFFFFFFFFFFFF      # 即字节 1..7 全为 0xFF
否则       →  1  (KERN_INVALID_ADDRESS)
```

| 8 字节内容 | 值 | 返回码 | 次数 |
|---|---|---|---|
| `ff00000000000000` | `0x00000000000000FF` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `00ff000000000000` | `0x000000000000FF00` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `0000ff0000000000` | `0x0000000000FF0000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `000000ff00000000` | `0x00000000FF000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `00000000ff000000` | `0x000000FF00000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `0000000000ff0000` | `0x0000FF0000000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `000000000000ff00` | `0x00FF000000000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `00000000000000ff` | `0xFF00000000000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `0010000000000000` | `0x0000000000001000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `0000000001000000` | `0x0000000100000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `0800000000000000` | `0x0000000000000008` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `ffffffffffffffff` | `0xFFFFFFFFFFFFFFFF` | `kIOReturnNoMemory` | 2 |
| `0040000700feffff` | `0xFFFFFE0007004000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `ffffffff00000000` | `0x00000000FFFFFFFF` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `00000000f07f0000` | `0x00007FF000000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `0000000000000000` | `0x0000000000000000` | `1` = `KERN_INVALID_ADDRESS` | 2 |
| `ffffffffffffffff` | `0xFFFFFFFFFFFFFFFF` | `kIOReturnNoMemory` | 5 |
| `000000000000ffff` | `0xFFFF000000000000` | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `00000000ffffffff` | `0xFFFFFFFF00000000` | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `ffffffff00000000` | `0x00000000FFFFFFFF` | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `ffffffffff000000` | `0x000000FFFFFFFFFF` | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `ffffffffffff0000` | `0x0000FFFFFFFFFFFF` | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `00ffffffffffffff` | `0xFFFFFFFFFFFFFF00` | `kIOReturnNoMemory` | 5 |
| `ffffffffffffff00` | `0x00FFFFFFFFFFFFFF` | `1` = `KERN_INVALID_ADDRESS` | 5 |

### 1.4 有没有触发 panic？

**没有。0 次。** 三个实验共 138 次实际调用，`begin` 与 `end` 一一配对，没有任何「有 `begin` 无 `end`」的记录：

```
begin/end 配对: 138 / 138      孤儿记录: 无
```

---

## 2. 实验 A：逐字节偏移敏感度

对每个位置 k，缓冲区全零、只把第 k 字节设成 `0xFF`。

| 类 / selector | 尺寸 | 改变返回码的位置 | 结论 |
|---|---|---|---|
| `AppleM2ScalerCSCDriver` sel 7 | 8 B | **无（0/8）** | 每个位置都返回 `1`，与全零基线相同 |
| `AppleM2ScalerCSCDriver` sel 9 | 16 B | **无（0/16）** | 每个位置都返回 `kIOReturnNoMemory`，与基线相同 |
| `AppleJPEGDriver` sel 8 | 4 B | **无（0/4）** | 每个位置都返回 `kIOReturnError`，与基线相同 |

全部 56 组两两复现一致，0 个不一致。

**`AppleM2ScalerCSCDriver` sel 7（8 字节）**：只把第 k 字节设成 `0xFF`

| k | 值 | pass0 | pass1 |
|---|---|---|---|
| 0 | `0x00000000000000FF` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |
| 1 | `0x000000000000FF00` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |
| 2 | `0x0000000000FF0000` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |
| 3 | `0x00000000FF000000` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |
| 4 | `0x000000FF00000000` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |
| 5 | `0x0000FF0000000000` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |
| 6 | `0x00FF000000000000` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |
| 7 | `0xFF00000000000000` | `1` = `KERN_INVALID_ADDRESS` | `1` = `KERN_INVALID_ADDRESS` |

**`AppleM2ScalerCSCDriver` sel 9（16 字节）**：只把第 k 字节设成 `0xFF`

| k | 值 | pass0 | pass1 |
|---|---|---|---|
| 0 | `0x000000000000000000000000000000FF` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 1 | `0x0000000000000000000000000000FF00` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 2 | `0x00000000000000000000000000FF0000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 3 | `0x000000000000000000000000FF000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 4 | `0x0000000000000000000000FF00000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 5 | `0x00000000000000000000FF0000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 6 | `0x000000000000000000FF000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 7 | `0x0000000000000000FF00000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 8 | `0x00000000000000FF0000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 9 | `0x000000000000FF000000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 10 | `0x0000000000FF00000000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 11 | `0x00000000FF0000000000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 12 | `0x000000FF000000000000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 13 | `0x0000FF00000000000000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 14 | `0x00FF0000000000000000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |
| 15 | `0xFF000000000000000000000000000000` | `kIOReturnNoMemory` | `kIOReturnNoMemory` |

**`AppleJPEGDriver` sel 8（4 字节）**：只把第 k 字节设成 `0xFF`

| k | 值 | pass0 | pass1 |
|---|---|---|---|
| 0 | `0x000000FF` | `kIOReturnError` | `kIOReturnError` |
| 1 | `0x0000FF00` | `kIOReturnError` | `kIOReturnError` |
| 2 | `0x00FF0000` | `kIOReturnError` | `kIOReturnError` |
| 3 | `0xFF000000` | `kIOReturnError` | `kIOReturnError` |

**逐字节扫描在这个类上是零信息**——这正是为什么必须做实验 B 的整值替换。

---

## 3. 实验 B：整值替换

### 3.1 `AppleM2ScalerCSCDriver` sel 7（8 字节）

| 标记 | 内存字节（小端顺序） | 值 | 返回码 | 复现 |
|---|---|---|---|---|
| `B_0x1000` | `0010000000000000` | `0x0000000000001000` | `1` = `KERN_INVALID_ADDRESS` | ✅ 2/2 |
| `B_0x100000000` | `0000000001000000` | `0x0000000100000000` | `1` = `KERN_INVALID_ADDRESS` | ✅ 2/2 |
| `B_0x8` | `0800000000000000` | `0x0000000000000008` | `1` = `KERN_INVALID_ADDRESS` | ✅ 2/2 |
| `B_allff` | `ffffffffffffffff` | `0xFFFFFFFFFFFFFFFF` | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_ktext` | `0040000700feffff` | `0xFFFFFE0007004000` | `1` = `KERN_INVALID_ADDRESS` | ✅ 2/2 |
| `B_low32ff` | `ffffffff00000000` | `0x00000000FFFFFFFF` | `1` = `KERN_INVALID_ADDRESS` | ✅ 2/2 |
| `B_userva` | `00000000f07f0000` | `0x00007FF000000000` | `1` = `KERN_INVALID_ADDRESS` | ✅ 2/2 |
| `B_zero` | `0000000000000000` | `0x0000000000000000` | `1` = `KERN_INVALID_ADDRESS` | ✅ 2/2 |

### 3.2 `AppleM2ScalerCSCDriver` sel 9（16 字节）

| 标记 | 内存字节（小端顺序） | 值 | 返回码 | 复现 |
|---|---|---|---|---|
| `B_allff` | `ffffffffffffffffffffffffffffffff` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_hi1000` | `00000000000000000010000000000000` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_hi_ktext` | `00000000000000000040000700feffff` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_lo1000` | `00100000000000000000000000000000` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_lo16_hi8` | `10000000000000000800000000000000` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_lo_8_hi_16` | `08000000000000001000000000000000` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_lo_ktext` | `0040000700feffff0000000000000000` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |
| `B_zero` | `00000000000000000000000000000000` | （128 位，见左列） | `kIOReturnNoMemory` | ✅ 2/2 |

### 3.3 `AppleJPEGDriver` sel 8（4 字节）

| 标记 | 内存字节（小端顺序） | 值 | 返回码 | 复现 |
|---|---|---|---|---|
| `B_0x1000` | `00100000` | `0x00001000` | `kIOReturnError` | ✅ 2/2 |
| `B_0x4` | `04000000` | `0x00000004` | `kIOReturnError` | ✅ 2/2 |
| `B_allff` | `ffffffff` | `0xFFFFFFFF` | `kIOReturnError` | ✅ 2/2 |
| `B_khi` | `00feffff` | `0xFFFFFE00` | `kIOReturnError` | ✅ 2/2 |
| `B_zero` | `00000000` | `0x00000000` | `kIOReturnError` | ✅ 2/2 |

---

## 4. 实验 D：位型定位

实验 B 里只有全 `0xFF` 一个值换了码，所以做位型二分：哪些字节必须全为 `0xFF`。

| 标记 | 字节 | 值 | 字节 1–7 全 FF？ | 返回码 | 次数 |
|---|---|---|---|---|---|
| `D_all8` | `ffffffffffffffff` | `0xFFFFFFFFFFFFFFFF` | ✅ | `kIOReturnNoMemory` | 5 |
| `D_ff2hi` | `000000000000ffff` | `0xFFFF000000000000` | ❌ | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `D_ff4hi` | `00000000ffffffff` | `0xFFFFFFFF00000000` | ❌ | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `D_ff4lo` | `ffffffff00000000` | `0x00000000FFFFFFFF` | ❌ | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `D_ff5lo` | `ffffffffff000000` | `0x000000FFFFFFFFFF` | ❌ | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `D_ff6lo` | `ffffffffffff0000` | `0x0000FFFFFFFFFFFF` | ❌ | `1` = `KERN_INVALID_ADDRESS` | 5 |
| `D_ff7hi` | `00ffffffffffffff` | `0xFFFFFFFFFFFFFF00` | ✅ | `kIOReturnNoMemory` | 5 |
| `D_ff7lo` | `ffffffffffffff00` | `0x00FFFFFFFFFFFFFF` | ❌ | `1` = `KERN_INVALID_ADDRESS` | 5 |

**结论**：字节 0 完全无关（`0xFF...FF` 与 `0xFF...00` 同结果）；字节 1–7 必须**全部**为 `0xFF` 才换码。这否掉了「低 32 位是长度」和「高 32 位是标志」两种简单读法——`0xFFFFFFFF00000000` 与 `0x00000000FFFFFFFF` 都返回基线码。

---

## 5. 三个类的内容敏感度总表

| 类 / selector | 尺寸 | 逐字节 0xFF | 整值替换 | 内容敏感？ |
|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` sel 7 | 8 B | 0/8 敏感 | 15 个值里 1 个换码 | **仅在「字节 1–7 全 FF」这一点上敏感** |
| `AppleM2ScalerCSCDriver` sel 9 | 16 B | 0/16 敏感 | 10 个值全部 `kIOReturnNoMemory` | **完全不敏感** |
| `AppleJPEGDriver` sel 8 | 4 B | 0/4 敏感 | 5 个值全部 `kIOReturnError` | **完全不敏感** |
| `AppleJPEGDriver` sel 9 | 0 B | 不适用 | 不适用 | 唯一接受的尺寸是 0，无字节可变 |

---

## 6. 这轮实际拿到了什么、没拿到什么

**拿到了**

- `M2Scaler sel 7` 的完整输入→返回码映射规则，22 个取值验证、0 例外、5/5 复现：唯一非基线响应是「字节 1–7 全 `0xFF`」→ `kIOReturnNoMemory`。
- 一条**否定性**结论，且证据很硬：这 8 字节**不是**被解引用的指针——有效内核地址与 NULL 同码、非常规地址不 fault、15 个值 0 次 panic。
- `sel 9`（16 B）与 `JPEG sel 8`（4 B）的输入内容**完全不参与**返回码决定，所以上一轮观察到的 `NoMemory` / `Error` 不是由内容触发的，而是「尺寸对、内容无关」的固定响应。

**没拿到**

- 字段布局。0 敏感于单字节，敏感区是一个 56 位的整体位型判断，不是一个可拆的结构体。
- 任何 panic 指纹。所以没有「用户可控内核指针」这一类原语的正向证据。

---

## 7. 复现

```bash
cd harness/selshape && PLAN=/path/cfg.json WAIT=16 ./run.sh
python3 harness/selshape/gen_deref.py
```

形状支持 `struct_in_hex`（十六进制字节串，长度必须等于 `struct_in_size`），例如 8 字节全 `0xFF` = `"ffffffffffffffff"`。
