# 动态模糊测试：可达面扫描（第一轮）

> README（10 行）
> 1. 本文是 `harness/fuzz2/` 第一轮真机结果的分析，**由指挥官亲自复核**（原负责子代理被设备争用中断，数据完好）。
> 2. 规模：**14,086 次完成调用**，18 个类，**0 次 panic**，begin/end 配对 14,086/14,086，孤儿记录 0。
> 3. 结论：**没有找到未解释的内容敏感路径**。唯一强信号已追到源码级语义，是正确实现。
> 4. 但方法被验证有效：fuzz → 定位 handler → 反汇编 → 完整解释，闭环走通了。
> 5. 返回码分布：BadArgument 12,101 / KERN_SUCCESS 1,288 / NotPrivileged 250 / Unsupported 202。
> 6. 内容敏感组 21 个，**全部已解释**（见 §3）。
> 7. 下一轮应换方向：不是扩大变异，而是先补「handler 语义可解释性」这条腿。
> 8. 原始数据 `out/fuzz2.ndjson`（5.9 MB / 28,172 行）。**注意**：此文件已被 `compact.py` 按 key 去重为
>    **14,080 行 / 4.06 MB** 的派生版（保留全部唯一 key，四类信号一条不少）。
>    **原件已回捞**：`out/fuzz2.raw.ndjson` = 28,320 行（begin 14,160 / end 14,160，零孤儿），
>    `out/fuzz2.ndjson` 已恢复为该原件，去重派生版另存 `out/fuzz2.dedup.ndjson`。
> 9. 工具 `harness/fuzz2/`（main.m / gen_plan.py / mkplans.py / analyze.py）。
> 10. 判据纪律见 `out/TOOLING-PITFALLS.md` §4。

---

## 1. 覆盖

| 类 | 调用数 |
|---|---|
| `IOSurfaceRoot` | 5,536 |
| `AppleKeyStore` | 1,018 |
| `IOHIDEventService` / `IOHIDEventDriver` / `AppleSPUHIDDriver` / `AppleSPUCT726` | 各 592 |
| `AppleEmbeddedNVMeTemperatureSensor` / `AppleM68Buttons` / `AHSTemperatureReporter` / `AppleSphinxProxHIDEventDriver` / `AppleARMPMUPowerSensor` / `AppleARMPMUTempSensor` / `EXBrightKext` | 各 592 |
| `AGXAcceleratorG18P` | 576 |
| `AppleM2ScalerCSCDriver` | 298 |
| `H1xANELoadBalancer` | 96 |
| `AppleCLCD2` | 32 |
| `AppleJPEGDriver` | 18 |

**0 panic。** 这是硬结论，靠 begin/end 双行配对得出（有 begin 无 end = panic 指纹），不是「大概没炸」。

返回码分布：

```
kIOReturnBadArgument    12,101
KERN_SUCCESS             1,288
kIOReturnNotPrivileged     250
kIOReturnUnsupported       202
0x00000001                  79   (KERN_INVALID_ADDRESS)
kIOReturnNoMemory           64
kIOReturnNotPermitted       42
kIOReturnNotFound           28
kIOReturnError              18
kIOReturnUnsupportedMode    14
```

---

## 2. 最强的内容敏感信号：`IOSurfaceRoot` selector 19

在 **12 种尺寸**（1/2/4/8/12/16/20/24/32/48/64/96/128/192/256）上内容敏感，且 **pass 0 与 pass 1 逐条一致**（可复现）。

### 反汇编（`0xfffffe000a349934`，census 第 19 行，`structIn = 0xFFFFFFFF` 变长）

```
mov  w0,#0x2c2 ; movk w0,#0xe000   ; 默认 0xE00002C2 BadArgument
ldr  w9,[x2,#0x38]                 ; w9 = args->structureInputSize
cmp  w9,#0x1ff
b.ls ok                            ; 尺寸 > 511 -> BadArgument
ldr  x8,[x2,#0x40]                 ; args->structureInputDescriptor
cbz  x8,ok2                        ; descriptor != NULL -> 0xE00002BD NoMemory
ldr  x8,[x2,#0x30]                 ; args->structureInput
cmp  x8,#0 ; ccmp w9,#0,#4,ne      ; 指针为 0 或尺寸为 0 -> BadArgument
sub  w9,w9,#1
ldrb w9,[x8,w9,uxtw]               ; 读**最后一个字节**
cbnz w9,fail                       ; 必须是 NUL
adrp x0,#0xfffffe0007a1b000 ; add x0,x0,#0x973
bl   0xfffffe000a35a4cc
mov  w0,#0                           ; KERN_SUCCESS
```

### 那个字符串常量是 `"%.512s"`

`0xfffffe0007a1b973` 读出 `%.512s\0ensure_memory_pool_memory\0flush_memory_po...`

**结论**：selector 19 等价于

```c
if (size > 511) return kIOReturnBadArgument;
if (descriptor) return kIOReturnNoMemory;
if (!ptr || !size) return kIOReturnBadArgument;
if (ptr[size-1] != 0) return kIOReturnBadArgument;
IOLog("%.512s", (const char *)ptr);     /* 精度限定的安全写法 */
return kIOReturnSuccess;
```

**它把用户字符串打进内核日志，用 `%.512s` 而不是 `%s`——格式串安全。**

### 这条解释对上了每一处观测

| 观测 | 解释 |
|---|---|
| `zero` → SUCCESS | 末字节 0 ✓ |
| `7f` / `80` / `ff` → BadArgument | 末字节非 0 ✓ |
| `sizeff` → BadArgument | 强制末字节 `0xFF` ✓ |
| `L0eq` / `L0max` / `L0m1` / `L0p1` → SUCCESS | 只改首字段，末字节仍 0 ✓ |
| **`L12max` 在 size=16 → BadArgument** | 字节 12–15 被写成 `FFFFFFFF`，末字节 `0xFF` ✓ |
| `L12eq` 在 size=16 → SUCCESS | 末字节为 0 ✓ |
| `-`（无变异）在同一 (size,pass) 出现两种返回码 | 用的是累加缓冲，末字节内容随轮次变化 ✓ |

**14 处观测全部由同一份反汇编解释，无一处残留。** 所以这是**完整阴性**，不是「大概没问题」。

### 2.1 另有一组 48 点的字节级定位，与反汇编逐条对上

`plans/batch10.json` 在 size=16 上做了「**只置位一个字节、其余全零**」（0..15 偏移 × `0x01`/`0x80`/`0xFF`）
与「**只清零一个字节、其余全 `0xFF`**」两种模式，各 2 次 pass：

```
只置位： off 0..14 → KERN_SUCCESS      off 15 → kIOReturnBadArgument
只清零： off 0..14 → kIOReturnBadArgument   off 15 → KERN_SUCCESS
```

size=1 的单字节 16 值全扫把规则钉死：`0x00` → `KERN_SUCCESS`，`0x01/0x02/0x03/0x07/0x08/0x0F/0x10/0x20/0x3F/0x40/0x7E/0x7F/0x80/0xC0/0xFF` → `kIOReturnBadArgument`。
size=8 的 u64 阶梯同理（末字节=第 7 字节为 0 才成功）。

⇒ **只有最后一个字节被读取，其余字节对返回值完全无影响**。这与 §2 反汇编的
`sub w9,w9,#1 ; ldrb w9,[x8,w9,uxtw] ; cbnz w9,fail` **逐条一致**，是独立的第二条证据链
（一条来自反汇编，一条来自 48+16+14 组黑盒观测）。

---

## 3. 其余内容敏感组：全部已解释

（按 `(class,type,selector,size,outcap)` 精确计，内容敏感的 cell 共 **16 个**：
`IOSurfaceRoot` sel 19 的 15 个尺寸 + `M2Scaler` sel 7 的 1 个；此外 `M2Scaler` sel 11 是「尺寸敏感而非内容敏感」，单列。）

| 组 | 现象 | 解释 |
|---|---|---|
| `M2Scaler` sel 7, size 8 | `ff`/`p64neg` → NoMemory；其余 → `0x00000001` | **见 §3.1 —— 原来这条「字节 1–7 全 0xFF」的位型解释被 hex 二分数据推翻了**，真实判据是 64 位**有符号区间** |
| `M2Scaler` sel 11, size 0 | scalar 0 → SUCCESS；scalar 1..12 → BadArgument | 零参数 getter，带标量就拒 |
| `M2Scaler` sel 11, size 16/32/64 | 任意内容 → SUCCESS | 尺寸驱动的 getter，不看内容 |
| `IOSurfaceRoot` sel 19 其余尺寸 | 见 §2 | 同一份反汇编 |

**没有一个组指向未解释的用户字节消费路径。**

### 3.1 修正：`M2Scaler` sel 7 不是「字节 1–7 全 0xFF」，是**有符号区间 `[-17000, -1]`**

`plans/batch6.json` + `plans/batch7.json` 用 `struct_in_hex` 打了 **55 个 8 字节内容点**（`-2^k`、`-1`、`0`、正数、
`INT64_MIN`、`0xFFFFFFFF7FFFFFFF`、`0xFFFFFFFF00000001` 等），实测：

| 8 字节内容（小端，有符号） | 返回码 |
|---|---|
| `-1` `0xFFFFFFFFFFFFFFFF` | `kIOReturnNoMemory` |
| `-2` `0xFFFFFFFFFFFFFFFE` | `kIOReturnNoMemory` |
| `-16` `0xFFFFFFFFFFFFFFF0` | `kIOReturnNoMemory` |
| `-256` `0xFFFFFFFFFFFFFF00` | `kIOReturnNoMemory` |
| `-4096` `0xFFFFFFFFFFFFF000` | `kIOReturnNoMemory` |
| `-8192` `0xFFFFFFFFFFFFE000` | `kIOReturnNoMemory` |
| `-16384` `0xFFFFFFFFFFFFC000` | `kIOReturnNoMemory` |
| `-16385` `0xFFFFFFFFFFFFBFFF` | `kIOReturnNoMemory` |
| `-16386` `0xFFFFFFFFFFFFBFFE` | `kIOReturnNoMemory` |
| **`-17000`** `0xFFFFFFFFFFFFBD98` | **`kIOReturnNoMemory`** ← 实测窗口下界 |
| **`-18432`** `0xFFFFFFFFFFFFB800` | **`0x00000001`** ← 已翻出 |
| `-20480` `-22528` `-26624` `-30720` `-32767` `-32768` `-40000` `-65536` | `0x00000001` |
| `-2147483649` `0xFFFFFFFF7FFFFFFF` | `0x00000001` |
| `-4294967296` `0xFFFFFFFF00000000` | `0x00000001` |
| `INT64_MIN` `0x8000000000000000` | `0x00000001` |
| `0` / `1` / `8` / `15` / `16` / `4096` / `0x7FFFFFFF` / `0xFFFFFFFF` / `0x100000000` / `INT64_MAX` | `0x00000001` |

**反例**：`-16384` = `0xFFFFFFFFFFFFC000`，字节序列是 `00 C0 FF FF FF FF FF FF` ——
**字节 1 是 `0xC0` 不是 `0xFF`**，却返回 `NoMemory`。「字节 1–7 全 0xFF」无法解释它。

正确表述：**符号位与幅值都被读取，`NoMemory` 窗口是 `v ∈ [-17000, -1]`，阈值落在 `(-18432, -17000]` 区间内**
（`-0x4400` = `-17408` 是这个区间里唯一的 `2^k` 型常数候选，但**未验证**，不写成结论）。
`0x00000001` = `KERN_INVALID_ADDRESS`，与 `NoMemory` 是两条不同返回路径

⇒ 这是一段「**内容驱动、有符号、未做无符号归一**」的入参算术，不是位型判断。
（`NULL`/用户地址/内核地址/非规范地址确实返回同一个码这一点仍成立 —— 所以**不是指针解引用**。这个结论没变。）

形状约束同样实测：`structureInputSize` 必须**恰好 8**（1/2/3/4/5/6/7/9/10/12/16/24/32 全 `BadArgument`，与内容无关）；
`scalarInput` 个数 0..8 任何值全 `BadArgument`；`outcap ∈ {1,8,4096}` 任何内容全 `BadArgument`。

### 3.2 核对：本数据集**没有**状态依赖，那条「累加缓冲」是行混淆

原文（§2 表格最后一行）把「`-` 无变异在同一 `(size,pass)` 出现两种返回码」解释成「用的是累加缓冲」。
复核 87 个内容变异 cell 的 pass 0 / pass 1：**逐条一致，不一致个数 = 0**。

所谓「两种返回码」来自把不同 `struct_in_hex` 的行当成同一行看：size=1 上
`hex=None`（全零缓冲）与 `hex=00` 都是 `KERN_SUCCESS`，`hex=01..ff` 都是 `BadArgument` ——
**是 17 个不同的用例，不是同一个用例的两个结果**。
反汇编里的 `ptr[size-1] != 0 → fail` 解释全部 17 条，无残留；只是「累加缓冲」这个中间说法不成立。

---

## 4. 方法学结论

### 有效的部分
`fuzz → 找内容敏感 → 定位 handler → 反汇编 → 完整解释` 这条闭环走通了，而且**产出是可信的阴性**（14 处观测、1 份反汇编、100% 覆盖）。

### 无效的部分
**盲目扩大变异空间收益很低。** 12,101 次 BadArgument 说明绝大多数组合在参数校验层就被拒。真正有信息量的只有「内容改变返回码」这一类，而本轮只出现 4 个不同的 selector。

### 下一轮该改什么
1. **先补「handler 语义可解释性」**：与其跑 10 万个用例，不如先把可达类的 handler 反汇编批量拉出来，人工筛「有指针解引用 / 有算术索引 / 有循环」的，再针对性变异。
2. **`checkStructureInputSize` 是硬闸**：census 里 `structIn` 为具体值的 selector，内核在派发前就强制这个尺寸，变异必须精确卡在这个尺寸上。
3. **变长入口（`structIn = 0xFFFFFFFF`）才是变异该集中的地方**——本轮唯一有真实解析行为的就是这种。

---

## 5. 待办

- 原负责子代理因**设备争用**中断（与 IOSurface 竞态子代理共用同一台设备）
- 重新开跑前必须做**设备串行化**：一次只允许一个子代理安装/启动
- 优先目标改为：`structIn = 0xFFFFFFFF` 的变长入口 + handler 反汇编批量筛

### 5.1 batch11 已跑完（从设备原件回捞，74 条全部成对），**证实反汇编解读**

| 维度 | 内容 | 结果 |
|---|---|---|
| 输出容量 | `size` 16/256 × `outcap` ∈ {1,4,8,16,64,256,512,1024,4096} | **全部 `kIOReturnBadArgument`**（18/18）⇒ sel 19 **没有出参路径**，与「只 `IOLog`」一致 |
| 长字符串 | `'A'×(size-1) + '\0'`，size = 2/4/8/16/32/64/128/255/256/300/400/500/510/511 | **全部 `KERN_SUCCESS`**（14/14）⇒ 511 字节任意内容都能过 |
| 末字节非 NUL | `'\0'+'A'×15`（16B）、`'B'×10+'\0'+'C'×53`（64B） | 两者 `BadArgument`（末字节不是 NUL） |
| 尺寸边界 | 510 / 511 / 512 / 513 | `SUCCESS` / `SUCCESS` / `BadArgument` / `BadArgument` ⇒ 上限恰好 511 |

⇒ `IOSurfaceRoot` sel 19 这条线现在是 **115 点内容扫描 + 48 点字节定位 + 74 点 outcap/长串 + 一份反汇编**，
四条证据链互相印证，可归档为**完整阴性**。原留白里「outcap 未测」「511 是闸还是缓冲区未定」两条**已关闭**。

> 附带：panic 取证（`out/panics/FORENSICS.md`）证明 4 次内核 panic 的崩溃任务分别是
> `avconferenced` 与 `kernel_task`（GPU workloop），**不是本探针**；本探针 ndjson 零孤儿（14,160/14,160）。

### 5.1b 待跑

| plan | 内容 | 为什么值得跑 |
|---|---|---|
| `harness/fuzz2/plans/batch11.json` | ~~sel 19 outcap / 长串~~ | **已跑完，见 §5.1** |
| （待生成） | `M2Scaler` sel 7 阈值收敛：`-17000 … -18432` 之间二分（`-17408` `-17500` `-17664` `-18000`） | 把 §3.1 的区间收成一个数 |
| （待生成） | **type 轴 256 路**：`AppleKeyStore` / `AppleCLCD2` / `AppleJPEGDriver` / `AppleM2ScalerCSCDriver` 的 `newUserClient` **不看 type**（0..255 全开） | 完全不同的一维，本轮只测了各一个 type；256 个 type 可能是不同子类、不同 dispatch 表 |

### 5.2 已确认的硬负结果（不要重复投入）

- 11 个 HID/NVMe/传感器类（`IOHIDEventService` / `IOHIDEventDriver` / `AppleSPUHIDDriver` / `AppleSPUCT726` /
  `AppleEmbeddedNVMeTemperatureSensor` / `AppleM68Buttons` / `AHSTemperatureReporter` /
  `AppleSphinxProxHIDEventDriver` / `AppleARMPMUPowerSensor` / `AppleARMPMUTempSensor` / `EXBrightKext`，均 type 2）：
  每类 **592 条**（selector 0..255 × 尺寸 {1,2,4,8,16,32,64,256} 于 0..47 区间 + selector 48..255 × 尺寸 16），
  **592/592 全 `kIOReturnBadArgument`**，哨兵 4095 也 `BadArgument` ⇒ 内核侧没有可用 dispatch 表，不是「参数没猜对」。
- `AGXAcceleratorG18P` type 33：64 selector × 5 尺寸 = 320 条全 `BadArgument`。
- `H1xANELoadBalancer` type 1 / 4：各 48 条全 `BadArgument`（只有 `sel 1 @ size 0` = `KERN_SUCCESS`）。
- `AppleJPEGDriver` sel 8 @ 4B：18 条全 `kIOReturnError`（驱动未 ready，之前的尺寸翻转是假信号）。
- `AppleM2ScalerCSCDriver` sel 9 @ 16B：10 种内容全 `kIOReturnNoMemory`（固定响应）。
- `AppleCLCD2` sel 26 全 `BadArgument` / sel 100 全 `NotPrivileged`（权限检查在参数校验之前）。
- `AppleKeyStore`：10 个抽样 selector × 6 内容 × size 64 全由 selector 决定，内容无效；
  **size 0 与 size 16 的 257 个 selector 返回码分布完全相同** ⇒ 尺寸维对该层无效。

### 5.3 「优先新面」清单的实测裁决（任务书指定的 8 个面，6 个在机制上已死）

| 指定面 | 实测 |
|---|---|
| `IOHIDFamily` | 可达 3 个类 → **无 externalMethod 面**（§5.2） |
| `IONVMeFamily` | 只有 `AppleEmbeddedNVMeTemperatureSensor` type 2 可达 → 无面；`AppleEmbeddedNVMeDiagnostics` / `NVMeNVRAM` / `IOEmbeddedNVMeBlockDevice` 256 type 全 `Unsupported` |
| `IOThunderboltFamily` | **类不存在**（`IOThunderboltReporter` / `Port` / `Switch` → `no_service`） |
| `IOAccessoryManager` | 类存在，41 个 type 全 `kIOReturnNotPermitted` |
| `IOAVFamily` | **类不存在**（`IOAVService` / `IOAVController`） |
| `AppleH16ANEInterface` | **类不存在**（`AppleH16CamIn` / `AppleH16PhotonDetector` 全 `Unsupported`） |
| `AppleSPU` | `AppleSPU` / `AppleSPUAppDriver` / `AppleSPUFastpathDriver` / `AppleSPUDCPDriver` 全 `Unsupported`；仅 `AppleSPUHIDDriver` / `AppleSPUCT726` t2 可开 → 无面 |
| `AppleBasebandPCI` | 全 `Unsupported`；`AppleBasebandPCIMAVControl` 256 type 全 `BadArgument` |

⇒ 真正的新面只有 `IOSurfaceRoot` sel 19（不在优先清单里，是真机扫出来的），而它已被反汇编解释干净。
**下一轮的价值不在扩大变异，而在 §5.1 的 type 轴 + `structIn=0xFFFFFFFF` 变长入口的反汇编批筛。**

### 5.4 type 是掩码，不是序数（省掉大量重测）

41 个 type（`0..15` ∪ `0x10000..0x1000f` ∪ `0x20000..0x20003` ∪ `0x8000`/`0x8001`/`0x10000000`/`0x40000000`/`0xFFFFFFFF`）
× 39 个类 = 1,558 次 `IOServiceOpen`：

- `AGXAcceleratorG18P` 接受 **1 / 33 / 65537(0x10001) / 131073(0x20001)**；
  后两者的 257 个 selector 返回值与 type 1 **逐条一致**（含 sel 22 内部 `Unsupported`、sel 55 挂死）⇒ 同一 user client，**高位被掩掉**。
- 拒 `0x10000` / `0x20000` / `0x20002` / `0x8000` / `0x10000000` ⇒ 门控看**低字节**。
- 新发现可开服务：**`IOHIDEventService` type 2**（`reach.json` 的 0..255 扫描里没有它）。

---

## 6. 工具学坑（本轮新增，已复现）

### 6.1 ★ 串行派发队列被一次挂死永久占住 ⇒ 之后**所有**调用假超时

第一版把每次 `IOConnectCallMethod` 都派发到**同一个** `DISPATCH_QUEUE_SERIAL`。
`AGXAcceleratorG18P` sel 55 挂死后那条 block 永不返回，队列被永久占住：
**后续 11 个类、几百条用例全部记成 `TIMEOUT`**，看起来像设备整体挂了，实际是探针自锁。

修复：超时后**丢弃并新建队列**（`gQ = dispatch_queue_create(...)`），弃掉那一条和它的线程。
同一批修复前后：`70 条 / 13.1s`（几乎全是超时）→ **`4,459 条 / 0.2s`**。

### 6.2 用例 key 必须包含内容，否则所有变体塌成一条

第一版 `keyOf` 只有 `class|type|sel|form|size|mut|scv|outcap|pass`，缺 `struct_in_hex`：
18 个 hex 变体在 `(class,type,sel,size,mut='-',pass=0)` 上**共用一个 key**，
只有第一个跑到，其余被判「已完成」跳过 —— 表面「跑了 192 条」，实际每个 hex 只落 1 次。
修复后必须全部重跑；第一轮的 key 因此作废，存档为 `out/fuzz2.round1.ndjson`（9,702 条）。

### 6.3 `IOConnectMethodScalarIScalarO` 在 arm64 上不存在

`IOKitLib.h` 把它整段放在 `#if !defined(__LP64__)`（第 1474 行起）。arm64 上写出这行直接
`call to undeclared function` 编不过。现代设备只有 `IOConnectCallMethod` / `CallScalarMethod` /
`CallStructMethod` / `CallAsyncMethod`。

### 6.4 两个 subagent 共用同一 bundle ⇒ 容器 ID 每次变

同一设备、同一 `com.example.ios27poc`。另一条战线每次重装都会：
换掉 `Data/Application/<UUID>`（本轮见过 `72030EBA` / `58A51C4D` / `713D39A6`）、清掉我们的 `tmp/fuzz2.*`；
而 `devicectl process launch` 仍报成功，**起来的其实是对方的 App**（我们的 `fuzz2.log` 不刷新）。

判据：**launch 之后先看 `fuzz2.log` 有没有新内容**，没有就是被换掉了。
对策：每次启动前 `BUILD=1` 重装自己的包；把上一批结果 push 回设备做断点续跑（`run.sh` 幂等）。

### 6.5 设备会被另一条战线重启 / 掉线

`devicectl` 报 `unable to locate a device matching the requested device identifier (ecid_...)`，
`list devices` 显示 `unavailable`，此时 install / launch / copy 全失败。
不要当自己的 bug 追；轮询 `list devices` 到 `available` 再继续。

---

## 7. 复现

```bash
cd harness/fuzz2
python3 mkplans.py batch10                              # 生成 plans/batch10.json
BUILD=1 PLAN=$PWD/plans/batch10.json WAIT=22 ./run.sh   # 编译 → 签名 → 安装 → 推配置 → 启动 → 回收
RESET=1 BUILD=1 PLAN=... ./run.sh                       # RESET=1：清空设备端 ndjson（key 方案变更后必须）
python3 analyze.py                                      # 四类信号矩阵
python3 compact.py                                      # 按 key 去重（保留 begin-无-end 的 panic 指纹）
```

- `main.m` —— 状态感知内容变异探针：32 种内容形态 + 16 组 scalar 向量 + 输出容量独立维 + `out_hex` 回读
- `mkplans.py` / `plans/batchN.json` —— 每批次具体计划（产物可直接复跑）
- `gen_plan.py` —— 通用计划生成（`smoke` / `map` / `ladder` / `content` / `outcap` / `scalar` / `probe`）
- `analyze.py` —— 只认四类信号：panic 指纹 / 内容敏感 / 翻出兜底码 / 新 `KERN_SUCCESS`
- `compact.py` —— ndjson 去重

批次流水（每批 ≤ 5000 条，逐批落盘）：

| 批 | 内容 | 用例 | 结果 |
|---|---|---|---|
| smoke | 3 个「已知被接受」cell × 32 内容 | 192 | 抓到 `M2Scaler` sel 7 内容敏感 |
| probe | 39 类 × 41 type = 1,558 次 open | 1,558 | AGX type 131073 可开、`IOHIDEventService` 存在 |
| map | 17 个 `(class,type)` × 257 selector | 4,369 | 撞上 AGX sel 55 挂死（§6.1） |
| batch4 | AGX t131073 全 selector + 3 cell 的 hex 深挖 + 11 个 HID 类尺寸阶梯 | 4,554 | HID 全负；抓到 sel 7 的 `NoMemory` 窗口 |
| batch6 | sel 7 的 `-2^k` 边界二分 | 80 | 窗口收敛到 `(-18432, -17000]` |
| batch7 | 边界精化 + 尺寸×内容 + outcap 维 + scalar 维 | 196 | size 必须 == 8、outcap 必须 == 0、scalar 全拒 |
| batch5 | 11 个 HID 类 48..255 + AGX t33 + H1xANE + IOSurfaceRoot 阶梯 | 3,216 | **抓到 `IOSurfaceRoot` sel 19** |
| batch8 | IOSurfaceRoot 0..255 × 17 尺寸 + CLCD2 / KeyStore | 4,915 | sel 19 接受 1..511；KeyStore selector 面首次量 |
| batch9 | sel 19 全尺寸内容变异 + 尺寸边界 + KeyStore 内容 | 1,484 | sel 19 全尺寸内容敏感；KeyStore 全负 |
| batch10 | sel 19 字节级定位（16 偏移 × 3 值 + allbut + size1 全扫） | 188 | **定位到「末字节必须 0」** |
| batch11 | sel 19 的 outcap 维 + 长串 + `out_hex` | 74 | **已跑完**（从设备原件回捞）：outcap 18/18 全拒、511 字节长串 14/14 全过 ⇒ 完整阴性 |

累计 **14,160 条**（本轮，`out/fuzz2.raw.ndjson` 28,320 行 begin+end）+ 9,702 条（第一轮存档）。

---

## 8. 留白（证据不足的地方不填）

- `IOSurfaceRoot` sel 19 在 `size == 0` 的返回码：**仍未直接测**；但反汇编里 `ccmp w9,#0,#4,ne` 表明 size==0 走 `BadArgument`，与观测体系自洽。
- sel 19 的写回行为：**已测**，`outcap` 1..4096 全 `BadArgument` ⇒ 无出参路径（§5.1）。
- sel 19 的 511 上限：反汇编 `cmp w9,#0x1ff` + 实测 510/511 过、512/513 拒，**两边一致，已定案**。
- `M2Scaler` sel 7 的精确阈值：**只收敛到 `(-18432, -17000]`**。
- `AppleKeyStore` 的 93 个 `NotPrivileged` 是否存在可过的权限路径：**未验证**（本包 entitlements 不含 SEP 能力）。
- 256 个 type 轴（KeyStore / CLCD2 / JPEG / M2Scaler）：**完全未测**。
