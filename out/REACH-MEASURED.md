# IOKit 可达面实测 — iPhone 17 Pro Max (iPhone18,2) / iOS 27.0.1 (24A446)

**一句话**：dev-signed app 在真机沙箱内枚举到 **1469** 个 IOService，实测 **85** 个能用 `IOServiceOpen` 打开（**17** 个不同 user client 类）；这 17 类覆盖的静态 selector 只占普查 2266 个中的 **265** 个（11.7%）。

生成于 2026-11-01 10:56:32。方法：`IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOService"), &iter)` 单次遍历全部服务，逐服务 `IOServiceOpen(type=0..3)` 各一次，成功即 `IOServiceClose`。
**全部「能否打开」都是设备返回的 `kern_return_t`，无一为推断**；只测「能否拿到 `io_connect_t`」，未调用任何 `externalMethod`，故本文件不对任何漏洞是否存在表态。
原始数据：`out/reach.json`（逐服务）· `out/reach-xref.json`（kext 归属）· `out/reach-meta.json` · `out/reach.log` · `out/reach.ndjson`。
**复现**：同一装置连跑两次，1469 个服务 / 85 个可打开实例 / 可打开集合完全相同（逐条比对相等）。

---

## 1. 总数

| 口径 | 数字 |
|---|---|
| 枚举到的 IOService 实例 | **1469** |
| `IOServiceOpen` 至少一个 type 成功（实例） | **85** |
| 去重到 user client 类 | **17** |
| 打开尝试次数（4 type × 全部服务） | 5876 |
| 因预算未尝试 | 0 |
| 截断 | 否 |
| 可打开率 | 5.8% |

## 2. 按打开成功的 type 分组

| type | 成功的服务数 | 说明 |
|---|---|---|
| 0 | 6 | 默认 user client |
| 1 | 7 | 次 user client（GPU/ANE 等） |
| 2 | 82 | 传感器/HID 类 secondary client——本次命中最多 |
| 3 | 5 | 第三 user client |

注意：同一服务可同时打开多个 type（如 `AppleKeyStore`、`AppleCLCD2`、`AppleJPEGDriver` 四个 type 全通），所以列和 100 > 实例数 85。**只用 type=0 探测会漏掉 79 个可打开实例**——这是本次最大的方法论修正。

## 3. type=0 返回码分布（全体服务，共 1469）

| 返回码 | 服务数 | 占比 |
|---|---|---|
| kIOReturnUnsupported | 901 | 61.3% |
| kIOReturnBadArgument | 238 | 16.2% |
| kIOReturnNotPermitted | 216 | 14.7% |
| kIOReturnError | 73 | 5.0% |
| kIOReturnNotPrivileged | 30 | 2.0% |
| KERN_SUCCESS | 6 | 0.4% |
| kIOReturnNoMemory | 3 | 0.2% |
| kIOReturnExclusiveAccess | 2 | 0.1% |

`kIOReturnUnsupported` 是「这类服务本来就没有 user client」，不是权限拒绝；`kIOReturnNotPrivileged` / `kIOReturnNotPermitted` 才是沙箱或授权层面被拒。

type=0 被**明确拒绝**的共 **246** 个（`kIOReturnNotPrivileged` 30 + `kIOReturnNotPermitted` 216），占 16.7%；`kIOReturnUnsupported` 901 个是「该类没有 user client」，属结构性不可达，与沙箱无关——这两者混谈会严重高估沙箱的拦截力度。

## 4. 可打开清单（按类聚合）

| # | 类名 | 实例数 | open 0/1/2/3 返回码 | 可开 type | kext | census selectors |
|---|---|---|---|---|---|---|
| 1 | `AppleARMPMUPowerSensor` | 11 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.driver.AppleEmbeddedTempSensor` | 6 |
| 2 | `AppleARMPMUTempSensor` | 32 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.driver.AppleEmbeddedTempSensor` | 6 |
| 3 | `AppleM68Buttons` | 1 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.driver.AppleM68Buttons` | 0 |
| 4 | `AppleEmbeddedNVMeTemperatureSensor` | 1 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.iokit.IONVMeFamily` | 18 |
| 5 | `AppleSPUHIDDriver` | 27 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.driver.AppleSPU` | 12 |
| 6 | `AppleSPUCT726` | 1 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.driver.AppleALSColorSensor` | 0 |
| 7 | `EXBrightKext` | 1 | kIOReturnNotPermitted / kIOReturnNotPermitted / KERN_SUCCESS / kIOReturnNotPermitted | 2 | `com.apple.EXBrightKext` | 0 |
| 8 | `IOHIDEventDriver` | 1 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.iokit.IOHIDFamily` | 18 |
| 9 | `AppleSphinxProxHIDEventDriver` | 1 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.driver.AppleProxDriver` | 0 |
| 10 | `AHSTemperatureReporter` | 1 | kIOReturnBadArgument / kIOReturnBadArgument / KERN_SUCCESS / kIOReturnBadArgument | 2 | `com.apple.driver.AppleHapticsSupportLEAP` | 4 |
| 11 | `H1xANELoadBalancer` | 1 | kIOReturnUnsupported / KERN_SUCCESS / kIOReturnUnsupported / kIOReturnUnsupported | 1 | `（未定位）` | — |
| 12 | `AppleKeyStore` | 1 | KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS | 0,1,2,3 | `com.apple.driver.AppleSEPKeyStore` | 0 |
| 13 | `IOSurfaceRoot` | 1 | KERN_SUCCESS / kIOReturnUnsupported / kIOReturnUnsupported / kIOReturnUnsupported | 0 | `com.apple.iokit.IOSurface` | 120 |
| 14 | `AGXAcceleratorG18P` | 1 | kIOReturnUnsupported / KERN_SUCCESS / kIOReturnUnsupported / kIOReturnUnsupported | 1 | `com.apple.AGXG18P` | 2 |
| 15 | `AppleCLCD2` | 2 | KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS | 0,1,2,3 | `com.apple.driver.AppleMobileDispH18P-DCP` | 0 |
| 16 | `AppleJPEGDriver` | 1 | KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS | 0,1,2,3 | `com.apple.driver.AppleJPEGDriver` | 10 |
| 17 | `AppleM2ScalerCSCDriver` | 1 | KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS / KERN_SUCCESS | 0,1,2,3 | `com.apple.driver.AppleM2ScalerCSCDriver` | 2 |

### 4.1 实例明细

| 类名 | 实例名 | eid | 可开 type |
|---|---|---|---|
| `AppleARMPMUPowerSensor` | `AppleARMPMUPowerSensor` | 4294968515 | 2 |
| `AppleARMPMUPowerSensor` | `AppleARMPMUPowerSensor` | 4294968852 | 2 |
| `AppleARMPMUPowerSensor` | `AppleARMPMUPowerSensor` | 4294968854 | 2 |
| `AppleARMPMUPowerSensor` | `AppleARMPMUPowerSensor` | 4294968861 | 2 |
| `AppleARMPMUPowerSensor` | `AppleARMPMUPowerSensor` | 4294968866 | 2 |
| `AppleARMPMUPowerSensor` | `AppleARMPMUPowerSensor` | 4294968877 | 2 |
| `AppleARMPMUPowerSensor` | …另外 5 个同类实例 | | 同上 |
| `AppleARMPMUTempSensor` | `AppleARMPMUTempSensor` | 4294968517 | 2 |
| `AppleARMPMUTempSensor` | `AppleARMPMUTempSensor` | 4294968522 | 2 |
| `AppleARMPMUTempSensor` | `AppleARMPMUTempSensor` | 4294968531 | 2 |
| `AppleARMPMUTempSensor` | `AppleARMPMUTempSensor` | 4294968535 | 2 |
| `AppleARMPMUTempSensor` | `AppleARMPMUTempSensor` | 4294968544 | 2 |
| `AppleARMPMUTempSensor` | `AppleARMPMUTempSensor` | 4294968548 | 2 |
| `AppleARMPMUTempSensor` | …另外 26 个同类实例 | | 同上 |
| `AppleM68Buttons` | `AppleM68Buttons` | 4294968073 | 2 |
| `AppleEmbeddedNVMeTemperatureSensor` | `AppleEmbeddedNVMeTemperatureSensor` | 4294968955 | 2 |
| `AppleSPUHIDDriver` | `AppleSPUHIDDriver` | 4294969707 | 2 |
| `AppleSPUHIDDriver` | `AppleSPUHIDDriver` | 4294969701 | 2 |
| `AppleSPUHIDDriver` | `AppleSPUHIDDriver` | 4294969708 | 2 |
| `AppleSPUHIDDriver` | `AppleSPUHIDDriver` | 4294969719 | 2 |
| `AppleSPUHIDDriver` | `AppleSPUHIDDriver` | 4294969720 | 2 |
| `AppleSPUHIDDriver` | `AppleSPUHIDDriver` | 4294969722 | 2 |
| `AppleSPUHIDDriver` | …另外 21 个同类实例 | | 同上 |
| `AppleSPUCT726` | `AppleSPUCT726` | 4294969832 | 2 |
| `EXBrightKext` | `EXBrightKext` | 4294968038 | 2 |
| `IOHIDEventDriver` | `IOHIDEventDriver` | 4294969702 | 2 |
| `AppleSphinxProxHIDEventDriver` | `AppleSphinxProxHIDEventDriver` | 4294969810 | 2 |
| `AHSTemperatureReporter` | `AHSTemperatureReporter` | 4294969954 | 2 |
| `H1xANELoadBalancer` | `ANEDriverRoot` | 4294968018 | 1 |
| `AppleKeyStore` | `AppleKeyStore` | 4294968023 | 0,1,2,3 |
| `IOSurfaceRoot` | `IOCoreSurfaceRoot` | 4294968802 | 0 |
| `AGXAcceleratorG18P` | `AGXAcceleratorG18P` | 4294968310 | 1 |
| `AppleCLCD2` | `AppleCLCD2` | 4294968865 | 0,1,2,3 |
| `AppleCLCD2` | `AppleCLCD2` | 4294968851 | 0,1,2,3 |
| `AppleJPEGDriver` | `AppleJPEGDriver` | 4294968294 | 0,1,2,3 |
| `AppleM2ScalerCSCDriver` | `AppleM2ScalerCSCDriver` | 4294968609 | 0,1,2,3 |

## 5. 与静态普查的交叉

普查口径（`out/census.json` 实测重算）：**2266** 个 selector / **245** 张派发表 / **301** 个 kext，其中 **85** 个 kext 确实登记了 selector。

（注：派发表按 `(kext, table)` 去重为 **245** 张；项目内此前的口径写作 244 张，差 1 张，以本文件重算值为准。）

### 5.1 覆盖率（按 selector 加权，这是决定项目靶子的数字）

> 口径与 `census.json` 的 2266 一致：按行计。同一 selector 号在不同表里各算一行。

| 口径 | 数字 |
|---|---|
| 普查 selector 总数 | 2266 |
| **实测可达**的 kext 覆盖的 selector 数 | **265** |
| 可达占比 | **11.7%** |
| 有派发表的 kext 数（与上面 85 个可打开实例无关，纯属数字巧合） | 85 |
| 其中经实测确认可达的 kext 数 | **9** |
| 不可达 kext 的 selector 数 | 2001 |

### 5.2 分类

| 分类 | 类数 | 含义 |
|---|---|---|
| 在普查覆盖内 | 10 | 所属 kext 在普查里有 selector，可直接对着现有派发表分析 |
| kext 在普查里但 0 个 selector | 6 | 该类可打开，但普查没登记它的 externalMethod —— **盲区** |
| kext 不在普查 kext 列表 | 0 | 整只 kext 没进普查 |
| 类名无法定位 kext | 1 | 字面量多命中且无唯一裁决，如实不猜 |

### 5.3 盲区清单（可打开、但静态普查没覆盖的 selector 面）

| 类名 | kext | 原因 | 实例数 | 可开 type |
|---|---|---|---|---|
| `AppleM68Buttons` | `com.apple.driver.AppleM68Buttons` | 普查 0 selector | 1 | 2 |
| `AppleSPUCT726` | `com.apple.driver.AppleALSColorSensor` | 普查 0 selector | 1 | 2 |
| `EXBrightKext` | `com.apple.EXBrightKext` | 普查 0 selector | 1 | 2 |
| `AppleSphinxProxHIDEventDriver` | `com.apple.driver.AppleProxDriver` | 普查 0 selector | 1 | 2 |
| `AppleKeyStore` | `com.apple.driver.AppleSEPKeyStore` | 普查 0 selector | 1 | 0,1,2,3 |
| `AppleCLCD2` | `com.apple.driver.AppleMobileDispH18P-DCP` | 普查 0 selector | 2 | 0,1,2,3 |
| `H1xANELoadBalancer` | 候选 2 个 | 归属未定 | 1 | 1 |

### 5.4 覆盖内可打开类，按 selector 行数排序

> `selectors` = **该 kext 在普查里的 selector 行数**（整只 kext 的量，不是这一个类的量）；两只类同属一个 kext 时会看到同一个数字，第 5.1 节的 265 已按 kext 去重。

| 类名 | kext | selectors（kext 行数） | 可开 type |
|---|---|---|---|
| `IOSurfaceRoot` | `com.apple.iokit.IOSurface` | 120 | 0 |
| `AppleSPUHIDDriver` | `com.apple.driver.AppleSPU` | 56 | 2 |
| `IOHIDEventDriver` | `com.apple.iokit.IOHIDFamily` | 42 | 2 |
| `AppleEmbeddedNVMeTemperatureSensor` | `com.apple.iokit.IONVMeFamily` | 21 | 2 |
| `AppleJPEGDriver` | `com.apple.driver.AppleJPEGDriver` | 10 | 0,1,2,3 |
| `AppleARMPMUPowerSensor` | `com.apple.driver.AppleEmbeddedTempSensor` | 6 | 2 |
| `AppleARMPMUTempSensor` | `com.apple.driver.AppleEmbeddedTempSensor` | 6 | 2 |
| `AHSTemperatureReporter` | `com.apple.driver.AppleHapticsSupportLEAP` | 4 | 2 |
| `AGXAcceleratorG18P` | `com.apple.AGXG18P` | 4 | 1 |
| `AppleM2ScalerCSCDriver` | `com.apple.driver.AppleM2ScalerCSCDriver` | 2 | 0,1,2,3 |

## 6. 直答

**从 dev-signed app 沙箱出发，实测能打开 85 个 IOKit service 实例，归并为 17 个 user client 类。**

清单（类名 → 可开 type）：

- `AppleARMPMUTempSensor` ×32 — type 2
- `AppleSPUHIDDriver` ×27 — type 2
- `AppleARMPMUPowerSensor` ×11 — type 2
- `AppleCLCD2` ×2 — type 0,1,2,3
- `AGXAcceleratorG18P` ×1 — type 1
- `AHSTemperatureReporter` ×1 — type 2
- `AppleEmbeddedNVMeTemperatureSensor` ×1 — type 2
- `AppleJPEGDriver` ×1 — type 0,1,2,3
- `AppleKeyStore` ×1 — type 0,1,2,3
- `AppleM2ScalerCSCDriver` ×1 — type 0,1,2,3
- `AppleM68Buttons` ×1 — type 2
- `AppleSPUCT726` ×1 — type 2
- `AppleSphinxProxHIDEventDriver` ×1 — type 2
- `EXBrightKext` ×1 — type 2
- `H1xANELoadBalancer` ×1 — type 1
- `IOHIDEventDriver` ×1 — type 2
- `IOSurfaceRoot` ×1 — type 0

高价值项（按攻击面判断，均经实测确认可打开）：

- `IOSurfaceRoot` (type 0)：IOSurface 全局命名空间，图形/媒体数据的核心容器。
- `AGXAcceleratorG18P` (type 1)：GPU 加速器 user client，type 1 才开。
- `H1xANELoadBalancer` (type 1)：ANE 负载均衡 user client，type 1 才开。
- `AppleKeyStore` (type 0/1/2/3)：keybag / 设备加密服务，四个 type 全通。
- `AppleJPEGDriver` / `AppleCLCD2` / `AppleM2ScalerCSCDriver` (type 0-3)：媒体与显示管线。
- `AppleSPUHIDDriver` ×27 (type 2)：传感器协处理 HID，实例最多。

## 7. 对项目的影响

- 静态普查的 2266 个 selector 里，实测可达的只有 265 个（11.7%）。**靶子必须重排**：实测可达的 kext 只有 **15** 个（其中 9 个在普查里有派发表），不在这 15 个 kext 里的 selector，先不要投人力。
- `only-type-0` 探测会把可达面低估 93%（6 vs 85）。此前的可达性推断若默认 type=0，结论系统性偏小。
- **下一步（最省力的一步）**：对上述可达类逐个调用 `IOConnectCallScalarMethod(conn, 0, ...)` 与 `IOServiceAuthorize`，把「能 open」和「能 call」分开——本轮只证明了前者，后者才是漏洞面的真实入口。
- 沙箱并非「一律 NotPrivileged」：type=0 只有 30 个 `kIOReturnNotPrivileged` + 216 个 `kIOReturnNotPermitted`，其余多为 `kIOReturnUnsupported`（该类无 user client）。可达性主要是**类白名单**决定的，不是统一拦截。

## 8. 方法与可信度

- app：`harness/rpenum/`，bundle `com.example.ios27poc`，签名 `iPhone Distribution: <DEVELOPER> (<TEAMID>)`，entitlements 取自 `/tmp/ents.plist`（含 kernel memory limit / extended-virtual-addressing / 多个 developer.* 项）。
- 逐服务记录：`IOObjectGetClass`、`IORegistryEntryGetName`、`CFBundleIdentifier`（缺则回退父节点）、`IOClass`、`IOProviderClass`、`IOObjectConformsTo("IOUserClient")`、`IORegistryEntryGetRegistryEntryID`。
- 打开探测：type 0..3 各一次，成功即 `IOServiceClose`；不保留句柄、不调用 externalMethod、不写任何硬件状态。
- 抗崩溃：结果逐条增量写 `reach.ndjson`（flush），另有 32 秒看门狗强制落盘；本次未截断、未崩溃（`truncated=0`，服务数两次一致）。
- kext 归属：从 kernelcache 的 fileset 头取段表（`vtable.segments` 返回 `(vmaddr, size, fileoff)`），只取 `__TEXT/__TEXT_EXEC/__DATA*/__LINKEDIT` 内的标识符字面量；类名是 OSMetaClass 构造参数，必落在其 kext 段内。多命中时用「类名 vs kext 末段」最长公共子串裁决（阈值 4，唯一最大者胜），并列则标未定位而不猜。
- 局限：`IOServiceOpen` 成功只说明拿到 `io_connect_t`。是否允许 `IOConnectCallMethod` 还另有 `IOServiceAuthorize` / 沙箱 `iokit-open` 与 selector 级检查，本文件未测。

