# UCALL 基线 — 打开之后，真的能调进去吗

生成于 2026-11-01 11:17:18　来源：`out/ucall-baseline.ndjson`（34 条）+ `out/ucall-sweep.ndjson`（600 条）

**一句话**：`out/REACH-MEASURED.md` 的 17 个可打开类，实测**只有 2 个类的 selector 0 真的调用成功**（`AppleKeyStore`、`AppleJPEGDriver`）；其余 15 个全部被拒。**没有任何一条调用导致 panic 或整机重启。**

> **追加（§12）**：把 `IOServiceOpen` 的 type 从 0..3 扩到 0..255 后，可打开服务数与类数**完全不变**（85 / 17）；`AppleAVE2Driver` 在任何 type 下都打不开。但 `AGXAcceleratorG18P` 的 **type 33** 是另一个 user client，旧扫描看不到。

> 本轮第一次真正执行了 `IOConnectCallScalarMethod` / `IOConnectCallStructMethod`。此前项目所有「可达」结论都停在 `IOServiceOpen` 返回 `KERN_SUCCESS` 为止，本文件把**能打开**和**能调用**分开了。

---

## 1. 直答

**17 个类里，打开之后 selector 0 真的调用成功的：2 个。**

| 类 | type | 空调用（count_in=0）返回码 |
|---|---|---|
| `AppleKeyStore` | 0 / 1 / 2 / 3 | **KERN_SUCCESS** |
| `AppleJPEGDriver` | 0 / 1 / 2 / 3 | **KERN_SUCCESS**（仅空调用；传 4 个零标量变 `kIOReturnBadArgument`） |

按 (类,type) 计，**8 个组合**可成功调用 selector 0；**其余 15 个类不可**：

| 类 | type | selector 0 返回码 | 判读 |
|---|---|---|---|
| `AppleCLCD2` | 0–3 | `kIOReturnBadArgument` | selector 存在，参数被拒（**不是**权限拒绝） |
| `AGXAcceleratorG18P` | 1 | `kIOReturnBadArgument` | 同上 |
| `H1xANELoadBalancer` | 1 | `kIOReturnBadArgument` | 同上 |
| `IOSurfaceRoot` | 0 | `kIOReturnBadArgument` | 同上，且 0–63 全 BadArgument（见 §5） |
| `AppleM2ScalerCSCDriver` | 0–3 | `kIOReturnUnsupported` | selector 0 不在派发表，**真正的「没有」** |
| 其余 10 个传感器/HID 类 | 2 | `kIOReturnBadArgument` | 参数被拒 |

**没有出现一例 `kIOReturnNotPrivileged` / `kIOReturnNotPermitted` 作为 selector 0 的返回**——沙箱在 selector 0 这一层没有拦，拦住的是参数校验。

---

## 2. 全表（17 类 / selector 0）

| # | 类名 | type | open | call（空调用） | 码 | call（4 个零标量） | 码 | eid | 耗时 ms |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `AppleKeyStore` | 0 | SUCCESS | KERN_SUCCESS ✅ | `SUCCESS` | KERN_SUCCESS | `SUCCESS` | 4294968023 | 0 |
| 2 | `H1xANELoadBalancer` | 1 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968018 | 0 |
| 3 | `IOSurfaceRoot` | 0 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968802 | 0 |
| 4 | `AGXAcceleratorG18P` | 1 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968310 | 0 |
| 5 | `AppleCLCD2` | 0 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968865 | 0 |
| 6 | `AppleJPEGDriver` | 0 | SUCCESS | KERN_SUCCESS ✅ | `SUCCESS` | kIOReturnBadArgument | `BadArgument` | 4294968294 | 0 |
| 7 | `AppleM2ScalerCSCDriver` | 0 | SUCCESS | kIOReturnUnsupported | `Unsupported` | kIOReturnUnsupported | `Unsupported` | 4294968609 | 0 |
| 8 | `AppleSPUHIDDriver` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294969707 | 0 |
| 9 | `IOHIDEventDriver` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294969702 | 0 |
| 10 | `AppleARMPMUTempSensor` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968517 | 0 |
| 11 | `AppleARMPMUPowerSensor` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968515 | 0 |
| 12 | `AppleEmbeddedNVMeTemperatureSensor` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968955 | 0 |
| 13 | `AHSTemperatureReporter` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294969954 | 0 |
| 14 | `AppleM68Buttons` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968073 | 0 |
| 15 | `AppleSPUCT726` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294969832 | 0 |
| 16 | `EXBrightKext` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294968038 | 0 |
| 17 | `AppleSphinxProxHIDEventDriver` | 2 | SUCCESS | kIOReturnBadArgument | `BadArgument` | kIOReturnBadArgument | `BadArgument` | 4294969810 | 0 |

- open 成功：**17/17**（与 REACH-MEASURED 一致）
- 空调用成功：**2/17**
- 4 个零标量调用成功：**1/17**
- 全部条目耗时 0–1 ms，无一条超过 10 ms，**无超时**

原始返回码为完整 32 位；`kIOReturnBadArgument = 0xE00002C2`，`kIOReturnUnsupported = 0xE00002C7`，`kIOReturnNotPrivileged = 0xE00002C1`，`kIOReturnNotPermitted = 0xE00002E2`。

---

## 3. 标量个数本身就是一个判据

`AppleJPEGDriver` type 0 selector 0：

| 入参 | 返回码 |
|---|---|
| `count_in=0`（空调用） | **KERN_SUCCESS** |
| `count_in=4`（4 个零标量） | `kIOReturnBadArgument` |

同一个 selector，只因为多传了 4 个零就从不接受变成接受——说明该 handler 在**入口处校验 `scalarInputCnt`**，而且它期望的是 0。这条对所有后续 selector 探测都成立：**「传几个标量」和「传什么值」是两个独立维度**，只试一种形态会把可达面判错。

---

## 4. 方法学修正：`kIOReturnBadArgument` 大多是通用码，不代表 selector 存在

这是本轮最重要的方法论结论。做法：对每个类额外打一发**已知不存在的 selector**（4095 / 65535）当哨兵，看它返回什么。

| 类 | 哨兵(4095/65535) 返回 | 0..15 内的返回 | 判读 |
|---|---|---|---|
| `AGXAcceleratorG18P` t=1 | Unsupported | BadArgument×16 | 哨兵 Unsupported ≠ 表内 BadArgument → **两者可区分，可用来画派发表** |
| `AppleCLCD2` t=0 | BadArgument | BadArgument×14, Unsupported×2 | **哨兵也是 BadArgument → BadArgument 是兜底码，无法区分「存在但参数错」和「不存在」** |
| `AppleJPEGDriver` t=0 | BadArgument | BadArgument×13, SUCCESS×2, Error×1 | **哨兵也是 BadArgument → BadArgument 是兜底码，无法区分「存在但参数错」和「不存在」** |
| `AppleKeyStore` t=0 | BadArgument | BadArgument×11, SUCCESS×2, NotPrivileged×2, NotPermitted×1 | **哨兵也是 BadArgument → BadArgument 是兜底码，无法区分「存在但参数错」和「不存在」** |
| `AppleM2ScalerCSCDriver` t=0 | Unsupported | BadArgument×8, Unsupported×7, SUCCESS×1 | 哨兵 Unsupported ≠ 表内 BadArgument → **两者可区分，可用来画派发表** |
| `H1xANELoadBalancer` t=1 | BadArgument | BadArgument×15, SUCCESS×1 | **哨兵也是 BadArgument → BadArgument 是兜底码，无法区分「存在但参数错」和「不存在」** |
| `IOSurfaceRoot` t=0 | BadArgument | BadArgument×16 | **哨兵也是 BadArgument → BadArgument 是兜底码，无法区分「存在但参数错」和「不存在」** |

后果很直接：

- **可区分（哨兵=Unsupported）**：`AGXAcceleratorG18P`、`AppleM2ScalerCSCDriver` —— 只有这两类能用「BadArgument ⇒ selector 在表里」来画派发表。
- **不可区分（哨兵也是 BadArgument）**：`AppleCLCD2`、`AppleJPEGDriver`、`AppleKeyStore`、`H1xANELoadBalancer`、`IOSurfaceRoot` —— 对它们，`BadArgument` 不能作为 selector 存在的证据。

也就是说 `REACH-MEASURED` §5 里按 kext 派发表做的静态推断，在这 5 个类上暂时无法用动态口径验证。

---

## 5. selector 派发图（0–63 扫描，空调用）

每行 64 个字符对应 selector 0–63。图例：`S`=KERN_SUCCESS　`B`=kIOReturnBadArgument　`U`=kIOReturnUnsupported　`P`=kIOReturnNotPrivileged　`M`=kIOReturnNotPermitted　`F`=kIOReturnNotFound　`E`=kIOReturnError　`C`=kIOReturnNoCompletion　`X`=kIOReturnUnsupportedMode　`T`=超时未返回　`·`=未测

| 类 | type | 0..63 |
|---|---|---|
| `AGXAcceleratorG18P` | 1 | `BBBBBBBBBBBBBBBBBBBBBBUBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBTUUUUUUUU` |
| `AppleCLCD2` | 0 | `BUUBBBBBBBBBBBBBBBBBBBBBBBSBBBBBBBBBUUUUUBBBBUUBBBBBBBBBBBBCCCCC` |
| `AppleJPEGDriver` | 0 | `SBSBBBBBBEBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB` |
| `AppleKeyStore` | 0 | `SSBBBPPBMBBBBBBBSFBMPPPBBBBBBBBBMPPFPPPPBPBBBBBBBBBPBPXBBBBBBBBP` |
| `AppleM2ScalerCSCDriver` | 0 | `UBUUBBBBBBBSUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU` |
| `H1xANELoadBalancer` | 1 | `BSBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB` |
| `IOSurfaceRoot` | 0 | `BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB` |

派发图里能直接读出来的东西：

- `AppleCLCD2` t=0：selector **26** 在空调用下直接 `KERN_SUCCESS`
- `AppleJPEGDriver` t=0：selector **0, 2** 在空调用下直接 `KERN_SUCCESS`
- `AppleKeyStore` t=0：selector **0, 1, 16** 在空调用下直接 `KERN_SUCCESS`
- `AppleM2ScalerCSCDriver` t=0：selector **11** 在空调用下直接 `KERN_SUCCESS`
- `H1xANELoadBalancer` t=1：selector **1** 在空调用下直接 `KERN_SUCCESS`
- `AGXAcceleratorG18P` t=1：selector **55** 调用不返回（见 §6）

- `AGXAcceleratorG18P` t=1（哨兵=Unsupported，可区分）：表内但参数被拒 [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54]；不在表内 9 个；无条件成功 []
- `AppleM2ScalerCSCDriver` t=0（哨兵=Unsupported，可区分）：表内但参数被拒 [1, 4, 5, 6, 7, 8, 9, 10]；不在表内 55 个；无条件成功 [11]

---

## 6. 唯一的异常：`AGXAcceleratorG18P` selector 55 调用不返回

| 字段 | 值 |
|---|---|
| 类 / type / selector | `AGXAcceleratorG18P` / 1 / **55** |
| 现象 | 调用发出后 3000 ms 仍未返回，记 `timeout` |
| 邻居对照 | selector 54 → `kIOReturnBadArgument`；selector 56 → `kIOReturnUnsupported` |
| 复现性 | **两次独立运行均复现**（1500 ms 与 3000 ms 两个预算下都超时） |

这不是 panic：进程继续跑完了后续条目，结果全部落盘，设备无重启。含义是 selector 55 **确实在派发表里**，且它的 handler 在等某个不发生的事件（GPU 电源状态 / 固件握手 / 未完成的 completion 是一类典型原因）。它是这 17 个类里唯一一个「有反应但不返回」的入口，也是目前最值得单独追的一条。

> 复测命令：`{"only":[0],"plan":[{"class":"AGXAcceleratorG18P","type":1,"sel":55,"timeout_ms":10000}]}` 推上去单条重试即可，见 §8。

---

## 7. `IOSurfaceRoot` 不是「缺 struct 入参」

`IOSurfaceRoot` 是覆盖 selectors 最多的可达 kext（120 个静态 selector），但它 0–63 全部 `kIOReturnBadArgument`，连哨兵也一样。本轮试过给它真实的 struct 入参，结果不变：

| 入参 | 返回码 |
|---|---|
| 16 字节 struct 入 | kIOReturnBadArgument |
| 64 字节 struct 入 | kIOReturnBadArgument |
| 256 字节 struct 入 | kIOReturnBadArgument |
| 64 字节 struct 入 / 64 字节 struct 出 | kIOReturnBadArgument |

所以「加 struct 就能进」这个假设**已排除**。`IOSurfaceRoot` 的 client 在派发前就统一返回 BadArgument，真正的前置条件更可能是 `IOServiceAuthorize` / 授权位，而不是入参形态。这一条留给下一轮。

---

## 8. 工具（`harness/ucall/`）

配置驱动：目标、type、selector、标量、struct 全在 `tmp/plan.json`，改参数不用重编译。

```json
[{"class":"AppleKeyStore","type":0,"sel":0,
  "scalars":{"in":[0,0,0,0],"count_in":0},"out_count":0,
  "struct_in_len":0,"struct_out_len":0,"note":"probe"}]
```

| 字段 | 作用 |
|---|---|
| `class` / `type` / `sel` | 类名、`IOServiceOpen` 的 type、selector |
| `scalars.in` / `count_in` | 标量入参；`count_in` 可单独指定（决定是否传 buffer） |
| `out_count` | 期望的标量输出个数（0 = 不请求输出） |
| `struct_in_len` / `struct_in_b64` | struct 入参；给长度就自动零填充，不必写 b64 |
| `struct_out_len` | struct 出参缓冲大小 |
| `method` | `scalar` / `struct` / `method` / `auto`（默认 auto，见下） |
| `instance` / `eid` | 同类多实例时选第 N 个，或直接按 registry entry id 定位 |
| `authorize` | 打开前先探一次 `IOServiceAuthorize`（dlsym，缺符号则记 `symbol_unavailable`） |
| `timeout_ms` | 单条超时，默认 1500 |
| `only` | `true` 时只跑该条；也可在根对象写 `{"only":[2],"plan":[...]}` 按 index 过滤 |

`auto` 的选择规则（重要，因为 `IOConnectCallStructMethod` 没有标量出参）：

| 情形 | 走哪条 API |
|---|---|
| 无 struct 入参、不请求标量输出 | `IOConnectCallScalarMethod` |
| 无 struct 入参、请求标量输出 | `IOConnectCallMethod`（通用形式） |
| 有 struct 入参、不请求标量输出 | `IOConnectCallStructMethod` |
| 有 struct 入参、请求标量输出 | `IOConnectCallMethod` |

抗崩溃：

- 每条独立 `@autoreleasepool` + 独立 `io_connect_t`，调完立刻 `IOServiceClose`，绝不跨条目复用
- 每条结果**产生即写 `tmp/ucall.ndjson` 并 `fflush`**，panic 时已跑完的条目一定还在
- 单条超时用 `dispatch_semaphore` + `dispatch_time`，**没有 sleep 轮询**；超时条目放弃线程、记录后继续，后续条目在并发队列上不受阻（`AGX` sel 55 卡住时其余 447 条照常完成，已实证）
- 总预算 22 s 后不再发起新条目；26 s 看门狗强制收尾并 `exit(0)`。**单次交互等待全程 < 35 s**

用法：

```bash
./harness/ucall/run.sh /tmp/plan.json        # 全量
./harness/ucall/run.sh /tmp/plan.json 55     # 只跑 idx 55（单条重试）
```

`only` 机制实测：根对象 `{"only":[2],"plan":[3 条]}` → 日志 `计划 3 条, only=2`，只发起 idx 2，其余跳过。

落盘约定：app 内写 `tmp/ucall.ndjson`（增量）+ `tmp/ucall.json`（汇总）+ `tmp/ucall.log`。`run.sh` 取回后默认写 `out/ucall-last.ndjson` / `out/ucall-last.log`，`APPEND=1` 时才追加进 `out/ucall-baseline.ndjson`——基线文件保持单次运行的纯净，不被后续试验污染。

---

## 9. 可重现性

| 对比 | 结果 |
|---|---|
| 4 个零标量：第 1 轮 vs 基线轮（17 类） | **0 条差异** |
| 空调用：基线轮 vs 第 2 轮（7 类） | **0 条差异** |
| 空调用：基线轮 vs 第 3 轮 0–63 扫描（7 类） | **0 条差异** |
| 全程 panic / 重启 | **0 次** |
| 全程超时 | **1 次**（AGX sel 55，可复现，见 §6） |

`AGX` sel 55 超时后设备状态正常，后续 4 轮运行全部正常完成，可执行映射未被内核拒绝。

---

## 10. 对项目的影响

1. **可达面从「能 open」收缩到「能 call」**：17 个类 → **2 个类**（`AppleKeyStore`、`AppleJPEGDriver`）在 selector 0 上真正被接受。其余 15 个类的 selector 0 是「进得去门，说不上话」。
2. **`REACH-MEASURED` §5 的 265 个静态 selector 覆盖率，不能当作动态可达面**。其中大部分挂在 `BadArgument` 兜底的类上，动态侧暂时分不出「存在」与「不存在」。
3. **真正的动态入口只有三个方向**：
   - `AppleKeyStore`：selector 0/1/16 直接成功；5/6/20/21/22/33/34/36/37/38/39/41/51/53/63 返回 `kIOReturnNotPrivileged`（**这些是真的进了 handler 才被权限拒的**，是权限绕过类的靶子）；8/19/32 返回 `kIOReturnNotPermitted`；17/35 返回 `kIOReturnNotFound`
   - `AppleJPEGDriver`：selector 0/2 直接成功；9 返回 `kIOReturnError`
   - `AppleM2ScalerCSCDriver`：selector 11 直接成功；1/4–10 表内（`BadArgument`）
4. **`AGXAcceleratorG18P` selector 55 挂起**是唯一「有状态反应」的观察，值得优先单点深挖。
5. `IOSurfaceRoot` 的 120 个 selector 目前**一个都进不去**，且已排除「缺 struct 入参」的解释；下一轮应转向授权路径（`IOServiceAuthorize` 探针已内建）而不是继续改入参。

---

## 11. 下一轮的最小动作

1. `AppleKeyStore` 对 `kIOReturnNotPrivileged` 那 15 个 selector 逐个加 `struct_in_len` / 不同 `count_in` 组合，把「参数错」推到「权限错」之前的最后一步。
2. `AGXAcceleratorG18P` sel 55 单独重跑，`timeout_ms` 拉到 10000，看是永久挂起还是有界等待。
3. 给 `AppleKeyStore` 打开 `authorize:true`，对比 `IOServiceAuthorize` 前后 selector 5/6 的返回码是否变化。
4. 把 `out/census.json` 里 `com.apple.driver.AppleSEPKeyStore` / `AppleJPEGDriver` 的派发表，与本文件的动态派发图逐条对齐——这两只 kext 是唯一能拿到真实 selector 语义的。

---

## 12. 追加：`IOServiceOpen` 的 type 维度扩到 0..255

复核要求：`type` 是任意 32 位值，只试 0..3 可能漏掉用别的值区分的 user client。本轮把全部 **1,469** 个服务在 **type 0..255** 上各打一发（376,064 次 `IOServiceOpen`，3.8 秒跑完）。

工具：`harness/tscan/`（配置 `tmp/tscan-cfg.json` 可指定 `type_max` / `skip_unsupported` / 输出文件名，支持按 eid 断点续跑）。原始数据：`out/tscan-type0-255.ndjson`。

### 12.1 三种扫描范围的对比

| 范围 | 尝试次数 | 可打开**服务**数 | 可打开**类**数 | 可打开 (服务,type) 组合 |
|---|---|---|---|---|
| type 0..3（旧结论） | 5,876 | 85 | 17 | 100 |
| type 0..15 | 23,504 | 85 | 17 | 161 |
| **type 0..255（本轮）** | **376,064** | **85** | **17** | **1362** |

**服务数和类数一个都没变**：85 → 85 → 85，17 个类。不存在「只有靠 type>3 才能打开」的服务（实测 0 个）。变的是 **(服务,type) 组合数**：100 → 1362，**13.6 倍**——这些组合各自是一个独立的 user client 实例，可能是不同的子类、不同的 selector 表。

### 12.2 各类成功 type 全集（0..255 实测）

| 类 | 实例数 | 可成功打开的 type |
|---|---|---|
| `AGXAcceleratorG18P` | 1 | [1, 33] |
| `AHSTemperatureReporter` | 1 | [2] |
| `AppleARMPMUPowerSensor` | 11 | [2] |
| `AppleARMPMUTempSensor` | 32 | [2] |
| `AppleCLCD2` | 2 | **全部 0..255（type 被完全忽略）** |
| `AppleEmbeddedNVMeTemperatureSensor` | 1 | [2] |
| `AppleJPEGDriver` | 1 | **全部 0..255（type 被完全忽略）** |
| `AppleKeyStore` | 1 | **全部 0..255（type 被完全忽略）** |
| `AppleM2ScalerCSCDriver` | 1 | **全部 0..255（type 被完全忽略）** |
| `AppleM68Buttons` | 1 | [2] |
| `AppleSPUCT726` | 1 | [2] |
| `AppleSPUHIDDriver` | 27 | [2] |
| `AppleSphinxProxHIDEventDriver` | 1 | [2] |
| `EXBrightKext` | 1 | [2] |
| `H1xANELoadBalancer` | 1 | [1, 4] |
| `IOHIDEventDriver` | 1 | [2] |
| `IOSurfaceRoot` | 1 | [0] |

四个类（`AppleKeyStore`、`AppleCLCD2`、`AppleJPEGDriver`、`AppleM2ScalerCSCDriver`）对 0..255 里**任意 type 都返回成功**——它们的 `newUserClient` 根本不看 type。所以对这四个类，「type 选哪个」不构成限制。

### 12.3 `AppleAVE2Driver`：打不开，但原因不是「type 不对」

`AppleAVE2Driver`（eid `4294968290`）在 **type 0..255 全部 256 个取值上都打不开**（`ok_types` 为空）。但返回码不是 `kIOReturnUnsupported`，而是两种：

| 返回码 | 个数 | type 取值 |
|---|---|---|
| `kIOReturnNoMemory` | 176 | [0, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23, 24, 25]… |
| `kIOReturnNotPermitted` | 80 | [1, 2, 3, 4, 5, 17, 18, 19, 20, 21, 33, 34, 35, 36, 37, 49]… |

**关键**：`rc(type) == rc(type mod 16)` 在 0..255 上逐条成立。也就是说这 256 次采样只覆盖了 **16 个行为等价的残类**，每个残类重复了 16 遍。type 的高位对这个 handler 没有影响。

再用高位验一次（`ucall`，type 取 0x1000 / 0x10000 / 0x80000000 / 0xFFFFFFFF）全部仍是 `kIOReturnNoMemory`，与 mod-16 预测一致：

| type | 预测（mod 16） | 实测 open |
|---|---|---|
| `0x00001000` | NoMemory | `kIOReturnNoMemory` |
| `0x00010000` | NoMemory | `kIOReturnNoMemory` |
| `0x80000000` | NoMemory | `kIOReturnNoMemory` |
| `0xFFFFFFFF` | NoMemory | `kIOReturnNoMemory` |

这说明两件事：

1. **它确实有 user client 路径**——`type ≡ 1..5 (mod 16)` 返回 `kIOReturnNotPermitted`，其余返回 `kIOReturnNoMemory`，两者都不是「这类服务没有 user client」的 `kIOReturnUnsupported`。所以服务里存在 `newUserClient` 实现，且分了分支。
2. **但在 `IOServiceOpen` 这一层就是进不去**：`NoMemory` 是 handler 内部创建上下文时分配失败返回的，不是「type 错了」。换任何 type 都只在 「权限拒」 和 「分配失败」 之间二选一。

> 对 AVEVideoEncoder 那 5 个 CVE 来说，这是一条**负结果但很确定的负结果**：在当前装置（iOS 27.0.1 / 24A446，dev-signed 沙箱）上，`AppleAVE2Driver` 拿不到 `io_connect_t`，连 selector 都调不到。要继续走这条路，前置条件只能是**别的东西**（更宽的 iokit-open 授权、或经别的服务间接驱动 AVE），而不是换 type。

### 12.3.1 `AppleAVD`：256 个 type 全被权限拒，与 AVE2 的失败方式不同

设备上**没有** `AppleAVDDriver` 这个名字；真正的解码器服务类叫 **`AppleAVD`**（eid `4294968628`）。它在 256 个 type 上返回：

| 返回码 | 个数 |
|---|---|
| `kIOReturnNotPrivileged` | 256 |

**256 个 type 全部 `kIOReturnNotPrivileged`**，一个例外都没有。这和 `AppleAVE2Driver` 是两种完全不同的失败：

| 服务 | 失败方式 | 含义 |
|---|---|---|
| `AppleAVD` | 均匀的 `NotPrivileged` ×256 | **在权限检查那一层就被挡死**，根本没有进入驱动逻辑 |
| `AppleAVE2Driver` | `NoMemory` / `NotPermitted` 按 mod 16 交替 | **过了权限层**，进到 handler 内部才失败 |

也就是说 `AppleAVE2Driver` 比 `AppleAVD` 更接近可用——它至少有一批 type 是走到分配那一步才断的。但两者在 `IOServiceOpen` 这一层都拿不到 `io_connect_t`。

### 12.4 type 维度确实有料：两个类藏着第二个 user client

| 类 | 已知 type | 本轮新发现 | 是否同一个 user client |
|---|---|---|---|
| `AGXAcceleratorG18P` | 1 | **33**，另有 **65537** | **不是**——见下 |
| `H1xANELoadBalancer` | 1 | **4** | 是（selector 表相同） |

`AGXAcceleratorG18P` type 33 用 `ucall` 扫 selector 0..15 的结果，和 type 1 明显不同：

| selector | type 1 | type 33 |
|---|---|---|
| 0, 1, 3–15 | `kIOReturnBadArgument` | `kIOReturnBadArgument` |
| **2** | `kIOReturnBadArgument` | **`kIOReturnNotPrivileged`** |
| 4095（已知不存在的哨兵） | `kIOReturnUnsupported` | `kIOReturnBadArgument` |

type 33 在 selector 2 上返回 `kIOReturnNotPrivileged`（进了 handler 才被权限拒），type 1 在同一位是 `kIOReturnBadArgument`。而且哨兵位也不一样：type 1 对不存在的是 `Unsupported`，type 33 对不存在的是 `BadArgument`（兜底码）。**两处差异同时出现，说明 type 1 和 type 33 是两个不同的 user client 子类，selector 2 在 type 33 上真实存在。**这是本轮唯一新增的「能进到权限检查」的入口，之前的 0..3 扫描完全看不到它。

`H1xANELoadBalancer` type 4 与 type 1 的行为完全一致（selector 1 返回 `KERN_SUCCESS`，其余 `BadArgument`，哨兵同为 `BadArgument`），是同表不同 type。

原始数据：`out/ucall-typeprobe.ndjson`（43 条）。

### 12.5 这一节的结论

1. **类数不变：17 → 17。** 把 type 从 0..3 扩到 0..255，没有解锁任何新的 user client 类。
2. **`AppleAVE2Driver` 打不开**，任何 type 都不行；返回码是 `NoMemory` / `NotPermitted` 二选一，且按 mod 16 周期分布——不是「type 选错」。
3. **但 type 维度不是无意义的**：`AGX` 的 type 33 是另一个 user client，`AGX`/`ANE` 各有旧扫描没看到的 type。后续所有 selector 探测都必须在**每个可打开 type 上分别做**，不能默认 type 0。

---

