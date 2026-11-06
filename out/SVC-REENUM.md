# SVC-REENUM — 用**正确姿势**（输出容量预填）重新枚举 selector 面

设备 `DEVICE-UDID`（iPhone18,2 / iOS 27.0.1）。根目录 `tasks/ios27-chain-poc`。代码 `harness/svcreenum/`，原始记录 `harness/svcreenum/results/`。

**一句话**：上一轮 `out/SVC2-PROBE.md` 的「Unsupported」判定被证伪。把 `scalarOutputCount` / `structOutputSize` 预填后，`AppleM2ScalerCSCDriver` 从 1 个 selector 变 12 个、`AGXAcceleratorG18P type 1` 的 `sel 1` 会回吐 ASCII `"AGXG18P"`、`IOMobileFramebuffer` / `AppleCLCD2` 各从 10 个变 **47** 个。同时踩出一个新事实：**C7 判据只对表驱动服务成立**，另 6 个服务未知 selector 返回 `BadArgument`，必须换判据（见 §2）。

## 1. 五态（build / sign / install / launch / 跑完）分开写

| stage | build | sign | install | launch | 跑完 |
|---|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` type 0（0..31） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=33ms） |
| `IOSurfaceRoot` type 0（0..255） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=120ms） |
| `AGXAcceleratorG18P` type 1（0..255） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=3152ms） |
| `AGXAcceleratorG18P` type 33（0..255） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=123ms） |
| `IOHIDEventService` type 2（0..127） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=64ms） |
| `AppleJPEGDriver` type 0（0..63） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=43ms） |
| `IOMobileFramebuffer` type 0（0..127） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=69ms） |
| `AppleCLCD2` type 0（0..127） | rc=0 | rc=0 | OK | rc=0 | ✅ @done（扫描 t=68ms） |

指纹 `REENUM-20261101-svcladder-b7f2e1`，每次装前 `strings Payload/UC.app/UC | grep REENUM-` 命中 **1**，残余旧指纹（m2reenum / svc2probe / m2op）**0**。`devicectl device copy from` 的 stderr 每次都单独打印（全为「无输出」）。

**`launch` 侧一次异常，如实记录、没有拿旧文件当新结果**：

1. 一次 `ERROR: The application failed to launch … Device disconnected during socket operation (error 10002)` （瞬时隧道抖动，不是锁屏）。该次取回的是**上一次**的 ndjson；已加 `@meta` 校验（svc/type 必须与本次请求一致），该次产物已删除、未归档。
2. 全程 **0 次锁屏**（`passcodeRequired: false` 一直保持），所以 `@locked` 分支没被触发；`idleTimerDisabled=YES` 与「锁屏等 60s 再试、最多 10 分钟」的逻辑都在 `run.sh` 里就位。

## 2. 本轮最重要的机制事实：C7 判据不是万能的

任务书给的判据是「任意容量组合下 `kr != 0xE00002C7` ⇒ 该 selector 存在」。这条在**表驱动**服务上完全成立，但在**手写 switch** 服务上失效——因为它们的 `externalMethod` 对「不认识的 selector」返回的是 `kIOReturnBadArgument`（`0xE00002C2`）而不是 `Unsupported`。两者一混，`0xE00002C2` 就再也分不清是「没有这个 selector」还是「有，但入参契约不对」。

| 服务 | type | 机制 | 缺失 selector 的返回 | C7 判据 |
|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 0 | `IOExternalMethodDispatch` 表 + 越界返回 Unsupported | `0xE00002C7` | **有效** |
| `IOSurfaceRoot` | 0 | 手写 switch（default → BadArgument） | `0xE00002C2` | **失效（退化）** |
| `AGXAcceleratorG18P` | 1 | `IOExternalMethodDispatch` 表 + 越界返回 Unsupported | `0xE00002C7` | **有效** |
| `AGXAcceleratorG18P` | 33 | 手写 switch（default → BadArgument） | `0xE00002C2` | **失效（退化）** |
| `IOHIDEventService` | 2 | 手写 switch（default → BadArgument） | `0xE00002C2` | **失效（退化）** |
| `AppleJPEGDriver` | 0 | 手写 switch（default → BadArgument） | `0xE00002C2` | **失效（退化）** |
| `IOMobileFramebuffer` | 0 | 手写 switch（default → BadArgument） | `0xE00002C2` | **失效（退化）** |
| `AppleCLCD2` | 0 | 手写 switch（default → BadArgument） | `0xE00002C2` | **失效（退化）** |

退化服务的实测形态：`IOSurfaceRoot` / `IOHIDEventService` / `AppleJPEGDriver` / `IOMobileFramebuffer` / `AppleCLCD2` / `AGXAcceleratorG18P type 33` 在 0..N 上，**除个别命中（见各服务表 B）外**，每个 selector 的每个容量组合都返回 `0xE00002C2`，于是「存在 256 / 全 C7 0」这种数字没有任何信息量。

所以本轮加了第二个阶段 `contract`：把入参也扫一遍 —— `scalarIn ∈ {0,1,2,3,4}` × `structIn ∈ {0,8,64,156,664,4096}` × `scalarOut ∈ {0,1,2,4}` × `structOut ∈ {0,4096}` （每个 selector 最多 240 组，命中一组即停）。判据换成：**返回码离开 `0xE00002C2` ⇒ handler 真的跑了 ⇒ selector 存在**。

## 3. 每个 (服务, type) 一张表

### 3.0 总览

| 服务 | type | 阶梯扫过 | 阶梯判「存在」 | 全 C7（真不存在） | contract 命中 | 挂死 | 超时 |
|---|---|---|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 0 | 32 | 12 | 20 | 3 | 0 | 0 |
| `IOSurfaceRoot` | 0 | 256 | 256 | 0 | 7 | 0 | 0 |
| `AGXAcceleratorG18P` | 1 | 256 | 56 | 200 | 9 | 0 | 1 |
| `AGXAcceleratorG18P` | 33 | 256 | 256 | 0 | 2 | 0 | 0 |
| `IOHIDEventService` | 2 | 128 | 128 | 0 | 3 | 0 | 0 |
| `AppleJPEGDriver` | 0 | 64 | 64 | 0 | 5 | 0 | 0 |
| `IOMobileFramebuffer` | 0 | 128 | 128 | 0 | 47 | 0 | 0 |
| `AppleCLCD2` | 0 | 128 | 128 | 0 | 47 | 0 | 0 |


---

### 3.x `AppleM2ScalerCSCDriver`（type 0）

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **表驱动（C7 有效）** · 范围 `0..31`
- 记录：`@pre`/`@r` 各 320 条（阶梯，逐组合全记）· `@ct` 3 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/msc-exist-20261101-172109.ndjson` + `mscct-contract-20261101-172714.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
| 0 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 8 |
| 1 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 2 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 1 | 0 |
| 3 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 1 | 0 |
| 4 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 5 | 是 | (1,0)✓ | `0x00000000` SUCCESS | 1 | 0 |
| 6 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 7 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 8 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 9 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 10 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 11 | 是 | (0,0)✓ (1,0)✓ (2,0)✓ (8,0)✓ (16,0)✓ (0,8)✓ (0,64)✓ (0,4096)✓ (16,4096)✓ (0,3176)✓ | `0x00000000` SUCCESS | 0 | 0 |

**存在的 selector（12 个）**：`0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11`

**全 10 组容量都是 C7（确实不存在）**：20 个 → `12–31`


> 表 A 与表 B 不矛盾：表 A 证明**行存在**（同一个 selector 在 `(0,0)` 给 C7、在 `(0,8)` 给 C2，这个翻转本身就是「行在表里」的证据）；表 B 只证明**零入参 + 240 组输出容量里恰好撞上契约**的那 3 个。`sel 0–4 / 6 / 8–10` 的入参契约（旧轮解码出的 1~3 个 scalarIn）本轮没猜到，所以 contract 阶段没命中，但它们的存在性由表 A 成立。


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 5 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 7 | sin=0, sti=8 | soc=0, sst=0 | `0x00000001` 1(非标准) | 契约命中，handler 跑了 |
| 11 | sin=0, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |

**存在的 selector（contract 判据）**：`5, 7, 11`（3 个，扫过 32 个）

未命中的 29 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

### 3.x `IOSurfaceRoot`（type 0）

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **手写 switch（C7 退化）** · 范围 `0..255`
- 记录：`@pre`/`@r` 各 2560 条（阶梯，逐组合全记）· `@ct` 7 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/iosurf-exist-20261101-172118.ndjson` + `iosurfct-contract-20261101-172651.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

> 本服务 C7 判据失效，下表「存在」列只是形式记录：只要不等于 C7 就算「存在」，所以几乎全表都是 1。真正有意义的是表 B。

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
（退化：0..255 全部「不等于 C7」。见下方表 B。）


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 19 | sin=0, sti=8 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 30 | sin=1, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 32 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 36 | sin=1, sti=0 | soc=2, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 37 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002BF` kIOReturnIPCError | 契约命中，handler 跑了 |
| 38 | sin=1, sti=0 | soc=4, sst=0 | `0xE00002BF` kIOReturnIPCError | 契约命中，handler 跑了 |
| 45 | sin=3, sti=0 | soc=0, sst=0 | `0xE00002BF` kIOReturnIPCError | 契约命中，handler 跑了 |

**存在的 selector（contract 判据）**：`19, 30, 32, 36, 37, 38, 45`（7 个，扫过 256 个）

未命中的 249 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

### 3.x `AGXAcceleratorG18P`（type 1）

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **表驱动（C7 有效）** · 范围 `0..255`
- 记录：`@pre`/`@r` 各 2559 条（阶梯，逐组合全记）· `@ct` 9 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/agx1-exist-20261101-172139.ndjson` + `agx1ct-contract-20261101-172720.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
| 0 | 是 | (0,64)✓ | `0x00000000` SUCCESS | 0 | 64 |
| 1 | 是 | (0,64)✓ | `0x00000000` SUCCESS | 0 | 64 |
| 2 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 3 | 是 | (0,8)✓ | `0x00000000` SUCCESS | 0 | 8 |
| 4 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 5 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 6 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 7 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 8 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 9 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 10 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 11 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 12 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 13 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 14 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 15 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 16 | 是 | (0,8)✓ | `0x00000000` SUCCESS | 0 | 8 |
| 17 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 18 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 19 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 20 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 21 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 22 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 1 | 0 |
| 23 | 是 | (1,0)✓ | `0x00000000` SUCCESS | 1 | 0 |
| 24 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 25 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 26 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 27 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 28 | 是 | (2,0)✓ | `0x00000000` SUCCESS | 2 | 0 |
| 29 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 30 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 31 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 32 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 33 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 34 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 35 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 36 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 37 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 38 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 39 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 40 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 41 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 42 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 43 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 44 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 45 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 46 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 47 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 48 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 49 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 50 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 51 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 52 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 53 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 54 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 0 | 0 |
| 55 | 是 | 全 10 组都是 `0xE00002C2`（行存在、零入参契约不符） | `0xE00002C2` kIOReturnBadArgument | 1 | 0 |

**存在的 selector（56 个）**：`0–55`

**全 10 组容量都是 C7（确实不存在）**：200 个 → `56–255`


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 8 | sin=0, sti=156 | soc=0, sst=4096 | `0xE00002BE` kIOReturnNoResources | 契约命中，handler 跑了 |
| 23 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 28 | sin=0, sti=0 | soc=2, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 32 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 33 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 34 | sin=1, sti=0 | soc=1, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 41 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 42 | sin=2, sti=0 | soc=2, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 54 | sin=2, sti=0 | soc=1, sst=0 | `0xE00002E2` kIOReturnNotAttached | 契约命中，handler 跑了 |

**存在的 selector（contract 判据）**：`8, 23, 28, 32, 33, 34, 41, 42, 54`（9 个，扫过 64 个）

未命中的 55 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

### 3.x `AGXAcceleratorG18P`（type 33）

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **手写 switch（C7 退化）** · 范围 `0..255`
- 记录：`@pre`/`@r` 各 2560 条（阶梯，逐组合全记）· `@ct` 2 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/agx33-exist-20261101-172154.ndjson` + `agx33ct-contract-20261101-172655.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

> 本服务 C7 判据失效，下表「存在」列只是形式记录：只要不等于 C7 就算「存在」，所以几乎全表都是 1。真正有意义的是表 B。

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
（退化：0..255 全部「不等于 C7」。见下方表 B。）


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 0 | sin=0, sti=0 | soc=1, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 2 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |

**存在的 selector（contract 判据）**：`0, 2`（2 个，扫过 256 个）

未命中的 254 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

### 3.x `IOHIDEventService`（type 2）

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **手写 switch（C7 退化）** · 范围 `0..127`
- 记录：`@pre`/`@r` 各 1280 条（阶梯，逐组合全记）· `@ct` 3 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/hid-exist-20261101-172232.ndjson` + `hidct-contract-20261101-172632.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

> 本服务 C7 判据失效，下表「存在」列只是形式记录：只要不等于 C7 就算「存在」，所以几乎全表都是 1。真正有意义的是表 B。

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
（退化：0..127 全部「不等于 C7」。见下方表 B。）


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 0 | sin=1, sti=0 | soc=0, sst=0 | `0xE00002C5` kIOReturnExclusiveAccess | 契约命中，handler 跑了 |
| 1 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 2 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002CD` kIOReturnNotOpen | 契约命中，handler 跑了 |

**存在的 selector（contract 判据）**：`0, 1, 2`（3 个，扫过 128 个）

未命中的 125 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

### 3.x `AppleJPEGDriver`（type 0）

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **手写 switch（C7 退化）** · 范围 `0..63`
- 记录：`@pre`/`@r` 各 640 条（阶梯，逐组合全记）· `@ct` 5 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/jpeg-exist-20261101-172245.ndjson` + `jpegct-contract-20261101-172658.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

> 本服务 C7 判据失效，下表「存在」列只是形式记录：只要不等于 C7 就算「存在」，所以几乎全表都是 1。真正有意义的是表 B。

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
（退化：0..63 全部「不等于 C7」。见下方表 B。）


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 0 | sin=0, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 2 | sin=0, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 4 | sin=0, sti=4096 | soc=0, sst=4096 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 5 | sin=0, sti=4096 | soc=0, sst=4096 | `0xE00002CC` kIOReturnNotWritable | 契约命中，handler 跑了 |
| 9 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |

**存在的 selector（contract 判据）**：`0, 2, 4, 5, 9`（5 个，扫过 64 个）

未命中的 59 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

### 3.x `IOMobileFramebuffer`（type 0）

> `AppleCLCD2` 与 `IOMobileFramebuffer` 的命中集合与契约**逐条一致**（47 个、每一项入参都相同），符合「CLCD2 走的是同一套 IOFramebuffer externalMethod」的预期；两者 `sel 77` 回的地址不同，说明各自实例数据独立。

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **手写 switch（C7 退化）** · 范围 `0..127`
- 记录：`@pre`/`@r` 各 1280 条（阶梯，逐组合全记）· `@ct` 47 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/mfb-exist-20261101-172252.ndjson` + `mfbct-contract-20261101-172707.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

> 本服务 C7 判据失效，下表「存在」列只是形式记录：只要不等于 C7 就算「存在」，所以几乎全表都是 1。真正有意义的是表 B。

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
（退化：0..127 全部「不等于 C7」。见下方表 B。）


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 3 | sin=2, sti=0 | soc=1, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 4 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 6 | sin=3, sti=0 | soc=0, sst=0 | `0xE00002E3` kIOReturnNotPermitted | 契约命中，handler 跑了 |
| 7 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 8 | sin=0, sti=0 | soc=2, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 12 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 13 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 14 | sin=2, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 15 | sin=2, sti=0 | soc=1, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 18 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 19 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 20 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 22 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 23 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 25 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 26 | sin=0, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 28 | sin=0, sti=0 | soc=1, sst=0 | `0xE00002F0` kIOReturnNotReady | 契约命中，handler 跑了 |
| 31 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 33 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 49 | sin=1, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 51 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 53 | sin=2, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 56 | sin=0, sti=156 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 59 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 60 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 61 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 62 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 63 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 64 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 65 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 70 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 71 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 72 | sin=4, sti=0 | soc=0, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 77 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 78 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 80 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 81 | sin=2, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 82 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 83 | sin=1, sti=0 | soc=1, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 86 | sin=0, sti=0 | soc=1, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 88 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 89 | sin=1, sti=0 | soc=0, sst=0 | `0x00000001` 1(非标准) | 契约命中，handler 跑了 |
| 90 | sin=0, sti=0 | soc=1, sst=0 | `0xE00002F0` kIOReturnNotReady | 契约命中，handler 跑了 |
| 91 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 92 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 98 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 100 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |

**存在的 selector（contract 判据）**：`3–4, 6–8, 12–15, 18–20, 22–23, 25–26, 28, 31, 33, 49, 51, 53, 56, 59–65, 70–72, 77–78, 80–83, 86, 88–92, 98, 100`（47 个，扫过 128 个）

未命中的 81 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

### 3.x `AppleCLCD2`（type 0）

> `AppleCLCD2` 与 `IOMobileFramebuffer` 的命中集合与契约**逐条一致**（47 个、每一项入参都相同），符合「CLCD2 走的是同一套 IOFramebuffer externalMethod」的预期；两者 `sel 77` 回的地址不同，说明各自实例数据独立。

- `IOServiceOpen` → `SUCCESS`（found=1）· 机制 **手写 switch（C7 退化）** · 范围 `0..127`
- 记录：`@pre`/`@r` 各 1280 条（阶梯，逐组合全记）· `@ct` 47 条（contract，每 selector 一行）
- 原始：`harness/svcreenum/results/clcd-exist-20261101-172259.ndjson` + `clcdct-contract-20261101-172710.ndjson`

**表 A：输出容量阶梯**（10 组容量：`(0,0)(1,0)(2,0)(8,0)(16,0)(0,8)(0,64)(0,4096)(16,4096)(0,3176)`）

> 本服务 C7 判据失效，下表「存在」列只是形式记录：只要不等于 C7 就算「存在」，所以几乎全表都是 1。真正有意义的是表 B。

| selector | 阶梯判存在 | 哪组容量返回码离开 C7 | kr（首个） | oc | sc |
|---|---|---|---|---|---|
（退化：0..127 全部「不等于 C7」。见下方表 B。）


**表 B：`contract` 阶段 —— 真正命中的 selector（返回码离开 `0xE00002C2`）**

| selector | 命中的入参 | 出参容量 | kr | 含义 |
|---|---|---|---|---|
| 3 | sin=2, sti=0 | soc=1, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 4 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 6 | sin=3, sti=0 | soc=0, sst=0 | `0xE00002E3` kIOReturnNotPermitted | 契约命中，handler 跑了 |
| 7 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 8 | sin=0, sti=0 | soc=2, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 12 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 13 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 14 | sin=2, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 15 | sin=2, sti=0 | soc=1, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 18 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 19 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 20 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 22 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 23 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 25 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 26 | sin=0, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 28 | sin=0, sti=0 | soc=1, sst=0 | `0xE00002F0` kIOReturnNotReady | 契约命中，handler 跑了 |
| 31 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 33 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 49 | sin=1, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 51 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 53 | sin=2, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 56 | sin=0, sti=156 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 59 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 60 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 61 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 62 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 63 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 64 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 65 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 70 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 71 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002EA` kIOReturnNotFound | 契约命中，handler 跑了 |
| 72 | sin=4, sti=0 | soc=0, sst=0 | `0xE00002BC` kIOReturnError | 契约命中，handler 跑了 |
| 77 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 78 | sin=2, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 80 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 81 | sin=2, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 82 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 83 | sin=1, sti=0 | soc=1, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 86 | sin=0, sti=0 | soc=1, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |
| 88 | sin=1, sti=0 | soc=0, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 89 | sin=1, sti=0 | soc=0, sst=0 | `0x00000001` 1(非标准) | 契约命中，handler 跑了 |
| 90 | sin=0, sti=0 | soc=1, sst=0 | `0xE00002F0` kIOReturnNotReady | 契约命中，handler 跑了 |
| 91 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 92 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 98 | sin=0, sti=0 | soc=1, sst=0 | `0x00000000` SUCCESS | **契约命中 + SUCCESS** |
| 100 | sin=0, sti=0 | soc=0, sst=0 | `0xE00002C1` kIOReturnNotPrivileged | **有权就能过** |

**存在的 selector（contract 判据）**：`3–4, 6–8, 12–15, 18–20, 22–23, 25–26, 28, 31, 33, 49, 51, 53, 56, 59–65, 70–72, 77–78, 80–83, 86, 88–92, 98, 100`（47 个，扫过 128 个）

未命中的 81 个 selector 在 240 组入参×出参组合下**全部**返回 `0xE00002C2`，按「handler 没跑」判为非本 user client 的方法。


---

## 4. 与旧结论 `out/SVC2-PROBE.md` / `out/GPU-PROBE.md` 对比：哪些是被 `(0,0)` 抹掉的

| 服务 | type | 旧轮报的 SUCCESS | 本轮命中 | 旧轮没看见的 | 旧轮怎么说的 |
|---|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 0 | 1 个 | 12 个（阶梯存在） | **11 个**：`0–10` | `(0,0)` 下 sel 0/2 直接 `0xE00002C7`，旧轮据此判「不存在」 |
| `AGXAcceleratorG18P` | 1 | 17 个 | 56 个（阶梯存在） | **39 个**：`6–15, 18, 20, 22, 24–27, 29–31, 35–40, 43–55` | 0–55 存在性旧轮就拿到了；`(0,0)` 只让它看不见输出 |
| `IOHIDEventService` | 2 | 1 个 | 3 个（contract 命中） | **2 个**：`0, 2` | 逐表试「声明入参 + 0 输出」，需要输出的行被抹成 BadArgument |
| `AppleJPEGDriver` | 0 | 2 个 | 5 个（contract 命中） | **3 个**：`4–5, 9` | 同上 |
| `IOMobileFramebuffer` | 0 | 10 个 | 47 个（contract 命中） | **37 个**：`3–4, 6–8, 14–15, 18, 20, 23, 25, 28, 49, 59–65, 70–72, 77–78, 80–83, 86, 88–92, 98, 100` | 同上；旧轮只有 10 个撞上 SUCCESS |
| `AppleCLCD2` | 0 | 10 个 | 47 个（contract 命中） | **37 个**：`3–4, 6–8, 14–15, 18, 20, 23, 25, 28, 49, 59–65, 70–72, 77–78, 80–83, 86, 88–92, 98, 100` | 同上；旧轮只有 10 个撞上 SUCCESS |

**「被 `(0,0)` 抹掉的」严格的三种形态**（别混为一谈）：

1. **存在性被抹掉**（真·误判）：`AppleM2ScalerCSCDriver` 的 `sel 0–10`。同一 selector 在 `(0,0)` 下返回 `0xE00002C7`，在 `(0,8)` 下返回 `0xE00002C2` —— C7 与 C2 的分界线本身就证明这一行在表里。旧轮只跑了 `(0,0)`，于是把 11 个真实存在的 selector 判成不存在。
2. **契约被抹掉**（撞不上 SUCCESS）：`IOMobileFramebuffer` / `AppleCLCD2` 各从 10 个变 47 个、`IOHIDEventService` 1→3、`AppleJPEGDriver` 2→5。旧轮对每个 selector 只试「表里声明的输入 + 0 输出」，而 `scalarOutputCount=0` 会把需要输出的行整个抹掉，于是这些 selector 只剩下 BadArgument。
3. **输出被抹掉**（能过但看不见数据）：`AGXAcceleratorG18P type 1`。存在性与表大小旧轮就是对的（0–55），但旧轮说「14 个 SUCCESS、零字节回吐」；本轮 `sel 1 @ (0,64)` 直接回吐 ASCII **"AGXG18P"**，`sel 0` / `sel 3` / `sel 16` 也都有字节。零字节是 `(0,0)` 的产物，不是内核没写。

另外两个旧轮根本没扫的服务（`IOSurfaceRoot`、`AGXAcceleratorG18P type 33`）本轮给了基线：IOSurface 命中 7 个（`sel 19/32/36` SUCCESS、`sel 30` NotPrivileged、`sel 37/38/45` IPCError），type 33 只命中 2 个（`sel 0/2`，都是 NotPrivileged）。


---

## 5. `kr==0` 且内核真的写了输出（哨兵被打过）的清单 + hexdump

判据不是「`oc`/`sc` > 0」——那只是容量被回写成计数。真判据是**哨兵**：`scalarOut` 预填 `0xA5A5A5A5A5A5A5A5`、`structOut` 预填 `0x5A`，调用后没被打过就说明内核没写。

| 服务 | type | selector | 容量 | oc | sc | 写了什么 |
|---|---|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 0 | 5 | (1,0) | 1 | 0 | scalar； |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (1,0) | 1 | 0 | scalar； |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (2,0) | 2 | 0 | scalar； |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (8,0) | 8 | 0 | scalar； |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (16,0) | 16 | 0 | scalar； |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (0,8) | 0 | 8 | struct |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (0,64) | 0 | 64 | struct |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (0,4096) | 0 | 664 | struct |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (16,4096) | 16 | 664 | scalar；struct |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (0,3176) | 0 | 664 | struct |
| `IOSurfaceRoot` | 0 | 32 | (1,0) | 1 | 0 | scalar； |
| `AGXAcceleratorG18P` | 1 | 0 | (0,64) | 0 | 64 | struct |
| `AGXAcceleratorG18P` | 1 | 1 | (0,64) | 0 | 64 | struct |
| `AGXAcceleratorG18P` | 1 | 3 | (0,8) | 0 | 8 | struct |
| `AGXAcceleratorG18P` | 1 | 16 | (0,8) | 0 | 8 | struct |
| `AGXAcceleratorG18P` | 1 | 23 | (1,0) | 1 | 0 | scalar； |
| `AGXAcceleratorG18P` | 1 | 28 | (2,0) | 2 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 4 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 7 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 8 | (2,0) | 2 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 18 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 25 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 77 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 80 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 82 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 91 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 92 | (1,0) | 1 | 0 | scalar； |
| `IOMobileFramebuffer` | 0 | 98 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 4 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 7 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 8 | (2,0) | 2 | 0 | scalar； |
| `AppleCLCD2` | 0 | 18 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 25 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 77 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 80 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 82 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 91 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 92 | (1,0) | 1 | 0 | scalar； |
| `AppleCLCD2` | 0 | 98 | (1,0) | 1 | 0 | scalar； |


**内核写了标量的 selector（`@so`，**不是容量回写**：值与容量无关且不等于哨兵）**

| 服务 | type | selector | 容量 | 写入的标量值 |
|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 0 | 5 | (1,0) | `0x0000000000000001` |
| `AppleM2ScalerCSCDriver` | 0 | 11 | (1,0), (16,0), (16,4096), (2,0), (8,0) | `0x0000000000000000` |
| `IOSurfaceRoot` | 0 | 32 | (1,0) | `0x0000000102c48000` |
| `AGXAcceleratorG18P` | 1 | 23 | (1,0) | `0x0000000000000000` |
| `AGXAcceleratorG18P` | 1 | 28 | (2,0) | `0x0000000000000001, 0x000000002739e192` |
| `IOMobileFramebuffer` | 0 | 4 | (1,0) | `0x0000000000000002` |
| `IOMobileFramebuffer` | 0 | 7 | (1,0) | `0x0000000000000001` |
| `IOMobileFramebuffer` | 0 | 8 | (2,0) | `0x0000000000000492, 0x00000000000009e4` |
| `IOMobileFramebuffer` | 0 | 18 | (1,0) | `0x0000000000000000` |
| `IOMobileFramebuffer` | 0 | 25 | (1,0) | `0x0000000000000000` |
| `IOMobileFramebuffer` | 0 | 77 | (1,0) | `0x00000030aec27220` |
| `IOMobileFramebuffer` | 0 | 80 | (1,0) | `0xffffffffffffffff` |
| `IOMobileFramebuffer` | 0 | 82 | (1,0) | `0x0000000000000007` |
| `IOMobileFramebuffer` | 0 | 91 | (1,0) | `0x0000000000000000` |
| `IOMobileFramebuffer` | 0 | 92 | (1,0) | `0x0000000000000000` |
| `IOMobileFramebuffer` | 0 | 98 | (1,0) | `0x0000000000000000` |
| `AppleCLCD2` | 0 | 4 | (1,0) | `0x0000000000000003` |
| `AppleCLCD2` | 0 | 7 | (1,0) | `0x0000000000000001` |
| `AppleCLCD2` | 0 | 8 | (2,0) | `0x0000000000000492, 0x00000000000009e4` |
| `AppleCLCD2` | 0 | 18 | (1,0) | `0x0000000000000000` |
| `AppleCLCD2` | 0 | 25 | (1,0) | `0x0000000000000000` |
| `AppleCLCD2` | 0 | 77 | (1,0) | `0x00000030b8f8b1a8` |
| `AppleCLCD2` | 0 | 80 | (1,0) | `0xffffffffffffffff` |
| `AppleCLCD2` | 0 | 82 | (1,0) | `0x0000000000000007` |
| `AppleCLCD2` | 0 | 91 | (1,0) | `0x0000000000000000` |
| `AppleCLCD2` | 0 | 92 | (1,0) | `0x0000000000000000` |
| `AppleCLCD2` | 0 | 98 | (1,0) | `0x0000000000000000` |


**`AppleM2ScalerCSCDriver` type 0 · sel 11**（同一段字节在 (1,0), (2,0), (8,0), (16,0), (0,8), (0,64), (0,4096), (16,4096), (0,3176) 下完全一致；下表取最大那发 `sc=664`，dump 最多 512B，小端）

```
  0000  19 00 00 00 07 00 10 00 01 01 01 01 01 01 01 01  ................
  0010  01 01 01 00 01 01 01 01 01 01 01 01 01 01 01 01  ................
  0020  01 01 01 01 40 00 00 00 04 00 00 00 20 00 00 00  ....@....... ...
  0030  00 00 01 00 00 00 01 00 00 80 00 00 00 80 00 00  ................
  0040  04 00 00 00 00 00 01 00 00 00 01 00 00 00 00 00  ................
  0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00e0  00 00 00 00 00 00 00 00 00 01 00 00 fe ff 00 00  ................
  00f0  fe ff 00 00 fe ff 00 00 fe ff 00 00 02 00 00 00  ................
  0100  16 00 00 00 04 00 00 00 16 00 00 00 01 01 00 00  ................
  0110  04 00 00 00 16 00 00 00 04 00 00 00 04 00 00 00  ................
  0120  0c 00 00 00 01 00 00 01 08 00 00 00 04 00 00 00  ................
  0130  08 00 00 00 04 00 00 00 01 00 00 00 23 01 00 00  ............#...
  0140  53 01 00 00 03 00 00 00 00 00 00 00 00 00 00 00  S...............
  0150  01 00 00 00 40 00 00 00 08 00 00 00 80 00 00 00  ....@...........
  0160  01 00 00 00 00 00 00 00 01 00 00 00 00 00 01 00  ................
  0170  01 00 01 00 01 01 00 00 10 00 00 00 01 00 00 00  ................
  0180  00 01 01 01 01 00 00 00 00 00 00 00 00 00 00 40  ...............@
  0190  01 00 00 00 04 00 00 00 02 00 00 00 04 00 00 00  ................
  01a0  02 00 00 00 04 00 00 00 00 01 00 00 01 00 00 00  ................
  01b0  00 01 01 01 02 00 00 00 03 00 00 00 01 00 00 00  ................
  01c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................
  01d0  01 01 01 00 00 00 00 00 00 00 00 00 00 00 c0 40  ...............@
  01e0  00 00 00 00 00 00 40 40 00 01 01 01 01 01 00 01  ......@@........
  01f0  01 01 01 00 01 02 01 00 80 80 10 20 04 01 01 01  ........... ....
```

**`AGXAcceleratorG18P` type 1 · sel 0**（同一段字节在 (0,64) 下完全一致；下表取最大那发 `sc=64`，dump 最多 512B，小端）

```
  0000  40 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00  @C..............
  0010  00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00  ................
  0020  00 40 00 00 02 00 00 00 00 00 00 80 01 00 00 00  .@..............
  0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

**`AGXAcceleratorG18P` type 1 · sel 1**（同一段字节在 (0,64) 下完全一致；下表取最大那发 `sc=64`，dump 最多 512B，小端）

```
  0000  41 47 58 47 31 38 50 00 00 00 00 00 00 00 00 00  AGXG18P.........
  0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

**`AGXAcceleratorG18P` type 1 · sel 3**（同一段字节在 (0,8) 下完全一致；下表取最大那发 `sc=8`，dump 最多 512B，小端）

```
  0000  00 00 00 00 00 00 00 00                          ........
```

**`AGXAcceleratorG18P` type 1 · sel 16**（同一段字节在 (0,8) 下完全一致；下表取最大那发 `sc=8`，dump 最多 512B，小端）

```
  0000  90 e1 39 27 00 00 00 00                          ..9'....
```


---

## 6. 内核指针判读（严格 8 字节对齐，显式小端）

规则：8 字节窗口**只从 `off % 8 == 0` 开始**；同时另打一份 4 字节对齐 dword 视图，避免上一轮把 4 字节 `0x0000feff` 用未对齐 8 字节窗口读成 `0xfffe` 那类误判。分类只认两种真形态：`0xfffffe..`（kernel）与最高字节 `>= 0xF0`（pac/hi）。

- `AppleM2ScalerCSCDriver` type 0：**0** 个
- `IOSurfaceRoot` type 0：**0** 个
- `AGXAcceleratorG18P` type 1：**0** 个
- `AGXAcceleratorG18P` type 33：**0** 个
- `IOHIDEventService` type 2：**0** 个
- `AppleJPEGDriver` type 0：**0** 个
- `IOMobileFramebuffer` type 0：**0** 个
- `AppleCLCD2` type 0：**0** 个

**结论：全库 0 个 `0xfffffe...`，0 个 PAC 形态。** dump 里看起来像指针的值（例如 `0x0000004001010101`、`0x000000020000fffe`）都是**两个 32 位字段被 8 字节窗口读到一起**的产物：

- `0x000000020000fffe`（`AppleM2ScalerCSCDriver` sel 11 off 248）= dword[248] `0x0000fffe` + dword[252] `0x00000002`，按 4 字节对齐读，就是两个小整数，不是地址，也不是 PAC。
- `0x0000004001010101`（同段 off 32）= dword[32] `0x01010101` + dword[36] `0x00000040`。

**三个值得注意但不是内核 VA 的 64 位值**（都在 `scalarOut`，不是 structOut）：

| 服务 | sel | 值 | 判读 |
|---|---|---|---|
| `IOSurfaceRoot` | 32 | `0x0000000102c48000` | 32 位有效宽度、4KiB 对齐（页对齐），像 IOVA / 物理地址，不是 `0xfffffe..` 内核 VA |
| `IOMobileFramebuffer` | 77 | `0x00000030aec27220` | 与 CLCD2 的同一 selector 不同值（`0x30b8f8b1a8`），量级一致 —— 像两个 client 各自的 IOVA/句柄，不是内核 VA |
| `AppleCLCD2` | 77 | `0x00000030b8f8b1a8` | 同上 |

这三条都**不满足**「8 字节对齐读到 `0xfffffe...`」的停机条件，所以没有中断枚举；但它们是本轮 dump 里最接近「地址」的东西，值得单列。

按任务书边界，这一条**没有触发**（要 8 字节对齐读到 `0xfffffe...` 才停），所以枚举继续跑完了全部 8 个目标。


---

## 7. panic / 挂死 / 超时 / 锁屏

| 项 | 结果 |
|---|---|
| `ls -1 out/panics/*.ips \| wc -l` | 跑前 **5** → 跑后 **5**（全程 16 次 install/launch 都没变） |
| 新增 panic | **0** |
| `@timeout`（3s 单发超时） | **1** 次：`AGXAcceleratorG18P` type 1 `sel 55` @ `(0,0)`。**这条也有新解释**：紧接着的 `(1,0)` 立刻返回 `0xE00002C2`，后面 8 组容量全部正常返回 —— 所以「`sel 55` handler 永不返回」同样是 `(0,0)` 的产物，不是 handler 本身挂死。 |
| `@hang`（同一 selector 连挂 2 次即跳过） | 0（`sel 55` 只挂了 1 次就没再试同 selector） |
| 锁屏 / `@locked` | **0 次**（`passcodeRequired: false` 全程保持） |
| 设备重启 | **无** |
| 设备侧 `systemCrashLogs` | 未新增（与 `.ips` 计数一致） |


---

## 8. 原始 ndjson

| 服务 | type | 阶段 | 文件 | 行数 |
|---|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 0 | exist | `harness/svcreenum/results/msc-exist-20261101-172109.ndjson` | 1063 |
| `IOSurfaceRoot` | 0 | exist | `harness/svcreenum/results/iosurf-exist-20261101-172118.ndjson` | 5386 |
| `AGXAcceleratorG18P` | 1 | exist | `harness/svcreenum/results/agx1-exist-20261101-172139.ndjson` | 5408 |
| `AGXAcceleratorG18P` | 33 | exist | `harness/svcreenum/results/agx33-exist-20261101-172154.ndjson` | 5385 |
| `IOHIDEventService` | 2 | exist | `harness/svcreenum/results/hid-exist-20261101-172232.ndjson` | 2697 |
| `AppleJPEGDriver` | 0 | exist | `harness/svcreenum/results/jpeg-exist-20261101-172245.ndjson` | 1355 |
| `IOMobileFramebuffer` | 0 | exist | `harness/svcreenum/results/mfb-exist-20261101-172252.ndjson` | 2711 |
| `AppleCLCD2` | 0 | exist | `harness/svcreenum/results/clcd-exist-20261101-172259.ndjson` | 2711 |
| `AppleM2ScalerCSCDriver` | 0 | contract | `harness/svcreenum/results/mscct-contract-20261101-172714.ndjson` | 14 |
| `IOSurfaceRoot` | 0 | contract | `harness/svcreenum/results/iosurfct-contract-20261101-172651.ndjson` | 20 |
| `AGXAcceleratorG18P` | 1 | contract | `harness/svcreenum/results/agx1ct-contract-20261101-172720.ndjson` | 25 |
| `AGXAcceleratorG18P` | 33 | contract | `harness/svcreenum/results/agx33ct-contract-20261101-172655.ndjson` | 11 |
| `IOHIDEventService` | 2 | contract | `harness/svcreenum/results/hidct-contract-20261101-172632.ndjson` | 13 |
| `AppleJPEGDriver` | 0 | contract | `harness/svcreenum/results/jpegct-contract-20261101-172658.ndjson` | 16 |
| `IOMobileFramebuffer` | 0 | contract | `harness/svcreenum/results/mfbct-contract-20261101-172707.ndjson` | 83 |
| `AppleCLCD2` | 0 | contract | `harness/svcreenum/results/clcdct-contract-20261101-172710.ndjson` | 83 |

## 9. 边界

- 只做了 selector 存在性枚举 + 输出 dump。没跑竞态，没碰 `harness/israce/`，没改 `out/` 既有文件。
- 没有 `git` 操作，没有重启设备。
- `contract` 阶段是辅助扫描（每 selector 一行 `@ct`），因为它要压 2.4 万～6 万次调用；**阶梯阶段（`exist`）保持逐组合全记录**（`@pre` + `@r` 各一行），符合任务书的记录要求。

