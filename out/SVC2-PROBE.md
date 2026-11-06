# SVC2-PROBE — 剩余 5 个可打开服务的外方法面真机探查

设备 `DEVICE-UDID`（iPhone18,2 / iOS 27.0.1），根目录 `tasks/ios27-chain-poc`。

**一句话**：5 个服务全部开得了。第一轮按契约表扫完 **325 个（服务 × selector × 表）组合**，拿到 **27 个 SUCCESS 组合 / 23 个 distinct selector**；交叉扫描再加 1 个（AppleM2ScalerCSCDriver s=11，sti 0~4096 共 27 个变体）。**但没有任何一个成功 selector 回吐字节 —— 本轮零 hexdump、零内核指针**。同时踩出两个机制事实，会直接改下一轮的打法（见 §1）。

## 0. 五态 / 记录纪律

| 项 | 结果 |
|---|---|
| build | 每次 `xcrun -sdk iphoneos clang` rc=0（无 warning） |
| 指纹 | `strings Payload/UC.app/UC \| grep -c SVC2PROBE-20261101-extmethod-d7b3e2` = **1**（装前校验，残留 gpuprobe/svcprobe 指纹 0） |
| sign | `codesign -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)"` rc=0，Identifier=`com.example.ios27poc` |
| install | 每个 stage 都 `App installed`（同一 bundle id 覆盖安装） |
| launch | `devicectl process launch --console`，进程自退出 rc=0 |
| 跑完 | 每个 stage ndjson 都有 `@done` 尾标记 |
| panic | `ls -1 out/panics/*.ips \| wc -l`：**跑前 5 → 跑后 5**，无新增 |
| 挂死/超时 | **0 次**（`@timeout` 一条都没有） |
| 重启设备 | 无 |

注：第一轮 `hid` 跑完后设备**自动锁屏**（`passcodeRequired: true`），`mfb` / `clcd` 被 SBMainWorkspace 以 `Locked` 拒启动；已给 app 加 `idleTimerDisabled = YES`，并由 `wait_unlock_run.sh` 等解锁后自动续跑，后续 6 个 stage 均一次通过。

## 1. 两个机制事实（本轮最重要的产出，先讲）

### 1.1 `scalarInputCount > 16` 在 MIG 层就被拒，进不到 handler

任务书说「派发校验是精确相等」。输入侧确实如此，但还有一个更早的闸门。用 `IOHIDEventService`（已确证能开）sel 0 做单变量扫描：

| scalarInputCount | 返回 | 结论 |
|---|---|---|
| 0 | `0xe00002c2` kIOReturnBadArgument | 进了派发（契约是 si=1） |
| 1 | `0xe00002c5` kIOReturnExclusiveAccess | **契约命中，handler 跑了** |
| 2 / 3 / 4 / 8 / 16 | `0xe00002c2` | 仍进派发（契约不符） |
| **17 / 20 / 32 / 54 / 55 / 56 / 128 / 279 / 1048** | **`0xfffffecd` = -307 `MIG_REMOTE_ERROR`** | **没进派发，MIG 层直接拒** |

⇒ 派发表里 `scalarIn ≥ 17` 的那些行（本工程里就是 IOHIDFamily 表 `0xfffffe000b977d98` 的全部 10 行，si 54~1048）**根本不可调用**，拿到 -307 不代表表是死的，代表这一行永远试不出来。另外这张表的 10 行契约本身是累积尺寸（55/55、55/79、54/87、54/143、56/151…），结构不像 `IOExternalMethodDispatch` 记录，**倾向判定为解码错位，不是真表**。

`structIn` 侧没有这个闸门：0 / 8 / 55 / 512 / 2048 / 4096 / 8192 / 32768 / 32776 / 65536 全部返回 `kIOReturnBadArgument`（即都进了派发，只是契约不符）。

### 1.2 输出侧是 `容量 ≥ 声明`，不是精确相等

上一轮在 AGX 上得出「开大一点就 BadArgument」。这 5 个服务上**不成立**：

- `IOMobileFramebuffer` s=26：同一 selector 分别用 `so=0`（表 0x832fd70 的声明值）和 `so=1`（表 0x83308b0 的声明值）**都返回 SUCCESS**。若要求精确相等，两者只能中一个。
- 交叉扫描（§7）把 `so` 固定成 8、`sto` 固定成 4096（远大于任何声明值 0/16/72/3084），照样命中同一批 selector，且全部 `oc=0` / `sc=0`。

⇒ 输入（si/sti）必须**精确相等**，输出（so/sto）只要**容量 ≥ 声明**就放行。这条对下一轮有用：**输出可以一律开大**，不用再猜 declared 值；但输入契约必须逐个试对。

## 2. 方法

1. `IOServiceOpen(name, task, TYPE, &c)`，TYPE：`IOHIDEventService`=2，其余 4 个=0。
2. 对每个 selector 索引 `s`（0 → 该 kext 最大表条数 + 8），把该 kext **每张表第 s 条**契约都试一遍，表内不足 s+1 条就跳过。契约按声明值原样传：`scalarIn` 填 si 个 0、`structIn` 传 sti 字节全 0 缓冲、`scalarOut` 容量 = so、`structOut` 容量 = sto；wildcard(4294967295) 传 0。
3. 调用前先落 `@pre`（含 handler VA、四项声明值）并 `fflush`+`fsync`；调用后落 `@r`（kr/oc/sc）。`kr==0` 时追加 `@so`（标量输出）与 `@h`/`@dump`（structOut 16 字节一行 hexdump，上限 512B）以及 `@ptr`/`@ascii`（内核指针 / PAC / 16KB 页对齐 / 可打印串扫描）。
4. **阻塞防护**（上一轮 sel 55 挂死 150s 的教训）：每次 `IOConnectCallMethod` 跑在独立 pthread，主线程 `pthread_cond_timedwait` 等 **3s**；超时记 `@timeout` 并 **detach+泄漏** 该线程与缓冲区（不 join，不 free），主线程继续下一个组合；同一服务连续 3 次超时即 `@abort` 熔断。另有 200ms 心跳线程（`@hb` 里带当前 svc/s/契约），挂死点可直接定位；再加一个整轮看门狗（`@watchdog` + `exit(3)`）。每个服务一次独立进程运行，一个 stage 挂死不影响下一个。
5. 契约表不手抄：`gen_contract.py` 把 `out/svc_selectors.txt` 机械编译成 `harness/svc2probe/contract.h`。

套件：`harness/svc2probe/{main.m,contract.h,gen_contract.py,run.sh,analyze.py,wait_unlock_run.sh}`，结果在 `harness/svc2probe/results/`。`harness/israce/`、`out/` 既有文件均未改动。

## 3. 哪些 selector 返回 SUCCESS（最重要）

| 服务 | type | SUCCESS 的 selector | 命中的声明契约 | 输出字节 |
|---|---|---|---|---|
| IOHIDEventService | 2 | **1** | s1: 1/0/0/0 | `oc=0 sc=0`（零字节） |
| AppleJPEGDriver | 0 | **0, 2** | s0: 0/0/0/0; s2: 0/0/0/0 | `oc=0 sc=0`（零字节） |
| IOMobileFramebuffer | 0 | **12, 13, 19, 22, 26, 31, 33, 51, 53, 56** | s12: 1/0/0/0; s13: 1/0/0/0; s19: 1/0/0/0; s22: 1/0/0/0 / 1/0/0/0; s26: 0/0/0/0 / 0/0/1/0; s31: 1/0/0/0; s33: 1/0/0/0; s51: 1/0/0/0; s53: 2/0/0/0; s56: 0/156/0/0 | `oc=0 sc=0`（零字节） |
| AppleCLCD2 | 0 | **12, 13, 19, 22, 26, 31, 33, 51, 53, 56** | s12: 1/0/0/0; s13: 1/0/0/0; s19: 1/0/0/0; s22: 1/0/0/0 / 1/0/0/0; s26: 0/0/0/0 / 0/0/1/0; s31: 1/0/0/0; s33: 1/0/0/0; s51: 1/0/0/0; s53: 2/0/0/0; s56: 0/156/0/0 | `oc=0 sc=0`（零字节） |
| AppleM2ScalerCSCDriver | 0 | **11**（第一轮 0 个；由交叉扫描挖出） | s11: `0/任意(0~4096)/≤8/0`（sti 全放行） | `oc=0 sc=0`（零字节） |

**每一个 SUCCESS 的 `sc` 都是 0、`oc` 都是 0** —— 一个字节都没回吐，所以 §5 的 hexdump 是空的。这不是没 dump，是内核确实什么都没写。

## 4. 每个服务一张表

### 4.1 IOHIDEventService（type 2，kext `com.apple.iokit.IOHIDFamily`）

- 记录：`@pre` 39 条，`@r` 39 条，`@timeout` 0 条
- 原始文件：`harness/svc2probe/results/hid-20261101-161200.ndjson`

| selector | 表VA | 声明契约 si/sti/so/sto | kr | 含义 |
|---|---|---|---|---|
| 0 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c5` | kIOReturnExclusiveAccess |
| 0 | `0xfffffe000b977d98` | 55/0/0/55 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 0 | `0xfffffe000831f9a0` | 1/0/0/0 | `0xe00002c5` | kIOReturnExclusiveAccess |
| 0 | `0xfffffe000831e300` | 1/0/0/0 | `0xe00002c5` | kIOReturnExclusiveAccess |
| 1 | `0xfffffe0008313f98` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe000b977d98` | 55/0/0/79 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 1 | `0xfffffe000831f9a0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe000831e300` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 2 | `0xfffffe0008313f98` | 2/0/1/0 | `0xe00002cd` | kIOReturnNotOpen |
| 2 | `0xfffffe000b977d98` | 54/0/0/87 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 2 | `0xfffffe000831f9a0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 2 | `0xfffffe000831e300` | 2/0/0/0 | `0xe00002cd` | kIOReturnNotOpen |
| 3 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe000b977d98` | 54/0/0/143 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 3 | `0xfffffe000831f9a0` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe000831e300` | 3/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe0008313f98` | 3/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe000b977d98` | 56/0/0/151 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 4 | `0xfffffe000831f9a0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe000831e300` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 5 | `0xfffffe0008313f98` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 5 | `0xfffffe000b977d98` | 56/0/0/271 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 5 | `0xfffffe000831f9a0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 6 | `0xfffffe0008313f98` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 6 | `0xfffffe000b977d98` | 271/0/0/279 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 7 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe000b977d98` | 279/0/0/1048 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 8 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe000b977d98` | 1048/0/1/2048 | `0xfffffecd` | MIG_REMOTE_ERROR(-307) |
| 9 | `0xfffffe0008313f98` | 3/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 9 | `0xfffffe000b977d98` | 0/0/255/255 | `0xe00002c2` | kIOReturnBadArgument |
| 10 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 11 | `0xfffffe0008313f98` | 3/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 12 | `0xfffffe0008313f98` | 3/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 13 | `0xfffffe0008313f98` | 0/0/2/0 | `0xe00002c2` | kIOReturnBadArgument |
| 14 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 15 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 16 | `0xfffffe0008313f98` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 17 | `0xfffffe0008313f98` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |

非 `kIOReturnBadArgument` 的 selector（= 至少过了派发校验 / handler 有语义动作）：

| s | 表 | kr |
|---|---|---|
| 0 | `0xfffffe0008313f98` | kIOReturnExclusiveAccess |
| 0 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 0 | `0xfffffe000831f9a0` | kIOReturnExclusiveAccess |
| 0 | `0xfffffe000831e300` | kIOReturnExclusiveAccess |
| 1 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 1 | `0xfffffe000831e300` | SUCCESS |
| 2 | `0xfffffe0008313f98` | kIOReturnNotOpen |
| 2 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 2 | `0xfffffe000831e300` | kIOReturnNotOpen |
| 3 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 4 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 5 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 6 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 7 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |
| 8 | `0xfffffe000b977d98` | MIG_REMOTE_ERROR(-307) |

### 4.2 AppleJPEGDriver（type 0，kext `com.apple.driver.AppleJPEGDriver`）

- 记录：`@pre` 10 条，`@r` 10 条，`@timeout` 0 条
- 原始文件：`harness/svc2probe/results/jpeg-20261101-160731.ndjson`

| selector | 表VA | 声明契约 si/sti/so/sto | kr | 含义 |
|---|---|---|---|---|
| 0 | `0xfffffe00080dd990` | 0/0/0/0 | `0x00000000` | SUCCESS |
| 1 | `0xfffffe00080dd990` | 0/88/0/88 | `0xe00002c2` | kIOReturnBadArgument |
| 2 | `0xfffffe00080dd990` | 0/0/0/0 | `0x00000000` | SUCCESS |
| 3 | `0xfffffe00080dd990` | 0/88/0/88 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe00080dd990` | 0/4096/0/4096 | `0xe00002c2` | kIOReturnBadArgument |
| 5 | `0xfffffe00080dd990` | 0/4096/0/4096 | `0xe00002c2` | kIOReturnBadArgument |
| 6 | `0xfffffe00080dd990` | 0/3488/0/3488 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe00080dd990` | 0/3488/0/3488 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe00080dd990` | 0/4/0/0 | `0xe00002bc` | kIOReturnError |
| 9 | `0xfffffe00080dd990` | 0/0/0/0 | `0xe00002bc` | kIOReturnError |

非 `kIOReturnBadArgument` 的 selector（= 至少过了派发校验 / handler 有语义动作）：

| s | 表 | kr |
|---|---|---|
| 0 | `0xfffffe00080dd990` | SUCCESS |
| 2 | `0xfffffe00080dd990` | SUCCESS |
| 8 | `0xfffffe00080dd990` | kIOReturnError |
| 9 | `0xfffffe00080dd990` | kIOReturnError |

### 4.3 AppleM2ScalerCSCDriver（type 0，kext `com.apple.iokit.IOMobileGraphicsFamily`）

- 记录：`@pre` 92 条，`@r` 92 条，`@timeout` 0 条
- 原始文件：`harness/svc2probe/results/msc-20261101-160744.ndjson`

| selector | 表VA | 声明契约 si/sti/so/sto | kr | 含义 |
|---|---|---|---|---|
| 0 | `0xfffffe000832fd70` | 3/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 0 | `0xfffffe00083308b0` | 4/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 0 | `0xfffffe00083307c0` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 1 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe00083308b0` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe00083307c0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 2 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 2 | `0xfffffe00083308b0` | 1/0/2/64 | `0xe00002c2` | kIOReturnBadArgument |
| 2 | `0xfffffe00083307c0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe00083308b0` | 0/32776/0/0 | `0xe00002bf` | kIOReturnIPCError |
| 3 | `0xfffffe00083307c0` | 0/136/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 4 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 5 | `0xfffffe000832fd70` | 0/1760/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 5 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 6 | `0xfffffe000832fd70` | 3/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 6 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe000832fd70` | 0/0/2/0 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 9 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 9 | `0xfffffe00083308b0` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 10 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 10 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 11 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 11 | `0xfffffe00083308b0` | 1/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 12 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 12 | `0xfffffe00083308b0` | 0/4/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 13 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 13 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 14 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 14 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 15 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 15 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 16 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 16 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 17 | `0xfffffe000832fd70` | 0/3084/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 17 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 18 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 18 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 19 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 19 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 20 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 20 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 21 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 21 | `0xfffffe00083308b0` | 1/20/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 22 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 22 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 23 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 23 | `0xfffffe00083308b0` | 1/20/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 24 | `0xfffffe000832fd70` | 0/0/0/16 | `0xe00002c7` | kIOReturnUnsupported |
| 24 | `0xfffffe00083308b0` | 1/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 25 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 25 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 26 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 26 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 27 | `0xfffffe000832fd70` | 0/0/0/3084 | `0xe00002c7` | kIOReturnUnsupported |
| 27 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 28 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 28 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 29 | `0xfffffe000832fd70` | 0/0/0/8 | `0xe00002c7` | kIOReturnUnsupported |
| 30 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 31 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 32 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 33 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 34 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 35 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 36 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 37 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 38 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 39 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 40 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 41 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 42 | `0xfffffe000832fd70` | 0/0/0/20 | `0xe00002c7` | kIOReturnUnsupported |
| 43 | `0xfffffe000832fd70` | 0/4/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 44 | `0xfffffe000832fd70` | 0/16/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 45 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 46 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 47 | `0xfffffe000832fd70` | 4/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 48 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 49 | `0xfffffe000832fd70` | 1/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 50 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 51 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 52 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 53 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 54 | `0xfffffe000832fd70` | 1/0/0/72 | `0xe00002c7` | kIOReturnUnsupported |
| 55 | `0xfffffe000832fd70` | 1/72/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 56 | `0xfffffe000832fd70` | 0/156/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 57 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 58 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |

非 `kIOReturnBadArgument` 的 selector（= 至少过了派发校验 / handler 有语义动作）：

| s | 表 | kr |
|---|---|---|
| 0 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 0 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 0 | `0xfffffe00083307c0` | kIOReturnUnsupported |
| 2 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 3 | `0xfffffe00083308b0` | kIOReturnIPCError |
| 3 | `0xfffffe00083307c0` | kIOReturnUnsupported |
| 12 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 12 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 13 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 13 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 14 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 14 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 15 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 15 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 16 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 16 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 17 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 17 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 18 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 18 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 19 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 19 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 20 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 20 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 21 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 21 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 22 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 22 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 23 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 23 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 24 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 24 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 25 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 25 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 26 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 26 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 27 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 27 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 28 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 28 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 29 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 30 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 31 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 32 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 33 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 34 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 35 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 36 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 37 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 38 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 39 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 40 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 41 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 42 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 43 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 44 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 45 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 46 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 47 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 48 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 49 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 50 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 51 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 52 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 53 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 54 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 55 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 56 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 57 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 58 | `0xfffffe000832fd70` | kIOReturnUnsupported |

### 4.4 IOMobileFramebuffer（type 0，kext `com.apple.iokit.IOMobileGraphicsFamily`）

- 记录：`@pre` 92 条，`@r` 92 条，`@timeout` 0 条
- 原始文件：`harness/svc2probe/results/mfb-20261101-161203.ndjson`

| selector | 表VA | 声明契约 si/sti/so/sto | kr | 含义 |
|---|---|---|---|---|
| 0 | `0xfffffe000832fd70` | 3/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 0 | `0xfffffe00083308b0` | 4/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 0 | `0xfffffe00083307c0` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 1 | `0xfffffe00083308b0` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe00083307c0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 2 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 2 | `0xfffffe00083308b0` | 1/0/2/64 | `0xe00002c2` | kIOReturnBadArgument |
| 2 | `0xfffffe00083307c0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe00083308b0` | 0/32776/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe00083307c0` | 0/136/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 5 | `0xfffffe000832fd70` | 0/1760/0/0 | `0xe00002bc` | kIOReturnError |
| 5 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 6 | `0xfffffe000832fd70` | 3/0/0/0 | `0xe00002e3` | kIOReturnNoPower |
| 6 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe000832fd70` | 0/0/2/0 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 9 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 9 | `0xfffffe00083308b0` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 10 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 10 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 11 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 11 | `0xfffffe00083308b0` | 1/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 12 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 12 | `0xfffffe00083308b0` | 0/4/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 13 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 13 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 14 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 14 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 15 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 15 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 16 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 16 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 17 | `0xfffffe000832fd70` | 0/3084/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 17 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 18 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 18 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 19 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 19 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 20 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002bc` | kIOReturnError |
| 20 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 21 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 21 | `0xfffffe00083308b0` | 1/20/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 22 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 22 | `0xfffffe00083308b0` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 23 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c1` | kIOReturnNotPrivileged |
| 23 | `0xfffffe00083308b0` | 1/20/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 24 | `0xfffffe000832fd70` | 0/0/0/16 | `0xe00002c2` | kIOReturnBadArgument |
| 24 | `0xfffffe00083308b0` | 1/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 25 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 25 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 26 | `0xfffffe000832fd70` | 0/0/0/0 | `0x00000000` | SUCCESS |
| 26 | `0xfffffe00083308b0` | 0/0/1/0 | `0x00000000` | SUCCESS |
| 27 | `0xfffffe000832fd70` | 0/0/0/3084 | `0xe00002c2` | kIOReturnBadArgument |
| 27 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 28 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 28 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 29 | `0xfffffe000832fd70` | 0/0/0/8 | `0xe00002c2` | kIOReturnBadArgument |
| 30 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 31 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 32 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 33 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 34 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 35 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 36 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 37 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 38 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 39 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 40 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 41 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 42 | `0xfffffe000832fd70` | 0/0/0/20 | `0xe00002c2` | kIOReturnBadArgument |
| 43 | `0xfffffe000832fd70` | 0/4/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 44 | `0xfffffe000832fd70` | 0/16/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 45 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 46 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 47 | `0xfffffe000832fd70` | 4/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 48 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 49 | `0xfffffe000832fd70` | 1/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 50 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 51 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 52 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 53 | `0xfffffe000832fd70` | 2/0/0/0 | `0x00000000` | SUCCESS |
| 54 | `0xfffffe000832fd70` | 1/0/0/72 | `0xe00002c2` | kIOReturnBadArgument |
| 55 | `0xfffffe000832fd70` | 1/72/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 56 | `0xfffffe000832fd70` | 0/156/0/0 | `0x00000000` | SUCCESS |
| 57 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 58 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |

非 `kIOReturnBadArgument` 的 selector（= 至少过了派发校验 / handler 有语义动作）：

| s | 表 | kr |
|---|---|---|
| 0 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 1 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 1 | `0xfffffe00083307c0` | kIOReturnUnsupported |
| 2 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 5 | `0xfffffe000832fd70` | kIOReturnError |
| 6 | `0xfffffe000832fd70` | kIOReturnNoPower |
| 9 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 9 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 10 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 11 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 12 | `0xfffffe000832fd70` | SUCCESS |
| 13 | `0xfffffe000832fd70` | SUCCESS |
| 16 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 16 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 17 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 19 | `0xfffffe000832fd70` | SUCCESS |
| 20 | `0xfffffe000832fd70` | kIOReturnError |
| 21 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 22 | `0xfffffe000832fd70` | SUCCESS |
| 22 | `0xfffffe00083308b0` | SUCCESS |
| 23 | `0xfffffe000832fd70` | kIOReturnNotPrivileged |
| 26 | `0xfffffe000832fd70` | SUCCESS |
| 26 | `0xfffffe00083308b0` | SUCCESS |
| 30 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 31 | `0xfffffe000832fd70` | SUCCESS |
| 32 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 33 | `0xfffffe000832fd70` | SUCCESS |
| 34 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 35 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 36 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 37 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 38 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 39 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 40 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 41 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 43 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 44 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 45 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 46 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 50 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 51 | `0xfffffe000832fd70` | SUCCESS |
| 53 | `0xfffffe000832fd70` | SUCCESS |
| 56 | `0xfffffe000832fd70` | SUCCESS |
| 58 | `0xfffffe000832fd70` | kIOReturnUnsupported |

### 4.5 AppleCLCD2（type 0，kext `com.apple.iokit.IOMobileGraphicsFamily`）

- 记录：`@pre` 92 条，`@r` 92 条，`@timeout` 0 条
- 原始文件：`harness/svc2probe/results/clcd-20261101-161206.ndjson`

| selector | 表VA | 声明契约 si/sti/so/sto | kr | 含义 |
|---|---|---|---|---|
| 0 | `0xfffffe000832fd70` | 3/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 0 | `0xfffffe00083308b0` | 4/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 0 | `0xfffffe00083307c0` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 1 | `0xfffffe00083308b0` | 2/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 1 | `0xfffffe00083307c0` | 0/0/1/0 | `0xe00002c7` | kIOReturnUnsupported |
| 2 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 2 | `0xfffffe00083308b0` | 1/0/2/64 | `0xe00002c2` | kIOReturnBadArgument |
| 2 | `0xfffffe00083307c0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe00083308b0` | 0/32776/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 3 | `0xfffffe00083307c0` | 0/136/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 4 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 5 | `0xfffffe000832fd70` | 0/1760/0/0 | `0xe00002bc` | kIOReturnError |
| 5 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 6 | `0xfffffe000832fd70` | 3/0/0/0 | `0xe00002e3` | kIOReturnNoPower |
| 6 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 7 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe000832fd70` | 0/0/2/0 | `0xe00002c2` | kIOReturnBadArgument |
| 8 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 9 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 9 | `0xfffffe00083308b0` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 10 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 10 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 11 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 11 | `0xfffffe00083308b0` | 1/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 12 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 12 | `0xfffffe00083308b0` | 0/4/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 13 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 13 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 14 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 14 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 15 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 15 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 16 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 16 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 17 | `0xfffffe000832fd70` | 0/3084/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 17 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 18 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 18 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 19 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 19 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 20 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002bc` | kIOReturnError |
| 20 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 21 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 21 | `0xfffffe00083308b0` | 1/20/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 22 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 22 | `0xfffffe00083308b0` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 23 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c1` | kIOReturnNotPrivileged |
| 23 | `0xfffffe00083308b0` | 1/20/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 24 | `0xfffffe000832fd70` | 0/0/0/16 | `0xe00002c2` | kIOReturnBadArgument |
| 24 | `0xfffffe00083308b0` | 1/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 25 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 25 | `0xfffffe00083308b0` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 26 | `0xfffffe000832fd70` | 0/0/0/0 | `0x00000000` | SUCCESS |
| 26 | `0xfffffe00083308b0` | 0/0/1/0 | `0x00000000` | SUCCESS |
| 27 | `0xfffffe000832fd70` | 0/0/0/3084 | `0xe00002c2` | kIOReturnBadArgument |
| 27 | `0xfffffe00083308b0` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 28 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 28 | `0xfffffe00083308b0` | 0/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 29 | `0xfffffe000832fd70` | 0/0/0/8 | `0xe00002c2` | kIOReturnBadArgument |
| 30 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 31 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 32 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 33 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 34 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 35 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 36 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 37 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 38 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 39 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 40 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 41 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 42 | `0xfffffe000832fd70` | 0/0/0/20 | `0xe00002c2` | kIOReturnBadArgument |
| 43 | `0xfffffe000832fd70` | 0/4/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 44 | `0xfffffe000832fd70` | 0/16/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 45 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 46 | `0xfffffe000832fd70` | 0/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 47 | `0xfffffe000832fd70` | 4/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 48 | `0xfffffe000832fd70` | 2/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 49 | `0xfffffe000832fd70` | 1/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 50 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |
| 51 | `0xfffffe000832fd70` | 1/0/0/0 | `0x00000000` | SUCCESS |
| 52 | `0xfffffe000832fd70` | 1/0/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 53 | `0xfffffe000832fd70` | 2/0/0/0 | `0x00000000` | SUCCESS |
| 54 | `0xfffffe000832fd70` | 1/0/0/72 | `0xe00002c2` | kIOReturnBadArgument |
| 55 | `0xfffffe000832fd70` | 1/72/0/0 | `0xe00002c2` | kIOReturnBadArgument |
| 56 | `0xfffffe000832fd70` | 0/156/0/0 | `0x00000000` | SUCCESS |
| 57 | `0xfffffe000832fd70` | 0/0/1/0 | `0xe00002c2` | kIOReturnBadArgument |
| 58 | `0xfffffe000832fd70` | 2/0/0/0 | `0xe00002c7` | kIOReturnUnsupported |

非 `kIOReturnBadArgument` 的 selector（= 至少过了派发校验 / handler 有语义动作）：

| s | 表 | kr |
|---|---|---|
| 0 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 1 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 1 | `0xfffffe00083307c0` | kIOReturnUnsupported |
| 2 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 5 | `0xfffffe000832fd70` | kIOReturnError |
| 6 | `0xfffffe000832fd70` | kIOReturnNoPower |
| 9 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 9 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 10 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 11 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 12 | `0xfffffe000832fd70` | SUCCESS |
| 13 | `0xfffffe000832fd70` | SUCCESS |
| 16 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 16 | `0xfffffe00083308b0` | kIOReturnUnsupported |
| 17 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 19 | `0xfffffe000832fd70` | SUCCESS |
| 20 | `0xfffffe000832fd70` | kIOReturnError |
| 21 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 22 | `0xfffffe000832fd70` | SUCCESS |
| 22 | `0xfffffe00083308b0` | SUCCESS |
| 23 | `0xfffffe000832fd70` | kIOReturnNotPrivileged |
| 26 | `0xfffffe000832fd70` | SUCCESS |
| 26 | `0xfffffe00083308b0` | SUCCESS |
| 30 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 31 | `0xfffffe000832fd70` | SUCCESS |
| 32 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 33 | `0xfffffe000832fd70` | SUCCESS |
| 34 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 35 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 36 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 37 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 38 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 39 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 40 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 41 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 43 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 44 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 45 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 46 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 50 | `0xfffffe000832fd70` | kIOReturnUnsupported |
| 51 | `0xfffffe000832fd70` | SUCCESS |
| 53 | `0xfffffe000832fd70` | SUCCESS |
| 56 | `0xfffffe000832fd70` | SUCCESS |
| 58 | `0xfffffe000832fd70` | kIOReturnUnsupported |

## 5. 成功 selector 的 hexdump 与内核指针

**无可贴内容：全部 SUCCESS 组合的 `structOutputSize` 回填值 `sc = 0`，`scalarOutputCount` 回填值 `oc = 0`。**

因此：

- `@h` / `@dump` / `@ptr` / `@ascii` 记录数：**0**。
- 没发现 `0xfffffe...`、没发现 PAC 形态（高字节 ≥ 0xf0）、没发现 16KB 页对齐值、没发现可打印 ASCII。
- **本项目第一个内核信息泄露原语仍未出现**；本轮不给这个结论。

值得说明的是：交叉扫描用 `sto = 4096`（远大于任何声明值）去调这批成功 selector，handler 依旧一个字节都不写。所以就「handler 按用户给的 `structureOutputSize` 越界写」这一类（EXTMETHOD-AUDIT §6 那 12 个「用而不校验」）来说，**这 5 个服务的用户客户端不是它的落点**。

## 6. 哪些表是活的

判定纪律：`SUCCESS` / `ExclusiveAccess` / `NotOpen` / `NotPrivileged` / `IPCError` / `IOReturnError` 这类**带语义**的返回 ⇒ 该契约命中了在用入口（handler 真的跑了）；`kIOReturnUnsupported` ⇒ 该 selector 在这个连接上**没有入口**；`kIOReturnBadArgument` ⇒ 可能是契约不符，**也可能是 handler 自己校验参数后返回**，所以「全 BadArgument」不能反证表是死的。

### 6.1 IOHIDEventService（type 2）：在用的表**不在** `svc_selectors.txt` 里

把 s=0/1/2 的命中反推成「在用契约」：

| s | 唯一能过的契约 | 排除依据 |
|---|---|---|
| 0 | `si=1`（so=0） | `si=1` 的三张表全 → ExclusiveAccess；`si=0/2/3` → BadArgument |
| 1 | `si=1, sti=0, so=0` | 同表策略下只有声明 `1/0/0/0` 的 `0xfffffe000831e300` → SUCCESS |
| 2 | `si=2, sti=0, so=0` | `si=2` 的两条都 → NotOpen；但若在用 `so=1`，传 `so=0` 会被拦成 BadArgument（§1.2），实测放行 ⇒ 在用 `so=0` |

但 s=3/4 把结论推翻：`0xfffffe000831e300` 的 idx3=`3/0/0/0`、idx4=`0/0/0/0` 分别照原样传，**都是 BadArgument**。三张候选表在 s≥3 全部对不上。

对账后的解释（`out/CENSUS-DISPATCH-TABLES.md` §3 行 235）：census 在 IOHIDFamily 找到 **5 张表 / 42 条**，而 `out/svc_selectors.txt` 只收了 **4 张 / 39 条**。
**差的正好是一张 3 条的表**，而它在用形态正是 idx0=`1/0/0/0`、idx1=`1/0/0/0`、idx2=`2/0/0/0`。

⇒ 结论：**type 2 连接的在用派发表是 census 那张没进 `svc_selectors.txt` 的 3 条表**；另外 4 张表（含 `0xfffffe000b977d98`）都不是它，其中 `0xb977d98` 连试都试不了（§1.1）。**下一轮第一件事：把那张 3 条表取出来**（census 有它的 VA，只是没进契约文件）。

### 6.2 AppleJPEGDriver：唯一的表是活的

`0xfffffe00080dd990`（10 条）：s=0（`0/0/0/0`）与 s=2（`0/0/0/0`）→ **SUCCESS**；s=8（`0/4/0/0`）与 s=9（`0/0/0/0`）→ `kIOReturnError`（handler 跑了，内部报错）。⇒ 这张表就是在用表，10 条里至少 4 条能进 handler。

注意 s=1/3/4/5/6/7 全部 BadArgument：它们的声明都是「sti=sto=88/4096/3488」，全零内容进去后被 handler 判非法（JPEG 头校验），**不是表死了**。下轮想推这几个，得构造合法 JPEG 头（`FF D8 FF ...`）。

### 6.3 IOMobileGraphicsFamily：3 张表里 `0xfffffe000832fd70` 是活的

census 对该 kext 报 **3 张表 / 92 条**，与 `svc_selectors.txt` 完全一致（59+29+4），没有缺口。
证据链：

- s=31 / 33 / 51 / 53 / 56 **只有 `0xfffffe000832fd70` 有对应行**（`0x83308b0` 只有 29 条），而这 5 个全部 SUCCESS / 有语义返回 ⇒ 在用的是 `0x832fd70`。
- s=22 / 26 两张表契约相同（`1/0/0/0` 与 `0/0/0/0` vs `0/0/1/0`），行为无法区分，但这只影响「归属标注」，不影响「该 selector 可用」。
- `0x83307c0`（4 条）唯一响应是 s=1 → **Unsupported**，是「索引不存在」，不是命中。

**与静态图的对照**（`out/MOBILEGFX-MAP.md`，同工作区另一条线在 16:14 产出，标注「等真机 selector 探测结果对照」）：该文把 `0x83308b0` 的**第 6、7 条**标为四个字段全 wildcard（「IOKit 完全不校验」），并把它当作新的可达面。本轮真机数据**不支持**这个读法：

- MFB s=6 用 `0x83308b0` 的 `W/W/W/W`（实际传 0/0/0/0）→ **kIOReturnBadArgument**；s=7 同样 BadArgument。
- 同一 s=6，用 `0x832fd70` 的 `3/0/0/0` → **kIOReturnNoPower**（`0xe00002e3`，handler 跑了）。

⇒ 这两个连接（`IOMobileFramebuffer` type 0 / `AppleCLCD2` type 0）的在用表是 `0x832fd70`，`0x83308b0` 的 wildcard 行**不是它们的入口**；那张表的 wildcard 行要另找可达服务（`IOMobileGraphicsFamily-DCP` 或别的 type）才有意义。**「wildcard ⇒ 不校验 ⇒ 可达」这一步不能省掉可达性验证**。

### 6.4 AppleM2ScalerCSCDriver：不走这三张表

s=0/2/12~58 大片 `kIOReturnUnsupported`（该索引无入口），静态表契约试探几乎全灭；census 给它报的是 `1 张表 / 2 条（置信度 C）`，形态可疑。唯一活口是 s=11，而且是**行为驱动**才发现的（§7/§8.1）——与任务书「静态 0 张表、手写 switch」的判断吻合：**它对 selector 的解析不走契约表**，而是自己看结构体内容。

### 6.5 归属汇总

| 服务 | 在用入口来源 | 状态 |
|---|---|---|
| IOHIDEventService | census 的**第 5 张表**（3 条，未进 `svc_selectors.txt`） | 需补表；已反推出 3 条在用契约 |
| AppleJPEGDriver | `0xfffffe00080dd990`（10 条） | 已确认，s=0/2 成功 |
| IOMobileFramebuffer | `0xfffffe000832fd70`（59 条） | 已确认，10 个成功 selector |
| AppleCLCD2 | `0xfffffe000832fd70`（同上，行为与 MFB 完全一致） | 已确认 |
| AppleM2ScalerCSCDriver | 手写 switch，非契约表 | s=11 可用，其余待内容探测 |

## 7. 交叉扫描（把输入契约和「表内索引」解耦）

第一轮等价于假设「静态表索引 == selector」。既然输出侧可以一律开大（§1.2），就能把输入契约 (si,sti) 单独拎出来交叉试：`s × 该 kext 出现过的所有 (si,sti)`，`so=8`、`sto=4096`。

| 服务 | 候选 (si,sti) 对数 | 交叉组合数 | SUCCESS | 与第一轮相比 |
|---|---|---|---|---|
| IOMobileFramebuffer | 14 | 952 | 10 | 同 10 个（s=12/13/19/22/26/31/33/51/53/56），无新增 |
| AppleCLCD2 | 14 | 952 | 10 | 同 10 个（与 MFB 完全一致），无新增 |
| AppleM2ScalerCSCDriver | 14 | 952 | 7 | **新增 s=11**（第一轮全 BadArgument/Unsupported 里没挖出来） |

**M2Scaler s=11 是本轮唯一的「新挖出来」的东西**，详见 §8。

## 8. 定向网格（只在「声明了 structOut / 大 structIn」的索引上做）

`si ∈ {0..4} × sti ∈ {0,4,8,…,4096}`，输出 `so=8 / sto=4096`。
只把**不是 BadArgument** 的记进日志。

| 服务 | s 范围 | 命中（非 BadArgument） |
|---|---|---|
| IOMobileFramebuffer | 5 | s=5 `si=0 sti=1760` → kIOReturnError（与静态行 0/1760/0/0 一致） |
| IOMobileFramebuffer | 17 | s=17 → Unsupported（该索引无入口） |
| IOMobileFramebuffer | 24–29 | s=26 `si=0 sti=0` → SUCCESS；s=24/27/29 的 `sto=16/3084/8` 声明行全部试不出（输入侧对不上） |
| IOMobileFramebuffer | 42–44 | s=43 `sti=4` 与 s=44 `sti=16` 都是 Unsupported ⇒ 这两个索引无入口 |
| IOMobileFramebuffer | 54–56 | s=56 `si=0 sti=156` → SUCCESS |
| AppleM2ScalerCSCDriver | 11 | **s=11 `si=0` + sti ∈ {0,4,8,12,16,20,24,32,40,48,56,64,72,80,88,96,128,136,156,176,256,512,1024,1760,3084,4096} 全部 SUCCESS**（26/26） |

### 8.1 AppleM2ScalerCSCDriver sel 11：`structureInput` 尺寸不受约束

| si | sti | kr |
|---|---|---|
| 0 | 0 / 4 / 8 / 12 / 16 / 20 / 24 / 32 / 40 / 48 / 56 / 64 / 72 / 80 / 88 / 96 / 128 / 136 / 156 / 176 / 256 / 512 / 1024 / 1760 / 3084 / 4096 | **SUCCESS**（26 个值全中） |
| 0 | 32776 | `0xe00002bf` kIOReturnIPCError |
| 1 / 2 / 3 / 4 | 0（或 20 / 72） | `kIOReturnBadArgument` |

读法：这个入口的 `scalarInputCount` 必须精确为 0，`structureInputSize` **基本不校验**（0~4096 全放行，32776 才报错），`structureOutput` 声明值 ≤ 8（我们给 8 就够）且**一个字节都不写**。也就是说：

- 这是一个**长度不受约束的用户可控内核输入通道**，非常像「手写 switch + 命令缓冲区」（首 4/8 字节当 opcode，其余当参数），全零内容正好落在命令 0，所以恒 SUCCESS。
- 下一轮该做的不是继续试契约，而是**改 `structIn` 内容**：首 4/8 字节换成 1、2、3… 探命令空间，再按命令填结构体；同时留意 `sti` 只有到 32776 才报错这一事实给出的上限线索。
- 这一条是本轮最值得继续投的东西，但它**还不是泄露原语**：现在只能证明「输入可控且不限长」，没有任何内核字节回来。

## 9. 挂死 / 超时 / panic 三态分开记

| 类别 | 数量 | 明细 |
|---|---|---|
| 挂死（内核调用不返回） | **0** | 本轮一次都没触发；3s 线程级超时 + 3 次熔断 + 200ms 心跳 + 整轮看门狗都就位但未用到 |
| 超时（`@timeout`） | **0** | 325 条契约 + 2856 条交叉 + 1950 条网格（共 5131 次 `IOConnectCallMethod`），全部在 3s 内返回 |
| panic（新增 `.ips`） | **0** | `out/panics/*.ips` 5 → 5 |
| 阴性（BadArgument / Unsupported） | 绝大多数 | 见 §4 各表 |

与上一轮的对比：上一轮 AGX `sel 55` 一次调用永久挂死、150s 后被看门狗收；本轮同样的调用形态（含 `si`/`sto` 更大、`sti` 到 32776）**没有任何一次超过 3s**。所以「AGX sel 55 挂死」是那个 handler 自己死锁，不是这条调用路径的通病。

## 10. 原始 ndjson（逐字）

约定：`@pre` 调用前、`@r` 调用后、`@h` hexdump、`@so` 标量输出、`@ptr`/`@ascii` 模式命中、`@timeout` 超时、`@abort` 熔断、`@cal` 校准、`@x*` 交叉扫描、`@g*` 定向网格。所有行都在调用前后 `fflush`+`fsync`，进程被杀也不丢已写出的行。

### 10.1 `hid-20261101-161200.ndjson`

```json
{"k":"@meta","fp":"SVC2PROBE-20261101-extmethod-d7b3e2","build":"Nov  1 2026 16:11:57","ios":"27.0.1","model":"iPhone","want":"hid","s_from":0,"s_to":4096,"wd":300,"rows":141,"timeout_s":3,"max_timeouts_per_stage":3}
{"k":"@stage","svc":"IOHIDEventService","kext":"com.apple.iokit.IOHIDFamily","type":2,"tabs":4,"maxn":18,"s_from":0,"s_to":26}
{"k":"@open","svc":"IOHIDEventService","found":1,"type":2,"kr":0,"krn":"SUCCESS","conn":24323}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":0,"h":"0xfffffe000a0aca1c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":0,"kr":3758097093,"krn":"kIOReturnExclusiveAccess","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":0,"h":"0xfffffe000a0dc050","si":55,"sti":0,"so":0,"sto":55}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":0,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":0,"h":"0xfffffe000a0f86a8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":0,"kr":3758097093,"krn":"kIOReturnExclusiveAccess","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":0,"h":"0xfffffe000a0f5e74","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":0,"kr":3758097093,"krn":"kIOReturnExclusiveAccess","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":1,"h":"0xfffffe000a0aca2c","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":1,"h":"0xfffffe000a0dc050","si":55,"sti":0,"so":0,"sto":79}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":1,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":1,"h":"0xfffffe000a0f86b4","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":1,"h":"0xfffffe000a0f5eb0","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":1,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":1,"n":0,"v":[]}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":2,"h":"0xfffffe000a0aca4c","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":2,"kr":3758097101,"krn":"kIOReturnNotOpen","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":2,"h":"0xfffffe000a0dc050","si":54,"sti":0,"so":0,"sto":87}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":2,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":2,"h":"0xfffffe000a0f86d4","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":2,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":2,"h":"0xfffffe000a11fe3c","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":2,"kr":3758097101,"krn":"kIOReturnNotOpen","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":3,"h":"0xfffffe000a0aca68","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":3,"h":"0xfffffe000a0dc050","si":54,"sti":0,"so":0,"sto":143}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":3,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":3,"h":"0xfffffe000a0f86e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":3,"h":"0xfffffe000a0f5ee4","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":4,"h":"0xfffffe000a0acab0","si":3,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":4,"h":"0xfffffe000a0dc050","si":56,"sti":0,"so":0,"sto":151}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":4,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":4,"h":"0xfffffe000a0f86ec","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":4,"h":"0xfffffe000a120114","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831e300","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":5,"h":"0xfffffe000a0acb04","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":5,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":5,"h":"0xfffffe000a0dc050","si":56,"sti":0,"so":0,"sto":271}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":5,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":5,"h":"0xfffffe000a0f8748","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000831f9a0","s":5,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":6,"h":"0xfffffe000a0acb58","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":6,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":6,"h":"0xfffffe000a0dc0b8","si":271,"sti":0,"so":0,"sto":279}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":6,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":7,"h":"0xfffffe000a0acbb0","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":7,"h":"0xfffffe000a0dc0b8","si":279,"sti":0,"so":0,"sto":1048}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":7,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":8,"h":"0xfffffe000a0acbf8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":8,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":8,"h":"0xfffffe000a0dc0b8","si":1048,"sti":0,"so":1,"sto":2048}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":8,"kr":4294966989,"krn":"MIG_REMOTE_ERROR","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":9,"h":"0xfffffe000a105bf4","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":9,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":9,"h":"0xfffffe000a0dc0f8","si":0,"sti":0,"so":255,"sto":255}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe000b977d98","s":9,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":10,"h":"0xfffffe000a0acc40","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":10,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":11,"h":"0xfffffe000a0ace3c","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":11,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":12,"h":"0xfffffe000a0ad19c","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":12,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":13,"h":"0xfffffe000a0ad3b4","si":0,"sti":0,"so":2,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":13,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":14,"h":"0xfffffe000a0ad3c4","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":14,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":15,"h":"0xfffffe000a0ad3f4","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":15,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":16,"h":"0xfffffe000a0ad458","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":16,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":17,"h":"0xfffffe000a0ad468","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOHIDEventService","tab":"0xfffffe0008313f98","s":17,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@svcdone","svc":"IOHIDEventService","timeouts":0}
{"k":"@done","t":14,"timeouts":0}
```

### 10.2 `jpeg-20261101-160731.ndjson`

```json
{"k":"@meta","fp":"SVC2PROBE-20261101-extmethod-d7b3e2","build":"Nov  1 2026 16:07:27","ios":"27.0.1","model":"iPhone","want":"jpeg","s_from":0,"s_to":4096,"wd":200,"rows":141,"timeout_s":3,"max_timeouts_per_stage":3}
{"k":"@stage","svc":"AppleJPEGDriver","kext":"com.apple.driver.AppleJPEGDriver","type":0,"tabs":1,"maxn":10,"s_from":0,"s_to":18}
{"k":"@open","svc":"AppleJPEGDriver","found":1,"type":0,"kr":0,"krn":"SUCCESS","conn":26371}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":0,"h":"0xfffffe0009016358","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":0,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":0,"n":0,"v":[]}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":1,"h":"0xfffffe0009016364","si":0,"sti":88,"so":0,"sto":88}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":2,"h":"0xfffffe0009016398","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":2,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":2,"n":0,"v":[]}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":3,"h":"0xfffffe00090163a4","si":0,"sti":88,"so":0,"sto":88}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":4,"h":"0xfffffe00090163d8","si":0,"sti":4096,"so":0,"sto":4096}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":5,"h":"0xfffffe000901640c","si":0,"sti":4096,"so":0,"sto":4096}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":5,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":6,"h":"0xfffffe0009016440","si":0,"sti":3488,"so":0,"sto":3488}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":6,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":7,"h":"0xfffffe0009016474","si":0,"sti":3488,"so":0,"sto":3488}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":8,"h":"0xfffffe00090164a8","si":0,"sti":4,"so":0,"sto":0}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":8,"kr":3758097084,"krn":"kIOReturnError","oc":0,"sc":0}
{"k":"@pre","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":9,"h":"0xfffffe00090164d8","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleJPEGDriver","tab":"0xfffffe00080dd990","s":9,"kr":3758097084,"krn":"kIOReturnError","oc":0,"sc":0}
{"k":"@svcdone","svc":"AppleJPEGDriver","timeouts":0}
{"k":"@done","t":4,"timeouts":0}
```

### 10.3 `msc-20261101-160744.ndjson`

```json
{"k":"@meta","fp":"SVC2PROBE-20261101-extmethod-d7b3e2","build":"Nov  1 2026 16:07:41","ios":"27.0.1","model":"iPhone","want":"msc","s_from":0,"s_to":4096,"wd":200,"rows":141,"timeout_s":3,"max_timeouts_per_stage":3}
{"k":"@stage","svc":"AppleM2ScalerCSCDriver","kext":"com.apple.iokit.IOMobileGraphicsFamily","type":0,"tabs":3,"maxn":59,"s_from":0,"s_to":67}
{"k":"@open","svc":"AppleM2ScalerCSCDriver","found":1,"type":0,"kr":0,"krn":"SUCCESS","conn":29443}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":0,"h":"0xfffffe000a17dc14","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":0,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":0,"h":"0xfffffe000a17f178","si":4,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":0,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":0,"h":"0xfffffe000a17e1b8","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":0,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":1,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":1,"h":"0xfffffe000a17f190","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":1,"h":"0xfffffe000a17e1f8","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":2,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":2,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":2,"h":"0xfffffe000a17f20c","si":1,"sti":0,"so":2,"sto":64}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":2,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":2,"h":"0xfffffe000a17e804","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":2,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":3,"h":"0xfffffe000a17dc5c","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":3,"h":"0xfffffe000a17f6d4","si":0,"sti":32776,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":3,"kr":3758097087,"krn":"OTHER","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":3,"h":"0xfffffe000a17f66c","si":0,"sti":136,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083307c0","s":3,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":4,"h":"0xfffffe000a17dd8c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":4,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":5,"h":"0xfffffe000a17ddd0","si":0,"sti":1760,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":5,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":5,"h":"0xfffffe000a17f6e4","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":5,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":6,"h":"0xfffffe000a17de58","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":6,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":6,"h":"0xfffffe000a17e264","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":6,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":7,"h":"0xfffffe000a17e02c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":7,"h":"0xfffffe000a17e35c","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":8,"h":"0xfffffe000a17e088","si":0,"sti":0,"so":2,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":8,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":8,"h":"0xfffffe000a17f738","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":8,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":9,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":9,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":9,"h":"0xfffffe000a17df18","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":9,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":10,"h":"0xfffffe000a17e900","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":10,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":10,"h":"0xfffffe000a17f58c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":10,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":11,"h":"0xfffffe000a17e940","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":11,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":11,"h":"0xfffffe000a17dcec","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":11,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":12,"h":"0xfffffe000a17e984","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":12,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":12,"h":"0xfffffe000a17ef68","si":0,"sti":4,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":12,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":13,"h":"0xfffffe000a17e994","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":13,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":13,"h":"0xfffffe000a17e438","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":13,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":14,"h":"0xfffffe000a17ea10","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":14,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":14,"h":"0xfffffe000a17e684","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":14,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":15,"h":"0xfffffe000a17ea84","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":15,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":15,"h":"0xfffffe000a17f840","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":15,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":16,"h":"0xfffffe000a17eaf8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":16,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":16,"h":"0xfffffe000a17f790","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":16,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":17,"h":"0xfffffe000a17eb38","si":0,"sti":3084,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":17,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":17,"h":"0xfffffe000a17eddc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":17,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":18,"h":"0xfffffe000a17eb8c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":18,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":18,"h":"0xfffffe000a17f050","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":18,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":19,"h":"0xfffffe000a17ebe8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":19,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":19,"h":"0xfffffe000a17df5c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":19,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":20,"h":"0xfffffe000a17ed14","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":20,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":20,"h":"0xfffffe000a17dfc4","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":20,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":21,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":21,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":21,"h":"0xfffffe000a17e4b8","si":1,"sti":20,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":21,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":22,"h":"0xfffffe000a17ed58","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":22,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":22,"h":"0xfffffe000a17e51c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":22,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":23,"h":"0xfffffe000a17ed98","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":23,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":23,"h":"0xfffffe000a17e57c","si":1,"sti":20,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":23,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":24,"h":"0xfffffe000a17ee24","si":0,"sti":0,"so":0,"sto":16}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":24,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":24,"h":"0xfffffe000a17e5e0","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":24,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":25,"h":"0xfffffe000a17ee60","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":25,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":25,"h":"0xfffffe000a17e3dc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":25,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":26,"h":"0xfffffe000a17eea4","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":26,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":26,"h":"0xfffffe000a17f880","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":26,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":27,"h":"0xfffffe000a17eee8","si":0,"sti":0,"so":0,"sto":3084}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":27,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":27,"h":"0xfffffe000a17e774","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":27,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":28,"h":"0xfffffe000a17efe8","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":28,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":28,"h":"0xfffffe000a17e714","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe00083308b0","s":28,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":29,"h":"0xfffffe000a17f0bc","si":0,"sti":0,"so":0,"sto":8}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":29,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":30,"h":"0xfffffe000a17f0f8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":30,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":31,"h":"0xfffffe000a17f138","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":31,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":32,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":32,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":33,"h":"0xfffffe000a17f29c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":33,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":34,"h":"0xfffffe000a17f2dc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":34,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":35,"h":"0xfffffe000a17f31c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":35,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":36,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":36,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":37,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":37,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":38,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":38,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":39,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":39,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":40,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":40,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":41,"h":"0xfffffe000a17f35c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":41,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":42,"h":"0xfffffe000a17f3a4","si":0,"sti":0,"so":0,"sto":20}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":42,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":43,"h":"0xfffffe000a17f3f8","si":0,"sti":4,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":43,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":44,"h":"0xfffffe000a17f44c","si":0,"sti":16,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":44,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":45,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":45,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":46,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":46,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":47,"h":"0xfffffe000a17f4a0","si":4,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":47,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":48,"h":"0xfffffe000a17f50c","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":48,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":49,"h":"0xfffffe000a17f5f8","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":49,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":50,"h":"0xfffffe000a17ecd4","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":50,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":51,"h":"0xfffffe000a17ec28","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":51,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":52,"h":"0xfffffe000a17ded8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":52,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":53,"h":"0xfffffe000a17e0f8","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":53,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":54,"h":"0xfffffe000a17efa4","si":1,"sti":0,"so":0,"sto":72}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":54,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":55,"h":"0xfffffe000a17ef24","si":1,"sti":72,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":55,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":56,"h":"0xfffffe000a17e13c","si":0,"sti":156,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":56,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":57,"h":"0xfffffe000a17ec68","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":57,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":58,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleM2ScalerCSCDriver","tab":"0xfffffe000832fd70","s":58,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@svcdone","svc":"AppleM2ScalerCSCDriver","timeouts":0}
{"k":"@done","t":29,"timeouts":0}
```

### 10.4 `mfb-20261101-161203.ndjson`

```json
{"k":"@meta","fp":"SVC2PROBE-20261101-extmethod-d7b3e2","build":"Nov  1 2026 16:12:00","ios":"27.0.1","model":"iPhone","want":"mfb","s_from":0,"s_to":4096,"wd":300,"rows":141,"timeout_s":3,"max_timeouts_per_stage":3}
{"k":"@stage","svc":"IOMobileFramebuffer","kext":"com.apple.iokit.IOMobileGraphicsFamily","type":0,"tabs":3,"maxn":59,"s_from":0,"s_to":67}
{"k":"@open","svc":"IOMobileFramebuffer","found":1,"type":0,"kr":0,"krn":"SUCCESS","conn":28931}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":0,"h":"0xfffffe000a17dc14","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":0,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":0,"h":"0xfffffe000a17f178","si":4,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":0,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":0,"h":"0xfffffe000a17e1b8","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":0,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":1,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":1,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":1,"h":"0xfffffe000a17f190","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":1,"h":"0xfffffe000a17e1f8","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":1,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":2,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":2,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":2,"h":"0xfffffe000a17f20c","si":1,"sti":0,"so":2,"sto":64}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":2,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":2,"h":"0xfffffe000a17e804","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":2,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":3,"h":"0xfffffe000a17dc5c","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":3,"h":"0xfffffe000a17f6d4","si":0,"sti":32776,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":3,"h":"0xfffffe000a17f66c","si":0,"sti":136,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083307c0","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":4,"h":"0xfffffe000a17dd8c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":4,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":5,"h":"0xfffffe000a17ddd0","si":0,"sti":1760,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":5,"kr":3758097084,"krn":"kIOReturnError","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":5,"h":"0xfffffe000a17f6e4","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":5,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":6,"h":"0xfffffe000a17de58","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":6,"kr":3758097123,"krn":"OTHER","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":6,"h":"0xfffffe000a17e264","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":6,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":7,"h":"0xfffffe000a17e02c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":7,"h":"0xfffffe000a17e35c","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":8,"h":"0xfffffe000a17e088","si":0,"sti":0,"so":2,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":8,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":8,"h":"0xfffffe000a17f738","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":8,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":9,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":9,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":9,"h":"0xfffffe000a17df18","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":9,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":10,"h":"0xfffffe000a17e900","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":10,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":10,"h":"0xfffffe000a17f58c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":10,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":11,"h":"0xfffffe000a17e940","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":11,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":11,"h":"0xfffffe000a17dcec","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":11,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":12,"h":"0xfffffe000a17e984","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":12,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":12,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":12,"h":"0xfffffe000a17ef68","si":0,"sti":4,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":12,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":13,"h":"0xfffffe000a17e994","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":13,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":13,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":13,"h":"0xfffffe000a17e438","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":13,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":14,"h":"0xfffffe000a17ea10","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":14,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":14,"h":"0xfffffe000a17e684","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":14,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":15,"h":"0xfffffe000a17ea84","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":15,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":15,"h":"0xfffffe000a17f840","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":15,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":16,"h":"0xfffffe000a17eaf8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":16,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":16,"h":"0xfffffe000a17f790","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":16,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":17,"h":"0xfffffe000a17eb38","si":0,"sti":3084,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":17,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":17,"h":"0xfffffe000a17eddc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":17,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":18,"h":"0xfffffe000a17eb8c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":18,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":18,"h":"0xfffffe000a17f050","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":18,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":19,"h":"0xfffffe000a17ebe8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":19,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":19,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":19,"h":"0xfffffe000a17df5c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":19,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":20,"h":"0xfffffe000a17ed14","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":20,"kr":3758097084,"krn":"kIOReturnError","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":20,"h":"0xfffffe000a17dfc4","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":20,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":21,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":21,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":21,"h":"0xfffffe000a17e4b8","si":1,"sti":20,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":21,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":22,"h":"0xfffffe000a17ed58","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":22,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":22,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":22,"h":"0xfffffe000a17e51c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":22,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":22,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":23,"h":"0xfffffe000a17ed98","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":23,"kr":3758097089,"krn":"kIOReturnNotPrivileged","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":23,"h":"0xfffffe000a17e57c","si":1,"sti":20,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":23,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":24,"h":"0xfffffe000a17ee24","si":0,"sti":0,"so":0,"sto":16}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":24,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":24,"h":"0xfffffe000a17e5e0","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":24,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":25,"h":"0xfffffe000a17ee60","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":25,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":25,"h":"0xfffffe000a17e3dc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":25,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":26,"h":"0xfffffe000a17eea4","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":26,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":26,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":26,"h":"0xfffffe000a17f880","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":26,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":26,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":27,"h":"0xfffffe000a17eee8","si":0,"sti":0,"so":0,"sto":3084}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":27,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":27,"h":"0xfffffe000a17e774","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":27,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":28,"h":"0xfffffe000a17efe8","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":28,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":28,"h":"0xfffffe000a17e714","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe00083308b0","s":28,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":29,"h":"0xfffffe000a17f0bc","si":0,"sti":0,"so":0,"sto":8}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":29,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":30,"h":"0xfffffe000a17f0f8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":30,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":31,"h":"0xfffffe000a17f138","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":31,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":31,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":32,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":32,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":33,"h":"0xfffffe000a17f29c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":33,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":33,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":34,"h":"0xfffffe000a17f2dc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":34,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":35,"h":"0xfffffe000a17f31c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":35,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":36,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":36,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":37,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":37,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":38,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":38,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":39,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":39,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":40,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":40,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":41,"h":"0xfffffe000a17f35c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":41,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":42,"h":"0xfffffe000a17f3a4","si":0,"sti":0,"so":0,"sto":20}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":42,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":43,"h":"0xfffffe000a17f3f8","si":0,"sti":4,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":43,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":44,"h":"0xfffffe000a17f44c","si":0,"sti":16,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":44,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":45,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":45,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":46,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":46,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":47,"h":"0xfffffe000a17f4a0","si":4,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":47,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":48,"h":"0xfffffe000a17f50c","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":48,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":49,"h":"0xfffffe000a17f5f8","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":49,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":50,"h":"0xfffffe000a17ecd4","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":50,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":51,"h":"0xfffffe000a17ec28","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":51,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":51,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":52,"h":"0xfffffe000a17ded8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":52,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":53,"h":"0xfffffe000a17e0f8","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":53,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":53,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":54,"h":"0xfffffe000a17efa4","si":1,"sti":0,"so":0,"sto":72}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":54,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":55,"h":"0xfffffe000a17ef24","si":1,"sti":72,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":55,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":56,"h":"0xfffffe000a17e13c","si":0,"sti":156,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":56,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":56,"n":0,"v":[]}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":57,"h":"0xfffffe000a17ec68","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":57,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":58,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"IOMobileFramebuffer","tab":"0xfffffe000832fd70","s":58,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@svcdone","svc":"IOMobileFramebuffer","timeouts":0}
{"k":"@done","t":35,"timeouts":0}
```

### 10.5 `clcd-20261101-161206.ndjson`

```json
{"k":"@meta","fp":"SVC2PROBE-20261101-extmethod-d7b3e2","build":"Nov  1 2026 16:12:03","ios":"27.0.1","model":"iPhone","want":"clcd","s_from":0,"s_to":4096,"wd":300,"rows":141,"timeout_s":3,"max_timeouts_per_stage":3}
{"k":"@stage","svc":"AppleCLCD2","kext":"com.apple.iokit.IOMobileGraphicsFamily","type":0,"tabs":3,"maxn":59,"s_from":0,"s_to":67}
{"k":"@open","svc":"AppleCLCD2","found":1,"type":0,"kr":0,"krn":"SUCCESS","conn":24079}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":0,"h":"0xfffffe000a17dc14","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":0,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":0,"h":"0xfffffe000a17f178","si":4,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":0,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":0,"h":"0xfffffe000a17e1b8","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":0,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":1,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":1,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":1,"h":"0xfffffe000a17f190","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":1,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":1,"h":"0xfffffe000a17e1f8","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":1,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":2,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":2,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":2,"h":"0xfffffe000a17f20c","si":1,"sti":0,"so":2,"sto":64}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":2,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":2,"h":"0xfffffe000a17e804","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":2,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":3,"h":"0xfffffe000a17dc5c","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":3,"h":"0xfffffe000a17f6d4","si":0,"sti":32776,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":3,"h":"0xfffffe000a17f66c","si":0,"sti":136,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083307c0","s":3,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":4,"h":"0xfffffe000a17dd8c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":4,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":4,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":5,"h":"0xfffffe000a17ddd0","si":0,"sti":1760,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":5,"kr":3758097084,"krn":"kIOReturnError","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":5,"h":"0xfffffe000a17f6e4","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":5,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":6,"h":"0xfffffe000a17de58","si":3,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":6,"kr":3758097123,"krn":"OTHER","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":6,"h":"0xfffffe000a17e264","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":6,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":7,"h":"0xfffffe000a17e02c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":7,"h":"0xfffffe000a17e35c","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":7,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":8,"h":"0xfffffe000a17e088","si":0,"sti":0,"so":2,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":8,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":8,"h":"0xfffffe000a17f738","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":8,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":9,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":9,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":9,"h":"0xfffffe000a17df18","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":9,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":10,"h":"0xfffffe000a17e900","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":10,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":10,"h":"0xfffffe000a17f58c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":10,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":11,"h":"0xfffffe000a17e940","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":11,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":11,"h":"0xfffffe000a17dcec","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":11,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":12,"h":"0xfffffe000a17e984","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":12,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":12,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":12,"h":"0xfffffe000a17ef68","si":0,"sti":4,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":12,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":13,"h":"0xfffffe000a17e994","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":13,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":13,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":13,"h":"0xfffffe000a17e438","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":13,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":14,"h":"0xfffffe000a17ea10","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":14,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":14,"h":"0xfffffe000a17e684","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":14,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":15,"h":"0xfffffe000a17ea84","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":15,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":15,"h":"0xfffffe000a17f840","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":15,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":16,"h":"0xfffffe000a17eaf8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":16,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":16,"h":"0xfffffe000a17f790","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":16,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":17,"h":"0xfffffe000a17eb38","si":0,"sti":3084,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":17,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":17,"h":"0xfffffe000a17eddc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":17,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":18,"h":"0xfffffe000a17eb8c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":18,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":18,"h":"0xfffffe000a17f050","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":18,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":19,"h":"0xfffffe000a17ebe8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":19,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":19,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":19,"h":"0xfffffe000a17df5c","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":19,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":20,"h":"0xfffffe000a17ed14","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":20,"kr":3758097084,"krn":"kIOReturnError","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":20,"h":"0xfffffe000a17dfc4","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":20,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":21,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":21,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":21,"h":"0xfffffe000a17e4b8","si":1,"sti":20,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":21,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":22,"h":"0xfffffe000a17ed58","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":22,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":22,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":22,"h":"0xfffffe000a17e51c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":22,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":22,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":23,"h":"0xfffffe000a17ed98","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":23,"kr":3758097089,"krn":"kIOReturnNotPrivileged","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":23,"h":"0xfffffe000a17e57c","si":1,"sti":20,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":23,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":24,"h":"0xfffffe000a17ee24","si":0,"sti":0,"so":0,"sto":16}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":24,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":24,"h":"0xfffffe000a17e5e0","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":24,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":25,"h":"0xfffffe000a17ee60","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":25,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":25,"h":"0xfffffe000a17e3dc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":25,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":26,"h":"0xfffffe000a17eea4","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":26,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":26,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":26,"h":"0xfffffe000a17f880","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":26,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":26,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":27,"h":"0xfffffe000a17eee8","si":0,"sti":0,"so":0,"sto":3084}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":27,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":27,"h":"0xfffffe000a17e774","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":27,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":28,"h":"0xfffffe000a17efe8","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":28,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":28,"h":"0xfffffe000a17e714","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe00083308b0","s":28,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":29,"h":"0xfffffe000a17f0bc","si":0,"sti":0,"so":0,"sto":8}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":29,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":30,"h":"0xfffffe000a17f0f8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":30,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":31,"h":"0xfffffe000a17f138","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":31,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":31,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":32,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":32,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":33,"h":"0xfffffe000a17f29c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":33,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":33,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":34,"h":"0xfffffe000a17f2dc","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":34,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":35,"h":"0xfffffe000a17f31c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":35,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":36,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":36,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":37,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":37,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":38,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":38,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":39,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":39,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":40,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":40,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":41,"h":"0xfffffe000a17f35c","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":41,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":42,"h":"0xfffffe000a17f3a4","si":0,"sti":0,"so":0,"sto":20}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":42,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":43,"h":"0xfffffe000a17f3f8","si":0,"sti":4,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":43,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":44,"h":"0xfffffe000a17f44c","si":0,"sti":16,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":44,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":45,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":45,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":46,"h":"0xfffffe000a17f8e0","si":0,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":46,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":47,"h":"0xfffffe000a17f4a0","si":4,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":47,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":48,"h":"0xfffffe000a17f50c","si":2,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":48,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":49,"h":"0xfffffe000a17f5f8","si":1,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":49,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":50,"h":"0xfffffe000a17ecd4","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":50,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":51,"h":"0xfffffe000a17ec28","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":51,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":51,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":52,"h":"0xfffffe000a17ded8","si":1,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":52,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":53,"h":"0xfffffe000a17e0f8","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":53,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":53,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":54,"h":"0xfffffe000a17efa4","si":1,"sti":0,"so":0,"sto":72}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":54,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":55,"h":"0xfffffe000a17ef24","si":1,"sti":72,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":55,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":56,"h":"0xfffffe000a17e13c","si":0,"sti":156,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":56,"kr":0,"krn":"SUCCESS","oc":0,"sc":0}
{"k":"@so","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":56,"n":0,"v":[]}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":57,"h":"0xfffffe000a17ec68","si":0,"sti":0,"so":1,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":57,"kr":3758097090,"krn":"kIOReturnBadArgument","oc":0,"sc":0}
{"k":"@pre","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":58,"h":"0xfffffe000a17f8e0","si":2,"sti":0,"so":0,"sto":0}
{"k":"@r","svc":"AppleCLCD2","tab":"0xfffffe000832fd70","s":58,"kr":3758097095,"krn":"kIOReturnUnsupported","oc":0,"sc":0}
{"k":"@svcdone","svc":"AppleCLCD2","timeouts":0}
{"k":"@done","t":33,"timeouts":0}
```

### 10.6 `cal-20261101-160716.ndjson`（MIG 校准）

```json
{"k":"@meta","fp":"SVC2PROBE-20261101-extmethod-d7b3e2","build":"Nov  1 2026 16:07:13","ios":"27.0.1","model":"iPhone","want":"cal","s_from":0,"s_to":0,"wd":120,"rows":141,"timeout_s":3,"max_timeouts_per_stage":3}
{"k":"@open","svc":"IOHIDEventService(cal)","found":1,"type":2,"kr":0,"krn":"SUCCESS"}
{"k":"@cal","axis":"start","svc":"IOHIDEventService"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":0,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":1,"kr":3758097093,"krn":"kIOReturnExclusiveAccess"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":2,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":3,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":4,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":8,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":16,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":17,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":20,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":32,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":54,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":55,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":56,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":128,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":279,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"si","v":1048,"kr":4294966989,"krn":"MIG_REMOTE_ERROR"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":0,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":8,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":55,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":512,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":2048,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":4096,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":8192,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":32768,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":32776,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","svc":"IOHIDEventService","axis":"sti","v":65536,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@cal","axis":"done","svc":"IOHIDEventService"}
{"k":"@done","t":10,"timeouts":0}
```

### 10.7 交叉扫描 / 定向网格（全量文件太大，这里贴全部非 BadArgument 行 + 头尾）

#### `x:mfb-20261101-161425.ndjson`（1920 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@xstage", "svc": "IOMobileFramebuffer", "type": 0, "pairs": 14, "s_from": 0, "s_to": 67, "so": 8, "sto": 4096}
{"k": "@xpairs", "svc": "IOMobileFramebuffer", "list": "[3,0],[0,0],[2,0],[0,1760],[1,0],[0,3084],[0,4],[0,16],[4,0],[1,72],[0,156],[0,32776],[1,20],[0,136]"}
{"k": "@xopen", "svc": "IOMobileFramebuffer", "found": 1, "type": 0, "kr": 0, "krn": "SUCCESS"}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 0, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 1, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 2, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 5, "si": 0, "sti": 1760, "kr": 3758097084, "krn": "kIOReturnError", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 6, "si": 3, "sti": 0, "kr": 3758097123, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 9, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 10, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 11, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 12, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 12, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 13, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 13, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 16, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 17, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 19, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 19, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 20, "si": 2, "sti": 0, "kr": 3758097084, "krn": "kIOReturnError", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 21, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 22, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 22, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 23, "si": 2, "sti": 0, "kr": 3758097089, "krn": "kIOReturnNotPrivileged", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 26, "si": 0, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 26, "si": 0, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 30, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 31, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 31, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 32, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 33, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 33, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 34, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 35, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 36, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 37, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 38, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 39, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 40, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 41, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 43, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 44, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 45, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 46, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 50, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 51, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 51, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 53, "si": 2, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 53, "si": 2, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 56, "si": 0, "sti": 156, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "IOMobileFramebuffer", "s": 56, "si": 0, "sti": 156, "n": 0, "v": []}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 58, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 59, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 60, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 61, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 62, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 63, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 64, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 65, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "IOMobileFramebuffer", "s": 66, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xdone", "svc": "IOMobileFramebuffer", "timeouts": 0}
```

#### `x:clcd-20261101-161543.ndjson`（1920 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@xstage", "svc": "AppleCLCD2", "type": 0, "pairs": 14, "s_from": 0, "s_to": 67, "so": 8, "sto": 4096}
{"k": "@xpairs", "svc": "AppleCLCD2", "list": "[3,0],[0,0],[2,0],[0,1760],[1,0],[0,3084],[0,4],[0,16],[4,0],[1,72],[0,156],[0,32776],[1,20],[0,136]"}
{"k": "@xopen", "svc": "AppleCLCD2", "found": 1, "type": 0, "kr": 0, "krn": "SUCCESS"}
{"k": "@xr", "svc": "AppleCLCD2", "s": 0, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 1, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 2, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 5, "si": 0, "sti": 1760, "kr": 3758097084, "krn": "kIOReturnError", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 6, "si": 3, "sti": 0, "kr": 3758097123, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 9, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 10, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 11, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 12, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 12, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 13, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 13, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 16, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 17, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 19, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 19, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 20, "si": 2, "sti": 0, "kr": 3758097084, "krn": "kIOReturnError", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 21, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 22, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 22, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 23, "si": 2, "sti": 0, "kr": 3758097089, "krn": "kIOReturnNotPrivileged", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 26, "si": 0, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 26, "si": 0, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 30, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 31, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 31, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 32, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 33, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 33, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 34, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 35, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 36, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 37, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 38, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 39, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 40, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 41, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 43, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 44, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 45, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 46, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 50, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 51, "si": 1, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 51, "si": 1, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 53, "si": 2, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 53, "si": 2, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 56, "si": 0, "sti": 156, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleCLCD2", "s": 56, "si": 0, "sti": 156, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleCLCD2", "s": 58, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 59, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 60, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 61, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 62, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 63, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 64, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 65, "si": 0, "sti": 0, "kr": 3758097130, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleCLCD2", "s": 66, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xdone", "svc": "AppleCLCD2", "timeouts": 0}
```

#### `x:msc-20261101-161546.ndjson`（1917 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@xstage", "svc": "AppleM2ScalerCSCDriver", "type": 0, "pairs": 14, "s_from": 0, "s_to": 67, "so": 8, "sto": 4096}
{"k": "@xpairs", "svc": "AppleM2ScalerCSCDriver", "list": "[3,0],[0,0],[2,0],[0,1760],[1,0],[0,3084],[0,4],[0,16],[4,0],[1,72],[0,156],[0,32776],[1,20],[0,136]"}
{"k": "@xopen", "svc": "AppleM2ScalerCSCDriver", "found": 1, "type": 0, "kr": 0, "krn": "SUCCESS"}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 0, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 1, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 2, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 3, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 4, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 5, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 6, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 7, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 8, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 9, "si": 0, "sti": 16, "kr": 3758097085, "krn": "kIOReturnNoMemory", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 9, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 10, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 0, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 1760, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 1760, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 3084, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 3084, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 4, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 4, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 16, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 16, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 156, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 156, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 136, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@xso", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 136, "n": 0, "v": []}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 12, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 13, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 14, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 15, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 16, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 17, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 18, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 19, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 20, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 21, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 22, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 23, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 24, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 25, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 26, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 27, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 28, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 29, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 30, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 31, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 32, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 33, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 34, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 35, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 36, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 37, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 38, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 39, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 40, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 41, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 42, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 43, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 44, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 45, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 46, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 47, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 48, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 49, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 50, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 51, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 52, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 53, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 54, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 55, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 56, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 57, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 58, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 59, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 60, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 61, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 62, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 63, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 64, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 65, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 66, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 3, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 2, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 1760, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 1, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 4, "sti": 0, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 1, "sti": 72, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 156, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 32776, "kr": 3758097087, "krn": "OTHER", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 1, "sti": 20, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xr", "svc": "AppleM2ScalerCSCDriver", "s": 67, "si": 0, "sti": 136, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@xdone", "svc": "AppleM2ScalerCSCDriver", "timeouts": 0}
```

#### `g:mfb-20261101-161513.ndjson`（135 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@gopen", "svc": "IOMobileFramebuffer", "type": 0, "kr": 0, "krn": "SUCCESS", "s_from": 5, "s_to": 5}
{"k": "@gr", "svc": "IOMobileFramebuffer", "s": 5, "si": 0, "sti": 1760, "kr": 3758097084, "krn": "kIOReturnError", "oc": 0, "sc": 0}
{"k": "@gdone", "svc": "IOMobileFramebuffer", "hits": 1, "timeouts": 0}
```

#### `g:mfb-20261101-161516.ndjson`（135 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@gopen", "svc": "IOMobileFramebuffer", "type": 0, "kr": 0, "krn": "SUCCESS", "s_from": 17, "s_to": 17}
{"k": "@gr", "svc": "IOMobileFramebuffer", "s": 17, "si": 0, "sti": 3084, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@gdone", "svc": "IOMobileFramebuffer", "hits": 1, "timeouts": 0}
```

#### `g:mfb-20261101-161519.ndjson`（785 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@gopen", "svc": "IOMobileFramebuffer", "type": 0, "kr": 0, "krn": "SUCCESS", "s_from": 24, "s_to": 29}
{"k": "@gr", "svc": "IOMobileFramebuffer", "s": 26, "si": 0, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gdone", "svc": "IOMobileFramebuffer", "hits": 1, "timeouts": 0}
```

#### `g:mfb-20261101-161537.ndjson`（396 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@gopen", "svc": "IOMobileFramebuffer", "type": 0, "kr": 0, "krn": "SUCCESS", "s_from": 42, "s_to": 44}
{"k": "@gr", "svc": "IOMobileFramebuffer", "s": 43, "si": 0, "sti": 4, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "IOMobileFramebuffer", "s": 44, "si": 0, "sti": 16, "kr": 3758097095, "krn": "kIOReturnUnsupported", "oc": 0, "sc": 0}
{"k": "@gdone", "svc": "IOMobileFramebuffer", "hits": 2, "timeouts": 0}
```

#### `g:mfb-20261101-161540.ndjson`（395 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@gopen", "svc": "IOMobileFramebuffer", "type": 0, "kr": 0, "krn": "SUCCESS", "s_from": 54, "s_to": 56}
{"k": "@gr", "svc": "IOMobileFramebuffer", "s": 56, "si": 0, "sti": 156, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gdone", "svc": "IOMobileFramebuffer", "hits": 1, "timeouts": 0}
```

#### `g:msc-20261101-161623.ndjson`（160 条记录，以下为全部非 BadArgument / 结构行）

```json
{"k": "@gopen", "svc": "AppleM2ScalerCSCDriver", "type": 0, "kr": 0, "krn": "SUCCESS", "s_from": 11, "s_to": 11}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 0, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 4, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 8, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 12, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 16, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 20, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 24, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 32, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 40, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 48, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 56, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 64, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 72, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 80, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 88, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 96, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 128, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 136, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 156, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 176, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 256, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 512, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 1024, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 1760, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 3084, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gr", "svc": "AppleM2ScalerCSCDriver", "s": 11, "si": 0, "sti": 4096, "kr": 0, "krn": "SUCCESS", "oc": 0, "sc": 0}
{"k": "@gdone", "svc": "AppleM2ScalerCSCDriver", "hits": 26, "timeouts": 0}
```

---

## 11. 一句话交接

1. **没有泄露原语**：27 个 SUCCESS 组合全部零字节回吐，hexdump 段是空的。
2. **下一轮别再猜契约**：输出一律开大即可（`so=8`/`sto=4096`），输入必须精确；且 `scalarIn > 16` 永远进不去，别再浪费调用。
3. **IOHIDEventService 要先补表**：type 2 的在用表是 census 里那张 **3 条**表（`svc_selectors.txt` 只收了 4/5 张，缺的正好是它）。把它的 VA 和 3 条契约取出来，HID 这条线才谈得上继续；现在能确认的在用契约是 idx0=`1/0/0/0`、idx1=`1/0/0/0`、idx2=`2/0/0/0`。
4. **JPEG 要喂合法内容**：s=1/3/4/5/6/7 的 BadArgument 来自全零 structIn 被 handler 判非法，不是契约不符；构造合法 JPEG 头（`FF D8 FF`）再试，才有机会吃到 `sti=4096/3488` 那条路。
5. **唯一下一步值得投的入口**：`AppleM2ScalerCSCDriver` sel 11 —— `si=0`、`sti` 0~4096 任意、恒 SUCCESS。改结构体内容（首 4/8 字节当 opcode）去探命令空间，是当前唯一「用户可控且不限长」的内核输入面。
6. 静态表的归属仍有一处不确定：`0x832fd70` 与 `0x83308b0` 在 s=22/26 上契约相同，无法用行为区分；但 s=31/33/51/53/56 只有 `0x832fd70` 有对应行且都 SUCCESS，**所以 graphics 的 live 表基本可以认定是 `0xfffffe000832fd70`**。

---

## 追加：本轮否定了什么（指挥侧更正）

**否掉了 `out/MOBILEGFX-MAP.md` 第 6 条的核心主张。** 我曾写「`0x83308b0` 的
第 6/7 条四字段全 wildcard ⇒ IOKit 不校验 ⇒ 是新可达面」。

真机实测：

```
MFB / CLCD2 调 0x83308b0 的 s=6, s=7   -> 全 BadArgument
MFB / CLCD2 调 0x832fd70 的 s=6        -> kIOReturnNoPower（handler 真的跑了）
```

⇒ **在用表是 `0x832fd70`，wildcard 那两行不在任何可达路径上。**

教训（比结论重要）：**「IOKit 不校验」只能说明校验不发生在那一步，
不能推出「这个 selector 可达」。可达性必须单独实测。**

该文件已加作废抬头。

---

## ⚠ 项目级更正：本文的 selector 面结论不可信，须重跑

后续（`out/M2SCALER-REENUM.md`）实测出一条会推翻本文全部 selector 判定的机制：

```
派发键包含输出维度。
scalarOutputCount / structOutputSize 传 0
  -> 该 selector 直接从派发里被抹掉 -> 返回 0xE00002C7 Unsupported
  -> 不是「不存在」，是「你没告诉它要输出」
```

对照证据：
- 本文 ndjson 中**没有一条 `kr=0 且 sto>0`**，`@so` / `@h` 段整体为空
- M2Scaler 用 `(0,0)` 跑只得 **1 个** selector（sel 11）；预填容量后得 **12 个**（sel 0–11）
- M2Scaler 预填后出现 **69 条 `kr==0 且 sc>0`**（本文 0 条）

**结论：本文「27 个 SUCCESS / 23 个 distinct selector、零 hexdump」是同一类假阴性的产物。**
表里那些 `Unsupported` 中，凡声明 `structOut > 0` 或 `scalarOut > 0` 的条目，
**必须在预填容量后重测**才能下结论。

`out/CENSUS-DISPATCH-TABLES.md` 里凡按「声明 out = 0」筛掉的 selector 同样需要复核。
