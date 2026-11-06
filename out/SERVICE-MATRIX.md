# SERVICE-MATRIX — 本 app 在真机上能打开的 IOKit 服务

设备 `DEVICE-UDID`（iPhone 17 Pro Max `iPhone18,2`，iOS **27.0.1**，build `Nov  1 2026 15:22:38`）
app：`com.example.ios27poc`（`harness/svcprobe/Payload/UC.app`，身份 `iPhone Distribution: <DEVELOPER> (<TEAMID>)`）
探针源码：`harness/svcprobe/main.m`（**未改** `harness/israce/main.m`）
二进制指纹 `SVCPROBE-20261101-matrix-9f4a21`：装前 `strings` 命中=1，`diag1-portdiag`(israce/main.m) 命中=0，`PORTPROBE`(portprobe) 命中=0 —— 装的确是本次新二进制。

调用形态（逐字按任务给定）：

```c
io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name));
for (uint32_t type = 0; type <= 3; type++) {
    io_connect_t c = 0;
    kern_return_t kr = IOServiceOpen(s, mach_task_self(), type, &c);
    if (kr == KERN_SUCCESS) { IOServiceClose(c); break; }
}
IOObjectRelease(s);
```

每行写盘后 `fflush + fsync`，中途崩溃也不丢已出来的行；另有 90s 看门狗。
启动用 `devicectl ... process launch --console`，阻塞到进程自己退出（**没有 sleep 拉长、没有轮询**，进程自己 `exit(0)`，console 报 `The app terminated with the exit code 0.`）。

---

## 1. 服务 × type 矩阵

`found` = `IOServiceGetMatchingService` 是否返回非 0。`能开的 type` 只列 `KERN_SUCCESS` 的那一个（命中即 Close 并停止试更大 type，所以空白格 = 未测，`—` = 测了但被拒/不支持）。

| # | 名字 | 是否找到 | 能开的 type | type0 | type1 | type2 | type3 | kern_return | 含义 |
|---|------|---------|------------|-------|-------|-------|-------|-------------|------|
| 1 | `IOSurfaceRoot` | **1** | **0** | **0 SUCCESS** | — | — | — | `0x00000000` SUCCESS | 打开了。`IOSurfaceRootUserClient`(type 0)，图形/视频/编解码共享内存的主入口，本 app 可直连 |
| 2 | `IOAccelerator` | 0 | — | — | — | — | — | — | 名字没有已发布的服务节点（抽象族名，未被实例化） |
| 3 | `AGXAcceleratorG18P` | **1** | **1** | `0xe00002c7` Unsupported | **0 SUCCESS** | 未测 | 未测 | type0 `0xe00002c7` / type1 `0x00000000` | 打开了。type 0 不是该类合法 userClient；**type 1 是**。GPU（A18 Pro class）加速器可直连，这是全表最有价值的一条 |
| 4 | `IOGPUDevice` | 0 | — | — | — | — | — | — | 无已发布节点（GPU 走 `AGXAcceleratorG18P` 名字暴露） |
| 5 | `IOHIDSystem` | 0 | — | — | — | — | — | — | 无已发布节点（HID 以 `IOHIDEventService` 暴露） |
| 6 | `IOHIDEventService` | **1** | **2** | `0xe00002c2` BadArgument | `0xe00002c2` BadArgument | **0 SUCCESS** | 未测 | type0/1 `0xe00002c2` / type2 `0x00000000` | 打开了。type 2 是 HID 事件系统客户端；type 0/1 是参数非法而非权限拒绝 |
| 7 | `AppleH13CamIn` | 0 | — | — | — | — | — | — | 无已发布节点（该机型无 H13 摄像头 ISP 节点，或是机型条件实例化） |
| 8 | `AppleJPEGDriver` | **1** | **0** | **0 SUCCESS** | — | — | — | `0x00000000` SUCCESS | 打开了。JPEG 硬件编解码器 userClient，可直连 |
| 9 | `AppleM2ScalerCSCDriver` | **1** | **0** | **0 SUCCESS** | — | — | — | `0x00000000` SUCCESS | 打开了。Scaler/CSC（色彩空间转换）驱动，可直连 |
| 10 | `IOMobileFramebuffer` | **1** | **0** | **0 SUCCESS** | — | — | — | `0x00000000` SUCCESS | 打开了。**显示帧缓冲**。普通 app 沙箱能开 type 0，属于本次最意外的一条 |
| 11 | `IOMobileFramebufferShim` | 0 | — | — | — | — | — | — | 无已发布节点（shim 类在该机型上没有实例） |
| 12 | `AppleCLCD2` | **1** | **0** | **0 SUCCESS** | — | — | — | `0x00000000` SUCCESS | 打开了。**LCD 控制器(CLCD2)**，同样意外，且它是 `IOMobileFramebuffer` 的上游 |
| 13 | `AppleSPU` | **1** | 无 | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | 四次 `0xe00002c7` | 找到了服务，但 0..3 全无 userClient（该类没有这四个 type 的客户端） |
| 14 | `AppleH16ANEInterface` | 0 | — | — | — | — | — | — | 无已发布节点（ANE 不以此名暴露，或需机型条件实例化） |
| 15 | `AppleVideoEncoder` | 0 | — | — | — | — | — | — | 无已发布节点（编码器以 `AppleAVE2Driver` / `AppleJPEGDriver` 暴露） |
| 16 | `AppleAVE2Driver` | **1** | 无 | `0xe00002bd` NoMemory | `0xe00002e2` NotPermitted | `0xe00002e2` NotPermitted | `0xe00002e2` NotPermitted | type0 `0xe00002bd` / type1..3 `0xe00002e2` | **混合拒绝**：type 1..3 是沙箱/entitlement 挡（NotPermitted）；type 0 不是权限错，走到了 userClient 初始化后因 NoMemory 失败，说明 **type 0 这条路径先被允许进到驱动内部**才失败 |
| 17 | `IOBiometricFamily` | 0 | — | — | — | — | — | — | 无已发布节点（生物识别不以该族名暴露给 app） |
| 18 | `AppleMultitouchDevice` | **1** | 无 | `0xe00002c2` BadArgument | `0xe00002c2` BadArgument | `0xe00002c2` BadArgument | `0xe00002c2` BadArgument | 四次 `0xe00002c2` | 找到了，但 0..3 都不是合法 userClient type（BadArgument，不是权限拒绝）。它是 nub，真正客户端在别处 |
| 19 | `AppleUSBHostDevice` | 0 | — | — | — | — | — | — | 无已发布节点（实例名是 `AppleUSBHostDeviceUserClient` 形态） |
| 20 | `IOSurfaceAccelerator` | 0 | — | — | — | — | — | — | 无已发布节点（该名在缓存里主要是符号/bundle 名，不是 IOService 类名） |
| 21 | `AppleProcessorTrace` | **1** | 无 | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | 四次 `0xe00002c7` | 找到了，0..3 无 userClient（真正的 trace userClient 需 entitlement 且 type 不在 0..3） |
| 22 | `AppleFirmwareKit` | 0 | — | — | — | — | — | — | 无已发布节点 |
| 23 | `IOStreamUserClient` | 0 | — | — | — | — | — | — | 无已发布节点（这是 userClient 类名，不是可匹配的服务类） |
| 24 | `AppleDisplayCrossbar` | **1** | 无 | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | `0xe00002c7` Unsupported | 四次 `0xe00002c7` | 找到了，0..3 无 userClient |
| 25 | `IOMobileGraphicsFamily` | 0 | — | — | — | — | — | — | 无已发布节点（族名，未实例化；实例走 `IOMobileFramebuffer` / `AppleCLCD2`） |

统计：**found=1 共 12 个，found=0 共 13 个；真正打开成功 7 个**（`IOSurfaceRoot` t0、`AGXAcceleratorG18P` t1、`IOHIDEventService` t2、`AppleJPEGDriver` t0、`AppleM2ScalerCSCDriver` t0、`IOMobileFramebuffer` t0、`AppleCLCD2` t0）。

---

## 2. 一句话结论

**本 app 实际能打开的服务是 7 个：`IOSurfaceRoot`(type 0)、`AGXAcceleratorG18P`(type 1)、`IOHIDEventService`(type 2)、`AppleJPEGDriver`(type 0)、`AppleM2ScalerCSCDriver`(type 0)、`IOMobileFramebuffer`(type 0)、`AppleCLCD2`(type 0)；其中 `AppleCLCD2` / `IOMobileFramebuffer` / `AppleJPEGDriver` / `AppleM2ScalerCSCDriver` 这四个是"显示与媒体硬件控制器在普通 app 沙箱内可直连"，是后续审计唯一有意义的实打实目标。**

补充三条判读（都有本次实测支撑，不是推测）：

- **查询不被沙箱拦，拒绝只发生在 open。** 12 个名字 `found=1`，其中 5 个 open 被 `0xE00002E2`/`0xE00002C7`/`0xE00002C2` 拒 —— 说明 `IOServiceGetMatchingService` 阶段能拿到端口，挡人的是 `IOServiceOpen` 的沙箱/entitlement 与 type 校验。因此 `found=0` 的 13 个名字不是"被沙箱挡住看不见"，而是**该名字在本进程 registry 视图里没有已发布的服务节点**（族名/基类未实例化、机型条件未满足、或该名字本身是 userClient/bundle/符号名而非 IOService 类名 —— 离线 `strings out/kc.27.0.1.full` 确认这些名字在 27.0.1 缓存里都有痕迹，所以是"存在但未发布为该名"，不是"内核里没有"）。
- **`0xE00002C2` / `0xE00002C7` 与 `0xE00002E2` 必须分开读。** `AppleMultitouchDevice`(全 BadArgument)、`AppleSPU`/`AppleProcessorTrace`/`AppleDisplayCrossbar`(全 Unsupported) 是"类在、但不提供 0..3 的客户端"，不是权限拒绝 —— 换 type 或换入口可能就有门，这几条不能当"已排除"。
- **`AppleAVE2Driver` type 0 返回 `0xE00002BD`（NoMemory）而不是 NotPermitted**，是全表唯一一个"越过了权限闸门后才在驱动内部失败"的样本，与 type 1..3 的 `NotPermitted` 形成对照。这条对"AVE 的 type 0 路径能不能进"给出的答案是：能进到分配内存那一步。

---

## 3. 原始 ndjson（逐字，来自 `build Nov  1 2026 15:22:38`，`ios":"27.0.1"`）

取回：`devicectl device copy from` rc=0，size=3805（**不是** 空文件；copy 的 stderr 单独捕获并原样打印，两轮均无 stderr 输出）。`@svc` 行 45 条 + `@meta`/`@done`，与 `wc -l` 一致，带 `@done` 尾标记 = 跑完了。

```json
{"k":"@svc","s":"@meta","fp":"SVCPROBE-20261101-matrix-9f4a21","build":"Nov  1 2026 15:22:38","ios":"27.0.1","model":"iPhone","names":25}
{"k":"@svc","name":"IOSurfaceRoot","found":1,"type":0,"kr":0,"krn":"SUCCESS"}
{"k":"@svc","name":"IOAccelerator","found":0}
{"k":"@svc","name":"AGXAcceleratorG18P","found":1,"type":0,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AGXAcceleratorG18P","found":1,"type":1,"kr":0,"krn":"SUCCESS"}
{"k":"@svc","name":"IOGPUDevice","found":0}
{"k":"@svc","name":"IOHIDSystem","found":0}
{"k":"@svc","name":"IOHIDEventService","found":1,"type":0,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@svc","name":"IOHIDEventService","found":1,"type":1,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@svc","name":"IOHIDEventService","found":1,"type":2,"kr":0,"krn":"SUCCESS"}
{"k":"@svc","name":"AppleH13CamIn","found":0}
{"k":"@svc","name":"AppleJPEGDriver","found":1,"type":0,"kr":0,"krn":"SUCCESS"}
{"k":"@svc","name":"AppleM2ScalerCSCDriver","found":1,"type":0,"kr":0,"krn":"SUCCESS"}
{"k":"@svc","name":"IOMobileFramebuffer","found":1,"type":0,"kr":0,"krn":"SUCCESS"}
{"k":"@svc","name":"IOMobileFramebufferShim","found":0}
{"k":"@svc","name":"AppleCLCD2","found":1,"type":0,"kr":0,"krn":"SUCCESS"}
{"k":"@svc","name":"AppleSPU","found":1,"type":0,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleSPU","found":1,"type":1,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleSPU","found":1,"type":2,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleSPU","found":1,"type":3,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleH16ANEInterface","found":0}
{"k":"@svc","name":"AppleVideoEncoder","found":0}
{"k":"@svc","name":"AppleAVE2Driver","found":1,"type":0,"kr":3758097085,"krn":"kIOReturnNoMemory","krh":"0xe00002bd"}
{"k":"@svc","name":"AppleAVE2Driver","found":1,"type":1,"kr":3758097122,"krn":"kIOReturnNotPermitted"}
{"k":"@svc","name":"AppleAVE2Driver","found":1,"type":2,"kr":3758097122,"krn":"kIOReturnNotPermitted"}
{"k":"@svc","name":"AppleAVE2Driver","found":1,"type":3,"kr":3758097122,"krn":"kIOReturnNotPermitted"}
{"k":"@svc","name":"IOBiometricFamily","found":0}
{"k":"@svc","name":"AppleMultitouchDevice","found":1,"type":0,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@svc","name":"AppleMultitouchDevice","found":1,"type":1,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@svc","name":"AppleMultitouchDevice","found":1,"type":2,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@svc","name":"AppleMultitouchDevice","found":1,"type":3,"kr":3758097090,"krn":"kIOReturnBadArgument"}
{"k":"@svc","name":"AppleUSBHostDevice","found":0}
{"k":"@svc","name":"IOSurfaceAccelerator","found":0}
{"k":"@svc","name":"AppleProcessorTrace","found":1,"type":0,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleProcessorTrace","found":1,"type":1,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleProcessorTrace","found":1,"type":2,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleProcessorTrace","found":1,"type":3,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleFirmwareKit","found":0}
{"k":"@svc","name":"IOStreamUserClient","found":0}
{"k":"@svc","name":"AppleDisplayCrossbar","found":1,"type":0,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleDisplayCrossbar","found":1,"type":1,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleDisplayCrossbar","found":1,"type":2,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"AppleDisplayCrossbar","found":1,"type":3,"kr":3758097095,"krn":"kIOReturnUnsupported"}
{"k":"@svc","name":"IOMobileGraphicsFamily","found":0}
{"k":"@svc","s":"@done","names":25,"t":0.000}
```

十进制/十六进制对照（本表里出现过的全部拒绝码）：

| kr 十进制 | 十六进制 | 名字 | 出现位置 |
|---|---|---|---|
| 0 | `0x00000000` | SUCCESS | 7 处（见上表「能开的 type」） |
| 3758097085 | `0xE00002BD` | kIOReturnNoMemory | `AppleAVE2Driver` type 0 |
| 3758097090 | `0xE00002C2` | kIOReturnBadArgument | `IOHIDEventService` t0/t1、`AppleMultitouchDevice` t0..3 |
| 3758097095 | `0xE00002C7` | kIOReturnUnsupported | `AGXAcceleratorG18P` t0、`AppleSPU` t0..3、`AppleProcessorTrace` t0..3、`AppleDisplayCrossbar` t0..3 |
| 3758097122 | `0xE00002E2` | kIOReturnNotPermitted | `AppleAVE2Driver` t1/t2/t3 |

---

## 4. 交付纪律核对（五态分开）

| 环节 | 结果 | 证据 |
|---|---|---|
| build | **成功** | `clang -sdk iphoneos` rc=0，产物 88192B，无 warning |
| 装前指纹校验 | **通过** | `SVCPROBE-...-9f4a21` 命中=1；`diag1-portdiag`=0；`PORTPROBE`=0 |
| sign | **成功** | `codesign -dv` → Identifier=`com.example.ios27poc`、TeamIdentifier=`DFH8ZCU6D4` |
| install | **成功** | `devicectl device install app` rc=0 |
| launch | **成功** | `--console` 输出 `The app terminated with the exit code 0.`，无 `SBMainWorkspace ... Locked` |
| 取回 | **成功，非空** | `svcprobe.ndjson` rc=0 size=3805；`svcprobe.log` rc=0 size=3710；copy stderr 为空 |
| 结果 | **跑完了** | 带 `@done` 尾标记，45 条 `@svc`，无看门狗触发、无崩溃 |
| 记录数 | **非零**（不是"零记录"） | 45 行 |

- 没有重启设备，没有 panic，没有 unreachable。
- 两轮独立跑（`152209`、`152242`）**除 `@meta.build` 外逐行完全一致**（`diff` 空），矩阵可复现。
- 前置条件：跑前两次查 lockState 都是 `passcodeRequired: false` / `unlockedSinceBoot: true`，未在锁屏态下 launch。
- `results/svcprobe-152209.*` / `152242.*` 两份原始副本与 `last.log` 都在 `harness/svcprobe/results/`，`out/` 既有文件一个没动（本文件是新建）。

### 已知瑕疵（不影响矩阵，如实记）

`@done` 的 `"t":0.000` 不是"0 秒跑完"，是本次归档那版构建的 `nowSec()` 首次调用才建立基准、而它只在收尾时被调用一次，所以恒为 0。源码已改为 `sweep()` 开头先建立基准；下一轮跑 `t` 才有意义。矩阵本身来自 `IOServiceOpen` 的返回值，与时间戳无关。

### 边界

只做了这一件事：单次名字 × type(0..3) 可打开性矩阵。没跑竞态、没跑漏洞变体、没碰 `harness/israce/main.m`、没 git、没改 `out/` 既有文件。type 0..3 之外（如 `out/tscan-type0-255.ndjson` 那种全量 type 扫描）不在本轮范围，所以上表里"未测"的格子不能读成"被拒"。
