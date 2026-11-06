# 全 cache 派发表普查（27.0.1 → 27.2）

1. 目标：把「用户 selector → 内核 handler」这条链在**全部 301 个 kext** 上机械打通，取代逐个 kext 手工找 handler。
2. 产出：`301` kext / `197,683` 真函数 / `244` 张疑似派发表 / `2266` 个 selector；机器可读在 `out/census.json`。
3. 函数起点一律用 `LC_FUNCTION_STARTS`（基址 = kext `__TEXT` vmaddr）。**自证门槛：首项必须等于 `__TEXT_EXEC` vmaddr**；301/301 通过，0 失败。
4. 指针解码：`va = 0xFFFFFE0007004000 + (auth ? word & 0xFFFFFFFF : word & 0xFFFFFFFFF)`。
5. 两条独立发现路径：**A 数据路**（解码后的指针成固定步长连续落在函数起点）/ **B 代码路**（`__TEXT_EXEC` 里 `adrp+add` 指向表基址）。两路都命中 = 置信度 A；只有数据路但 ≥半数 handler 读 args = B；只有数据路且 handler 不读 args = C（疑似 vtable）。
6. 验证基准：三名已知 kext 全部精确复现——JPEG `0xfffffe00080dd990` stride `0x28` n=10、ProRes `0xfffffe000b905ce0` stride `0x28` n=5、H16Cam `0xfffffe0008086ae0` stride `0x18` n=117。
7. 步长两种：`0x28`（内核侧索引）与 `0x18`（kext 自己索引）。**没有假设 24 字节**（判据 9）；全部靠内容形状判定。
8. 风险排序不用 dChk，用「用户可控长度/索引是否进到内存操作」，并对每一分 ≥3 的候选**人工读反汇编**（判据 7 已扣掉 `0x2bad` 位移溢出检查的假象）。
9. 机械候选 12 个（分数 ≥3），手读 9 个，**9/9 都有界**，原因集中在三类：`buf[size-1]` 的 NUL 结尾检查（带 `cbz`/`ccmp` 双闸）、`scalarInputCount` 先乘再比再解引用、容量除法（`size/33`）只当输出参数。
10. 最后一节直答：全 cache 里「用户可控长度/索引直进内存操作且无上界检查」的 selector —— **确认 0 个**，连同未读项的边界条件一起写在 §6。

---

## 1. 方法

### 1.1 三条自证（缺一不可）

| 自证 | 判据 | 结果 |
|---|---|---|
| 函数起点 | `LC_FUNCTION_STARTS` 首项 == `__TEXT_EXEC` vmaddr | 301/301 通过 |
| 指针解码 | 解出的 VA 落在函数起点集合里 | JPEG 表 10/10、ProRes 5/5、H16Cam 117/117 全中 |
| 派发表 | 步长两端必须同时成立：`fn` 解出来是函数起点 + 4 个 u32 字段健全 | 三名已知表全部命中，且不长出多余表 |

### 1.2 为什么「两条路」是必要的

- 只有数据路会被 **vtable** 骗：连续的函数指针数组在 `__DATA_CONST` 里到处都是。加了「步长之间的填充字不能是本 kext 的函数指针」这一条之后，IOSurface 的 26 槽全零 vtable 立刻被剔除，JPEG/ProRes/H16Cam 三张真表一张不少。
- 只有代码路会被 **参数传递** 骗：很多 kext 把表基址当参数传给通用函数，`adrp+add` 出现在别处，也可能根本不出现（表在页首时只有 `adrp`）。
- 所以：**A = 两路都对上**；B = 数据路成立 + 行为像（过半 handler 读 `IOExternalMethodArguments` 字段）；C = 只有数据路、handler 不读 args，按 vtable 处理、不进风险排序。

### 1.3 字段偏移（实测，与别的子代理给的表有出入）

用本普查的实测数据校准（`IOExternalMethodAction(target=x0, reference=x1, arguments=x2)`，args 用 `x2`）：

| 偏移 | 本普查观测到的语义 | 证据 |
|---|---|---|
| `0x20` | `scalarInput` 指针 | EEPROM sel7 `ldr x8,[x2,#0x20]; ldrb w20,[x8]`；BasebandM20 `add x10,x8,count lsl3` |
| `0x28` | `scalarInputCount` | 同上，随后 `cmp count*8,#7/#0xf` |
| `0x30` | `structureInput` | IOSurface sel19 `ldr x8,[x2,#0x30]` 直接当 `buf` |
| `0x38` | `structureInputSize` | 同上，`cmp w9,#0x1ff` 用的就是它 |
| `0x40` | `structureInputDescriptor` | IOAccessoryManager sel4 `ldr x19,[x2,#0x40]` 后打 vtable |
| `0x58` | `structureOutput` | JPEG sel1 `ldr x8,[x2,#0x58]` 传 x2；EEPROM 传 x2 |
| `0x60` | 一个**尺寸**（描述符路径之外用） | EEPROM `mov w8,#0x60; ldr w24,[x19,x8]` |
| `0x68` | `structureOutputDescriptor` | EEPROM `ldr x8,[x19,#0x68]` 后打 vtable |
| `0x70` | 另一个**尺寸**，且会被回写 | EEPROM `str w0,[x19,#0x70]` |

> `0x60`/`0x70` 两个尺寸字段在既有的偏移表里没有。**本表的偏移是从汇编现场读出来的，不是我推断的**；但每个字段的确切名字（`structureOutputSize` 还是 `structureVariableOutputDataSize`）没有符号可证，**不写**。

---

## 2. 普查表（301 kext）

列说明：`真函数` = `LC_FUNCTION_STARTS` 解出的数量；`派发表` = 数据路发现的表数；`selector` = 表条目总数；`双路互证` = 该 kext 全部表都同时被代码路引用的比例；`置信度` = A/B/C 集合；`27.2 同字段` = 27.2 里同 selector 位置的 4 个 check 字段仍一致的比例。

| # | kext | 真函数 | 派发表 | selector | 双路互证 | 置信度 | 27.2 函数数 | 27.2 同字段 |
|---:|---|---:|---:|---:|---|---|---:|---:|
| 1 | `com.apple.kernel` | 21793 | 58 | 210 | 16/210 | ABC | 21843 | 29/29 |
| 2 | `com.apple.kec.Libm` | 55 | — | — | — | 无 | — | — |
| 3 | `com.apple.kec.pthread` | 95 | — | — | — | 无 | — | — |
| 4 | `com.apple.driver.AFKHIDTBDevice` | 305 | — | — | — | 无 | — | — |
| 5 | `com.apple.AGXFirmwareKextG18PRTBuddy` | 72 | — | — | — | 无 | — | — |
| 6 | `com.apple.AGXFirmwareKextRTBuddy64` | 2 | — | — | — | 无 | — | — |
| 7 | `com.apple.AGXG18P` | 3421 | 2 | 4 | 单路 | BC | 3442 | 2/2 |
| 8 | `com.apple.security.AKSAnalytics` | 130 | 1 | 8 | 全双路 | A | 130 | 8/8 |
| 9 | `com.apple.driver.AOPAudio2` | 120 | — | — | — | 无 | — | — |
| 10 | `com.apple.driver.AOPTouchKext` | 96 | — | — | — | 无 | — | — |
| 11 | `com.apple.driver.ASIOKit` | 98 | 1 | 7 | 全双路 | A | 97 | 7/7 |
| 12 | `com.apple.AUC` | 240 | 2 | 6 | 4/6 | AB | 240 | 6/6 |
| 13 | `com.apple.driver.AppleA7IOP-ASCWrap-v6` | 124 | — | — | — | 无 | — | — |
| 14 | `com.apple.driver.AppleA7IOP` | 280 | — | — | — | 无 | — | — |
| 15 | `com.apple.driver.AppleALSColorSensor` | 642 | — | — | — | 无 | — | — |
| 16 | `com.apple.driver.AppleAOP2` | 148 | — | — | — | 无 | — | — |
| 17 | `com.apple.driver.AppleAOPAudio` | 1225 | 3 | 11 | 全双路 | A | 1225 | 11/11 |
| 18 | `com.apple.iokit.AppleARMIISAudio` | 323 | — | — | — | 无 | — | — |
| 19 | `com.apple.driver.AppleARMPMU` | 269 | — | — | — | 无 | — | — |
| 20 | `com.apple.driver.AppleARMPlatform` | 2238 | 3 | 18 | 全双路 | A | 2238 | 18/18 |
| 21 | `com.apple.driver.AppleARMWatchdogTimer` | 189 | 1 | 10 | 全双路 | A | 189 | 10/10 |
| 22 | `com.apple.driver.AppleAVD` | 2328 | 1 | 9 | 全双路 | A | 2328 | 9/9 |
| 23 | `com.apple.driver.AppleAVE2` | 2995 | 2 | 13 | 单路 | B | 2998 | 13/13 |
| 24 | `com.apple.driver.AppleActuatorDriver` | 214 | — | — | — | 无 | — | — |
| 25 | `com.apple.driver.AppleAstrisGpioProbe` | 132 | 1 | 4 | 全双路 | A | 132 | 4/4 |
| 26 | `com.apple.driver.AppleAudioClockLibs` | 13 | — | — | — | 无 | — | — |
| 27 | `com.apple.driver.AppleAuthCP` | 639 | 1 | 25 | 全双路 | A | 639 | 25/25 |
| 28 | `com.apple.driver.AppleBSDKextStarter` | 25 | — | — | — | 无 | — | — |
| 29 | `com.apple.driver.AppleBasebandM20` | 844 | 2 | 51 | 24/51 | AB | 844 | 51/51 |
| 30 | `com.apple.driver.AppleBasebandPCI` | 2233 | 2 | 17 | 全双路 | A | 2233 | 17/17 |
| 31 | `com.apple.driver.AppleBasebandPCIMAVControl` | 1079 | — | — | — | 无 | — | — |
| 32 | `com.apple.driver.AppleBasebandPCIMAVPDP` | 390 | — | — | — | 无 | — | — |
| 33 | `com.apple.driver.AppleC26Charger` | 603 | — | — | — | 无 | — | — |
| 34 | `com.apple.driver.AppleCSEmbeddedAudio` | 243 | — | — | — | 无 | — | — |
| 35 | `com.apple.driver.AppleCallbackPowerSource` | 63 | — | — | — | 无 | — | — |
| 36 | `com.apple.driver.AppleCentauriManager` | 641 | 1 | 8 | 全双路 | A | 641 | 8/8 |
| 37 | `com.apple.driver.AppleDAPF` | 35 | — | — | — | 无 | — | — |
| 38 | `com.apple.driver.AppleDCP` | 205 | — | — | — | 无 | — | — |
| 39 | `com.apple.driver.AppleDCPDPTXProxy` | 334 | — | — | — | 无 | — | — |
| 40 | `com.apple.driver.AppleDiagnosticDataAccessReadOnly` | 36 | — | — | — | 无 | — | — |
| 41 | `com.apple.driver.AppleDialogPMU` | 90 | — | — | — | 无 | — | — |
| 42 | `com.apple.driver.AppleDiskImages2` | 400 | 2 | 11 | 全双路 | A | 400 | 11/11 |
| 43 | `com.apple.driver.AppleDisplayCrossbar` | 2263 | — | — | — | 无 | — | — |
| 44 | `com.apple.driver.AppleDockChannel` | 89 | 1 | 3 | 全双路 | A | 89 | 3/3 |
| 45 | `com.apple.driver.AppleEffaceableBlockDevice` | 51 | — | — | — | 无 | — | — |
| 46 | `com.apple.driver.AppleEffaceableStorage` | 135 | — | — | — | 无 | — | — |
| 47 | `com.apple.driver.AppleEmbeddedAudio` | 1121 | — | — | — | 无 | — | — |
| 48 | `com.apple.driver.AppleAOPHaptics` | 154 | — | — | — | 无 | — | — |
| 49 | `com.apple.driver.AppleCS42L79Audio` | 382 | — | — | — | 无 | — | — |
| 50 | `com.apple.driver.IOPAudioSpeaker` | 65 | — | — | — | 无 | — | — |
| 51 | `com.apple.driver.IOPEmbeddedAudio` | 91 | — | — | — | 无 | — | — |
| 52 | `com.apple.driver.IOPHaptics` | 92 | — | — | — | 无 | — | — |
| 53 | `com.apple.driver.AppleEmbeddedAudioLibs` | 438 | — | — | — | 无 | — | — |
| 54 | `com.apple.driver.AppleEmbeddedAudioResourceManager` | 54 | — | — | — | 无 | — | — |
| 55 | `com.apple.driver.AppleEmbeddedGPS` | 134 | 1 | 9 | 全双路 | A | 134 | 9/9 |
| 56 | `com.apple.driver.AppleEmbeddedLightSensor` | 350 | — | — | — | 无 | — | — |
| 57 | `com.apple.driver.AppleEmbeddedMikeyBus` | 515 | — | — | — | 无 | — | — |
| 58 | `com.apple.driver.AppleEmbeddedPCIE` | 507 | — | — | — | 无 | — | — |
| 59 | `com.apple.driver.AppleEmbeddedTempSensor` | 561 | 1 | 6 | 全双路 | A | 561 | 6/6 |
| 60 | `com.apple.driver.AppleEmbeddedTouchEEPROM` | 72 | 1 | 9 | 全双路 | A | 72 | 9/9 |
| 61 | `com.apple.driver.AppleEmbeddedUSB` | 210 | — | — | — | 无 | — | — |
| 62 | `com.apple.driver.AppleEmbeddedUSBHost` | 224 | — | — | — | 无 | — | — |
| 63 | `com.apple.driver.AppleEpochManager` | 83 | 1 | 3 | 全双路 | A | 83 | 3/3 |
| 64 | `com.apple.driver.AppleEventLogHandler` | 54 | — | — | — | 无 | — | — |
| 65 | `com.apple.driver.AppleEverestErrorHandler` | 38 | — | — | — | 无 | — | — |
| 66 | `com.apple.driver.AppleFAN53740` | 57 | — | — | — | 无 | — | — |
| 67 | `com.apple.AppleFSCompression.AppleFSCompressionTypeZlib` | 67 | — | — | — | 无 | — | — |
| 68 | `com.apple.driver.AppleFirmwareKit` | 2640 | 6 | 68 | 33/68 | AC | 2640 | 33/33 |
| 69 | `com.apple.driver.AppleFirmwareUpdateKext` | 84 | — | — | — | 无 | — | — |
| 70 | `com.apple.driver.AppleGPIOCanary` | 25 | — | — | — | 无 | — | — |
| 71 | `com.apple.driver.AppleGPIOICController` | 294 | 1 | 3 | 全双路 | A | 294 | 3/3 |
| 72 | `com.apple.driver.AppleGameControllerPersonality` | 77 | — | — | — | 无 | — | — |
| 73 | `com.apple.driver.AppleGenericMultitouch` | 247 | — | — | — | 无 | — | — |
| 74 | `com.apple.driver.AppleH10PearlCameraInterface` | 390 | — | — | — | 无 | — | — |
| 75 | `com.apple.driver.AppleH16ANEInterface` | 4959 | 3 | 26 | 全双路 | A | 5100 | 26/26 |
| 76 | `com.apple.driver.AppleH16CameraInterface · 已审(H16Cam)` | 1822 | 2 | 120 | 全双路 | A | 1822 | 120/120 |
| 77 | `com.apple.driver.AppleH16PhotonDetector` | 95 | 1 | 7 | 全双路 | A | 95 | 7/7 |
| 78 | `com.apple.driver.AppleHIDALSService` | 27 | — | — | — | 无 | — | — |
| 79 | `com.apple.driver.AppleHIDKeyboard` | 123 | — | — | — | 无 | — | — |
| 80 | `com.apple.driver.AppleHIDTransport` | 2236 | 4 | 19 | 14/19 | AB | 2236 | 19/19 |
| 81 | `com.apple.driver.AppleHIDTransportFIFO` | 333 | — | — | — | 无 | — | — |
| 82 | `com.apple.driver.AppleHIDTransportMailbox` | 357 | — | — | — | 无 | — | — |
| 83 | `com.apple.driver.AppleHIDTransportSCMCommon` | 158 | — | — | — | 无 | — | — |
| 84 | `com.apple.driver.AppleHIDTransportSPI` | 1017 | — | — | — | 无 | — | — |
| 85 | `com.apple.driver.AppleHPM` | 1654 | — | — | — | 无 | — | — |
| 86 | `com.apple.driver.AppleHapticsSupportLEAP` | 1201 | 1 | 4 | 全双路 | A | 1201 | 4/4 |
| 87 | `com.apple.driver.AppleHapticsSupportNVM` | 35 | — | — | — | 无 | — | — |
| 88 | `com.apple.driver.AppleIDAMInterface` | 31 | — | — | — | 无 | — | — |
| 89 | `com.apple.driver.AppleIDV` | 187 | 1 | 15 | 全双路 | A | 177 | 15/15 |
| 90 | `com.apple.driver.AppleIISController` | 202 | — | — | — | 无 | — | — |
| 91 | `com.apple.driver.AppleIOPADMAStream` | 245 | — | — | — | 无 | — | — |
| 92 | `com.apple.driver.AppleIPAppender` | 168 | 1 | 21 | 全双路 | A | 168 | 21/21 |
| 93 | `com.apple.security.AppleImage4` | 1190 | 3 | 15 | 6/15 | AB | 1190 | 15/15 |
| 94 | `com.apple.driver.AppleInputDeviceSupport` | 878 | — | — | — | 无 | — | — |
| 95 | `com.apple.driver.AppleInterruptControllerV3` | 122 | 1 | 5 | 全双路 | A | 122 | 5/5 |
| 96 | `com.apple.driver.AppleJPEGDriver · 已审(JPEG)` | 1807 | 1 | 10 | 全双路 | A | 1807 | 10/10 |
| 97 | `com.apple.driver.AppleLockdownMode` | 211 | — | — | — | 无 | — | — |
| 98 | `com.apple.driver.AppleM2ScalerCSCDriver · 已审(M2Scaler)` | 10262 | 1 | 2 | 单路 | C | 10276 | — |
| 99 | `com.apple.driver.AppleM68Buttons` | 328 | — | — | — | 无 | — | — |
| 100 | `com.apple.driver.AppleMSG` | 1768 | 6 | 92 | 58/92 | ABC | 1768 | 89/89 |
| 101 | `com.apple.kext.AppleMatch` | 35 | — | — | — | 无 | — | — |
| 102 | `com.apple.driver.AppleMikeyBusAudio` | 357 | — | — | — | 无 | — | — |
| 103 | `com.apple.driver.AppleMobileApNonce` | 104 | — | — | — | 无 | — | — |
| 104 | `com.apple.driver.AppleMobileDispH18P-DCP` | 1460 | — | — | — | 无 | — | — |
| 105 | `com.apple.driver.AppleMobileFileIntegrity` | 917 | 2 | 11 | 单路 | C | 917 | — |
| 106 | `com.apple.driver.AppleMultitouchDriver` | 546 | — | — | — | 无 | — | — |
| 107 | `com.apple.driver.AppleMultitouchSPI` | 19 | — | — | — | 无 | — | — |
| 108 | `com.apple.driver.AppleNANDConfigAccess` | 26 | — | — | — | 无 | — | — |
| 109 | `com.apple.driver.AppleOnboardSerial` | 462 | — | — | — | 无 | — | — |
| 110 | `com.apple.driver.ApplePIODMA` | 97 | — | — | — | 无 | — | — |
| 111 | `com.apple.driver.ApplePMGR` | 2866 | — | — | — | 无 | — | — |
| 112 | `com.apple.driver.ApplePMP` | 403 | 3 | 27 | 全双路 | A | 403 | 27/27 |
| 113 | `com.apple.driver.ApplePMPFirmware` | 33 | — | — | — | 无 | — | — |
| 114 | `com.apple.driver.ApplePMUFirmwareDriver` | 81 | — | — | — | 无 | — | — |
| 115 | `com.apple.driver.ApplePPMCPMS` | 2170 | 1 | 56 | 全双路 | A | 2185 | 56/56 |
| 116 | `com.apple.driver.ApplePTD` | 270 | — | — | — | 无 | — | — |
| 117 | `com.apple.driver.AppleParrot` | 35 | — | — | — | 无 | — | — |
| 118 | `com.apple.driver.ApplePearlSEPDriver` | 751 | — | — | — | 无 | — | — |
| 119 | `com.apple.driver.ApplePhoneBTM` | 1114 | — | — | — | 无 | — | — |
| 120 | `com.apple.driver.ApplePhotonDetector` | 97 | 1 | 7 | 全双路 | A | 97 | 7/7 |
| 121 | `com.apple.driver.AppleProResHW · 已审(ProRes)` | 3015 | 1 | 5 | 全双路 | A | 3015 | 5/5 |
| 122 | `com.apple.driver.AppleProcessorTrace` | 1314 | 1 | 11 | 全双路 | A | 1317 | 11/11 |
| 123 | `com.apple.driver.AppleProxDriver` | 196 | — | — | — | 无 | — | — |
| 124 | `com.apple.driver.AppleS5L8920XPWM` | 80 | — | — | — | 无 | — | — |
| 125 | `com.apple.driver.AppleS5L8940XI2C` | 57 | — | — | — | 无 | — | — |
| 126 | `com.apple.driver.AppleS5L8960XNCO` | 45 | — | — | — | 无 | — | — |
| 127 | `com.apple.driver.AppleS8000AES` | 112 | — | — | — | 无 | — | — |
| 128 | `com.apple.driver.AppleS8000DWI` | 65 | — | — | — | 无 | — | — |
| 129 | `com.apple.driver.AppleSARService` | 1866 | 1 | 80 | 全双路 | A | 1876 | 79/80 |
| 130 | `com.apple.driver.AppleSART` | 126 | — | — | — | 无 | — | — |
| 131 | `com.apple.driver.AppleSEPCredentialManager` | 1021 | 1 | 3 | 全双路 | A | 1022 | 3/3 |
| 132 | `com.apple.iokit.AppleSEPGenericTransfer` | 106 | — | — | — | 无 | — | — |
| 133 | `com.apple.driver.AppleSEPHDCPManager` | 186 | — | — | — | 无 | — | — |
| 134 | `com.apple.driver.AppleSEPKeyStore` | 1058 | — | — | — | 无 | — | — |
| 135 | `com.apple.driver.AppleSEPManager` | 2544 | 7 | 83 | 17/83 | AB | 2544 | 83/83 |
| 136 | `com.apple.driver.AppleSMC` | 1010 | 1 | 7 | 全双路 | A | 1010 | 7/7 |
| 137 | `com.apple.driver.AppleSMCWirelessCharger` | 212 | — | — | — | 无 | — | — |
| 138 | `com.apple.driver.AppleSPIMC` | 131 | — | — | — | 无 | — | — |
| 139 | `com.apple.driver.AppleSPMI` | 226 | — | — | — | 无 | — | — |
| 140 | `com.apple.driver.AppleSPMIPMU` | 192 | — | — | — | 无 | — | — |
| 141 | `com.apple.driver.AppleSPU` | 2330 | 11 | 56 | 51/56 | AB | 2330 | 56/56 |
| 142 | `com.apple.driver.AppleSPURose` | 670 | 3 | 46 | 44/46 | AC | 670 | 44/44 |
| 143 | `com.apple.driver.AppleSPUSphere` | 59 | — | — | — | 无 | — | — |
| 144 | `com.apple.driver.AppleSSE` | 132 | — | — | — | 无 | — | — |
| 145 | `com.apple.driver.AppleSamsungSerial` | 55 | — | — | — | 无 | — | — |
| 146 | `com.apple.driver.AppleSerialShim` | 25 | — | — | — | 无 | — | — |
| 147 | `com.apple.driver.AppleSmartBatteryManagerEmbedded` | 695 | 2 | 9 | 全双路 | A | 696 | 9/9 |
| 148 | `com.apple.driver.AppleSmartIO2` | 494 | 1 | 4 | 全双路 | A | 494 | 4/4 |
| 149 | `com.apple.driver.AppleStockholmControl` | 240 | 1 | 14 | 全双路 | A | 240 | 14/14 |
| 150 | `com.apple.driver.AppleUSBCardReader` | 225 | — | — | — | 无 | — | — |
| 151 | `com.apple.driver.AppleUSBMassStorageInterfaceNub` | 32 | — | — | — | 无 | — | — |
| 152 | `com.apple.driver.AppleSynopsysMIPIDSI` | 240 | — | — | — | 无 | — | — |
| 153 | `com.apple.driver.AppleT6020PCIePIODMA` | 72 | — | — | — | 无 | — | — |
| 154 | `com.apple.driver.AppleT8030SOCTuner` | 90 | — | — | — | 无 | — | — |
| 155 | `com.apple.driver.AppleT8110DART` | 162 | — | — | — | 无 | — | — |
| 156 | `com.apple.driver.AppleT8150` | 441 | — | — | — | 无 | — | — |
| 157 | `com.apple.driver.AppleT8150ANEHAL` | 728 | — | — | — | 无 | — | — |
| 158 | `com.apple.driver.AppleT8150CLPC` | 1420 | 10 | 46 | 10/46 | AC | 1422 | 10/10 |
| 159 | `com.apple.driver.AppleT8150MCC` | 569 | — | — | — | 无 | — | — |
| 160 | `com.apple.driver.AppleT8150PCIe` | 251 | — | — | — | 无 | — | — |
| 161 | `com.apple.driver.AppleT8150PMGR` | 309 | — | — | — | 无 | — | — |
| 162 | `com.apple.driver.AppleTemperatureSensor` | 366 | — | — | — | 无 | — | — |
| 163 | `com.apple.driver.AppleThunderboltDPAdapterFamily` | 341 | — | — | — | 无 | — | — |
| 164 | `com.apple.driver.AppleThunderboltDPInAdapter` | 163 | — | — | — | 无 | — | — |
| 165 | `com.apple.driver.AppleThunderboltDPOutAdapter` | 613 | — | — | — | 无 | — | — |
| 166 | `com.apple.driver.AppleThunderboltEDMSource` | 266 | — | — | — | 无 | — | — |
| 167 | `com.apple.driver.AppleThunderboltIP` | 362 | — | — | — | 无 | — | — |
| 168 | `com.apple.driver.AppleThunderboltNHI` | 957 | — | — | — | 无 | — | — |
| 169 | `com.apple.driver.AppleThunderboltPCIDownAdapter` | 75 | — | — | — | 无 | — | — |
| 170 | `com.apple.driver.AppleThunderboltPCIUpAdapter` | 114 | — | — | — | 无 | — | — |
| 171 | `com.apple.driver.AppleThunderboltUSBDownAdapter` | 30 | — | — | — | 无 | — | — |
| 172 | `com.apple.driver.AppleThunderboltUSBType2DownAdapter` | 33 | — | — | — | 无 | — | — |
| 173 | `com.apple.driver.AppleThunderboltUSBType2UpAdapter` | 58 | — | — | — | 无 | — | — |
| 174 | `com.apple.driver.AppleThunderboltUSBUpAdapter` | 53 | — | — | — | 无 | — | — |
| 175 | `com.apple.driver.AppleTopCaseHIDEventDriver` | 163 | — | — | — | 无 | — | — |
| 176 | `com.apple.driver.AppleUSBTopCaseDriver` | 23 | — | — | — | 无 | — | — |
| 177 | `com.apple.driver.AppleTriStar` | 559 | — | — | — | 无 | — | — |
| 178 | `com.apple.driver.AppleTypeCPhy` | 253 | — | — | — | 无 | — | — |
| 179 | `com.apple.driver.AppleT8103TypeCPhy` | 162 | — | — | — | 无 | — | — |
| 180 | `com.apple.driver.AppleT8130TypeCPhy` | 131 | — | — | — | 无 | — | — |
| 181 | `com.apple.driver.AppleTypeCPhyAUSBC` | 58 | — | — | — | 无 | — | — |
| 182 | `com.apple.driver.AppleUSBAudio` | 1606 | — | — | — | 无 | — | — |
| 183 | `com.apple.driver.usb.cdc` | 60 | — | — | — | 无 | — | — |
| 184 | `com.apple.driver.usb.AppleUSBCommon` | 219 | — | — | — | 无 | — | — |
| 185 | `com.apple.driver.AppleUSBDeviceAudioController` | 79 | — | — | — | 无 | — | — |
| 186 | `com.apple.driver.AppleUSBDeviceMux` | 98 | — | — | — | 无 | — | — |
| 187 | `com.apple.driver.AppleUSBDeviceNCM` | 226 | — | — | — | 无 | — | — |
| 188 | `com.apple.driver.usb.cdc.ecm` | 137 | — | — | — | 无 | — | — |
| 189 | `com.apple.driver.usb.ethernet.asix` | 294 | — | — | — | 无 | — | — |
| 190 | `com.apple.driver.AppleUSBEthernetDevice` | 106 | — | — | — | 无 | — | — |
| 191 | `com.apple.driver.AppleUSBEthernetHost` | 109 | — | — | — | 无 | — | — |
| 192 | `com.apple.driver.AppleUSBLightningAdapter` | 107 | — | — | — | 无 | — | — |
| 193 | `com.apple.driver.AppleUSBMike` | 71 | — | — | — | 无 | — | — |
| 194 | `com.apple.driver.usb.cdc.ncm` | 355 | — | — | — | 无 | — | — |
| 195 | `com.apple.driver.usb.networking` | 152 | — | — | — | 无 | — | — |
| 196 | `com.apple.driver.AppleUVDM` | 59 | 1 | 7 | 全双路 | A | 59 | 7/7 |
| 197 | `com.apple.driver.AppleUVDMDriver` | 132 | — | — | — | 无 | — | — |
| 198 | `com.apple.driver.AudioDMACLLTEscalationDetector-T8150` | 83 | — | — | — | 无 | — | — |
| 199 | `com.apple.driver.AudioDMAController-T8150` | 467 | — | — | — | 无 | — | — |
| 200 | `com.apple.driver.AudioDMAFamily` | 79 | — | — | — | 无 | — | — |
| 201 | `com.apple.kec.Compression` | 41 | — | — | — | 无 | — | — |
| 202 | `com.apple.iokit.CoreAnalyticsFamily` | 261 | 1 | 2 | 单路 | C | 261 | — |
| 203 | `com.apple.kext.CoreTrust` | 139 | — | — | — | 无 | — | — |
| 204 | `com.apple.driver.DCPAVFamilyProxy` | 891 | — | — | — | 无 | — | — |
| 205 | `com.apple.driver.DCPDPFamilyProxy` | 203 | — | — | — | 无 | — | — |
| 206 | `com.apple.iokit.IOMIPIFamily` | 69 | — | — | — | 无 | — | — |
| 207 | `com.apple.driver.DMAChannelProxy` | 149 | — | — | — | 无 | — | — |
| 208 | `com.apple.EXBrightCalibrationConsumer` | 30 | — | — | — | 无 | — | — |
| 209 | `com.apple.EXBrightKext` | 585 | — | — | — | 无 | — | — |
| 210 | `com.apple.driver.EXDisplayPipeH18P` | 187 | — | — | — | 无 | — | — |
| 211 | `com.apple.ExclaveKextClient` | 71 | — | — | — | 无 | — | — |
| 212 | `com.apple.driver.ExclaveSEPManagerProxy` | 69 | — | — | — | 无 | — | — |
| 213 | `com.apple.driver.ExclavesAudioKext` | 702 | — | — | — | 无 | — | — |
| 214 | `com.apple.driver.FairPlayIOKit` | 479 | 1 | 2 | 单路 | C | 479 | — |
| 215 | `com.apple.driver.IISAudioIsolatedStreamECProxy` | 91 | — | — | — | 无 | — | — |
| 216 | `com.apple.iokit.IOAVFamily` | 3446 | 7 | 85 | 全双路 | A | 3448 | 85/85 |
| 217 | `com.apple.iokit.IOAccessoryManager` | 5013 | 11 | 82 | 全双路 | A | 5013 | 82/82 |
| 218 | `com.apple.iokit.IOAccessoryPortUSB` | 46 | — | — | — | 无 | — | — |
| 219 | `com.apple.iokit.IOAudio2Family` | 254 | — | — | — | 无 | — | — |
| 220 | `com.apple.driver.IOAudioCodecs` | 401 | 1 | 6 | 全双路 | A | 402 | 6/6 |
| 221 | `com.apple.iokit.IOBiometricFamily` | 509 | — | — | — | 无 | — | — |
| 222 | `com.apple.iokit.IOCECFamily` | 103 | 1 | 7 | 全双路 | A | 103 | 7/7 |
| 223 | `com.apple.iokit.IOCryptoAcceleratorFamily` | 106 | — | — | — | 无 | — | — |
| 224 | `com.apple.driver.IODARTFamily` | 385 | — | — | — | 无 | — | — |
| 225 | `com.apple.iokit.IODisplayPortFamily` | 2623 | 5 | 33 | 全双路 | A | 2624 | 33/33 |
| 226 | `com.apple.iokit.IOGPUFamily · 已审(IOGPU)` | 2002 | 2 | 115 | 全双路 | A | 2004 | 115/115 |
| 227 | `com.apple.iokit.IOGameControllerFamily` | 673 | 3 | 11 | 全双路 | A | 673 | 11/11 |
| 228 | `com.apple.iokit.IOHDCPFamily` | 395 | — | — | — | 无 | — | — |
| 229 | `com.apple.driver.DiskImages` | 265 | 1 | 2 | 单路 | C | 265 | — |
| 230 | `com.apple.driver.DiskImages.FileBackingStore` | 32 | — | — | — | 无 | — | — |
| 231 | `com.apple.driver.DiskImages.KernelBacked` | 212 | — | — | — | 无 | — | — |
| 232 | `com.apple.driver.DiskImages.RAMBackingStore` | 28 | — | — | — | 无 | — | — |
| 233 | `com.apple.driver.DiskImages.ReadWriteDiskImage` | 24 | — | — | — | 无 | — | — |
| 234 | `com.apple.driver.DiskImages.UDIFDiskImage` | 191 | — | — | — | 无 | — | — |
| 235 | `com.apple.iokit.IOHIDFamily` | 2808 | 5 | 42 | 14/42 | ABC | 2809 | 32/32 |
| 236 | `com.apple.driver.IOHIDPowerSource` | 237 | — | — | — | 无 | — | — |
| 237 | `com.apple.iokit.IOMikeyBusFamily` | 676 | — | — | — | 无 | — | — |
| 238 | `com.apple.iokit.IOMobileGraphicsFamily-DCP` | 800 | — | — | — | 无 | — | — |
| 239 | `com.apple.iokit.IOMobileGraphicsFamily` | 1156 | 3 | 92 | 59/92 | AB | 1156 | 92/92 |
| 240 | `com.apple.iokit.IONVMeFamily` | 3589 | 2 | 21 | 全双路 | A | 3556 | 21/21 |
| 241 | `com.apple.iokit.IONetworkFamily` | 22 | — | — | — | 无 | — | — |
| 242 | `com.apple.iokit.IONetworkingFamily` | 862 | — | — | — | 无 | — | — |
| 243 | `com.apple.driver.IOPAudioAssetManagerDevice` | 40 | — | — | — | 无 | — | — |
| 244 | `com.apple.driver.IOPAudioClientManagerDevice` | 163 | 1 | 7 | 全双路 | A | 163 | 7/7 |
| 245 | `com.apple.iokit.IOPAudioDriverFamily` | 635 | — | — | — | 无 | — | — |
| 246 | `com.apple.driver.IOPAudioHapticsLEAPControlDevice` | 32 | — | — | — | 无 | — | — |
| 247 | `com.apple.driver.IOPAudioIOBufferDevice` | 81 | — | — | — | 无 | — | — |
| 248 | `com.apple.driver.IOPAudioIsolatedIOBufferDevice` | 118 | 1 | 6 | 全双路 | A | 118 | 6/6 |
| 249 | `com.apple.driver.IOPAudioLEAPControlDevice` | 50 | — | — | — | 无 | — | — |
| 250 | `com.apple.driver.IOPAudioLPMicDevice` | 178 | 1 | 4 | 全双路 | A | 178 | 4/4 |
| 251 | `com.apple.driver.IOPAudioPCMAssetManagerDevice` | 101 | 1 | 3 | 全双路 | A | 101 | 3/3 |
| 252 | `com.apple.driver.IOPAudioVoiceTriggerDevice` | 305 | 1 | 4 | 全双路 | A | 305 | 4/4 |
| 253 | `com.apple.iokit.IOPCIFamily` | 723 | — | — | — | 无 | — | — |
| 254 | `com.apple.iokit.IOPortFamily` | 5 | — | — | — | 无 | — | — |
| 255 | `com.apple.iokit.IOReportFamily` | 69 | 1 | 4 | 全双路 | A | 69 | 4/4 |
| 256 | `com.apple.iokit.IOSCSIArchitectureModelFamily` | 734 | — | — | — | 无 | — | — |
| 257 | `com.apple.iokit.IOSCSIBlockCommandsDevice` | 303 | — | — | — | 无 | — | — |
| 258 | `com.apple.iokit.IOSerialFamily` | 155 | — | — | — | 无 | — | — |
| 259 | `com.apple.iokit.IOSkywalkFamily` | 2166 | — | — | — | 无 | — | — |
| 260 | `com.apple.driver.IOSlaveProcessor` | 110 | — | — | — | 无 | — | — |
| 261 | `com.apple.iokit.IOSlowAdaptiveClockingFamily` | 76 | — | — | — | 无 | — | — |
| 262 | `com.apple.iokit.IOStorageFamily` | 563 | — | — | — | 无 | — | — |
| 263 | `com.apple.iokit.IOStreamFamily` | 159 | 1 | 2 | 单路 | C | 159 | — |
| 264 | `com.apple.iokit.IOSurface · 已审(IOSurface)` | 1330 | 1 | 120 | 全双路 | A | 1330 | 120/120 |
| 265 | `com.apple.IOTextEncryptionFamily` | 88 | — | — | — | 无 | — | — |
| 266 | `com.apple.iokit.IOThunderboltFamily` | 5701 | — | — | — | 无 | — | — |
| 267 | `com.apple.iokit.IOTimeSyncFamily` | 1488 | — | — | — | 无 | — | — |
| 268 | `com.apple.iokit.IOUSBDeviceFamily` | 739 | 1 | 29 | 全双路 | A | 739 | 29/29 |
| 269 | `com.apple.driver.AppleUSBXDCI` | 287 | — | — | — | 无 | — | — |
| 270 | `com.apple.driver.AppleUSBXDCIARM` | 465 | — | — | — | 无 | — | — |
| 271 | `com.apple.iokit.IOUSBHostFamily` | 1977 | 4 | 100 | 全双路 | A | 1977 | 100/100 |
| 272 | `com.apple.driver.usb.AppleSynopsysUSB40XHCI` | 545 | — | — | — | 无 | — | — |
| 273 | `com.apple.driver.usb.AppleSynopsysUSBXHCI` | 644 | — | — | — | 无 | — | — |
| 274 | `com.apple.driver.usb.AppleUSBHostBillboardDevice` | 33 | — | — | — | 无 | — | — |
| 275 | `com.apple.driver.usb.AppleUSBHostCompositeDevice` | 67 | — | — | — | 无 | — | — |
| 276 | `com.apple.driver.usb.AppleUSBHostDeviceSupport` | 24 | — | — | — | 无 | — | — |
| 277 | `com.apple.driver.AppleUSBHostMergeProperties` | 25 | — | — | — | 无 | — | — |
| 278 | `com.apple.driver.usb.AppleUSBHostPacketFilter` | 38 | — | — | — | 无 | — | — |
| 279 | `com.apple.driver.usb.AppleUSBHostiOSDevice` | 29 | — | — | — | 无 | — | — |
| 280 | `com.apple.driver.usb.AppleUSBHub` | 253 | — | — | — | 无 | — | — |
| 281 | `com.apple.driver.usb.AppleUSBXHCI` | 839 | — | — | — | 无 | — | — |
| 282 | `com.apple.driver.usb.IOUSBHostHIDDevice` | 86 | — | — | — | 无 | — | — |
| 283 | `com.apple.iokit.IOUSBMassStorageDriver` | 669 | — | — | — | 无 | — | — |
| 284 | `com.apple.iokit.IOUserEthernet` | 166 | 1 | 5 | 全双路 | A | 167 | 5/5 |
| 285 | `com.apple.plugin.IOgPTPPlugin` | 1641 | — | — | — | 无 | — | — |
| 286 | `com.apple.security.Image4` | 513 | 1 | 9 | 全双路 | A | 513 | 9/9 |
| 287 | `com.apple.nke.l2tp` | 61 | — | — | — | 无 | — | — |
| 288 | `com.apple.nke.ppp` | 107 | — | — | — | 无 | — | — |
| 289 | `com.apple.driver.RTBuddy` | 2426 | 1 | 14 | 全双路 | A | 2456 | 14/14 |
| 290 | `com.apple.security.sandbox` | 659 | — | — | — | 无 | — | — |
| 291 | `com.apple.driver.SecureRTBuddyProxy` | 300 | — | — | — | 无 | — | — |
| 292 | `com.apple.driver.AudioSharedDARTMapperProxy` | 157 | — | — | — | 无 | — | — |
| 293 | `com.apple.audio.TrustedClockingKEXT` | 446 | 1 | 3 | 全双路 | A | 446 | 3/3 |
| 294 | `com.apple.driver.VideoProcessing` | 32 | 1 | 3 | 全双路 | A | 32 | 3/3 |
| 295 | `com.apple.kec.XrtHostedXnu` | 97 | — | — | — | 无 | — | — |
| 296 | `com.apple.filesystems.apfs` | 2396 | 10 | 52 | 11/52 | ABC | 2399 | 43/43 |
| 297 | `com.apple.driver.corecapture` | 880 | 2 | 24 | 单路 | BC | 880 | 16/16 |
| 298 | `com.apple.kec.corecrypto` | 1948 | 1 | 2 | 单路 | C | 1955 | — |
| 299 | `com.apple.filesystems.lifs` | 460 | 1 | 52 | 单路 | B | 463 | 52/52 |
| 300 | `com.apple.driver.mDNSOffloadUserClient-Embedded` | 73 | 1 | 2 | 单路 | C | 73 | — |
| 301 | `com.apple.filesystems.tmpfs` | 153 | — | — | — | 无 | — | — |

---

## 3. 汇总

| 项 | 值 |
|---|---|
| kext 总数 | 301 |
| 真函数总数 | 197,683 |
| 有派发表的 kext | 85 |
| 派发表总数 | 244 |
| selector 总数 | 2266 |
| 置信度 A（双路互证） | 1631 |
| 置信度 B（单路 + 行为像） | 324 |
| 置信度 C（疑似 vtable） | 311 |
| A+B 中声明 variable-size 的 selector | 294 |
| A+B 中 27.2 四个 check 字段不变 | 1954 |
| A+B 中 27.2 字段有变 | 1 |
| 27.2 函数数有变的 kext | 24 |

### 3.1 置信度 C 的集中地（按 vtable 处理，不进风险排序）

| kext | C 行数 |
|---|---:|
| `com.apple.kernel` | 181 |
| `com.apple.driver.AppleT8150CLPC` | 36 |
| `com.apple.driver.AppleFirmwareKit` | 35 |
| `com.apple.driver.AppleMobileFileIntegrity` | 11 |
| `com.apple.iokit.IOHIDFamily` | 10 |
| `com.apple.filesystems.apfs` | 9 |
| `com.apple.driver.corecapture` | 8 |
| `com.apple.driver.AppleMSG` | 3 |
| `com.apple.AGXG18P` | 2 |
| `com.apple.driver.AppleM2ScalerCSCDriver` | 2 |

`com.apple.kernel` 占 181 行，是最大的噪声源：kernel 的 `__DATA_CONST` 里有大量「函数指针 + 小整数」的静态表（`OSMetaClass`、`IOCommand`、分发表），形状与 `IOExternalMethodDispatch` 高度相似。**它们被标 C 而不是被删掉**——因为「不读 args 字段」只是强证据，不是证明。

### 3.2 已知三个 kext 的对账

| kext | 本次 | 已有结论 | 一致 |
|---|---|---|---|
| AppleJPEGDriver | 表 `0xfffffe00080dd990` stride 0x28 n=10 | 10 | ✅ |
| AppleProResHW | 表 `0xfffffe000b905ce0` stride 0x28 n=5 | 5 | ✅ |
| AppleH16CameraInterface | 表 `0xfffffe0008086ae0` stride 0x18 n=120（117 + 另一张 3 槽表） | 117 | ✅（多出的 3 槽表见 §5） |

### 3.3 27.2 侧唯一有字段变化的是 AppleSARService

A+B 共 1955 行，27.2 里 check 字段变了的只有 1 行，全在 `com.apple.driver.AppleSARService`。这跟另一条线（差分审计）把 SARService 判成「真改动」是**独立吻合**的两条证据。

---

## 4. 每个 selector 的入参画像

全部 2266 行都在 `out/census.json`，每行字段：

```json
{"kext":"...","selector":7,"table":"0xfffffe000894b6f4","stride":24,
 "handler":"0xfffffe000894b6f4",
 "scalarIn":2,"structIn":0,"scalarOut":0,"structOut":0,
 "variable":false,"reads":["scalarInput64","scalarInputCount","structureInput","structureInputSize"],
 "tail":"0xfffffe0008962f70","dual":true,"conf":"B","refs":["0xfffffe000894b3f0"],
 "risk":7,"why":["idx:scalarInput64","reads:structureInputSize","variable-size"]}
```

`reads` 的口径：handler 前 128 条指令 + 最多 3 层 tail-call，按 §1.3 的偏移记录它读了 args 的哪些字段；**通过 `structureInput` 指针解引用得到的值也算用户可控**（标成 `structureInput(field)`）。

A+B 合计 1955 行的字段读取分布：

| 字段 | 读它的 selector 数 |
|---|---:|
| `scalarInput`(0x20) | 815 |
| `structureInput`(0x30) | 466 |
| `structureOutput`(0x58) | 412 |
| `structureInputSize`(0x38) | 261 |
| 尺寸 `0x60` | 222 |
| `structureOutputDescriptor`(0x68) | 86 |
| `scalarInputCount`(0x28) | 65 |

**局限（必须说清）**：`reads` 只覆盖 handler 入口 128 条指令与 3 层尾调用。深层调用链里的字段使用**完全没跟踪**。所以「reads 里没有 `structureInputSize`」不等于「这个 selector 不用尺寸」，只等于「前 128 条里没读」。

---

## 5. 高风险候选

> **为什么只有 12 行、凑不满 20**：分数 ≥4 的只有 9 个，到 3 分的再 3 个，剩下 1926 行是 0 分。要凑 20 就得把置信度 C 的 vtable 行拉进来充数——那是拿噪声冒充候选，不做。

排序规则（不用 dChk）：用户可控值（`structureInputSize` / `scalarInput*` / 经 `structureInput` 解引用得到的字段）**未被立即数比较**就用于（a）缩放索引（b）作为 `x2..x4` 实参进调用（长度位），各记 5 分；进算术记 1 分；声明 variable-size 记 1 分。

| # | kext | sel | handler | conf | 分数 | 触发点 | 手读结论 |
|---:|---|---:|---|---|---:|---|---|
| 1 | `com.apple.driver.AppleIPAppender` | 18 | `0xfffffe0008fb7f60` | A | 8 | arith:size@0x60<br>idx:size@0x60<br>variable-size | **有界**。`umull`+`lsr #0x25` 是**除以 33**（魔数 0x3e0f83e1），算出记录数后只当输出容量传给虚方法，不进内存操作。 |
| 2 | `com.apple.driver.AppleBasebandM20` | 7 | `0xfffffe000894b6f4` | B | 7 | idx:scalarInput64<br>reads:structureInputSize<br>variable-size | **有界**。`scalarInputCount` 先 `add x10,x8,x9,lsl#3` 求尾指针，再 `subs`/`lsr #0x20`/`cmp #7`/`cmp #0xf` 四重检查，count<3 直接跳走，之后才 `ldr [x8]`/`ldr [x8+8]`。 |
| 3 | `com.apple.driver.AppleBasebandM20` | 8 | `0xfffffe000894b7bc` | B | 7 | idx:scalarInput64<br>reads:structureInputSize<br>variable-size | **有界**。与 sel7 同一段检查序列（`cmp x9,#7` / `cmp x9,#0xf`）。 |
| 4 | `com.apple.driver.AppleSPU` | 5 | `0xfffffe00096bdb80` | A | 7 | idx:structureInput(field)<br>reads:structureInputSize<br>variable-size | **有界**。`ldr w9,[args,#0x38]` → `cbz` → `sub w9,#1` → `ldrb [buf,w9,uxtw]`，是 NUL 结尾检查（`cbnz` 就失败）。 |
| 5 | `com.apple.iokit.IOAccessoryManager` | 4 | `0xfffffe0009f69bd4` | A | 7 | idx:structureInput(field)(field)<br>reads:structureInputSize<br>variable-size | **有界**。用 `[args+0x40]` 描述符或 `(structureInput, structureInputSize)` 现造描述符，没有裸指针算术。 |
| 6 | `com.apple.iokit.IOSurface` | 19 | `0xfffffe000a349934` | A | 7 | idx:structureInput(field)<br>reads:structureInputSize<br>variable-size | **有界**。`cmp w9,#0x1ff; b.ls` + `ccmp w9,#0` 双闸，再 `sub w9,#1; ldrb [buf,w9,uxtw]`，同样是 NUL 结尾检查。 |
| 7 | `com.apple.driver.AppleEmbeddedTouchEEPROM` | 7 | `0xfffffe0008b70d18` | A | 6 | idx:scalarInput64<br>variable-size | **有界**。`ldr w24,[args,x8]`（x8=0x60/0x70 常量字段，不是数组索引）+ `cbz w24` 后才 `sub w8,w24,#1; strb wzr,[x23,w8,uxtw]`，写的是 `size-1`。 |
| 8 | `com.apple.driver.AppleBasebandM20` | 3 | `0xfffffe000894b568` | B | 5 | idx:scalarInput64 | **有界**。同族，`cmp x9,#7` / `cmp x9,#0xf` 后 `b.ls` 跳走。 |
| 9 | `com.apple.driver.AppleBasebandM20` | 19 | `0xfffffe000894bb14` | B | 5 | idx:scalarInput64 | **有界**。同族。 |
| 10 | `com.apple.driver.VideoProcessing` | 2 | `0xfffffe000a923194` | A | 3 | arith:scalarInput64(field)<br>arith:scalarInput64(field)(field)(field) | 未逐条读（分数 3） |
| 11 | `com.apple.filesystems.apfs` | 1 | `0xfffffe000a976360` | B | 3 | arith:structureInput<br>arith:structureInput(field)<br>arith:structureInput(field)(field) | 未逐条读（分数 3） |
| 12 | `com.apple.iokit.IOReportFamily` | 2 | `0xfffffe000a28d48c` | A | 3 | arith:structureInput(field)<br>reads:structureInputSize<br>variable-size | 未逐条读（分数 3） |

### 5.1 三类「看起来像洞、实际有界」的固定形状

手读的 9 个候选全部落进这三类，记下来作为后续判据：

1. **NUL 结尾检查**：`ldr w9,[args,#0x38]; cbz w9,fail; sub w9,w9,#1; ldrb [buf,w9,uxtw]`。读的是 `buf[size-1]`，`size!=0` 先挡住。IOSurface sel19 还额外有 `cmp w9,#0x1ff; b.ls` 上界。
2. **`scalarInputCount` 先乘再比再解引用**：`add x10,x8,x9,lsl#3`（尾指针）→ `subs` 下溢检查 → `lsr #0x20; cbnz` 溢出检查 → `cmp x9,#7` / `cmp x9,#0xf` 两道最小长度检查，之后才 `ldr [x8]`、`ldr [x8,#8]`。BasebandM20 的 4 个候选全是这个模板。
3. **容量除法**：`umull + lsr #0x25` 配魔数 `0x3e0f83e1` = 除以 33，算出的记录数只当输出容量（out 参数）传给虚方法，不参与任何内存操作。AppleIPAppender sel18。

这三类正是「形状扫描」的天然假阳性来源——它们的形状与真正的无界拷贝**在最前面几条指令上完全一致**，只有读到后面才知道有没有护栏。

### 5.2 H16Cam 多出来的那张 3 槽表

`0xfffffe0008087ed0` stride `0x18` n=3，不在已知的 117 项里。它的条目字段全 0，handler 也不读 args → 置信度 C。**按 3 槽小表 + 全零字段判断，更像 vtable 片段**，不作为新 selector 计入。

---

## 6. 直答

**全 cache 里，「用户可控长度/索引直进内存操作且没有上界检查」的 selector：确认 0 个。**

拆开说：

- 机械筛出**分数 ≥3 的候选 12 个**（占 2266 的 0.5%）。
- 其中 **9 个我逐条读了反汇编**，9 个全部有界，原因就是 §5.1 那三类。清单：`BasebandM20` sel 3/7/8/19、`AppleEmbeddedTouchEEPROM` sel 7、`AppleIPAppender` sel 18、`AppleSPU` sel 5、`IOAccessoryManager` sel 4、`IOSurface` sel 19。
- **另 3 个没读**（分数 3，未定性）：`IOReportFamily` sel 2、`VideoProcessing` sel 2、`apfs` sel 1。这 3 个不计入「0」，也不计入「有」。
- 另有 **311 个置信度 C 的 selector 根本没进风险排序**——因为它们不读 args 字段，几乎肯定不是派发表（`com.apple.kernel` 一家占 181）。

**这个「0」的射程必须写清楚**：

1. 它只覆盖 `reads` 的可见范围（入口 128 条指令 + 3 层尾调用）。深层调用链里的长度使用没跟踪。
2. 它只覆盖「长度/索引」这一类。**结构体字段的解释、状态机、竞态、引用计数、对象生命周期**全部没碰。
3. 它依赖 §1.3 的字段偏移；`0x60`/`0x70` 两个尺寸字段是我从汇编现场认出来的，没有符号可证。
4. 置信度 B 的 324 个 selector 只有数据路证据（没有代码路 `adrp+add` 交叉验证），其中 4 个（BasebandM20）已手读，其余 320 个的「它真的是外部方法」这一点本身还是**待证**。

所以准确表述是：**在机械可覆盖的范围内，没有任何 selector 把用户可控长度/索引无上界地送进内存操作。** 这是「没找到」，不是「不存在」——上半句的覆盖范围就是它的全部射程。

---

## 附录 A：合并缺陷修复（2026-11-01）

### A.1 缺陷

`com.apple.iokit.IOGPUFamily` 的 `table=0xfffffe00082f64b0` 报了 **112 行、selector 0..111**。真实情况是**两张 56 条表**：

| 表 | 基址 | 上界（代码证据） | 条数 |
|---|---|---|---|
| B | `0xfffffe00082f64b0` | — | 56 |
| A | `0xfffffe00082f69f0` | `cmp w1,#0x37` @ `0xfffffe000a024da8` | 56 |

两表基址相差 `0x82f69f0 - 0x82f64b0 = 0x540 = 56 × 24`，**首尾相接**。发现流程按「数据段指针连续」一路走到 112 行，没有按 bound 截断。

选表逻辑（同一函数内）：

```asm
0xfffffe000a024db8  ldrb w8, [x0, #0x103]   ; 运行期标志
0xfffffe000a024dc0  umull x9, w1, #24
0xfffffe000a024dc8  add  x10, ..., #0x9f0    ; 表 A
0xfffffe000a024de4  add  x10, ..., #0x4b0    ; 表 B
0xfffffe000a024dfc  tst  w8, #1
0xfffffe000a024e00  csel x3, x11, x12, ne    ; dispatch = (flag&1) ? A[sel] : B[sel]
```

### A.2 修复

- 备份：`out/census.pre-split.json`
- 规则：`selector >= 56` 的行 → `selector -= 56`，`table` 改为 `0xfffffe00082f69f0`，加字段 `split_of` / `orig_selector` / `bound=55`
- 结果：**行数 2266 → 2266（未删任何行）**，**表数 244 → 245**，**56 行幽灵 selector（56–111）重新编号为 0–55**

核验：`sel 0 = sel 56 = 0xfffffe000a021ee8`、`sel 55 = sel 111 = 0xfffffe000a0240cc` ⇒ 前后各 56 行的首尾 handler 一一对应，拆分点无歧义。

### A.3 全表复查（244 张，自动 + 未手读扫查）

判据：`handler[k] == handler[0]` 且各 count 相同，`k | n`，再看 `rows[0:n-k]` 与 `rows[k:n]` 的同形比例。

| 结果 | 表数 | 说明 |
|---|---|---|
| 干净 | 228 | 无重复签名 |
| `k=1` 假阳性 | 15 | 相邻 selector 共用同一 handler 属正常（`com.apple.kernel` 13 张、`com.apple.driver.AppleMSG` 2 张） |
| **已修** | **1** | `IOGPUFamily 0x82f64b0`（k=56，28/56 同形 + 代码证据） |
| **疑似未修** | **1** | `IOSurface 0x837fa10`（120 行，k=60，37/60 同形） |

### A.4 未修的那一张（留白，不擅改）

`com.apple.iokit.IOSurface` `table=0xfffffe000837fa10`，120 行，`k=60` 处 `handler[60] == handler[0]`，两半同形 37/60 —— 与 IOGPU 的双表模式**形状一致**。但：

- 在 IOSurface `__text` 里**没找到**对应的 `cmp w1,#0x3b`（60）上界 + 两个 24 字节表基址的组合；
- 唯一一处 `umull #24`（`0xfffffe000a328b8c`）是另一个函数：`cmp w1,#0x3`（4 条）、基址 `[this+0x58]+8`、记录 24 字节、比较 `[rec+8]`，与 120 行无关。

**证据不足，保持原样**，标记为待查。若后续确认，同一脚本可复用。
