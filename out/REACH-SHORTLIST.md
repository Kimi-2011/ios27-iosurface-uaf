# 可达性批处理结果（27.0.1 侧）

方法：① 放宽指针解码找分发表槽位 ② 读表邻近字符串定语义 ③ 查 kext 的 entitlement 串判断门控

总计 **32** 个候选落在数据表里；kext 级门控判定：可疑受控 20 / 未见门控 12

| kext | fn | 表内字符串 | 门控 |
|---|---|---|---|
| `com.apple.iokit.IOPCIFamily` | 0x2861064 | B16@?0^{OSObject=^^?i}8, IOPCIMatch, .driver.AppleSPUSphere | 否 |
| `com.apple.driver.AppleSARService` | 0x1e0e414 | i8@?0, Ry60, Ry61 | 否 |
| `com.apple.kec.corecrypto` | 0x2d392cc | pleEmbeddedLightSensor, ccaes_ctr_crypt_mode | 否 |
| `com.apple.driver.AppleTypeCPhy` | 0x21525f8 | i8@?0, B16@?0^{OSObject=^^?i}8 | 否 |
| `com.apple.filesystems.tmpfs` | 0x2d6fd3c | odArguments *), com.apple.driver.AppleFirmwareUpdateKext | 否 |
| `com.apple.iokit.IOBiometricFamily` | 0x2625234 | B24@?0^{OSObject=^^?i}8^B16, B16@?0^{OSObject=^^?i}8 | 否 |
| `com.apple.kec.corecrypto` | 0x2d391d8 | pleEmbeddedLightSensor | 否 |
| `com.apple.driver.AppleSARService` | 0x1db9450 | - | 否 |
| `com.apple.driver.AppleMobileDispH18P-DCP` | 0x1bc2194 | - | 否 |
| `com.apple.driver.AppleM2ScalerCSCDriver` | 0x1bb7fdc | - | 否 |
| `com.apple.iokit.IOSCSIArchitectureModelFamily` | 0x288ed8c | - | 否 |
| `com.apple.driver.AppleBasebandM20` | 0x15adf64 | - | 否 |
| `com.apple.kernel` | 0x3dd20d4 | pcbcount, platform_exec_logging, log cdhashes for all platfo | 是 |
| `com.apple.driver.AppleH16ANEInterface` | 0x18b5328 | ANE2, ANE3, B16@?0^v8 | 是 |
| `com.apple.driver.ApplePearlSEPDriver` | 0x1ccafd4 | B20@?0^v8{?=SS}16, InitializeEngine, GetProvisioningData | 是 |
| `com.apple.driver.ApplePPMCPMS` | 0x1ca187c | Instantaneous, 100 ms, Fast Die | 是 |
| `com.apple.driver.AppleH16ANEInterface` | 0x18de7e4 | i8@?0, ANE0, ANE1 | 是 |
| `com.apple.iokit.IODisplayPortFamily` | 0x2675720 | i8@?0, None, ConfigChange | 是 |
| `com.apple.kernel` | 0x3ded880 | lowpri_throttle_tier1_window_msecs, lowpri_throttle_tier2_wi | 是 |
| `com.apple.AGXG18P` | 0x13b7920 | i8@?0, v24@?0^v8Q16 | 是 |
| `com.apple.AGXG18P` | 0x1452934 | Count, i8@?0 | 是 |
| `com.apple.kernel` | 0x401b5b0 |  range, pmap=%p, start=%p, end=%p @%s:%d | 是 |
| `com.apple.kernel` | 0x41c1e44 | - | 是 |
| `com.apple.kernel` | 0x4072ac4 | - | 是 |
| `com.apple.kernel` | 0x4017fa0 | - | 是 |
| `com.apple.driver.AppleSmartBatteryManagerEmbedded` | 0x1fc3394 | - | 是 |
| `com.apple.AGXG18P` | 0x1390664 | - | 是 |
| `com.apple.filesystems.lifs` | 0x2d4f2c0 | - | 是 |
| `com.apple.filesystems.lifs` | 0x2d50ffc | - | 是 |
| `com.apple.filesystems.lifs` | 0x2d51b24 | - | 是 |
| `com.apple.iokit.IOTimeSyncFamily` | 0x2aa1708 | - | 是 |
| `com.apple.iokit.IOMobileGraphicsFamily-DCP` | 0x2795eb8 | - | 是 |

## 已确认语义的一例

ANE `0x1810784` → 表 `0xfffffe0008050f30`，邻近字符串为 `Wire/Unwire/DartMap/PrepareForFirmware/ANE0..3`，
构造函数 `FUN_fffffe0008c3c8c0` 分配 0x28d0/0x2748 字节对象并把 vtable（`0x8050de0`/`0x8050da0`）写进首字段。
即：这是 ANE 的固件/电源状态机对象，procedure IO 计数校验挂在状态机方法里。

## 门控结论

ANE 需要 `com.apple.ane.allow`、`com.apple.ane.iokit` 等授权，第三方 app 无法直接触达 → **不是链的第一跳**。
同理 PearlSEP（`com.apple.private.applepearl.allow`）、PPM（`com.apple.private.ppm.*`）、AGX（`com.apple.private.agx.performance`）均需私有授权。

## 局限

- 门控判定是 **kext 级** 的（扫该 kext 的 `com.apple.*.allow|iokit|private` 字符串），不是函数级；
- 表邻近字符串可能与相邻结构混淆，仅作语义线索；
- 判定“否”只代表该 kext 里没有明显授权串，不等于普通 app 一定可达。