# DISPATCH-SWEEP — 全内核 `ldrsw`+`br` 型派发点普查

1. **目标**：找出 census（245 张表 / 2266 selector）看不见的第三类派发形态 —— `ldrsw` int32 相对偏移表 + `adr` + `add` + `br`。
2. **范围**：`out/kc.27.0.1.full` 全部 **301 个 kext** 的 `__TEXT` / `__TEXT_EXEC` / `__TEXT_BOOT_EXEC`。
3. **签名**：`ldrsw xT, [xN, xM, lsl #2]`，编码掩码 `(w & 0xFFE0EC00) == 0xB8A06800`（用 AGX 已知实例 `0xb8b07a30` 验证过）。
4. **判据**：命中后 ≤6 条内必须出现 `adr` + `add` + `br`（或 `braa`），否则丢弃 —— 这样排除了「按 4 字节读数组元素」的普通 `ldrsw`。
5. **结果**：原始命中 **581**，确认 int32 相对派发 **532**，分布于 **80 个 kext**。
6. **与 census 交叉**：**0 / 532** 的表基址出现在 census 的 245 张表里 —— 两者根本不相交（census 的表全在数据段 `0x7xx/0x8xx`，这 532 张全在代码段 `0x9xx–0xbxx`）。
7. **验证**：`com.apple.driver.AppleSEPKeyStore` 扫到 `bound=168`（169 项）在 `0xfffffe00095cc2d4`，与已知的 169-handler 大函数吻合 ⇒ 扫描器确实能抓到 census 漏掉的那种。
8. **重要限定**：这 532 个里绝大多数是**编译器为普通 C `switch` 生成的跳转表**，不是安全相关的派发。只有「位于 externalMethod 形态函数内 + 条目数大」的才是靶子，本节用 `bound ≥ 60` 做粗筛（59 个）。
9. **未做**：没有逐个手读这 532 处；下表 `bound ≥ 60` 的 59 个也只做了自动提取，**未手读**。
10. **判据纪律**：全程完整 VA；本轮未使用 auth 指针解码；未用 `v>>63` 过滤。

---

## §1 方法

```asm
cmp  w?, #BOUND            ; 上界（-14..-1 条内找）
...
adrp x17, PAGE
add  x17, x17, #lo         ; ← 表基址 = PAGE+lo
ldrsw xT, [x17, xM, lsl #2]  ; int32 相对偏移
adr  x17, #<cur>
add  xT, x17, xT
br   xT
```

`adr` 的地址是**相对基准**，表项是「目标 − adr」的 int32。这与指针表（`ldr` + `braa`）形态不同，本扫描只收前者。

## §2 总量

| 项 | 数 |
|---|---|
| kext 总数 | 301 |
| 原始 `ldrsw` 变址命中 | 581 |
| 确认 int32 相对派发点 | **532** |
| 涉及 kext 数 | **80** |
| 表基址落在 census 245 张表内 | **0** |
| `bound ≥ 60` 的粗筛靶子 | 59 |

## §3 与 census 的差集

| 方向 | 数量 | 说明 |
|---|---|---|
| census 有、扫描没有 | 245 张 | **不是假表**：它们是 `IOExternalMethodDispatch` 记录数组（24/40 字节步长），本来就不是跳转表，两种对象没有可比性 |
| 扫描有、census 没有 | **532** | 结构上必然：census 只扫数据段表，这 532 张全在代码段 |

⇒ **census 对「代码跳转表型派发」是零覆盖**，不是漏了几张，是这一类从未进入扫描视野。

## §4 `bound ≥ 60` 的 59 个（自动提取，未手读）

| kext | 派发点 VA | 表基址 | 条目数 | bound | 在 census |
|---|---|---|---|---|---|
| com.apple.iokit.IOMobileGraphicsFamily | `0xfffffe000a17ff80` | `0xfffffe000a17ffbc` | 322 | 321 | 否 |
| com.apple.iokit.IOMobileGraphicsFamily | `0xfffffe000a180808` | `0xfffffe000a181c24` | 322 | 321 | 否 |
| com.apple.kernel | `0xfffffe000b171b70` | `0xfffffe000b172c44` | 311 | 310 | 否 |
| com.apple.kernel | `0xfffffe000b174158` | `0xfffffe000b1748ec` | 311 | 310 | 否 |
| com.apple.kernel | `0xfffffe000affc390` | `0xfffffe000affc430` | 306 | 305 | 否 |
| com.apple.kernel | `0xfffffe000b000194` | `0xfffffe000b0005f0` | 304 | 303 | 否 |
| com.apple.kernel | `0xfffffe000aece0d4` | `0xfffffe000aecf318` | 252 | 251 | 否 |
| com.apple.driver.ApplePPMCPMS | `0xfffffe0009312e30` | `0xfffffe0009313f10` | 249 | 248 | 否 |
| com.apple.driver.ApplePPMCPMS | `0xfffffe0009314314` | `0xfffffe0009314d54` | 248 | 247 | 否 |
| com.apple.driver.ApplePPMCPMS | `0xfffffe00093358bc` | `0xfffffe000933632c` | 248 | 247 | 否 |
| com.apple.kernel | `0xfffffe000ae2b414` | `0xfffffe000ae2c48c` | 219 | 218 | 否 |
| com.apple.kernel | `0xfffffe000ae2e278` | `0xfffffe000ae30070` | 219 | 218 | 否 |
| com.apple.kernel | `0xfffffe000ae2b3d0` | `0xfffffe000ae2c7f8` | 216 | 215 | 否 |
| com.apple.kernel | `0xfffffe000ae2dcd0` | `0xfffffe000ae303dc` | 216 | 215 | 否 |
| com.apple.kernel | `0xfffffe000ae2b7d0` | `0xfffffe000ae2cb58` | 212 | 211 | 否 |
| com.apple.kernel | `0xfffffe000ae2d568` | `0xfffffe000ae2d6f8` | 212 | 211 | 否 |
| com.apple.driver.AppleH16ANEInterface | `0xfffffe0008ca1d04` | `0xfffffe0008ca2f40` | 196 | 195 | 否 |
| com.apple.kernel | `0xfffffe000ae1008c` | `0xfffffe000ae10588` | 178 | 177 | 否 |
| com.apple.driver.AppleSEPKeyStore | `0xfffffe00095cc2d4` | `0xfffffe00095d47a0` | 169 | 168 | 否 |
| com.apple.kernel | `0xfffffe000b02c8bc` | `0xfffffe000b02d310` | 158 | 157 | 否 |
| com.apple.kernel | `0xfffffe000b0279c4` | `0xfffffe000b02838c` | 140 | 139 | 否 |
| com.apple.kernel | `0xfffffe000b027138` | `0xfffffe000b027350` | 137 | 136 | 否 |
| com.apple.kernel | `0xfffffe000b07d6a0` | `0xfffffe000b07d998` | 137 | 136 | 否 |
| com.apple.kernel | `0xfffffe000ad61264` | `0xfffffe000ad62264` | 132 | 131 | 否 |
| com.apple.kernel | `0xfffffe000aba5e88` | `0xfffffe000aba5ee0` | 130 | 129 | 否 |
| com.apple.kernel | `0xfffffe000aba0cc0` | `0xfffffe000aba0ce4` | 129 | 128 | 否 |
| com.apple.kernel | `0xfffffe000b14ac98` | `0xfffffe000b14c034` | 128 | 127 | 否 |
| com.apple.kernel | `0xfffffe000ad80988` | `0xfffffe000ad80d1c` | 123 | 122 | 否 |
| com.apple.kernel | `0xfffffe000aeb3560` | `0xfffffe000aeb6a80` | 123 | 122 | 否 |
| com.apple.kernel | `0xfffffe000b02be60` | `0xfffffe000b02bea4` | 122 | 121 | 否 |
| com.apple.kernel | `0xfffffe000b040d2c` | `0xfffffe000b041ba8` | 122 | 121 | 否 |
| com.apple.kernel | `0xfffffe000b040e98` | `0xfffffe000b041ee8` | 122 | 121 | 否 |
| com.apple.driver.AppleM2ScalerCSCDriver | `0xfffffe00090cf0c4` | `0xfffffe00090d00f0` | 122 | 121 | 否 |
| com.apple.kernel | `0xfffffe000abe0c38` | `0xfffffe000abe168c` | 121 | 120 | 否 |
| com.apple.kernel | `0xfffffe000ad20e4c` | `0xfffffe000ad21110` | 121 | 120 | 否 |
| com.apple.kernel | `0xfffffe000b0bea48` | `0xfffffe000b0c2e84` | 117 | 116 | 否 |
| com.apple.driver.ApplePPMCPMS | `0xfffffe0009305768` | `0xfffffe0009305c38` | 116 | 115 | 否 |
| com.apple.security.sandbox | `0xfffffe000a8e7430` | `0xfffffe000a8ea8f8` | 112 | 111 | 否 |
| com.apple.kernel | `0xfffffe000b11f414` | `0xfffffe000b11f7f4` | 100 | 99 | 否 |
| com.apple.driver.ApplePearlSEPDriver | `0xfffffe000935be40` | `0xfffffe0009360c20` | 94 | 93 | 否 |
| com.apple.kernel | `0xfffffe000b2b1c20` | `0xfffffe000b2b20d0` | 91 | 90 | 否 |
| com.apple.kernel | `0xfffffe000af96f88` | `0xfffffe000af97a1c` | 85 | 84 | 否 |
| com.apple.kernel | `0xfffffe000b2aef60` | `0xfffffe000b2af864` | 84 | 83 | 否 |
| com.apple.kernel | `0xfffffe000af73d08` | `0xfffffe000af74818` | 77 | 76 | 否 |
| com.apple.kernel | `0xfffffe000b04c328` | `0xfffffe000b04da64` | 77 | 76 | 否 |
| com.apple.kernel | `0xfffffe000add6194` | `0xfffffe000add6a30` | 76 | 75 | 否 |
| com.apple.kernel | `0xfffffe000af96e24` | `0xfffffe000af9788c` | 74 | 73 | 否 |
| com.apple.kernel | `0xfffffe000ad4234c` | `0xfffffe000ad42514` | 72 | 71 | 否 |
| com.apple.driver.AppleM2ScalerCSCDriver | `0xfffffe00090f067c` | `0xfffffe00090f1350` | 70 | 69 | 否 |
| com.apple.driver.AppleM2ScalerCSCDriver | `0xfffffe00090ff828` | `0xfffffe00091004fc` | 70 | 69 | 否 |
| com.apple.AGXG18P | `0xfffffe00084b820c` | `0xfffffe00084b82d4` | 66 | 65 | 否 |
| com.apple.driver.AppleM2ScalerCSCDriver | `0xfffffe0009051a0c` | `0xfffffe0009051d70` | 66 | 65 | 否 |
| com.apple.driver.AppleM2ScalerCSCDriver | `0xfffffe000906d694` | `0xfffffe000906e650` | 66 | 65 | 否 |
| com.apple.driver.AppleM2ScalerCSCDriver | `0xfffffe0009078364` | `0xfffffe00090791fc` | 66 | 65 | 否 |
| com.apple.driver.AppleM2ScalerCSCDriver | `0xfffffe0009101c98` | `0xfffffe0009102b04` | 66 | 65 | 否 |
| com.apple.kernel | `0xfffffe000ad1f0b8` | `0xfffffe000ad1fdcc` | 65 | 64 | 否 |
| com.apple.kernel | `0xfffffe000ad51bd0` | `0xfffffe000ad52734` | 64 | 63 | 否 |
| com.apple.driver.ASIOKit | `0xfffffe00085c2c14` | `0xfffffe00085c6fe8` | 62 | 61 | 否 |
| com.apple.kernel | `0xfffffe000ac4d158` | `0xfffffe000ac4d1f0` | 61 | 60 | 否 |

## §5 分布（全部 532）

| kext | 数量 |
|---|---|
| com.apple.kernel | 159 |
| com.apple.iokit.IOHIDFamily | 53 |
| com.apple.driver.AppleM2ScalerCSCDriver | 32 |
| com.apple.filesystems.apfs | 17 |
| com.apple.driver.AppleH16ANEInterface | 16 |
| com.apple.kext.AppleMatch | 12 |
| com.apple.driver.AppleSEPCredentialManager | 12 |
| com.apple.driver.AppleJPEGDriver | 10 |
| com.apple.iokit.IOSkywalkFamily | 10 |
| com.apple.security.sandbox | 9 |
| com.apple.iokit.IOAVFamily | 8 |
| com.apple.iokit.IOAccessoryManager | 8 |
| com.apple.driver.AppleAVE2 | 7 |
| com.apple.driver.AppleH16CameraInterface | 7 |
| com.apple.driver.AppleLockdownMode | 7 |
| （其余 65 个 kext） | 各 1–6 |

## §6 直答

> **全内核 `ldrsw`+`br` 型派发点：532 个，分布在 80 个 kext。census 漏了全部 532 个（重合度 0）。**

漏检最集中的 kext：`com.apple.kernel` 159、`IOHIDFamily` 53、`AppleM2ScalerCSCDriver` 32、`apfs` 17、`AppleH16ANEInterface` 16。

**但「532 全是靶子」不成立**：其中多数是普通 `switch`。按 `bound ≥ 60` 粗筛剩 **59 个**，其中用户可达性最高的是：

- `com.apple.driver.AppleSEPKeyStore` `bound=168` @ `0xfffffe00095cc2d4` —— 这个已验证与已知的 169-handler 大函数吻合
- `com.apple.driver.AppleH16ANEInterface` `bound ≥ 60` 有 1 个
- `com.apple.AGXG18P` 1 个、`ApplePearlSEPDriver` 1 个、`ASIOKit` 1 个

**下一步**：对这 59 个逐个手读「派发前是否校验 selector 上界 + 目标是否 externalMethod 形态」，才是真正的新靶子清单。本节只做到定位。
