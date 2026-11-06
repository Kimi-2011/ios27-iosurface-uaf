# 有 UserClient 且有 external method 的 kext：27.0.1 → 27.2 差分与可达性

1. 换靶原因：`com.apple.kernel` 的 159 个候选已全部判完，没有 app 沙箱可达的内核内存破坏原语；下一批靶子只能从「对外开 UserClient、且有 external method 派发」的 kext 里找。
2. 数据：27.0.1 用 `out/kc.27.0.1.full`（78,135,296 B，Mach-O 64-bit arm64e fileset）；27.2 从 `out/kc.27.2.ga.im4p` 解 lzfse 得到 `/tmp/kc272.bin`（78,512,128 B）。两侧各 301 个 kext，bundle id 集合完全一致。
3. 方法沿用自建的那一套，没有回退到旧工具：起点 = `PACIBSP ∪ (BTI c 且下一条 ≠ PACIBSP)`；配对 = 锚定配对（`SequenceMatcher` 找 replace/insert/delete 块后块内全对全相似度匹配 + 两遍语义规范化），不是位置配对；判据 = guard-signature 多重集差分，`dChk` 只当闸门。
4. 普查表是**字符串级启发式**，不是权威分类：122 个 kext 含 `*UserClient` 类名串，42 个含 `externalMethod`/`IOExternalMethod*` 串，两者兼有 40 个。
5. `selector 数`这一列**全部没取到**。原因见 §1.3：这个 cache 里 kext 的 `__DATA_CONST` 不含任何绝对内核指针，派发表被编码过，我没能把 `IOExternalMethodDispatch` 表解出来。
6. 因为普查表不可靠（漏了 AGXG18P 这种肯定有 IOAccelerator UserClient 的 kext，又多算了 `com.apple.kernel`），**差分没有把普查表当闸门**：301 个 kext 里除了已结案的 4 个，其余 298 个全差，0 报错。
7. 全量结果：654 个 dChk>0 且配对成功的函数，其中净新增签名>0 的 330 个，分布在 65 个 kext。
8. 人工反汇编 15 对（AGXG18P 4 对、AppleAVE2 2 对、AppleSARService 2 对，其余各 1 对）：10 条功能新增（其中 6 条同时带防御加固）、2 条纯防御加固、2 条结构体重排、1 条未定性。**没有一条**具备「用户可控标量/结构体字段当索引或长度、27.0.1 不校验、27.2 补上校验」的形状。
9. 新抓到的第六种形态误判：guard 签名里保留了内存操作数位移，于是**结构体整体增长**会把每一处字段位移变成「新增签名」。AGXG18P 就是整类对象 +8 字节，21 个候选里绝大多数是这一个原因（详见 §3.1）。
10. 最后一句是直答。

---

## 1. 可达性普查表

### 1.1 口径

对 301 个 kext 各自独立取段（fileset 条目里的 segment `fileoff` 是**外层文件绝对偏移**，不是条目内相对偏移——这一点和 `tools/kext_extract.py` 的注释不一致，实测按绝对偏移才对），从 `__TEXT`/`__DATA_CONST`/`__DATA` 里抽可打印串，然后：

- **有 UserClient 类名** = 抽到形如 `\b[A-Z][A-Za-z0-9_]{2,50}UserClient(V2|V3)?\b` 的串（OSMetaClass 注册名就存在 cstring 池里）。
- **有 external method 证据** = 抽到含 `externalMethod` / `IOExternalMethodArguments` / `IOExternalMethodDispatch` 的串，计条数。
- **ent 列** = 该 kext 里出现的 `com.apple.private|security|system.*` 权限串条数，用来粗判「要不要特权才打得开」。
- **27.2 改动** = `dChk>0 的可配对函数数 / 其中净新增签名>0 的个数`，由 §2 的全量差分给出。

### 1.2 表（40 行，准入 = 类名串 ∧ externalMethod 串）

| kext (bundle id) | UserClient 类数 | 首个类名 | ext 串数 | selector 数 | 27.2 改动 | 函数数 | Δ函数数 |
|---|---|---|---|---|---|---|---|
| `com.apple.EXBrightKext` | 1 | `EXBrightKextUserClient` | 1 | 未取 | 10/10 | 582 | +14 |
| `com.apple.audio.TrustedClockingKEXT` | 1 | `TrustedClockingUserClient` | 2 | 未取 | 0/0 | 450 | +0 |
| `com.apple.driver.AppleARMPlatform` | 9 | `AggressorUserClient` | 1 | 未取 | 3/3 | 2243 | +0 |
| `com.apple.driver.AppleAVD` | 1 | `AppleAVDUserClient` | 1 | 未取 | 未跑 | 2392 | +0 |
| `com.apple.driver.AppleAVE2` | 1 | `AppleAVE2UserClient` | 1 | 未取 | 18/17 | 3067 | +3 |
| `com.apple.driver.AppleAstrisGpioProbe` | 1 | `AppleAstrisGpioProbeUserClient` | 1 | 未取 | 0/0 | 133 | +0 |
| `com.apple.driver.AppleCentauriManager` | 1 | `AppleCentauriManagerUserClient` | 1 | 未取 | 0/0 | 533 | +0 |
| `com.apple.driver.AppleDialogPMU` | 1 | `AppleDialogPMUUserClient` | 1 | 未取 | 0/0 | 90 | +0 |
| `com.apple.driver.AppleDiskImages2` | 2 | `DIDeviceCreatorUserClient` | 10 | 未取 | 2/2 | 408 | +0 |
| `com.apple.driver.AppleEffaceableStorage` | 1 | `AppleEffaceableStorageUserClient` | 1 | 未取 | 0/0 | 142 | +0 |
| `com.apple.driver.AppleEmbeddedPCIE` | 1 | `AppleEmbeddedPCIEUserClient` | 1 | 未取 | 0/0 | 506 | +0 |
| `com.apple.driver.AppleFirmwareKit` | 4 | `AFKEndpointInterfaceUserClient` | 1 | 未取 | 0/0 | 2621 | +0 |
| `com.apple.driver.AppleFirmwareUpdateKext` | 1 | `AppleFirmwareUpdateUserClient` | 1 | 未取 | 0/0 | 80 | +0 |
| `com.apple.driver.AppleHIDTransport` | 3 | `AppleHIDTransportBootloaderUserClient` | 1 | 未取 | 0/0 | 2164 | +0 |
| `com.apple.driver.AppleIDV` | 1 | `AppleIDVUserClient` | 1 | 未取 | 1/1 | 123 | -4 |
| `com.apple.driver.AppleInputDeviceSupport` | 3 | `AIDFirmwareUpdateUserClient` | 1 | 未取 | 6/3 | 871 | +0 |
| `com.apple.driver.AppleMobileApNonce` | 1 | `AppleMobileApNonceUserClient` | 1 | 未取 | 0/0 | 103 | +0 |
| `com.apple.driver.AppleMobileFileIntegrity` | 1 | `AppleMobileFileIntegrityUserClient` | 5 | 未取 | 1/1 | 984 | +0 |
| `com.apple.driver.ApplePMP` | 3 | `ApplePMPThermalUserClient` | 17 | 未取 | 0/0 | 403 | +0 |
| `com.apple.driver.ApplePPMCPMS` | 1 | `ApplePPMUserClient` | 1 | 未取 | 9/8 | 2110 | +14 |
| `com.apple.driver.ApplePearlSEPDriver` | 1 | `ApplePearlUserClient` | 1 | 未取 | 4/4 | 683 | +1 |
| `com.apple.driver.AppleProResHW` | 1 | `AppleProResUserClient` | 1 | 未取 | 0/0 | 3773 | +0 |
| `com.apple.driver.AppleProcessorTrace` | 2 | `AppleProcessorTraceUserClient` | 23 | 未取 | 6/6 | 1389 | +3 |
| `com.apple.driver.AppleSARService` | 2 | `ABSUserClient` | 70 | 未取 | 18/18 | 1969 | +9 |
| `com.apple.driver.AppleSEPCredentialManager` | 1 | `AppleCredentialManagerUserClient` | 1 | 未取 | 6/5 | 1028 | +1 |
| `com.apple.driver.AppleSEPManager` | 1 | `AppleSEPUserClient` | 18 | 未取 | 1/1 | 2499 | +0 |
| `com.apple.driver.AppleSmartIO2` | 1 | `AppleSmartIOUserClient` | 2 | 未取 | 0/0 | 479 | +0 |
| `com.apple.driver.AppleT8150MCC` | 1 | `AppleMCCUserClientV2` | 1 | 未取 | 3/3 | 560 | +0 |
| `com.apple.driver.corecapture` | 3 | `CCDataPipeUserClient` | 1 | 未取 | 0/0 | 897 | +0 |
| `com.apple.filesystems.lifs` | 1 | `AppleLIFSUserClient` | 3 | 未取 | 5/5 | 467 | +3 |
| `com.apple.iokit.CoreAnalyticsFamily` | 2 | `CoreAnalyticsTestUserClient` | 9 | 未取 | 0/0 | 244 | +0 |
| `com.apple.iokit.IOAccessoryManager` | 14 | `IOAccessoryConfigStreamUserClient` | 1 | 未取 | 1/0 | 4821 | -1 |
| `com.apple.iokit.IOGPUFamily` | 2 | `IOGPUDeviceUserClient` | 7 | 未取 | 4/4 | 2044 | +2 |
| `com.apple.iokit.IONVMeFamily` | 4 | `AppleNVMeSMARTUserClient` | 8 | 未取 | 1/1 | 4089 | -35 |
| `com.apple.iokit.IOThunderboltFamily` | 1 | `IOThunderboltFamilyUserClient` | 10 | 未取 | 0/0 | 5762 | +0 |
| `com.apple.iokit.IOTimeSyncFamily` | 7 | `IOTimeSyncClockManagerUserClient` | 1 | 未取 | 3/3 | 1489 | -18 |
| `com.apple.iokit.IOUSBHostFamily` | 8 | `AppleUSBHostDeviceUserClient` | 1 | 未取 | 6/6 | 2039 | +0 |
| `com.apple.kernel` | 2 | `IOUserUserClient` | 1 | 未取 | 未跑 | 23277 | +55 |
| `com.apple.plugin.IOgPTPPlugin` | 8 | `IOTimeSyncClockManagerUserClient` | 5 | 未取 | 5/4 | 1639 | -21 |
| `com.apple.security.Image4` | 1 | `Image4UserClient` | 1 | 未取 | 0/0 | 517 | +0 |
> 排除与覆盖说明：`com.apple.driver.AppleAVD`、`com.apple.kernel` 在普查表里但没跑差分（前者已结案、后者是上一轮靶子）。`com.apple.driver.AppleH16ANEInterface`、`IOSkywalkFamily` 同样已结案，不在普查表内。`com.apple.AGXG18P`（GPU，Metal 可达）、`com.apple.driver.AppleJPEGDriver`、`com.apple.iokit.IOSurface` 这类必然有 UserClient 的 kext **没进普查表**——字符串启发式漏了，但它们在 §2 的全量差分里都被覆盖到了。

### 1.3 selector 数为什么没取到（实测证据，不是没试）

三条路都试了，都不通：

1. **直接扫 `IOExternalMethodDispatch` 表**：结构是 `{u64 func; u32 checkScalarIn; u32 checkStructInSize; u32 checkScalarOut; u32 checkStructOutSize}` 24 字节记录。按「首字段落在本 kext `__TEXT_EXEC` 范围 + 后 4 个 u32 都很小」扫，301 个 kext 命中 **0**。
2. **查指针编码**：对 `AppleAVE2`、`AppleH16CameraInterface`、`sandbox` 三个 kext 统计 `__DATA_CONST`/`__DATA` 里形如 `0xfffffe00_xxxxxxxx` 的字，命中 **0**。首字是 `0x0010000001784a2c` 这类值（bit62/63=0、bits51..61=2、低 36 位 0x01784a2c），是 dyld chained-fixup 编码而不是裸指针；我没能把 chain 首地址和 `seg_info` 解出来，所以解不回去。
3. **放弃指针、改认代码形状**：假设 `UserClient::externalMethod` 覆写里会 `adrp+add x2,&table`、`mov w3,#count`，再 `bl` 到 kext 外。对 `AppleAVE2`/`sandbox`/`AppleH16CameraInterface` 扫描命中 **0**——说明参数位置不是我假设的那套（很可能 count 不是立即数，或经 `blraa` 间接调用）。
4. **退化成「24 字节记录后 4 个字段都很小」**：`AppleAVE2` 的 `__DATA_CONST` 命中 505 处、`sandbox` 84 处——完全是噪声，不能用。

结论：selector 数在这个 build 上取不到，表中一律写「未取」。这不影响 §2 的差分，因为差分不靠这张表。

---

## 2. 差分结果

### 2.1 覆盖率

| 项 | 数 |
|---|---|
| kernelcache 内 kext 总数（两侧） | 301 / 301 |
| 实际差分 kext | 298（跳过 `com.apple.kernel`、`AppleAVD`、`IOSkywalkFamily`、`AppleH16ANE*`） |
| 差分过程报错 | 0 |
| dChk>0 且配对成功（候选） | 654 |
| 其中净新增签名 > 0 | 330 |
| 其中净新增签名 = 0（纯重排/纯位移） | 324 |
| 涉及的 kext | 65 |
| 人工反汇编 | 15 对 |
| **人工覆盖率** | **15/330 = 4.5%（对候选总数 15/654 = 2.3%）** |

### 2.2 按 kext 排（净新增签名>0 的前 18 名）

| kext | dChk>0 | 净新增>0 | 单函数最大净新增 |
|---|---|---|---|
| `com.apple.driver.RTBuddy` | 28 | 28 | 13 |
| `com.apple.AGXG18P` | 21 | 20 | 15 |
| `com.apple.filesystems.apfs` | 23 | 18 | 27 |
| `com.apple.driver.AppleSARService` | 18 | 18 | 13 |
| `com.apple.driver.ASIOKit` | 18 | 18 | 8 |
| `com.apple.driver.AppleAVE2` | 18 | 17 | 39 |
| `com.apple.driver.SecureRTBuddyProxy` | 12 | 12 | 4 |
| `com.apple.EXBrightKext` | 10 | 10 | 2 |
| `com.apple.driver.IOAudioCodecs` | 9 | 9 | 12 |
| `com.apple.security.sandbox` | 9 | 8 | 13 |
| `com.apple.driver.ApplePPMCPMS` | 9 | 8 | 10 |
| `com.apple.driver.AppleDCP` | 8 | 8 | 9 |
| `com.apple.kec.corecrypto` | 9 | 8 | 4 |
| `com.apple.AppleFSCompression.AppleFSCompressionTypeZlib` | 7 | 7 | 40 |
| `com.apple.driver.AppleM2ScalerCSCDriver` | 14 | 7 | 10 |
| `com.apple.driver.AppleDisplayCrossbar` | 7 | 7 | 3 |
| `com.apple.iokit.IOUSBHostFamily` | 6 | 6 | 4 |
| `com.apple.driver.DiskImages.UDIFDiskImage` | 6 | 6 | 3 |

### 2.3 42 个有净新增大立即数比较的候选（这是「新增边界检查」的最高产筛子）

对 330 个候选，筛出「新增签名里含 `CMP/SUBS/TST/ANDS` 且立即数 ≥ 0x10」的，42 个候选命中（与 §1 里「42 个 kext 含 externalMethod 串」只是数字巧合，口径无关）。前几名：

| kext | A → B | 净新增 | 相似度 | Δ指令 | 新增比较 |
|---|---|---|---|---|---|
| `AppleAVE2` | `0x878e224`→`0x87c4dc8` | 39 | 0.49 | +532 | `hi w,#0x10` `hs w,#0x3f` `hs w,#0x41` `hs w,#0x11` |
| `AppleFSCompressionTypeZlib` | `0x8b90a20`→`0x8bce5d0` | 40 | 0.37 | +449 | `eq w,#0x2ff` `ne w,#0x306` `eq w,#0x5ff` |
| `ApplePPMCPMS` | `0x9335a64`→`0x937e980` | 10 | 0.65 | −117 | `gt w,#0x67` `eq w,#0x66` `ne w,#0x67` `eq w,#0x68` |
| `AGXG18P` | `0x856d2f0`→`0x8586780` | 3 | **0.998** | **+4** | `hi x,#0x24` `eq x,#0x1d` `eq x,#0x21` `ne x,#0x28` |
| `AGXG18P` | `0x850c0c0`→`0x8525228` | 1 | 0.952 | +3 | `eq x,#0x28` `ls x,#0x24` |
| `apfs` | `0xa9f1740`→`0xaa4056c` | 3 | 0.959 | +6 | `hi w,#0x2f` |
| `corecrypto` | `0xaac9c28`→`0xab18a58` | 2 | 0.79 | +13 | `lo w,#0x88` `hi x,#0x87` |
| `AppleSEPCredentialManager` | `0x95a02b4`→`0x95eae38` | 2 | 0.71 | +26 | `hs x,#0x753` `hi w,#0x46` |

（`TST x,#0xffc0000000000000` 那几处不是边界检查，是**指针 tag 校验**，见 §3.12。）

---

## 3. 人工确认的候选（15 对）

### 3.1 先说新发现的方法缺陷：结构体增长会伪装成「新增边界检查」

`AGXG18P` 有 21 个候选，其中至少 4 对我逐条看完，差异几乎全部是**字段位移整体 +8**：

- `0x84f76b4→0x8510670`：`[0x5e0]→[0x5e8]`、`add x20,x9,#0x5d0→#0x5d8`、`add x9,x0,#0xab8→#0xac0`、`mov w27,#0xcdb8→#0xcdc0`、`ldr x8,[x19,#0x2a0]→#0x2a8`、`mov w9,#0xab98→#0xaba0`。
- `0x850c0c0→0x8525228`：`[0x2a0]→[0x2a8]`、`mov w19,#0xcd58→#0xcd60`、`mov x17,#0x300→#0x308`、`[0x2e0]→[0x2e8]`、`[0xcb8]→[0xcc0]`、`[0x5bc]→[0x5c4]`。

原因在我的 `opnorm()`：它把内存操作数的位移原样保留（`[MEM+0x300]` vs `[MEM+0x308]`），于是**每一次字段平移都会生成一条「新签名」**。后果是「净新增签名>0」在结构体改版的 kext 里会系统性虚高。这是第六种「把形态当语义」的误判，必须在读 §2 数字时扣掉。判读规则：**若某函数的新增签名里 `[MEM+…]` 位移成等差数列且步长一致，优先判结构体重排，不要判成新增校验。**

### 3.2 `AGXG18P` `0x84f76b4 → 0x8510670`（相似度 0.921，Δ+13）
对象 +8 字节后的字段平移；6 条新增签名全部是状态枚举新 case（`cmp w27,#2/#3`、`cmp w8,#4`、`cmp w11,#1/#2/#5` 分支）。判 **重构（结构体增长）+ 功能新增（新状态分支）**。无校验语义。

### 3.3 `AGXG18P` `0x84b9f28 → 0x84d2170`（2886→3000 指令，净新增 22 / 消失 7）
新增：`ldrb w9,[x21,#0x648]; tbnz w9,#0` 特性位、`blraa`（PAC 后的虚调用）后 `cbz x0` 空指针、`bl` 后 `tbz w0,#0` 返回值检查、`subs x9,x9,x10` 遍历计数。消失侧是 `SUBS eq`、`CMP eq x,w,uxth` 各 2 条被搬走。判 **功能新增（GPU 初始化/提交路径新分支）+ 防御加固（空指针/返回值检查）**。

### 3.4 `AGXG18P` `0x856d2f0 → 0x8586780`（4765→4769，净新增 3）——最像边界检查，但整段是新代码
B 侧新增一个完整循环：

```
mov  x23, #0
x21 = 0x712b878   (表 1, 8 字节元素)
x22 = 0x712b9a0   (表 2, 8 字节元素)
loop:
  cmp  x23, #0x24        ← 新增签名
  b.hi skip
  ldr  x2, [x21, x23, lsl #3]
  cmp  x23, #0x1d        ← 新增签名
  b.eq body
  cmp  x2, #0x21         ← 新增签名
  b.eq skip
body:
  ldr  x3, [x22, x23, lsl #3]
  bl   ...
skip:
  add  x23, x23, #1
  cmp  x23, #0x28        ← 新增签名
  b.ne loop
```

看起来是「表 37 项、循环 40 次、用 `cmp x23,#0x24` 挡住 0x25..0x27 的越界读」。**但在 27.0.1 的函数里，这串指令一条都不存在**：`ldr x2,[x21,x23,lsl#3]`、`cmp x23,#0x28`、`mov x23,#0` 在 4765 条指令里命中 0 次。所以这是 27.2 **新写的循环**，边界检查是随新代码一起写进来的，不是给既有代码补的。判 **功能新增**。

### 3.5 `AGXG18P` `0x850c0c0 → 0x8525228`（净新增 1）
除了 §3.1 的 +8 平移，新增的是循环里 `cmp x21,#0x24`（`ldr x3,[x8]` 前的边界）和 `cmp x21,#0x28`（循环上限）；同样在 A 里没有对应旧代码。判 **功能新增**。

### 3.6 `AppleDCP` `0x8a21ddc → 0x8a5c448`（548→663，净新增 9 / 消失 0）
9 条新增签名形状完全一致，是把字符串当参数传给一个 `blraa` 虚方法并测返回位：

```
ldr  x8, [x16, #0xb8]!
adrp x1, #0x73d0000 / add x1, #0xcdf      → "DCP"
movk x16, #0x3f20, lsl #48
blraa x8, x16
tbz  w0, #0
```

字符串依次是 `DCP`、`DCPSEC`、`DCPEXT`、`DCPEXT0`、`DCPEXT1`、`DCPEXT2`、`DCPEXT3`。判 **功能新增（显示协处理器新域/新时钟探测）**。

### 3.7 `AppleAVE2` `0x87cb1c4 → 0x8804ff0`（9125→9187，相似度 0.997，净新增 6）
6 条全是 `bl` 之后对返回值的判读：`cbz w0`、`tbnz w0,#0x1f`（负数=错误码）、`tbnz w0,#0`、`tbnz w0,#5`。判 **防御加固（错误传播）**。

### 3.8 `AppleAVE2` `0x878e224 → 0x87c4dc8`（361→893，净新增 39）
新增大量 `mov w0,#0x74; mov w1,#4; bl`（带 tag 的小分配）紧跟 `cbz w0`/`cbz x0`。判 **功能新增（+532 指令新逻辑）+ 防御加固（分配后判空）**。`hs w,#0x3f`/`#0x41`/`#0x11` 是 H.264/HEVC profile、level 位域判断，不是缓冲区边界。

### 3.9 `AppleSEPKeyStore` `0x95fad3c → 0x96459ac`（126→160，净新增 10）
两类：`cbnz w0` 接在 `bl 0x9645344`（返回状态传播）之后 ×5；`cbz x` 接在 `bl 0x9633dc4; bl 0x9645344` 之后 ×5，随后连续读 `[x21,#0x54]`、`[#0x5c]`、`[#0x64]`、`[#0x6c]`、`[#0x74]`（步长 8，5 个新字段被序列化）。判 **功能新增（新字段）+ 防御加固（状态传播）**。

### 3.10 `AppleDisplayCrossbar` `0x8a769dc → 0x8ab3e58`（净新增 3 / 消失 0）
3 条新增签名是同一段 PAC 校验，出现了 3 次：

```
ldr   x16, [x19]
autda x16, x17
mov   x17, x16
xpacd x17
cmp   x16, x17     ← 新增签名
```

`autda` 验签后 `xpacd` 去掉签名再比较，是**指针认证是否通过的判定**。判 **防御加固（PAC 校验补全）**，与内存边界无关。

### 3.11 `AppleT8150` `0x979e200 → 0x97e9c60`（289→460，净新增 14）
新增多个 `ubfiz x1,x0,#2,#0x20` + `bl 0x97ecc4c`（分配）后 `str x0,[x19,#0xa0/#0xa8/#0xb0/#0xc0]`，每个都跟 `cbz x0`；另有 1 条 `autda/xpacd/cmp` PAC 校验和 4 条 `tst x,#0xffc0000000000000`（指针 tag 检查）。判 **功能新增（新成员）+ 防御加固**。

### 3.12 `AppleFSCompressionTypeZlib` / `UDIFDiskImage` / `ASIOKit` 的 `tst x,#0xffc0000000000000`
`tst x, #0xffc0000000000000` 是测指针高字节 tag 位，不是「长度上限」。判 **防御加固（tag 校验）**。

### 3.13 `AppleSARService` `0x94ddcf8 → 0x9527b84`（280→294）——第七次「像真修复、实为布局变更」
27.2 侧：

```
ldrb w8, [x21]        ; byte 0
cmp  x8, #9           ← 新增签名
b.hi fail
x9 = 0x8195000+0xec8
ldr  x8, [x9, x8, lsl #3]     ; 表[byte0]
ldrb w9, [x21, #1]; cmp x9,#4; b.ls fail
ldrb w10,[x21, #2]; cmp x10,#6; b.ls fail
ldrb w11,[x21, #3]; cmp x11,#6; b.ls fail
ldrb w12,[x21, #4]; cmp x12,#2; b.ls fail
```

27.0.1 侧：

```
ldrb w8, [x21, #2]    ; byte 2
cmp  x8, #4           ; ← 老代码本来就有边界
b.hi fail
x9 = 0x817f000+0xa68
ldr  x8, [x9, x8, lsl #3]     ; 表[byte2]
ldrb w9, [x21, #3]; cmp x9,#6; b.ls fail
ldrb w10,[x21, #4]; cmp x10,#6; b.ls fail
ldrsh w11,[x21]       ; 半字
ldrb w12,[x21, #5]; cmp x12,#2; b.ls fail
```

字段整体**后移 1 字节**（A 用 +2/+3/+4/+5 和半字 [0]；B 用 0/+1/+2/+3/+4），表从 5 项（bound 4）扩到 10 项（bound 9）。**两侧都自带索引边界**，A 侧并不是「无校验直接用索引」。判 **重构（记录格式变更 + 表扩容）**，不是修复。这一条最容易被误判成「27.2 新增了 `cmp byte,#9` 挡住了越界」，实际是同一套代码换了字段编号。

### 3.14 `AppleSARService` `0x949d99c → 0x94e7670`（202→306，净新增 8）
新增两条全局特性字节（`0xb968000+0xbf0`、`+0xe08`，各 `ldrb` + `tbz #0`）、`cbz x21` 判空、`cmp w8,#2` + `b.hi`（输入结构里一个计数字段 ≤2）、`blraa` 后 `cbnz x0`。判 **功能新增 + 防御加固**。

### 3.15 `AppleM2ScalerCSCDriver` `0x905ef5c → 0x90a60c8`（66→174，净新增 10 / 消失 2）
新增 `fmov d0,x8; cnt v0.8b,v0.8b; addv b0,v0.8b; fmov x9,d0; cmp x9,#0x10`（8 字节位计数）与 `ldr x8,[x19,#0x4c0]; lsr x8,x8,x22; tbnz w8,#0`（特性位图按变量位移取位）。两者都是位图/位计数判定，不是数组边界；`lsr` 的移位量在这里没有掩码，但因为是在**定长 64 位位图**上移位（`lsr` 对 64 位寄存器天然截断到 6 位），不构成越界。判 **功能新增**。

### 3.16 `ApplePearlSEPDriver` `0x9395d38 → 0x93df0e4`（1312→1429，净新增 6）
`cbz x`（配置对象判空）、`cbnz w`/`cbz w`（状态检查）、`cmp w8,#4`（`and w8,w8,#0xfffffffd` 后比较，是状态归一）。判 **功能新增 + 防御加固**。

### 3.17 **`apfs` `0xa9f1740 → 0xaa4056c`（120→126，净新增 3）——本轮唯一值得再追的一条**

27.2 新增（A 侧完全没有这两条比较）：

```
subs x8, x2, #0xa
b.lo  fail
ldrh w9, [x1, #8]
cmp  x8, x9          ← 新增：读到的长度减 10 与记录里的字段比较
b.lo  fail
ldrh w8, [x3, #2]
cmp  x9, x8
b.lo  fail
cmp  w8, #0x2f       ← 新增：字段必须 ≤ 0x2f
b.hi  <另一条路径>
ldrh w8, [x3]
```

形状是「**外部记录里的长度字段 vs 实际读入长度**交叉校验 + **枚举上限 0x2f**」。如果 A 侧真的没有这两条校验，那么 A 会用未经交叉验证的长度/计数继续往下走——这是**理论上**可导致 OOB 的形状。

但按纪律，三条都还不满足：

1. **调用者为 0 个直接 `bl`**（在 apfs kext 内全函数扫描）。按既定纪律，这只能读作「没有直接 `bl`/`b`」，**不能**读作死代码——PAC 签名的表项无法反查。
2. **输入来源没追到**。`x1`/`x2`/`x3` 三个寄存器对应「缓冲/length/另一记录」，谁传进来的、是不是磁盘上攻击者可控的结构，没有实证。
3. **可达性**：走到这条路径需要挂载一个攻击者可控的 APFS 容器，而当前能力位是「dev-signed app 沙箱 + WebKit + networkextension」，没有 mount 权限。

判 **未定性**，并在 §4 里列为唯一需要继续追的条目。

---

## 4. 未覆盖清单与盲区

### 4.1 没做的

| 项 | 规模 | 原因 |
|---|---|---|
| 人工反汇编剩余候选 | 315/330 | 时间；已按「新增大立即数比较」筛过 42 个，人工只读了 15 对 |
| `selector 数` / 派发表 | 301 kext 全部 | §1.3，指针编码解不开 |
| 每个候选的 external-method selector 溯源 | 全部 | 派发表都取不到，selector 无从谈起 |
| `IOSkywalkFamily`/`AppleAVD`/`AppleH16ANE*`/`com.apple.kernel` | 4 kext | 上一轮已结案，本轮跳过 |
| 27.2 侧 `__AUTH_CONST` 里的 PAC 表项反查 | 全部 | 需要解 chained fixups，未做 |
| 净新增签名 = 0 的 324 个候选 | 324 | 判据只当前置闸门，没做人工确认；其中可能藏「同数量换位置」的真变动 |

### 4.2 方法本身的盲区

1. **`dChk` 只能当闸门**：它数条件分支条数，基本块重排就会虚高。本轮 654 个候选里 324 个净新增签名 = 0，就是重排造成的（占 49.5%）。
2. **签名保留内存位移 → 结构体增长伪装成新增校验**（§3.1）。AGXG18P 21 个候选里至少 4 对是这个原因。
3. **签名不区分寄存器身份**：`(cmp-op, cond, operand-shape, compared-reg)` 把 `w8` 和 `w27` 都压成 `w`，所以「同一个校验换了个寄存器」会算成不新增（漏报），「同一个校验换了个立即数」会算成新增（虚报）。
4. **`brk #0x5519` 这类显式陷阱不算签名**：它在 `__TEXT_EXEC` 里是数据/指令流中断，我没把它纳入判据。
5. **普查表是字符串级**，漏 AGXG18P/JPEG/Surface 这类（类名串可能在别处），多算 `com.apple.kernel`。表中 40 行是**下界性质的参考**，不是准入结论。

### 4.3 需要继续追的唯一一条

`apfs 0xa9f1740 → 0xaa4056c`：追 `x1`/`x2`/`x3` 的来源，确认是不是从磁盘读入的记录；若确认，再看这条路径是否只能由特权挂载触发。这是本轮唯一具备「新增交叉校验」形状且不在已结案清单里的候选。

---

## 5. 直答

**这批 kext（301 个，298 个跑了全量差分、15 对人工反汇编）里，没有 app 沙箱可达的内核内存破坏原语。**

依据：330 个净新增签名>0 的候选里，15 对逐条看完的结果是 10 条功能新增（其中 6 条同时只是补空指针/返回值/PAC 校验）、2 条纯防御加固、2 条结构体重排、1 条未定性；没有一条是「用户可控标量或结构体字段当索引/长度，27.0.1 不校验、27.2 补上校验」。最像的三条都被推翻：AGXG18P `0x856d2f0` 的 `cmp x23,#0x24` 是随新循环一起写进来的（A 里整段不存在）；AppleSARService `0x94ddcf8` 的 `cmp byte,#9` 只是记录布局后移 1 字节、表从 5 项扩到 10 项，A 侧本来就有同构校验；apfs `0xa9f1740` 确实新增了「长度 vs 字段」交叉校验和枚举上限，但调用者反查为 0 个直接 `bl`、输入来源未证实、且触发需要挂载攻击者可控 APFS 卷，当前能力位（dev-signed app 沙箱 + WebKit + networkextension）打不通。

---

## 附：复算命令

```bash
# 0) 解 27.2 全量 cache（im4p = DER 头 + lzfse 流，载荷从 0x38 开始）
python3 /tmp/lz2.py out/kc.27.2.ga.im4p /tmp/kc272.bin 0x38      # → 78,512,128 B

# 1) 普查表
python3 /tmp/uccensus.py /tmp/kc2701.bin /tmp/k137/cenA.json
python3 /tmp/uccensus.py /tmp/kc272.bin  /tmp/k137/cenB.json
python3 /tmp/gen2.py                                             # → /tmp/k137/adm.json

# 2) 全量差分（298 个 kext，约 12 分钟）
python3 /tmp/kallkext.py                                          # → /tmp/kkext/<bundleid>.json

# 3) 单对人工反汇编
python3 /tmp/kshowK.py com.apple.filesystems.apfs 0xfffffe000a9f1740 0xfffffe000aa4056c
python3 /tmp/kcmpK.py  com.apple.AGXG18P 0xfffffe000856d2f0 0xfffffe0008586780
```
