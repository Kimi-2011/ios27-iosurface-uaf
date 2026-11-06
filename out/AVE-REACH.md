# AVE 可达性实验（真机 27.0.1 / iPhone18,2）

## 目的
273.2 给 AVE 新增了 22 项参数集/属性校验。要判断：**普通 app 能否触达被校验的那些输入**。

## 实验 1：属性名探测（VTCompressionSession，HEVC）
对照组：已知有效属性 `RealTime` 返回 0，虚构属性返回 -12900。

| 属性名 | 结果 |
|---|---|
| **`UserParameterSetsIds`** | **0（被接受）** |
| **`NumberOfTemporalLayers`** | **0（被接受）** |
| ParameterSets / GenerateVPS / GenerateSPS / SetSPS | -12900（不存在） |
| HEVCUserParameterSets / UserParameterSets / EnableUserParameterSets | -12900 |
| UpdateParameterSets / ParameterSetsIds / MCTFStrength 等 14 个 | -12900 |

**结论：找到了两个未公开但对 app 开放的编码器属性。**

## 实验 2：取值类型
`UserParameterSetsIds` 只接受**整数数组**（`@[@1]`、`@[@7]` → 0；
标量 `@1` 和 NSData → -12900）。
→ 它只是"参数集 ID 列表"，**不承载参数集内容**。
尝试 19 个候选键（HEVCParameterSets、VideoParameterSets 等）**全部 -12900**，
没有找到可注入原始 VPS/SPS/PPS 字节的属性。

## 实验 3：`NumberOfTemporalLayers` 极端值扫描（带真实编码）
```
=0     -> -12900（被拒）
=1     -> 0  编码 3 帧全部成功
=2     -> 0  成功
=4     -> 0  成功
=255   -> 0  成功
=1024  -> 0  成功
=65535 -> 0  成功     ← 27.0.1 完全不校验
=-1    -> -12900
```
**设备全程存活，无 panic。**

## 与 27.2 修补的对应
27.2 新增字符串：
```
"number of temporal layers (prop) is out of range %d %d %d"
```
**"(prop)" 明确指属性** → 这正是 `NumberOfTemporalLayers` 的校验。

## 结论
1. ✅ **证实**：27.0.1 上 app 可以把 `NumberOfTemporalLayers` 设为 65535，编码器照单全收；
   27.2 才加上"out of range"校验。
2. ✅ **证伪**：不存在让 app 直接注入原始 VPS/SPS/PPS 字节的公开属性
   → 那批 `HEVC VPS num_add_layer_sets is out of range` 一类的校验，
   输入源不是 app 提供的码流。
3. ❓ 未触发崩溃：设置极端值后编码正常。可能原因：
   - 用户态 VideoToolbox 在下发给 AVE 前做了钳位
   - 需要配合其它属性（时间可分层开关 / layer id）才走到危险路径
   - 需要真实帧内容与更大分辨率

## 下一步（若继续）
- 组合属性：`NumberOfTemporalLayers` + 时间可分层开关 + 每帧 attachment 指定 temporalLayerId
- 换 HEVC 主档次配置（Main10 / 更大分辨率 / 多 slice）
- 观察 media 相关守护进程崩溃日志

---

## 实验 4：内核日志判定（决定性）

抓 `syslog live` 的同时跑极端值扫描，得到：

```
videocodecd{ave.videoencoder}[457] AVE ERR:
  AVE_Prop_HEVC_SetNumberOfTemporalLayers:6111
  iNumberOfTemporalLayers >= 1 | out of range  ...  0
同样一条                                              ... -1
```

### 结论一：属性值确实下到了内核
- 只有我们设的 `0` 和 `-1` 产生错误日志（2 条，一一对应）
- `1 / 2 / 4 / 255 / 1024 / 65535` **全部无错误** → 内核 AVE 照单全收
- 调用链已确认：**app → `videocodecd`（`ave.videoencoder` 插件）→ `kernel{AppleAVE2}`**

### 结论二：27.0.1 只检查下界
日志里的断言是 `iNumberOfTemporalLayers >= 1`——**只有下界**。
27.2 新增的是 `number of temporal layers (prop) is out of range %d %d %d`（带上界）。
→ 这正是 CVE 描述里的 "improved input validation"。

### 结论三：我们拿到了一个内核函数名
```
AVE_Prop_HEVC_SetNumberOfTemporalLayers      (源码行号 6111)
AVE_Prop_HEVC_SetProperty                    (行号 21733)
AVE_Prop_SetProperty                         (行号 268)
```
Apple 的 AVE 把自己的函数名和行号都打进日志里了——**不需要 KDK 就能建立符号**。

## 修正此前判断
- ❌ 之前认为"用户态可能钳位" → **错，实测值到了内核**
- ✅ AVE 这条路对 app 是**真实可达的**，且已定位到具体属性与函数
- ❓ 65535 未触发崩溃：需要继续看该函数把值用在何处（分配/索引），
  可能还需配合 temporal scalability 开关与每帧 layer id 才能走到危险分支

## 下一步
1. 反编译 `AVE_Prop_HEVC_SetNumberOfTemporalLayers`（27.0.1），看 65535 被拿去做什么
2. 若用于定长数组索引/分配 → 直接构造触发条件
3. 用同一套路批量收割 AVE/ANE 的日志函数名，建立**免 KDK 的部分符号表**

---

## 实验 5：定位内核侧处理函数（受挫，但有收获）

### 尝试路径与结果
| 尝试 | 结果 |
|---|---|
| 在 27.0.1/27.2 kernelcache 搜 `iNumberOfTemporalLayers >= 1` | ❌ 不存在（该断言在**用户态** `videocodecd` 插件里） |
| 搜 `AVE_Prop_HEVC_SetNumberOfTemporalLayers` | ❌ 只在运行时日志里出现，二进制中无明文 |
| Ghidra 解析 27.2 新串 `number of temporal layers (prop) is out of range`（VA `0xfffffe0007304fda`）的引用 | ❌ **0 引用** |
| 扫描数据段找指向该串的指针（绝对/相对/相对32位/带 tag） | ❌ **0 命中** |
| 按属性 ID `0x102` 找比较指令 | ❌ 两个版本都 0 命中（分发表而非比较链） |

**结论：AVE kext 的日志串不通过 adrp/add、也不通过指针表引用**，
推测是运行时构建的消息表（日志宏用 ID 索引）→ 现有工具无法做字符串到函数的映射。

### 收获：内核侧日志本身就是符号预言机
`kernel{AppleAVE2}` 打出的日志带 **C++ 方法名 + 源码行号**：
```
AVE_FPS::CalcAvg:408
AVE_FPS::CalcOverall:457
AVE_FPS::CalcRt:301
```
这次短跑只触发了 3 个。**主动走更多代码路径就能系统性收割内核函数名**，
这是免 KDK 建立 AVE 符号表的可行途径（虽然只覆盖会打日志的函数）。

## 当前完整结论
| 问题 | 结论 |
|---|---|
| AVE 对普通 app 可达 | ✅ app → videocodecd → kernel AppleAVE2 |
| `NumberOfTemporalLayers` 值到内核 | ✅ 已确认（0/-1 被拒日志来自我们的调用） |
| 27.0.1 缺上界校验 | ✅ 65535 被接受，27.2 才加上界 |
| 65535 是否造成内存破坏 | ❌ 未触发（3 帧编码正常） |
| 能否定位内核处理函数 | ❌ 字符串 xref 全路径失效 |

---

## 实验 6（决定性）：完整失败链 + 6 个内核函数名

### 构造
每个值用**全新 VTCompressionSession**（320×240 HEVC），属性在 `Create` 之后、`Prepare` 之前设置，
编码 10 帧，全程抓 syslog。

### 行为梯度（可复现）
| 取值 | 帧产出 | app 状态 |
|---|---|---|
| 1 .. 7 | 正常 10 帧 | 正常 |
| 8 / 9 / 16 | **0 帧**（静默丢弃） | 继续运行 |
| 255 | 0 帧 | 继续运行 |
| 65535 / INT_MAX | — | **`EncodeFrame` 永久阻塞 → 被 SIGKILL** |

### 崩溃栈（app 侧）
```
VideoToolbox  vtCompressionSessionRemote_EncodeFrameCommon
VideoToolbox  VTCompressionSessionEncodeFrame
H             runOne
```

### 内核侧完整失败链（syslog 原文，均带函数名与行号）
```
kernel{AppleAVE2} AVE : ... 350 NumberOfTemporalLayers 8          ← 值进入内核
kernel{AppleAVE2} AVEIOP0 ERR: HEVC_VPS::video_parameter_set_rbsp:969 | failed -1001
kernel{AppleAVE2} AVEIOP0 ERR: HEVC_VPS::Generate:109 | failed to generate VPS 0 -1001
videocodecd AVE ERR: AVE_PS_ComposeNALUArray:486 cnt != 0 | no PS 2
videocodecd AVE ERR: AVE_FrameRecv::SendPS:1080 ret == 0 | failed to create format descriptor
videocodecd AVE ERR: AVE_FrameRecv::SendPS:1011 psPSInfo->iNum > 0 | wrong PS number   （每帧重复）
```

### 顺带恢复的 6 个内核/插件函数名
```
AVE_Prop_HEVC_SetNumberOfTemporalLayers
HEVC_VPS::video_parameter_set_rbsp
HEVC_VPS::Generate
AVE_PS_ComposeNALUArray
AVE_PS_Compose_hvcC
AVE_FrameRecv::SendPS
```

### 与 CVE 的对应
| CVE | 描述 | 匹配度 |
|---|---|---|
| **CVE-2026-112705** | 越界写 / **An app may be able to cause unexpected system termination** | **高**——我们的效果就是编码器挂死 |
| CVE-2026-112689 / 112470 | 越界写 / 破坏内核内存 | 未观察到位内存破坏，属其它属性/路径 |

### 判定
- ✅ **确认为 app 可达的真机可复现缺陷**：未校验的 `NumberOfTemporalLayers`（>7）导致
  内核 HEVC VPS 生成失败 → 参数集缺失 → 编码器永久丢帧 / 阻塞
- ✅ 27.2 的修补方式正是**在属性设置时提前拒绝**（`number of temporal layers (prop) is out of range`）
- ❌ 未观察到内核内存破坏：`video_parameter_set_rbsp` 是干净的错误返回（-1001），
  不是越界写。想拿"破坏内核内存"的那两条，需要换属性/换路径

---

## 实验 7：MCTF 与属性面测绘

### 属性名收割通道（重要方法）
AVE 在日志里会**打印它收到的属性名清单**（`AVE WARN: <...> 390 AllowTemporalCompression 1` 这类）。
抓 syslog 即可收割真实属性名——本次共收到 **104 个 CamelCase 标识符**，去噪后 79 个。

### 15 个被 VTCompressionSession 接受的属性
```
AllowFrameReordering            AllowTemporalCompression      ChromaQPIndexOffsetMultiPPS
EnableStatsCollect              EnableUserQPMap               EnableUserRefForFacetime
EnableWeightedPrediction        EncoderUsage                  MaxKeyFrameInterval
NumberOfTemporalLayers          Priority                      Quality
QuantizationScalingMatrixPreset RealTime                      SourceFrameCount
```
另有前期发现的 **EnableMCTF**（必须 CFBoolean）与 **UserParameterSetsIds**（整数数组）。

### EnableMCTF 的确切行为
| 取值 | VT 返回 | 内核日志 |
|---|---|---|
| `@YES` | 0 | 无错误，但**编码器 0 帧产出** |
| `@(1)` 整数 | -12900 | `AVE_Prop_HEVC_SetEnableMCTF:13095 CFBooleanGetTypeID() == CFGetTypeID(pValue) | wrong property type` |

- 函数名：**`AVE_Prop_HEVC_SetEnableMCTF`**
- 开启 MCTF 后编码器不吐帧（原因未查明，可能需要配合 `EnableUserRefForFacetime` 等）

### 尚未命中的目标
`SrcNeighborInfo` / `SrcNeighborData` / `MCDataMessaging` / `LRSNeighborMV`
**均不被接受** → MCTF/LRME 的 "info is not correct" 校验输入不是 VT 属性，可能来自固件或内部结构。

## 新的高价值目标：EnableUserQPMap
`EnableUserQPMap` 与 `EnableUserRefForFacetime` 被接受，语义是"**由 app 提供 QP 映射表 / 参考帧**"。
这类"app 提供的缓冲区 + 按宏块尺寸索引"的组合是内存破坏的经典形态，
比 temporal layers 更接近 CVE-2026-112689 / -112470 描述的"破坏内核内存"。

---

## 实验 8：EnableUserQPMap —— 第二个挂死触发点

### 类型要求（与 EnableMCTF 相同）
传整数 → 内核报 `AVE_Prop_HEVC_SetEnableUserQPMap:6318 CFBooleanGetTypeID() == CFGetTypeID(pValue) | wrong property type`
传 `@YES` → 接受（返回 0），内核日志确认：
```
kernel{AppleAVE2} AVE : 480 QPModFeature: 0x10776 QPModLevel: 0
kernel{AppleAVE2} AVE : 480 EnableUserQPMap 1
kernel{AppleAVE2} AVE : 480 EnableUserRefForFacetime 0
```

### 行为：不提供 QP 映射表 → 编码器挂死
```
app 日志停在 qpmap=1 useref=0 setQPMap=0 之后就没了（无 frames= 行）
crash: EXC_CRASH SIGKILL
  CoreMedia   FigSemaphoreWaitRelative
  VideoToolbox vtCompressionSessionRemote_EncodeFrameCommon
```
与 `NumberOfTemporalLayers > 7` **完全相同的挂死签名**。
推测：编码器在等待 app 应该提供的 QP 映射表，永远等不到。

### 尝试寻找 QP 表的承载属性（失败）
测试 12 个候选名 × 7 种取值类型（含 CFData 4B/1000B/100000B、数组、字典）：
```
UserQPMap / QPMap / QPMapData / UserQPMapData / StaticAreaQPModInfo / QPModInfo
BlkQPRange / RCQPRange / QPModFeature / QPModLevel / LambdaModFeature
→ 全部 -12900，只有 EnableUserQPMap 被接受
```

---

## 阶段性总结：两个已确证的真机缺陷

| # | 属性 | 触发条件 | 效果 | 内核证据 |
|---|---|---|---|---|
| 1 | `NumberOfTemporalLayers` | 取值 > 7 | 8~255：静默 0 帧；≥65535：`EncodeFrame` 永久阻塞 → app SIGKILL | `HEVC_VPS::video_parameter_set_rbsp:969 failed -1001` |
| 2 | `EnableUserQPMap` | `@YES` 且不提供 QP 表 | `EncodeFrame` 永久阻塞 → app SIGKILL | 内核日志确认属性已生效，无错误，静默挂起 |

两者在 27.2 都被修补（新增 `out of range` / 输入校验），27.0.1 均未校验。

### 方法论沉淀（本轮最有价值的产出）
1. **syslog 是可达性判据**：属性值是否到内核、走到哪一步，日志里全有
2. **类型错误日志是存在性判据**：传错类型时内核打 `wrong property type` + 函数名 + 行号
   → 传错类型 = 属性真实存在；静默 -12900 = 属性不存在
3. **属性名收割**：AVE 会打印收到的属性名清单，抓日志即可获得真实属性名（本次 104 个）
4. **免 KDK 符号**：所有 `AVE_*:行号` 形式的日志都是函数名来源

---

## ⚠️ 更正（2026-10-31 09:10）：撤回 EnableUserQPMap 挂死结论

### 复核方法与结果
`EnableUserQPMap=@YES`，全新会话，重复 5 次：
```
qpmap=YES try0..try4 -> 20, 20, 20, 20, 20     全部正常
qpmap=NO  try0..try2 -> 20, 20, 20             全部正常
```
**5/5 正常，没有挂死。**

### 之前那次挂死的真实原因
早先那一轮的第一个变体 `create fail -12912`（kVTVideoEncoderNotAvailableNowErr），
即上一个会话未完全释放导致编码器处于坏状态，随后的编码才挂住。
**与 EnableUserQPMap 属性本身无关。**

→ **撤回"实验 8"中把它列为第二个 DoS 触发点的结论。**
`EnableUserQPMap` 只是"被接受的属性"，未观察到任何异常行为。

---

## ✅ NumberOfTemporalLayers 确定性复核（3/3 可复现）

```
nt=7  try0/1/2 -> 20 / 20 / 20 帧   正常
nt=8  try0/1/2 ->  0 /  0 /  0 帧   全部失败
```
边界精确落在 **7**（HEVC 规范 sps_max_sub_layers_minus1 上限 + 1），
且 **100% 确定性**，非偶发。

### 完整证据链（唯一的已确证缺陷）
```
app: VTSessionSetProperty(NumberOfTemporalLayers, 8)     → 返回 0（用户态接受）
  ↓
kernel{AppleAVE2}: "350 NumberOfTemporalLayers 8"        ← 值进入内核
  ↓
kernel{AppleAVE2} AVEIOP0 ERR: HEVC_VPS::video_parameter_set_rbsp:969 | failed -1001
kernel{AppleAVE2} AVEIOP0 ERR: HEVC_VPS::Generate:109 | failed to generate VPS 0 -1001
  ↓
videocodecd AVE ERR: AVE_PS_ComposeNALUArray:486 cnt != 0 | no PS 2
videocodecd AVE ERR: AVE_FrameRecv::SendPS:1080 failed to create format descriptor
  ↓
编码器永久产出 0 帧（取值 ≥65535 时 EncodeFrame 阻塞 → app 被 SIGKILL）
```
27.2 的修补：属性设置时即拒绝超出范围的值。

---

## 属性面最终清单（真机实测被接受）

| 属性 | 类型要求 | 备注 |
|---|---|---|
| `NumberOfTemporalLayers` | 数字 | **>7 确定性失败** |
| `EnableMCTF` | **CFBoolean** | 开启后 0 帧产出（未深究） |
| `EnableUserQPMap` | **CFBoolean** | 无异常行为 |
| `UserParameterSetsIds` | 整数数组 | 仅 ID，不承载内容 |
| `AllowFrameReordering` / `AllowTemporalCompression` | - | |
| `EnableUserRefForFacetime` / `EnableWeightedPrediction` | - | |
| `EnableStatsCollect` / `EncoderUsage` / `Priority` / `Quality` | - | |
| `MaxKeyFrameInterval` / `SourceFrameCount` | - | |
| `ChromaQPIndexOffsetMultiPPS` / `QuantizationScalingMatrixPreset` | - | |
| `AverageBitRate` / `ExpectedFrameRate` | - | HEVC+H264 均支持 |
| `MaximizePowerEfficiency` / `PrioritizeEncodingSpeedOverQuality` | - | HEVC+H264 均支持 |

**共 18 个 app 可设属性，其中约 1/3 未公开。**

---

## 实验 9：解码侧（AVD）属性收割 — 未打通

### 做的
1. 用 AVAssetWriter 生成 HEVC/H.264 码流 → AVAssetReader 解码，
   抓 syslog 得到 **618 行 AppleAVD/videocodecd 解码器日志**，收割 63 个标识符：
```
kAppleAVDSetMiscPreferences      kAppleAVDMultiViewDecodeClient
AppleAVDWrapperHEVCDecoderCreateInstance/StartSession/Invalidate/Finalize
AppleAVDWrapperH264Decoder*      CreateAVDHEVCInstance / CreateAVDH264Instance
AppleAVDCommandBuilder           VideoParserEngine / VADecodeFrame
setClientInfo / insertSetPropertiesCommand / readPreferences / miscPreferences
usageMode / encryptionScheme / isTestApp / tryAllFrames / memCacheMode / loadBalanceMode
```
2. 用 `AVAssetTrack.formatDescriptions` 成功建立真正的 `VTDecompressionSession`（create=0）
3. 用 12 个候选键 × 6 种取值类型测试

### 结果
**全部不被接受**（无一条 `DECOMP ACCEPTED`）。
→ AVD 的 misc preferences 不是通过 VT 属性暴露给 app 的，
  大概率走 `videocodecd` 内部或 IOKit 用户客户端（而后者实测 0xE00002C7 不可开）。

---

# 📋 AVE/AVD 方向最终收口（2026-10-31 09:15）

## 一、确证结论（可真机复现）

| 项 | 内容 |
|---|---|
| **唯一确证缺陷** | `VTCompressionSession` 属性 `NumberOfTemporalLayers > 7` |
| 确定性 | 3/3（nt=7 → 20 帧；nt=8 → 0 帧） |
| 效果 | 8~255：编码器永久 0 帧；≥65535：`EncodeFrame` 阻塞 → app 被 SIGKILL |
| 内核证据 | `HEVC_VPS::video_parameter_set_rbsp:969 failed -1001` → `HEVC_VPS::Generate:109` → 无参数集 |
| 27.2 修补 | 属性设置时即拒绝（`number of temporal layers (prop) is out of range`） |
| 对应 CVE | 最接近 **CVE-2026-112705**（"An app may be able to cause unexpected system termination"） |
| 性质 | **DoS**，非内存破坏 |

## 二、已证伪（避免重复劳动）

| 假设 | 结论 |
|---|---|
| app 可直接注入原始 VPS/SPS/PPS | ❌ 19 个候选键全 -12900 |
| `EnableUserQPMap` 导致挂死 | ❌ 5/5 正常，早先挂死是前序会话创建失败(-12912)所致 |
| `SrcNeighborInfo`/`MCDataMessaging` 等是 MCTF 输入通道 | ❌ 均不被接受 |
| AVD misc preferences 可通过 VT 属性设置 | ❌ 12 个候选键全不接受 |
| 内核 AVE 处理函数可通过字符串 xref 定位 | ❌ Ghidra 与自建扫描器均 0 引用（日志走运行时消息表） |

## 三、可复用资产

**18 个 app 可设的编码器属性**（约 1/3 未公开）：
```
NumberOfTemporalLayers  EnableMCTF  EnableUserQPMap  UserParameterSetsIds
AllowFrameReordering    AllowTemporalCompression      EnableUserRefForFacetime
EnableWeightedPrediction EnableStatsCollect           EncoderUsage
Priority  Quality  MaxKeyFrameInterval  SourceFrameCount
ChromaQPIndexOffsetMultiPPS  QuantizationScalingMatrixPreset
AverageBitRate  ExpectedFrameRate  MaximizePowerEfficiency
PrioritizeEncodingSpeedOverQuality
```

**方法学（本轮最大产出）**
1. **syslog = 可达性判据**：值是否到内核、走到哪一步，日志全有
2. **类型错误日志 = 存在性判据**：传错类型若内核报 `wrong property type` + 函数名，
   则属性真实存在；静默 `-12900` 则不存在
3. **属性名收割**：AVE 会打印收到的属性名清单（相机负载一次收 27 个新名）
4. **免 KDK 符号**：`AVE_xxx:行号` 日志即函数名来源，本轮共获得 10+ 个

## 四、若继续的方向
- 只有当出现**新的数据通道**（能承载 app 自定义缓冲区内容的属性）时，才可能推进到内存破坏
- 现有 18 个属性中不含此类通道；继续猜测的成本已高于收益
- 建议转其它组件（27.2 还有 20+ 条内核侧 CVE 未处理）
