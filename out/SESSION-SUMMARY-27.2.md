# iOS 27.2 发布日攻坚 — 完整成果总结（2026-10-30 ~ 10-31）

## 一、拿到了什么（按价值排序）

### 1. 一个逐函数级确证的真机缺陷
**`NumberOfTemporalLayers > 7` → 内核 HEVC 编码器失效**
- 确定性：3/3（nt=7 → 20 帧；nt=8 → 0 帧）
- 完整证据链（全部来自真机 syslog）：
```
属性设置值 → 内核日志 "NumberOfTemporalLayers 8"
→ HEVC_VPS::video_parameter_set_rbsp:969 failed -1001
→ HEVC_VPS::Generate:109 failed to generate VPS
→ AVE_PS_ComposeNALUArray:486 no PS
→ AVE_FrameRecv::SendPS:1080 failed to create format descriptor
→ 编码器永久 0 帧（≥65535 时 EncodeFrame 阻塞 → app SIGKILL）
```
- 27.2 修补方式：属性设置时即拒绝（`number of temporal layers (prop) is out of range`）
- 对应 CVE：最接近 **CVE-2026-112705**
- 性质：**DoS，非内存破坏**

### 2. 一条可复用的"免 KDK 符号化"方法
Apple 的日志宏把 `函数名:行号` 打进 syslog。本轮由此白捡 10+ 个内核函数名：
```
AVE_Prop_HEVC_SetNumberOfTemporalLayers  AVE_Prop_HEVC_SetEnableMCTF
AVE_Prop_HEVC_SetEnableUserQPMap         AVE_Prop_HEVC_SetProperty
HEVC_VPS::video_parameter_set_rbsp       HEVC_VPS::Generate
AVE_PS_ComposeNALUArray                  AVE_PS_Compose_hvcC
AVE_FrameRecv::SendPS                    AVE_FPS::CalcAvg/CalcOverall/CalcRt
```

### 3. 三个运转良好的"黑盒预言机"
| 预言机 | 判据 | 用途 |
|---|---|---|
| **syslog 可达性** | 属性值是否出现在内核日志 | 判断输入是否到达内核代码 |
| **类型错误存在性** | 传错类型 → 内核报 `wrong property type` + 函数名 | 判断属性是否真实存在（静默 -12900 = 不存在） |
| **日志属性转储** | AVE 打印收到的属性名清单 | 收割未公开属性名（相机负载一次 +27） |

### 4. 18 个 app 可设的编码器属性（约 1/3 未公开）
```
NumberOfTemporalLayers  EnableMCTF  EnableUserQPMap  UserParameterSetsIds
AllowFrameReordering    AllowTemporalCompression      EnableUserRefForFacetime
EnableWeightedPrediction EnableStatsCollect           EncoderUsage
Priority  Quality  MaxKeyFrameInterval  SourceFrameCount
ChromaQPIndexOffsetMultiPPS  QuantizationScalingMatrixPreset
AverageBitRate  ExpectedFrameRate  MaximizePowerEfficiency
PrioritizeEncodingSpeedOverQuality
```

### 5. 27.2 的完整 CVE × kext 对表
见 `out/CVE-KEXT-MAP.md`。核心结论：**163 条 CVE 中约 80 条修在加密用户态**，
内核侧真正可分析的只有 `com.apple.kernel`（449 改动）、`AppleAVE2`（31）、`AppleH16ANEInterface`（229）。

### 6. 一个重要的方法学修正
**kext "改动函数数"被内联重构严重污染**：
IOSkywalkFamily 的 108 处、IOStorageFamily 的 21 处、AppleAVD 的 6 处
全部是"访问器内联"（`ldr [x0]; ldr [x8,#0x20]; cmp` → `ldp`），**不是安全修补**。
必须用 `dChk>0` 或指令级差分才能筛出真实修补。

---

## 二、已证伪的假设（避免重复劳动，共 9 项）

| # | 假设 | 证伪方式 |
|---|---|---|
| 1 | ANE 可从普通 app 直开 IOKit | 5 个 ANE 类全部 `0xE00002C7` Unsupported |
| 2 | CoreML 模型 IO 数可传导到 ANE procedure | 300 输入模型退回 CPU（85.7ms） |
| 3 | app 可注入原始 VPS/SPS/PPS | 19 个候选属性键全 -12900 |
| 4 | `EnableUserQPMap` 导致编码器挂死 | 5/5 正常（早先挂死是前序会话 -12912 所致） |
| 5 | MCTF/LRME 输入来自 VT 属性 | `SrcNeighbor*`/`MCDataMessaging` 均不接受 |
| 6 | AVD misc preferences 可通过 VT 属性设置 | 12 个候选键全不接受 |
| 7 | 内核 AVE 函数可用字符串 xref 定位 | Ghidra 与自建扫描器均 0 引用（日志走运行时消息表） |
| 8 | AppleAVD 的 3 条 CVE 修在 kext 里 | kext 仅 6 处内联重构，无实质改动 |
| 9 | IOSkywalk/IOStorage 的大量改动是安全修补 | 全部为内联重构 |

---

## 三、当前阻塞点（按难度）

1. **无符号** → `com.apple.kernel` 的 8 个候选无法确认结构体类型与子系统
   （反编译显示函数操作 0x7xx 字节大对象，无法区分 `proc`/`task`）
2. **用户态加密** → 约 80 条 CVE（ImageIO/WebKit/FontParser/Model I/O/AVD/I-O/Wi-Fi…）无法静态分析
3. **数据通道缺失** → 18 个已确认属性中没有一个能承载 app 自定义缓冲区内容，
   因此只能打到 DoS，打不到内存破坏

## 四、若要继续，三条可选路径
| 路径 | 前提 | 预期 |
|---|---|---|
| KDK 符号化 | 下载安装 KDK | 解决阻塞点 1，可分析 13 条 Kernel CVE |
| 日志预言机符号化 | 无 | 只能覆盖会打日志的函数，覆盖不全 |
| 等 27.3 | 时间 | 新版本当天用现有工具链抢首发 |
