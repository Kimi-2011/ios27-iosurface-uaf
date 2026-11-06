# 外部情报与方向校准（2026-10-24）

## 1. Calif 的演示（事实）
- 2026-10-16，Hexacon（巴黎），iPhone 18 Pro 上演示 **iOS 27.0.1 无根越狱**
- 构建号 24A446 与公开版本一致；有真实 panic 日志佐证
- 未公开工具；报道提到 **AI 辅助**找链
- 来源：[jailbreakly](https://jailbreakly.com/ios/27.0.1)、[iclarified](https://www.iclarified.com/102876/untethered-ios-2701-jailbreak-demonstrated-on-iphone-18-pro-video)、[cybersecuritynews](https://cybersecuritynews.com/ios-27-0-1-jailbreak-demonstrated/)

## 2. iOS 27.0.1 的安全说明：**无任何 CVE**
Apple 安全发布页原文：`iOS 27.0.1 and iPadOS 27.0.1 — This update has no published CVE entries`（2026-09-28）。

对照实验：**27.0 (24A437) 与 27.0.1 (24A446) 的 kernelcache 完全一致**（301 kext 全部 0 改动）。
→ 27.0.1 是纯用户态更新，内核未变。

## 3. iOS 27.0 的修复清单（129 条，按组件）
其中有 **7+ 条内核"app 可导致内核内存破坏"**（STAR Labs SG、Peter Malone、Iru），
以及大量 app 可达的解析器漏洞：

| 组件 | 类型 |
|---|---|
| Kernel（7+） | app → 内核内存破坏 / 内核内存泄露 |
| CoreMedia | 恶意图片 → **任意代码执行** |
| CoreMedia | 沙箱进程可绕过沙箱限制 |
| ImageIO / FontParser / CoreText | 恶意图片/字体 → 内存破坏 |
| SceneKit / RealityKit（6） | 恶意 3D 模型 → 内存破坏 |
| IOMobileFrameBuffer | app → 内核内存破坏 |
| APFS / FAT / NFS | 恶意卷 → 内核内存破坏 |
| Apple Neural Engine | app → 系统异常终止 |
| MobileAccessoryUpdater | 恶意配件 → 系统异常终止 |

来源：[Apple 安全说明 iOS 27](https://support.apple.com/en-us/149034)

## 4. 方向含义

1. **27.0.1 内核 = 27.0 内核**，所以 iOS 27.0 的 129 条修复在 27.0.1 上已全部生效
2. 我们唯一能观察"未修补窗口"的，仍然只有 **27.0.1 → 27.2** 的差分
3. 在这份 CVE 清单里，与我们差分热点重合的是：
   - **Apple Neural Engine**（27.2 新增 202 条串，且历史上有 app 可达崩溃 CVE）
   - **APFS**（27.2 有 23 条新串 + 恶意卷历史）
   - **Kernel / IOMobileFrameBuffer**
4. CoreMedia 虽然有"任意代码执行"，但它是用户态，系统卷加密，**无法差分**；不过我们实测它有 35 个可交互 XPC 端点

## 5. 结论
"AI 辅助找链"这个细节说明对方的做法很可能就是**大规模自动化差分 + 语义标注**——
和我们走的路一致，但规模不同。这反过来说明我们的方法方向没错，问题在产能。

---

## 6. Calif 团队在 iOS 27 安全说明中的署名（关键）

Apple 官方文档中，Calif 相关研究人员署名的 CVE：

| CVE | 组件 | Impact | 描述 | 署名 |
|---|---|---|---|---|
| **CVE-2026-28968** | **Kernel** | app 可导致系统终止**或破坏内核内存** | **越界写**，改进边界检查 | genter0, Svetoslav Stolarov, **Josh Maine of Calif.io** |
| **CVE-2026-65410** | **AVEVideoEncoder** | app 可导致系统异常终止 | **改进检查** | **Calif.io in collaboration with Claude and Anthropic Research** |
| CVE-2026-65409 | Foundation | app 可导致拒绝服务 | **类型混淆**，改进内存处理 | **Bruce Dang of Calif.io** + Claude/Anthropic |
| CVE-2026-86886 | TCC | app 可修改受保护系统文件 | **路径穿越**，改进输入校验 | Constantin Clerc, Shad J, huami1314, Huy Nguyen of Calif.io |

### 这三条信息改变判断

1. **AVEVideoEncoder 是他们亲自下手的地方**，而且修法是"改进检查"——
   和我们在 27.2 AVE2 里看到的 62 条 "out of range" 校验**完全同一类**。
   今天我们挖 AVE2 的方向是对的，只是看的是下一批（未发布的）改动。

2. **Bruce Dang**（前 Apple/Google 安全研究员，iOS 逆向名家）在名单里，
   且署名"in collaboration with Claude and Anthropic Research"——AI 辅助确认属实。

3. **Kernel 那条是越界写（OOB write）**，app 可达，由 Calif 三人署名。
   这正是越狱链第一跳需要的原语类型。

### 对我们的直接含义
- 27.0.1 已包含上述全部修复（内核与 27.0 一致）
- 我们要找的是 **27.2 里新出现的同类修补** —— 也就是下一批尚未公布的 CVE
- 已定位的 AVE2 改动（34 个形状变化函数 + 62 条新校验串）就是候选池

---

# 补充情报（2026-10-24 下午，heise/Mac&i 专访 + secureinseconds 复盘）

## 7. 入口向量与链形态（首次披露）

| 项 | 事实 | 来源 |
|---|---|---|
| 入口向量 | **iMessage + Signal，恶意 PDF（1-click）**；另有自装 app 入口 | Calif X 视频（10-19 更新至 heise 报道） |
| 链路 | PDF 解析器（渲染层）→ 沙箱逃逸 → 内核 → **持久化（重启存活，untethered）** | 同上 |
| MIE | **被绕过**（Esser 确认基于 EMTE 的 MIE 没拦住） | heise 原文 |
| 设备覆盖 | "任何跑 27.0.1 的 iPhone"（Esser 原话） | heise 原文 |
| 发布计划 | 不做终端用户工具；**可能放 PoC**；等 27.2 公开发布后披露 | Mac & i 专访 |
| 关键人物 | **Stefan Esser（i0n1c）在 Calif 团队内**；CEO Thai Duong（BEAST/CRIME/POODLE） | secureinseconds |

## 8. 对我们方法论的直接证伪与确认

1. **证伪 HUNT.md 的核心假设**：Esser 明确说链**不是**靠 27.0.1↔27.2 差分找的（他们 8 月用差分法做过 macOS 屏幕共享洞，这次不是）。Calif 的路径是 **AI（前沿 LLM）辅助发现 + 资深人工领域知识配对**。差分仍是好方法，但不是他们的方法。
2. **证伪 LADDER.md "untether 在 A19 判死"**：他们做到了重启存活。第四张演示幻灯片写着 "APT stands for Apple Persistent Threat"。持久化机制未知——这是最大的新谜题（A19 引导链无公开洞的前提下如何 untether）。
3. **确认**：27.2 beta 已修链上大部分洞（与我们差分候选池直接相关——**我们的候选清单大概率包含他们的部分链**）。
4. **确认**：CVE-2026-28968（内核 OOB write）+ CVE-2026-86886（TCC 路径穿越）都是 Calif 署名、19 号追加进 iOS 27 advisory 的——时间点与链的组成高度吻合（OOB write = 内核原语层；TCC 路径穿越 = 用户态提权/沙箱层）。
5. **新事实**：27.1 只装在 iPhone Duo 上，存量机停在 27.0.1 → 攻击窗口至少到 27.2 GA（预期 ~10-28）。

## 9. 含义：把候选清单与"PDF 入口"对齐

入口是 **PDF 解析器**（iMessage/Signal 共用的系统渲染路径 = CoreGraphics PDF / PDFKit）。
这与我们的差分热点（ANE/IOSurface/AVE2/USB/sandbox）**完全不重叠**——但注意：
- PDF 解析在**用户态**（系统卷加密，无法差分）→ 这解释了为什么我们的差分没看到入口；
- 我们的 41 条可达候选里有的是**内核侧**链环（OOB write 类）——CVE-2026-28968 的形态（内核越界写、app 可达）**与 CVE 清单里 Kernel 组完全同型**；
- 27.2 GA 的安全说明 = 把我们的内核差分候选与他们的 CVE 对表的唯一机会。

## 10. 行动更新

| # | 动作 | 触发条件 |
|---|---|---|
| 1 | `tools/watch_release.sh` 每日跑 | 27.2 GA |
| 2 | GA 当天：拉 27.2 正式 kernelcache + support.apple.com 安全说明，对表 Calif/Claude 署名 CVE 与我们 41 条候选 | 同上 |
| 3 | 新攻击面：Mach 服务清单里筛 PDF/文档渲染相关服务（`out/device/mach-services.txt` 已有 295 个） | 立即可做 |
| 4 | 逆向 CoreGraphics PDF 路径的入口可达性（AppCryptex 里的 WebKit/PDFKit 系组件） | 立即可做 |

## 11. 追加（2026-10-24 晚）：sptm/txm 独立镜像已提取

27.0.1 的 `sptm.t8150.release.im4p` / `txm.iphoneos.release.im4p` 已用 zipfetch+lzfse 拉出并解包
（见 `out/METHOD-CALIBRATION.md` §5）。注意 27.2 RC 的 IPSW 来源未存档——对表当天需先定位
27.2 正式 IPSW URL（ipsw.me API）再拉同名组件做差分。
