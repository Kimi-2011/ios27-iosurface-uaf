# 外部方法论（五步挖掘框架）校准与落地映射
- 日期：2026-10-24
- 输入：外部提交的"A19 Pro 挖洞五步法"（样本测绘 / Tag 泄露 / 类型混淆 / SPTM-TXM / AI 漏斗）
- 性质：方法论评估，不是新事实

## 1. 事实校准（对照 INTEL.md 已核实项）

| 该文断言 | 校准结果 |
|---|---|
| Calif CVE-2026-64699 (WebDAV) / 64704 (smbfs) | ⚠️ 查无实据。可确认的 Calif 署名 CVE 只有 4 条：**28968（内核 OOB write）/ 65410（AVE 改进检查）/ 65409（Foundation 类型混淆）/ 86886（TCC 路径穿越）**。WebDAV/smbfs 叙事可能是合成示例，不引用为事实 |
| "smbfs 模式：响应 tag 决定分支" | ⚠️ 未经证实，但作为**抽象模式**成立（模式 1 描述的"判别变量来自外部输入而非锁定上下文"本身是好审计口径） |
| 五步法描述的是 Calif 的工作流 | ❌ heise 原文只说"AI 帮了忙但没说怎么帮"。Esser 原话：LLM 用于评估发现与利用，需人工领域知识配对。此五步法是**作者推测的合理工作流**，不是披露 |
| 挖掘重点是内核（第二/三步全部面向内核） | ⚠️ 需重排优先级：已证实的链入口是**用户态 PDF 解析器**（iMessage/Signal 1-click）。内核原语（OOB write 类）是链的中段。且内核代码可差分、用户态加密不可差分——方向恰好与"先看内核"相反的理由不冲突，但入口审计必须补 PDF/CGPDFService |
| "等待差分找同源变体（Variant Analysis）" | ✅ 方向正确，但注意 Esser 明确说他们**没用**差分找这条链（8 月的 macOS 屏幕共享洞用了）。差分对我们仍是性价比最高的手段，只是别指望"复刻 Calif 的方法" |

## 2. 技术内核正确性（可采纳的部分）

以下四类模式与 MTE/EMTE 硬件语义自洽，值得直接转成扫描规则：
1. **未清零堆 + 早退返回 0 + 原长度 copyout**：真实高危模式。注：泄露出的残留指针高位确实带合法 tag（MTE tag 在 bit 56-59）——这是"泄露一次解决 KASLR+Tag 保密性"论述的硬件依据，成立。
2. **union 标量/指针双态 + 无锁状态翻转**：成立。反编译层表现为"同偏移在函数 A 写整数、函数 B 解引用"。
3. **同分配块内部索引越界（Intra-object OOB）**：成立且是 EMTE 的真实架构盲区——16 字节粒度同块同 tag，块内越界硬件放行。
4. **句柄查表错误码当指针**：成立，与我们的 `kalloc_type` 混淆候选同型。

## 3. 落地映射（用现有工具做什么）

| 五步法环节 | 我们已有 | 缺口 / 行动 |
|---|---|---|
| 固件解包/组件提取 | ✅ kernelcache 已解（未加密），kext 提取可用 | sptm/txm 独立镜像未提取——kernelcache 内是否含 fileset 成员待查（`tools/kernelcache.py` 列表核对） |
| 符号对齐 | ❌ 符号被 strip（nsyms=0） | KDK 迁移未做：macOS 26 KDK + Diaphora 对 mac_arm64 kernelcache ↔ iOS kernelcache。M5/A19 同构性是前提假设，需先验证 |
| 沙箱可达性 | ✅ 295 Mach 服务 + 5 IOKit 类实测可达 | sandbox profile 字节码反编译未做（`libsandbox` profile 反编译器可开源获取） |
| Tag 泄露模式扫描 | ❌ | 新工具 `uninitscan.py`：找 `bl copyout`（通过 thunk/GOT 定位）且长度寄存器 ≠ 写入路径的函数——无符号下只能做指令形态启发式，预期噪音大 |
| union/块内越界扫描 | 部分（checkscan 187 条是"新增检查"口径） | 需换口径："同偏移整数写 + 指针解引用"跨函数交叉——Ghidra 批量导出后做 |
| SPTM/TXM 审计 | ❌ 镜像都没提取 | 前置：确认 sptm/txm 在 kernelcache fileset 内且可重建 |
| AI 漏斗 | 部分（Ghidra 导出伪代码管线可用） | 三阶段漏斗的阶段 1 产出（200-500 切面）目前只有 41 条可达候选，量级不够，先补 KDK 符号 |
| Variant Analysis | ✅ 差分管线完备 | 27.2 GA 后对表 + 同模式横向扫，这正是既定计划 |

## 4. 优先级结论

1. 该五步法**采纳为 HUNT.md 的补充口径**（四个模式扫描规则），但**不采纳其"Calif 如此操作"的归因**。
2. 入口层补 PDF 方向：CGPDFService 目前不在 295 可达集（bootstrap_look_up 未命中），需按 services.txt 扩测 + AppCryptex 提取 PDFKit/CoreGraphics 二进制做静态审计。
3. 比五步法更紧迫的仍是 27.2 GA 对表（预期 ~10-28）：差分已就绪，对表一次顶模式扫描数周。

---

## 5. 执行结果（同日完成）

### 5.1 SPTM / TXM 镜像提取（原判 ❌ → ✅）

- 来源：27.0.1 IPSW 的 BuildManifest 独立组件（非 kernelcache fileset 成员）：
  - `Ap,SecurePageTableMonitor` → `Firmware/sptm.t8150.release.im4p`（213 KB → 解压 1.26 MB arm64e EXEC）
  - `Ap,TrustedExecutionMonitor` → `Firmware/txm.iphoneos.release.im4p`（224 KB → 解压 557 KB arm64e EXEC）
- 均未加密、可反编译；**27.2 对应镜像可用同一管线拉取做差分**。
- 版本戳：`txm.iphoneos.release.TrustedExecutionMonitor_Guarded-217.0.2`

### 5.2 初步语义确认（strings 层）

SPTM 侧已有完整审计线索：
- Frame Retyping 状态机字符串直接可见：`VIOLATION_UAT_ILLEGAL_PAGE_TABLE`、`VIOLATION_UAT_SAPT_REVOKE_FRAME_HELD_SHARED`、`uat_retype_in/out`、`retyping from XNU_IOMMU but not to XNU_DEFAULT`、`FTE %p should be held exclusive by sptm_retype()`
- 即五步法第四步第 3 项（Retype 状态机审计）的**具体函数与断言点已可定位**。

TXM 侧：
- trustcache 操作面：`com.apple.private.pmap.load-trust-cache`、`unload-trust-cache`、`amfi-only-platform-code`、`can-load-cdhash`、外部 trust cache 模块加载
- entitlement 加速路径（`accelerate/decelerate entitlements`）——TOCTOU/double-fetch 审计的入口字符串已就位
- amfid 关联确认（`com.apple.amfid`）

### 5.3 工具缺口现状

- sptm/txm 均 `nsyms=0`（strip），与 kernelcache 同病 → KDK 符号迁移需求不变
- 下一步需做的三件事：
  1. 拉 27.2 的 sptm/txm 同名组件，跑 kdiff（现成工具直接可用）
  2. SPTM retype 状态机：按 `sptm_retype` 相关字符串 xref 定位函数，Ghidra 建模状态转换边
  3. TXM 侧围绕 trustcache 加载/卸载 + entitlement 加速做伪代码导出，先看"校验后是否二次读共享内存"的 double-fetch 模式
