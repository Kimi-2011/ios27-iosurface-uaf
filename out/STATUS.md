# iOS 27.0.1 真机漏洞清单（修正版索引）

**最后更新**：2026-10-31 23:30
**设备**：iPhone 18,2 / iOS 27.0.1 (24A446)
**入口**：dev-signed app (`com.example.ios27poc`) → WKWebView

---

## A. 真机确认存在（4 个）

| # | 漏洞 | 类别 | 组件 | 危害层级 | 文档 |
|---|---|---|---|---|---|
| 1 | **CVE-2026-112695** (bug 321669) | UAF | WebCore 渲染树 checkmark | WebContent DoS | `POC-CONFIRMED-CVE-2026-112695.md` |
| 2 | **CVE-2026-113897** (bug 322743) | 竞态 | BroadcastChannel | WebContent DoS | `POC-CONFIRMED-CVE-2026-113897.md` |
| 3 | **bug 322033** | **JIT 类型混淆** | **JavaScriptCore** | **R/W 路径** | `POC-JSC-TYPECONFUSION-322033.md` |
| 4 | **bug 323148** | **越界取数** | **WebGPU 顶点取数** | GPU 进程 | `POC-WEBGPU-OOB-323148.md` |

## B. 有效阴性（测试确实完整执行）

| 测试 | 结论 |
|---|---|
| 318331 JSC DirectTailCall JIT-code UAF | 50 代全跑完、结果正确、未崩；需 `--zeroExecutableMemoryOnFree` 才能观测 |
| 323130 WebGPU drawIndexedIndirect | 断言全部通过，27.0.1 无该 bug |
| 323079 AV1 packetizer OOB | 前提全满足但 `onrtctransform` 不触发 → 不可达 |

## C. 已验证的环境事实

| 事实 | 证据 |
|---|---|
| WebGPU 完全可用 | `adapter=ok` `device=ok`，features 含 bc/astc/timestamp |
| 2 GiB ArrayBuffer 可分配 | `bytes=2147483652` 成功 |
| AV1 编解码器在列 | `AV1 codecs=1 video/AV1` |
| `RTCRtpScriptTransform` 可构造但**不投递帧** | `transform set=true` → `RESULT=timeout` |
| 内核版本 | xnu-13432.2.10（**未公开**，公开最高 12377.121.6）|
| iOS 27.0.1 / 27.1 公告 | **无任何 CVE**（只有 27.2 有）|

## D. 方法学铁律（本轮血的教训）

**任何"未崩/未复现"必须先证明脚本执行到了断言处。**

原因：我自己造的错比漏洞本身更误导人
1. **假阴**：`js-test.js` 的 `noInline`/`description`/`testFailed` 缺失 →
   脚本首行 `ReferenceError` 静默中止 → 报"未崩"（322033/323130/323148 全中招，补 shim 后全部翻案）
2. **假阳**：`shouldBeEqualToString(a,b)` 的 `a` 是**源码字符串需 `eval()`**，
   按字面量比会制造假 FAIL
3. **插桩自我破坏**：`worker.onmessage = ...` 覆盖测试自己的 handler

**当前 shim**：`harness/wkpoc/Payload/WK.app/wptshim.js`（5232 B，含 eval 语义的完整 js-test 兼容层）

## E. 新方向：27.2 之后公开修复的 JSC 漏洞

窗口（9/2–10/31）内 7 条真 JSC 安全修复，详见 `DIRECTION-POST272-FIXES.md`。
**边界已实测确认**：有内存破坏潜力的（321608 / 319303 / 318331）都需要
`jsc` shell 的**同步 GC** 或 `$vm` 内建；浏览器里弱引用处理只在让出事件循环后发生，
同步循环内无法插入该时序点。纯 JS 可跑的几条多为逻辑错误。

## F. 通用能力：在 WKWebView 里强制 GC

```js
function bigGC(mb){ var h=[],n=mb|0;
  for(var i=0;i<n;i++) h.push(new Float64Array(131072));  // 每个约1MB，持住
  var g=h.length; h=null; return g; }
bigGC(180);
await new Promise(r=>setTimeout(r,300));   // ← 必须让出，否则弱引用不处理
```
实测：`tokenAlive` 由 true 变 false，8 个 FinalizationRegistry 回调全部投递。


## H. 内核目标优先级（2026-11-01 更新）

| 目标 | 改动函数 | 语义清晰度 | 可达性 | 结论 |
|---|---|---|---|---|
| **AppleAVD** | **6** | ★★★ 有容量字段/截断逻辑 | VideoToolbox，预期可达 | **首选**（见 `POC-AVD-OOB-WRITE.md`） |
| IOSkywalkFamily | 108 | **dChk 全 0 → 无安全修补**（我先前结论作废） | ✗ | **出局** |
| AppleH16ANE | 155 | **42 个 dChk>0**（最大 +34） | CoreML + H1xANELoadBalancer | **次选，待收敛** |
| AppleAVE2 | — | ✗ 读取点全是日志形态 | 已实测可达 | 已降级 |

### 判据（必须遵守）
**「是否新增安全检查」只看 dChk（条件分支增量）。**
看新增立即数 / 新增指令 / 字符串增量都会误报——本工程已误判三次。

### 关键结论
- **AppleAVD 27.0.1 的拷贝路径缺少「偏移+长度 ≤ 容量」校验与溢出检测**，
  27.2 补上了 `adds/b.hs` 溢出检测 + `cmp capacity/b.hi` + `csel` 截断。
  待确认 `w24` 是否来自码流。
- skywalk **双重出局**：dChk 净 0（无安全修补）+ 无 UserClient；
  `com.apple.nexus` kctl 在 `com.apple.kernel`；本 kernelcache **无 Wi-Fi kext**。
- AVE 的 `0x1888` 推断作废：读取点是日志格式化，不是数组索引。

### 复用工具
- `/tmp/fnorm.py` `/tmp/fdelta.py` `/tmp/fshow.py`（函数级归一化差分 / 增量排序 / 逐条对比）
- 函数起点用 **`BTI c`**（`5f 24 03 d5`），不是 PACIASP
- `kext_extract.py --kext` 要写**全限定名**（如 `com.apple.iokit.IOSkywalkFamily`）

## G. 下一步优先级

1. **322033 JSC 类型混淆（最高）**——唯一在 R/W 路径上的确认漏洞。
   当前混淆值被 `JSCell::toObjectSlow` 的 release 断言拦住（`EXC_BREAKPOINT`）。
   往利用走：让混淆值落成一个"看似合法"的 JSCell 类型以绕过断言。
2. 重扫其余 JSC 测试（现在 shim 已正确，此前的判定全部作废需重来）
3. 深化 WebKit 仓库历史，重建 27.2 那 32 个 bug 的 ground truth

## I. 最终判定（2026-11-01 02:00，全部经 dChk 复核）

| 目标 | 改动 | dChk>0 | 性质 | 判定 |
|---|---|---|---|---|
| IOSkywalkFamily | 108 | **0** | 访问器内联重构 | **出局** |
| AppleH16ANE | 155 | 42 | 防御性加固（NULL 检查/全局区间/数值钳制） | **出局** |
| com.apple.kernel | 358 | 57 | 含 4 条 NAT64/PF（需设备作网关） | 不可本地触发 |
| AppleAVD | 5 | **1** | 拷贝路径缺容量校验，但**索引/长度来自硬件寄存器** | **关闭** |

### 关键：链设计结论
`out/CHAIN-DESIGN.md`：**4 个已确认漏洞一个都不能入链。**
缺的是唯一一环 —— **app 沙箱可达的内核内存破坏原语（S2）**。

### 我犯过并已更正的错误（三次同类）
| 错误 | 表现 | 根因 |
|---|---|---|
| AVE 0x1888 | 把日志参数当数组索引 | 未追数据流 |
| AVD 0xD84 | 把 `__cstring` 偏移当结构体字段 | 立即数匹配不可靠 |
| **skywalk 尺寸检查** | 把内联搬入的 `cmp` 当新增校验 | **口径错：应看 dChk** |

→ **铁律：判定"是否新增安全检查"只看 dChk。** 立即数/指令数/字符串增量都会系统性误报。

### 已确认能力（此前未记录）
- app 持 `com.apple.developer.networking.networkextension`（含 packet-tunnel-provider 等 8 项）
- 可建 `NEPacketTunnelProvider → utun → 向内核 IPv6 栈注入报文`
- **但** IPv6 栈相关函数 dChk 全 ≤0 → 只能当运行时探针通道
- nexus 真实控制名：`com.apple.nexus.{kpipe,netif,upipe,utun.kpipe,...}`

### 命名陷阱
`NAMED-CHANGED.md` 里 36 个函数名来自 **KDK 形状匹配，不是符号表**。
`null_getnewvnode` / `nullfs` / `devfs_getnewvnode` 在 iOS kernelcache 中
**一条字符串都不存在**。名字只能当提示，不能当事实。

## J. 方法学修正（2026-11-01 04:30）——两条缺陷，影响所有 dChk 数字

1. **BTI 单一边界检测会合并无 BTI 的函数**（有些函数只被直接调用，直接以 `pacibsp` 开头）
   → 修正规则见 `METHOD-FUNCTION-BOUNDARY.md` §三；工具改用 `/tmp/dchk2.py`
2. **按位置配对会产生假配对**（函数增删时 `SequenceMatcher` 在 replace 块内一对一错配）
   → kernel 的「0→50 检查」是假象，已证伪
   → 详见 `METHOD-FUNCTION-BOUNDARY.md` §六

### 可信度分级（新增）
| 级 | 含义 |
|---|---|
| **A** | 人工反汇编逐条确认语义对应 |
| B | 配对可靠（函数数一致），dChk 可用 |
| C | 有增删，配对可能错位 |
| D | 已证伪 |

### 修正后各目标等级
| 目标 | 等级 | dChk>0 | 判定 |
|---|---|---|---|
| AppleAVD | **A** | 1（+3） | **代码缺陷，但非可用原语**（索引来自硬件寄存器） |
| IOSkywalkFamily | B（1909=1909） | 0 | 出局 |
| AppleH16ANE | C（4284→4409） | 43 | 出局（可达性） |
| com.apple.kernel | C（14961→14993） | 137，但含 D 级假象 | 需人工逐个确认 |

## K. 内核目标全部关闭（2026-11-01 09:55）

走完 AVD 的完整数据流后，最后一个候选也关掉了：

```
索引 = 解码硬件寄存器值 & 0xF   （经 PAC 虚调用读寄存器）
长度 = 固件共享记录的 +0xD84 字段
```

两者都**不是用户参数**。27.0.1 确实缺校验，但要触发需先让固件产生异常尺寸，
超出「app 沙箱直接打」的范围。

### 四个内核目标的最终状态
| 目标 | 判定 | 关闭理由 |
|---|---|---|
| AppleAVD | 代码缺陷，非原语 | 索引/长度来自硬件寄存器 |
| IOSkywalkFamily | 出局 | dChk 全 0，无安全修补 |
| AppleH16ANE | 出局 | 43 个 dChk>0 均为内部状态加固；CoreML 挡住 IO 路径 |
| com.apple.kernel | 未收敛 | 137 个 dChk>0，含已证伪的假配对，需人工逐个确认 |

### 净结论
**iOS 27.0.1 内核侧没有找到 app 沙箱可达的内存破坏原语。**
越狱链仍缺 S2 这一环。

### 剩余唯一未穷尽的面
`com.apple.kernel` 的 137 个 dChk>0，但必须**逐个人工反汇编确认**
（按位置配对产生的排名不可信，已证伪两例）。
成本高，且其中多数可能是内部状态加固。

## L. 阶段③ 结论（B 方向，2026-11-01 10:10）——链条存在**第二个结构性死结**

产物：`out/STAGE3-CODESIGN-AMFI.md`（527 行）

### 核心：代码签名已经不在 XNU 里了

iOS 27 的 SPTM 设备上，校验 / cdhash / entitlement 解析 / trust cache **全部搬进 TXM**
（`TrustedExecutionMonitor_Guarded-217.0.2`），XNU 只剩 34 个 `txm_kernel_call` 调用方。

三条证据（我已独立复核，全部命中）：
| 断言 | 复核结果 |
|---|---|
| `CTAmfiInitializeContextWithOptions` / `CTAmfiVerifyCMS` 在 TXM 镜像 | ✅ `out/txm.27.0.1.macho` 各 1 次 |
| `TXM_SLAB_TRUST_CACHE` 在 SPTM 帧类型表 | ✅ `out/sptm.27.0.1.macho` 命中（**不在** TXM 镜像里） |
| 三条 CONFIG_SPTM 分支串在内核 | ✅ `amfi interface is stale` / `legacy trust caches are not supported` / `attempted to overwrite TXM trust on the pmap` 各 1 次 |

Apple 自己在 `bsd/kern/code_signing/xnu.c:44` 写明：没有 monitor 环境时
"someone with a kernel memory exploit will be able to corrupt code signing state"——
**有 monitor 的机器上这句话不成立**，而这正是 iPhone 17 Pro Max。

### 影响：即使拿到 S2，S5 也不通

| 路线 | 结果 |
|---|---|
| 改 AMFI 内存态开关 / `cs_enforcement_disable` | 作废：`code_signing_enabled` 是 `SECURITY_READ_ONLY_LATE`，值取自 TXM RO 数据 |
| Trust cache 注入 | 作废：TC 条目住在 TXM 独占物理页类型，注入 = 过 Image4 = 要 Apple 私钥 |
| 改 `pmap->txm_trust_level` | 诱饵：全工程 4 处引用，唯一消费者是 KDP 诊断读取 |
| 改 `cs_blob` 哈希槽 | 改不到：注册后 `csb_mem_kaddr` 指向 TXM 内存 |
| **entitlement 捷径** | **已排除**：44 项里无 `dynamic-codesigning` / `cs.debugger` / `pmap.load-trust-cache` |

### 唯一还开着的口子
`txm_accelerate_entitlements`（`txm.c:1610`）的 **double-fetch**：
TXM 侧 `CEQueryContext_t` 交回 XNU 使用，若校验后被 XNU 侧改动影响，就是 r/w ⇒ entitlement 的桥。
纯离线可查，已列为最高优先级。

### 结论原文
「在『只有内核 r/w、没有内核代码执行与 PAC 签名』的前提下，S5 不可行；
阶段③的现实形态只能是数据面语义伪造（root/去沙箱/CS_PLATFORM_BINARY）+ 复用已签名二进制，
而不是让未签名代码跑起来。」

### 新增风险提示
TXM 有串 `denying executable mapping as the kernel has panicked`
—— **一次 panic 之后，本轮所有「执行新代码」的观测都是假的**，必须重启设备。
与 STATUS §D 的假阴性教训同类。

### 工程树陷阱（引用源码前必看）
- `fw/xnu/bsd/kern/kern_trustcache.c` 已被换成 25 行 stub，真源码在 `kern_trustcache.c.orig`
- `EXTERNAL_HEADERS/TrustCache/API.h` 是本地重建桩，枚举值全 0，不能从它读 TC 类型

## M. 最终收敛（2026-11-01 10:20）——两条链全部走到底，S2 与 S5 都是死结

### M.1 方向 A：`com.apple.kernel` 已收敛
产物：`out/KERNEL-137-TRIAGE.md`（491 行）

**结论：159 个候选（不是 137）里没有 app 沙箱可达的内核内存破坏原语。**

| 分类 | 数量 |
|---|---|
| 功能新增 | 56 |
| 防御加固 | 38 |
| 重构/内联/重排 | 19 |
| 未定性（留白，不推断） | 37 |
| 假配对/合并待查 | 5 |
| 可疑 | 2 |
| **真补丁** | **2** |

两个真补丁都不是内存破坏：
- **bindfs 类型门**（`0xb1b4624→0xb20a528`）：需 mount 权限 → app 不可达
- **TCP 选项长度**（`0xaf21830→0xaf758d8`）：访问早被现有边界检查覆盖

→ **建议把 `com.apple.kernel` 移出候选池。**

### M.2 方向 A 推翻了一条旧推论（重要）
`0x41a8624` 的字符串锚点是 **`bindfs`**，不是 `null_getnewvnode`。
→ `CHAIN-DESIGN.md` 「`/dev/null` 路径无门槛可达」**作废**（已在该文件 §6.5 记录）。
→ 原「两条真实通道」只剩 NetworkExtension 一条，而网络栈函数 dChk 全部 ≤ 0。

### M.3 方向 B：S5 在架构上被堵死
产物：`out/STAGE3-CODESIGN-AMFI.md`（527 行）

代码签名已从 XNU 搬进 **TXM**（独立 monitor），XNU 只剩 34 个调用方。
**即使拿到 S2（内核任意 r/w），也无法伪造代码签名。**
四条路线全部堵死，entitlement 捷径也已排除（44 项里无 CS 相关特权项）。

唯一还开着的口子：`txm_accelerate_entitlements` 的 double-fetch（纯离线可查）。

### M.4 五个内核目标，五份阴性
| 目标 | dChk>0 | 死因 |
|---|---|---|
| AppleAVD | 1 | 索引/长度来自硬件寄存器 |
| IOSkywalkFamily | 0 | 无安全修补 |
| AppleH16ANE | 43 | 内部状态加固 + CoreML 挡路 |
| com.apple.kernel | 159 | 60% 功能新增，25% 加固，2 个真补丁均非内存破坏 |
| JSC（非内核但同面） | — | WKWebView 内无法同步触发 GC |

### M.5 方法学：这一轮一共找出**四条**缺陷
1. BTI 单一边界会合并无 BTI 函数
2. 按位置配对产生假配对
3. **边界规则少切 6807 个函数**（残留 pacibsp 无一例外后接栈帧建立）
4. **dChk 把搬走的分支算成新增**（须配签名多重集差分）

→ 最终边界规则见 `METHOD-FUNCTION-BOUNDARY.md` §十二。
→ **任何引用「137」「99」「57」这些数字的文档都必须标口径，它们是方法选择的产物，不是事实。**

### M.6 整体判定
**这条攻击路线（app → 内核 r/w → 代码签名绕过 → 持久化）在 iOS 27.0.1 / iPhone 17 Pro Max 上不成立。**
不是因为某一个 bug 没找到，而是因为：
- S2 在五个面上都没找到
- S5 即使有 S2 也被 TXM 架构堵死

### M.7 还开着的
1. `txm_accelerate_entitlements` double-fetch（离线可查，唯一真正未探索的技术点）
2. 换靶：有 UserClient 且有 external method 的 kext（可达性可静态证明）
3. 换目标：找有公开在野利用的版本，而非在 27.0.1 硬啃

## N. 换靶结果（2026-11-01 10:20）——UserClient kext 全量差分，仍是阴性

产物：`out/USERCLIENT-TARGETS.md`（352 行）

### N.1 做法上的一个正确决定
普查表（字符串启发式）不可靠：漏了 AGXG18P（GPU，Metal 可达，必然有 IOAccelerator UserClient），
又多算了 `com.apple.kernel`。因此**没有拿普查表当闸门**——
301 个 kext 里除已结案 4 个外，其余 **298 个全差，0 报错**。
这顺手覆盖了普查表漏掉的 AGX / GZlib / UDIF / Surface 类。

### N.2 新增资产
- **27.2 全量 kernelcache 解出**：`out/kc.27.2.ga.im4p` → lzfse → 78,512,128 B
  （载荷起点 0x38 不是 0x37），与 27.0.1 的 78,135,296 B 同构，两侧各 301 kext，bundle id 完全一致
- 全量差分：**654 个 dChk>0 且配对成功 → 330 个净新增签名>0 → 65 个 kext**

### N.3 结果
人工读 **15 / 330（4.5%）**：
| 分类 | 数量 |
|---|---|
| 功能新增（其中 6 条同时只是补空指针/返回值/PAC 校验） | 10 |
| 纯防御加固 | 2 |
| 结构体重排 | 2 |
| 未定性 | 1 |

**没有一条**具备「用户可控标量/结构体字段当索引或长度、27.0.1 不校验、27.2 补上校验」的形状。

### N.4 第六条形态误判（A 自己抓的）
`opnorm()` 保留了内存操作数位移 → **结构体整体增长会伪装成「新增边界检查」**。
AGXG18P 整类对象 +8 字节（`[0x2a0]→[0x2a8]`、`#0xcd58→#0xcd60`…），21 个候选里至少 4 对全是这个原因。

**新判读规则**：新增签名里 `[MEM+…]` 位移成等差数列且步长一致 ⇒ 先判结构体重排。

### N.5 三条「像真修复」全部推翻
| 候选 | 表面证据 | 推翻依据 |
|---|---|---|
| AGXG18P `0x856d2f0` | 相似度 0.998、`cmp x23,#0x24` 挡越界读，形状完美 | 27.0.1 里 `ldr x2,[x21,x23,lsl#3]` 等**一条都不存在**，整段循环是 27.2 新写的 |
| AppleSARService `0x94ddcf8` | 表从 5 项扩到 10 项 | 字段整体后移 1 字节 + 表扩容，两侧都自带索引边界 |
| apfs `0xa9f1740` | 真的新增了长度交叉校验 | 调用者 `bl` = 0；触发需挂载攻击者可控 APFS 卷，当前能力打不通 |

### N.6 直答
**这批 kext 里没有 app 沙箱可达的内核内存破坏原语。**

### N.7 按纪律留白的部分（不伪造）
- 315/330 未人工读
- 净新增签名 = 0 的 324 个候选（占 49.5%）只当闸门，未人工确认，
  理论上可能藏「同数量换位置」的真变动
- `selector 数`一列**全部未取到**：这个 cache 里 kext 的 `__DATA_CONST` 不含绝对内核指针，
  派发表被 chained-fixup 编码过，`IOExternalMethodDispatch` 表没能解出来

### N.8 唯一建议继续追的
`apfs 0xa9f1740 → 0xaa4056c`：真的新增了「(len−10) vs `ldrh[rec+8]` 交叉校验」
与「`ldrh[rec+2] ≤ 0x2f`」，A 侧完全没有这两条比较。
但需要挂载攻击者可控的 APFS 卷——**当前能力位打不通**。

## O. TXM double-fetch 收敛（2026-11-01）——两条自我更正 + 一条真发现

产物：`out/STAGE3-CODESIGN-AMFI.md`（955 行）、`out/amfi.clean.macho`（265,920 B）

### O.1 更正：我此前说「代码签名整个搬进 TXM」只对了一半

| 组件 | 实际位置 |
|---|---|
| CDhash / CMS / 证书链 / trust cache | **TXM** |
| **entitlements 解析与求值（`OSEntitlements.cpp`、`CEValidateWithOptions`、`der_vm_*`）** | **EL1 的 kext** |

`com.apple.driver.AppleMobileFileIntegrity` = **55,760 B 的 EL1 kext**，不是 TXM 的一部分。
→ `STATUS.md` §L 与 `STAGE3-CODESIGN-AMFI.md` §1.3/§8 已按此更正。

另：TXM selector 数是 **40** 不是 34（`grep` 在数字前截断，7 个 `Image4*` 被折叠）。

### O.2 真发现：`ceCtx` 指针**没有 PAC 保护**（我已独立复核到指令级）

> ⚠️ **本节偏移已作废**：`+0xd8` 是 `identity`（strdup 字符串），`ceCtx` 在 **`+0xd0`**。
> 更正与验证见 §Q。以下代码片段保留仅为记录原始（错误的）判断。

同一 kext 里另有 **669 条 `pacd*`/`autd*`**，只有这两处没有 → **刻意省略，不是疏漏**。
`ceCtx` 位于 `OSEntitlementsReadOnly+0xd8`，写入前有 write-once panic 保护，
但**读取点是裸 `ldr`**。对象在可写内核堆，0xf0 字节。

### O.3 判定

| 升级方向 | 能否 |
|---|---|
| r/w ⇒ **代码签名绕过** | ❌ **不能**。TXM 在 trust cache 载入、JIT 映射、调试映射三处都不消费 XNU 侧 entitlement，伪造只买到「排队资格」 |
| r/w ⇒ **平台级 entitlement 伪造** | ✅ **结构上可以**。把 `+0xd8` 重定向到自造 CE 上下文，EL1 的 `der_vm_*` 会对伪造 DER 求值 |

### O.4 这实际上补的是 S4，不是 S5

伪造平台级 entitlement = 过 XNU 侧的 IOKit / task 端口门 = **沙箱逃逸的方法**。
这是 S4 的具体机制，**不是 S5 的绕过**。
S5 判定**不变（不可行）**。

### O.5 仍然卡在 S2
这条路径需要先能写内核堆里那个 0xf0 字节对象。**没有 S2 就没有起点。**
严格说：它有 kernel r/w 之后才成立，**不解除 S2 这道门**。

### O.6 唯一未闭合项
查询读的是 `+0xd8` 的**指针**，还是 `+0x48` 起 0x88 字节的**按值副本**——
两条路都不需伪造 PAC，只是改哪个偏移。真机未验证。

## P. 方法学彻底重建（2026-11-01 10:40）—— 我的边界规则被权威表取代

**新文档**：`out/METHOD-AUTHORITATIVE-TABLE.md`（157 行）**取代** `METHOD-FUNCTION-BOUNDARY.md` 全部内容。

### P.1 `LC_FUNCTION_STARTS` 可用（此前判死是错的）
- 解码：ULEB128 增量累加，基址 = `__TEXT` vmaddr
- **自证：首项恰好等于 `__TEXT_EXEC` vmaddr**，六个 kext 全部命中
- 覆盖：m2s 10,262 / avd 2,328 / ane 4,959 / skywalk 2,166 / kern 21,793

### P.2 我的边界规则两个方向都错
| kext | 真表 | 我的 | 偏差 |
|---|---|---|---|
| m2s | 10,262 | 10,354 | 多 92 |
| avd | 2,328 | 2,092 | 少 236 |
| ane | 4,959 | 4,284 | 少 675 |
| kern | 21,793 | 23,277 | 多 1,484 |

根因：我把规则写成「`BTI c` 且下一条 ≠ `PACIBSP`」，
而真实序言恰恰是 `bti c; pacibsp` —— **主动排除了最常见的情况**，每个函数晚 4 字节。

### P.3 AVD 数字：原始是对的，我的「修正」是错的
| 版本 | 起点 | dChk |
|---|---|---|
| 原始报告 | `0x8707cf0` | **+5（34→39）** |
| 我的「修正」 | `0x8707c34` | +3 |
| **真表复核** | **`0x8707cf0`** | **+5（34→39）** |

真表下 AVD 两版各 2,328 个函数（数量一致无增删），6 对 replace，1 个 dChk>0。
**→ 数值结论不变；可利用性结论也不变（索引来自硬件寄存器）。**

### P.4 指针解码已解开（三路互证）
```
va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)
```
| 证据 | 来源 |
|---|---|
| JPEG `__DATA_CONST` 2635 字里 2365（89.8%）落在函数序言 | 子代理 1 |
| H16Cam `adrp+add` 表地址与纯指针扫描**完全一致** | 子代理 1（代码/数据双向） |
| `kaudit.py` 独立得出同一常量 | 子代理 2 |
| M2Scaler 解出 30,884 指针，5,079 精确落在函数起点 | 子代理 3 |

**「kext `__DATA_CONST` 无绝对指针、派发表解不出」作废。**

### P.5 新增三条判据
- **判据 7**：`ubfiz → cmp → csel 毒指针(0x2bad)` 是**位移溢出检查**，不检查 `idx < count`。4 元素表配 `idx=1000` 能完整通过。
- **判据 8**：`IOExternalMethodArguments` 偏移（`0x20` scalarInput64 / `0x38` structInSize / `0x68` structOutDesc / `0x78` variableOut）
- **判据 9**：派发表步长有 `0x28` 与 `0x18` 两种，不能假设 24 字节

### P.6 教训（必须留在文档里）
同一问题错了三次：① 只用 BTI ② 排除 `bti c; pacibsp` ③ 基于错误边界去「修正」一个本来正确的结论。
根因：**用启发式去猜一个本来就有权威数据源的东西**。
`LC_FUNCTION_STARTS` 一直在文件里，我早期测了一次失败就把它判死，之后全部建立在猜测上。
**纪律：遇到「解析失败」，要区分「数据不存在」和「我的解析器写错了」。**

## Q. S4 地基更正（2026-11-01）—— `ceCtx` 在 `+0xD0`，`+0xD8` 是 identity

产物：`out/S4-SANDBOX-ESCAPE.md`（475 行）

### Q.1 我上一轮记录的 `+0xd8` 是错的

那两处裸 `ldr` 读的是 **identity**（strdup 得到的 C 字符串），不是 `ceCtx`。

**三条独立证据（我已亲自复核前两条）：**
1. **panic 串自证字段名** —— `amfi.clean.macho` 里三条串全部命中：
   ```
   AMFI: attempted to reinitialize OSEntitlementsReadOnly ceCtx: %p
   AMFI: attempted to reinitialize OSEntitlementsReadOnly identity: %p
   AMFI: attempted to reinitialize OSEntitlementsReadOnly data: %p
   ```
2. **ObjC 类型编码**（`__cstring @0xfffffe0007662f42`）给出字段顺序：
   ```
   ^{OSEntitlements} {CEQueryContext=…} {_CEContext=…} ^{_CEContext} * {?=^{__SC_GenericBlob}} {?=BB}
   ```
   据此算偏移：`+0x00` 指针 → `+0x08` CEQueryContext(0x40) → `+0x48` _CEContext(0x88)
   → **`+0xD0` = 指向 +0x48 的指针** → **`+0xD8` = `*`（identity）** → 尾部两个小结构，总长 **0xF0**
3. 构造立即数逐一对上：`copy(0x08,src,0x40)` / `copy(0x48,src,0x88)` / `copy(0xD0,&(payload+0x48),8)`

### Q.2 结论仍然成立，只是偏移改一格

我实测 `#0xd0` 的对象字段读取共 18 处（`[x19,#0xd0]` / `[x20,#0xd0]` / `[x1,#0xd0]`），
**全部是裸 `ldr`，无一跟 `autda`** → 「无 PAC 保护」这一点在正确偏移上依然成立。

同时证实了子代理的警告：`#0xd8` 的 27 处里 **15 处是 `[x16, #0xd8]!`**（带 `!` 的预索引，虚调用取 vtable），不是字段读取。

### Q.3 S4 的产出必须重新定义

| 能做 | 不能做 |
|---|---|
| **伪造任意内核 entitlement** ⇒ 打开此前打不开的 IOKit 门 | **改沙箱标签 / 脱离 seatbelt** |

三个硬约束让「改标签」此路不通：两套数据面分离（`cr_label` 也是 PAC 保护的 `struct label*`，seatbelt 走 MACF hook，不调 `IOTaskHasEntitlement`）；标签在 exec 时贴、事后不回溯；能改标签的地方全在 PAC 后面。

### Q.4 四个候选 entitlement 全部否证（重要负面）

| entitlement | 结果 |
|---|---|
| `com.apple.private.security.no-sandbox` | XNU 唯一命中 `kern_exec.c:7960`，整段在 `#if XNU_TARGET_OS_OSX` 内 → **iOS 不消费** |
| `container-required` / `platform-application` | XNU 源码 0 命中，字符串在 `com.apple.security.sandbox` kext，exec 时消费 |
| `task_for_pid-allow` | XNU 源码 0 命中；`task_for_pid_posix_check()` 用 uid/gid + `P_SUGID`，**不查 entitlement** |

→ 所以「最小伪造集合」不是一个固定列表，而是**任意字符串**：门禁由调用点给名。
→ 两个真正的杠杆是 **`IOUserClient.cpp:4549`（类级 `IOUserClientEntitlementsKey`）** 与 **`:6653`（每 selector `dispatch->checkEntitlement`）**。

### Q.5 仍然压在 S2 上
「伪造 entitlement」需要写内核堆里那个 0xF0 字节对象。**没有 S2 就没有起点。**
可绕开 cred 的 PAC：整 zone 扫描，判据是 `payload+0xd0 == payload+0x48`。

### Q.6 方法学留痕 5 条
1. **panic 串才是字段名的一手证据**（比类型编码、比猜测都硬）
2. `ldr x8,[x16,#0xd8]!` 带 `!` 的是 vtable 偏移不是字段 —— 27 处里 15 处是虚调用
3. 拷贝长度比类型编码可信
4. 版本差必须写进结论（v12377 的 `cr_label=0x78` 在 13432 上不成立）
5. write-once 只是构造期 `cbnz`+panic，不是硬件/SPTM 陷门，r/w 直接绕过

## R. 全 cache 派发表普查完成（2026-11-01 10:42）—— 经典 IOKit 漏洞类被扫干净

产物：`out/CENSUS-DISPATCH-TABLES.md`（494 行）、**`out/census.json`**（1.2 MB，2266 行，可查询）

### R.1 规模与自证
| 项 | 值 |
|---|---|
| kext | 301 |
| 真函数（`LC_FUNCTION_STARTS`） | **197,683** |
| 派发表 | 244 |
| selector | **2,266** |
| 自证「首项 == `__TEXT_EXEC` vmaddr」 | **301/301 通过，0 失败** |

三条已知基准精确复现：JPEG `0x80dd990`(0x28×10) / ProRes `0xb905ce0`(0x28×5) / H16Cam `0x8086ae0`(0x18×117)。

### R.2 双路互证分级
| 档 | 数量 | 含义 |
|---|---|---|
| A | 1,631 | 数据路 + 代码路 `adrp+add` 双命中 |
| B | 324 | 只有数据路，但过半 handler 读 args |
| C | 311 | 只有数据路、handler 不读 args（按 vtable 处理）；`com.apple.kernel` 占 181 |

### R.3 直答：**「用户可控长度/索引直进内存操作且无上界检查」= 确认 0 个**

机械候选 12 个，手读 9 个，**9/9 全部有界**，落进三个固定形状：
1. **NUL 结尾检查**：`ldr w9,[args,#0x38]; cbz; sub w9,#1; ldrb [buf,w9,uxtw]`（IOSurface sel19 另有 `cmp w9,#0x1ff`）
2. **`scalarInputCount` 先乘再比再解引用**：`add x10,x8,x9,lsl#3` → 溢出检查 → `cmp x9,#7`/`#0xf` 后才 `ldr`（BasebandM20 四个）
3. **容量除法**：`umull`+`lsr #0x25` 配魔数 `0x3e0f83e1`（除以 33），只当输出容量（IPAppender sel18）

未读 3 个（分数 3）：IOReportFamily sel2、VideoProcessing sel2、apfs sel1。

### R.4 声明 vs 实现一致性核对（B 方向）：**140 条记录，0 条不一致**

修正了一个范畴错误：`0xa053e40` 是**代码段 switch 跳表**，不是派发表。
真派发表靠运行时乘 24 定位，B 先前漏了 `mov w?,#0x18`+`umull` 形态（假阴性）。
修正后 IOGPU 得 **4 张表**（A/B 各 56 selector + C/D 各 14），`externalMethod` 在 `0xa024d94`。

| 表 | 记录 | 判据 | 不一致 |
|---|---|---|---|
| A (56) | 56 | 严格寄存器追踪 | 0 |
| B (56) | 56 | 同上 | 0 |
| C (14) | 14 | 声明全 0，只看是否解引用 | 0 |
| D (14) | 14 | 同上 | 0 |

**诚实标注**：严格追踪版报出的 2 条，手读后 **2/2 全是假阳性**（寄存器复用未及时作废）。
所以「0 不一致」的证据强度分三档：C/D 那 28 条判据最硬；A/B 里被报的 2 条是手读推翻；**其余 110 条只有自动判据、没逐条手读**。

### R.5 顺带修正的两处
- `args` 偏移表补两个：**`0x60`、`0x70` 也是尺寸字段**；`0x28`=scalarInputCount、`0x40`=structureInputDescriptor
- `__DATA_CONST` 里的 code 指针**大量带 `bit63=1`**（arm64e auth-rebase），旧扫描把 `v>>63` 当非法过滤，才得出「只有 34 个 rebase 槽、无 vtable」的错误结论

### R.6 这个「0」的射程（必须连带引用）
- 只覆盖 handler **入口 128 条指令 + 3 层尾调用**
- **只覆盖长度/索引，不碰状态机、竞态、引用计数**
- 324 个 B 类里除已读 4 个，其余「它真的是外部方法」本身仍待证
- AGX / UDIF 的 5 张表是 switch 跳表，本判据不适用

**→ 准确说法是「在机械可覆盖的范围内没找到」，不是「不存在」。**
**→ 但可以下一个结论：经典 IOKit 无界长度/索引漏洞类在 27.0.1 上已被扫干净。**

## S. 普查分母被证伪（2026-11-01）—— AGX/IOGPU 有大块缺口

产物：`out/CENSUS-GAP.md`（96 行）

### S.1 直答：**7 个缺口**

| # | kext | 派发器 | bound | 在 census？ | 派发方式 |
|---|---|---|---|---|---|
| 1 | IOGPU | `0xa024d94` | 0x37 | **部分**（表被合并、编号虚增） | 2×56 条 24B 记录 |
| 2 | IOGPU | `0xa024e4c` | 0x0d | **否** | 2×14 条记录 |
| 3 | AGX | `0x850f170` | 0x10 | **否** | `__TEXT` 跳表 |
| 4 | AGX | `0x851070c` | 0x0f | **否** | 跳表 |
| 5 | AGX | `0x8514ae0` | 0x64 | **否** | 跳表 |
| 6 | AGX | `0x851cfd0` | 0x11 | **否** | 跳表（18 项，12 live） |
| 7 | AGX | `0x85335f4` | 0x32 | **否** | 跳表（51 项） |
| 8 | AGX | `0x84b81c0`（4 个 vtable 共用） | 0x41 | **否** | 跳表（66 项） |

### S.2 两条缺口成因（都可修）

**① AGX — 结构性不可见**
派发用 `__TEXT` 里的 PC 相对跳表：
```asm
ldrsw x16, [x17, x16, lsl #2]   ; 32 位相对偏移
adr   x17, .+8
add   x17, x17, x16
br    x17
```
表项是**相对偏移不是数据段指针** → 「数据段指针连续」这条判据**按构造看不见**。
AGX 侧共 5 张跳表：66/15/18/51/17 = **167 个 switch 项**。

**② IOGPU — 合并缺陷（可修的数据质量 bug）**
表 B `0x82f64b0` 后紧接表 A `0x82f69f0`，间距正好 `0x540` = 56×24。
普查没按 bound 截断，一路走到 **112 行**，报成 `selector 0..111`。
核验：`sel 0 → 0xa021ee8`、`sel 55 → 0xa0240cc`、**`sel 56 → 0xa021ee8`（B[0] 又出现）**
⇒ **selector 56–111 是幽灵行**，真实上界 `0x37` = 55。

**危害双向**：查「IOGPU selector 100」会拿到假数据，同时「上界只有 55」这个正确结论被 112 行掩盖。

### S.3 对 §R 结论的影响

§R 写的「经典 IOKit 无界长度/索引漏洞类已被扫干净」**只对普查覆盖集成立**。
而普查覆盖集**不含 AGX 的 167 个 switch 项、不含 IOGPU 的 28 个 selector、IOGPU 另 56 个被错编号**。

→ **§R.3 的「0 个」必须降级为「在普查覆盖集内为 0」。**
→ AGX 是 Metal 可达（**无 entitlement 门槛**），167 个 switch 项是当前最大的未审计面。

### S.4 一条不加级的留白
那 6 个 AGX 派发器是不是 `externalMethod` **未证明**——全部不读
`IOExternalMethodArguments` 特征偏移（`+0x20/28/30/38/40/48/50/58/60` 零命中）。
所以只能叫「vtable 引用的 selector 派发器」。
若它们真不是 externalMethod，**AGX 真正的 externalMethod 仍未被找到**。

## T. census 修正 + AGX 派发器性质判定（2026-11-01）

### T.1 census.json 已修（备份 `out/census.pre-split.json`）
| 项 | 修正前 | 修正后 |
|---|---|---|
| 行数 | 2266 | **2266**（未删任何行） |
| 表数 | 244 | **245** |
| IOGPU selector 编号 | 0..111（含 56 行幽灵） | A/B 各 0..55 |

- 两基址相差 `0x540 = 56×24`，首尾相接；选表靠 `tst w8,#1` + `csel`
- 核验：`sel 0 = sel 56 = 0xa021ee8`、`sel 55 = sel 111 = 0xa0240cc`，拆分点无歧义
- 每行加 `bound=55` / `split_of` / `orig_selector`

**全 244 张复查**（自动、未手读）：干净 228 / `k=1` 假阳性 15（相邻 selector 共用 handler，kernel 13 + AppleMSG 2）/ **已修 1** / **疑似未修 1**。

**未修的那张**：IOSurface `0x837fa10`，120 行，`k=60`，两半同形 37/60 —— 与 IOGPU 双表模式形状一致，
但 `__text` 里找不到对应的 `cmp w1,#0x3b` + 两个 24 字节表基址。
唯一 `umull #24`（`0xa328b8c`）属另一函数（`cmp w1,#0x3`、4 条、基址 `[this+0x58]+8`）。
**证据不足，保持原样，标记待查。**

### T.2 AGX 那 6 个派发器：**全部不是 `externalMethod`**

先立 ABI（用 IOGPU 已确证实例）：`x1` = selector、`x2` = `IOExternalMethodArguments*`（`ldr x9,[x2,#0x10]`）、`x3` = dispatch、`x4` = target。
**任何真 override 都不可能一次不碰 `[x2,…]`。**

| 派发器 | 长度 | 解引用 x2 | 结论 |
|---|---|---|---|
| `0x84b81c0` | 3 | 否（尾跳 thunk） | 否 |
| `0x850f170` | 37 | 否 | 否 |
| `0x851070c` | 10 | 否 | 否 |
| `0x8514ae0` | 20 | 否 | 否 |
| `0x85335f4` | 2 | 否（thunk） | 否 |
| `0x851cfd4` | 2309 | 否（逐条手读） | 否 |

（5 个「否」是自动扫描**未手读**；`0x851cfd4` 手读。自动扫描曾对它报 24 处「x2 解引用」，
全是 `[x28,…]`/`[x0,…]` —— 别名追踪器假阳性，**假阳性史更新为 3/4**。）

### T.3 连带结论
- 那 **167 个 switch 项既不因此变成用户可达，也不能就此排除**
- **AGX 真正的 externalMethod 仍未找到**
- 正确搜索签名应为「`cmp w1,#N`」+「`ldr x,[x2,#0x10]`」+「`ldr x,[x2,#0x30]`/`[x2,#0x20]`」三者同函数
  → **AGX 里一个都没有**（`[x2,#0x30]` 全 kext 仅 1 处且不是 args，`[x2,#0x38]` 0 处）
- 说明 user-client 层要么参数被上一层拆好，要么入口不在这个 kext 的 `__TEXT_EXEC`

### T.4 唯一反证与新的头号候选
AGX 里唯一读 `[x2,#0x30]` 的 **`0x8558c18`**，把该值当**用户缓冲区逐字节解析**：
- `ldrb w19,[x2,#0x2]` 当**计数**
- `×0x38` 作为记录大小
- 有 `b.ls` 上界

而 args 的 `+0x2` 不是计数字段 ⇒ 那是**子类自定义的精简参数结构**，不是 args。
**但 `b.ls` 比较的到底是缓冲区的实际大小还是固定常数——这一条没验。**
若比的是固定常数而缓冲区由用户定大小，就是 OOB 读。**这是当前最窄、最可判的一条静态线索。**

## U. 苹果公告推翻本项目核心结论（2026-11-01）—— dChk 方法系统性漏报

**情报源**：[About the security content of iOS 27.2](https://support.apple.com/en-us/149230)（2026-10-26）
本地存档：`out/advisory-27.2.json`（141 条记录 / 131 个 CVE / 63 个组件）

### U.1 公告直说「一个 app 就能」破坏内核内存

| CVE | 组件 | 影响 | 修复方式 |
|---|---|---|---|
| CVE-2026-112507 | Kernel | **写内核内存**（OOB write） | improved bounds checking |
| CVE-2026-112514 | Kernel | **破坏内核内存**（UAF） | improved memory management |
| CVE-2026-112517 | Kernel | **破坏内核内存**（UAF） | improved memory management |
| CVE-2026-65350 / 112679 | Kernel | **破坏内核内存**（UAF） | improved memory management |
| CVE-2026-84495 / 112474 | Kernel | **写内核内存**（UAF） | improved memory management |
| CVE-2026-112696 | **Apple Neural Engine** | **破坏内核内存**（OOB write） | improved bounds checking |
| CVE-2026-84494 | **Apple Neural Engine** | **写内核内存**（OOB write） | improved bounds checking |
| CVE-2026-112689 | **AVEVideoEncoder** | **破坏内核内存**（OOB write） | improved input validation |
| CVE-2026-112468/469/470 | **AVEVideoEncoder** | **破坏内核内存**（OOB write） | improved bounds checking |
| CVE-2026-112705 | AVEVideoEncoder | 系统终止（OOB write） | improved bounds checking |
| CVE-2026-112466 | AVEVideoEncoder | **读内核内存**（OOB read） | improved input validation |

**这些在 27.0.1 上全部存在。**

### U.2 我们的结论是错的
本项目 §K/§M 判「com.apple.kernel 无 app 可达的内核内存破坏原语」、§S 判 ANE「内部状态加固，出局」。
**苹果公告直接否证这两条。** 至少 5 个内核 + 2 个 ANE + 3 个 AVE 条目是「一个 app 能写/破坏内核内存」。

### U.3 根因：**dChk 看不见 UAF 和竞态修复**

dChk 只数条件分支（`b.cond`/`cbz`/`csel` 等）。而按修复方式分类：

| 修复方式 | 编译产物 | dChk 能否看见 |
|---|---|---|
| improved **bounds checking** | 新增 `cmp` + `b.hi` | ✅ 能 |
| improved **input validation** | 新增校验分支 | ✅ 能 |
| improved **memory management**（UAF） | 新增 `retain`/`release` 调用 → **`bl`** | ❌ **看不见** |
| improved **locking**（竞态） | 新增 `IOLockLock/Unlock` 调用 → **`bl`** | ❌ **看不见** |
| improved **state handling** | 新增状态比较 + 断言调用 | ⚠️ 部分 |

**而内核类 CVE 里 UAF + 竞态占多数。**

→ 这解释了本项目全部「阴性」：**不是洞里没有东西，是探照灯只照 OOB 那一类。**
→ A 方向的 37「未定性」+ 38「防御加固」里，极可能藏着这些 UAF/竞态修复。

### U.4 与实测可达面的交叉（决定性）

实测 17 个可打开类，与公告组件对应：

| 公告组件 | 实测可达？ | 我们此前判定 | 必须重做 |
|---|---|---|---|
| **Apple Neural Engine** | ✅ `H1xANELoadBalancer` type=1（`ANEDriverRoot`） | ❌「出局」 | **是** |
| **AVEVideoEncoder** | 待查（`AppleH16ANEInterface` 26 selector） | ⚠️ 部分审 | **是** |
| **IOSurface** | ✅ type=0（竞态 + locking） | ✅ 只审了属性路径 | **是**（竞态没审） |
| **IOHIDFamily** | ✅ `AppleSPUHIDDriver`×27 / `IOHIDEventDriver` | 未审 | **是** |
| **IOMobileFrameBuffer** | ✅ `AppleCLCD2` type=0,1,2,3 | 未审 | **是** |
| **Kernel** | ✅ 全部 | ❌「无原语」 | **是** |

### U.5 五项方法修正
1. **dChk 不能作为 UAF/竞态的唯一判据**。必须配「新增 `bl` 目标的语义」——这正是 A 方向 `out/stubs.json`（19,938 桩）能做的
2. **「防御加固」不是「不是洞」**。公告里 OOB write 的修复就叫 "improved bounds checking"——和我们标为「防御加固」的是同一个东西
3. **公告的修复措辞是最强先验**：「improved memory management」⇒ 找新增 `retain`/`release`；「improved locking」⇒ 找新增锁调用
4. 可达性必须实测（已完成）：`type=0` 只覆盖 7% 的可达面
5. 候选排序应按「公告点名的组件 × 实测可达」交叉，不按 dChk 数值
