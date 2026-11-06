# iOS 27.0.1 越狱攻击链设计

## README（摘要，10 行内）

1. 现状：4 个真机确认漏洞**全部不能入链**——两个 DoS，322033 已定性为确定性错误常量（无内存原语），323148 是 GPU 进程越界读。
2. 缺的是**唯一一环**：app 沙箱可达的内核内存破坏原语（S2）。有它才有后面全部。
3. **本次新证据**：我们的 app 持有 `com.apple.developer.networking.networkextension`（含 `packet-tunnel-provider` / `app-proxy-provider`），44 个 entitlement 与 profile 完全一致 —— 内核网络面从"仅远程"变成**本地可控入口**。
4. **本次否证**：IOSkywalkFamily 的 108 处改动 **dChk 净变化 = 0**，是访问器内联重构，**不含检查缺失**。nexus 入口可达，但 skywalk 自身不是漏洞面。
5. **本次定位**：`0x41a8624`（→ 27.2 `0x41fe528`，dChk=2）新增了一个**判空 + 字节字段取值范围校验**（`[x1,#0x71] ∈ {3,4}`）。⚠️ 该处被 KDK 形状匹配命名为 `null_getnewvnode`，但**该符号在 iOS kernelcache 中不存在**，名字与"`/dev/null` 可达"均属【推断】，不可依赖。
6. `com.apple.kernel` 358 个改动函数中 **57 个 dChk>0**，是真修补的所在；最高 dChk=6 的 `0x3eef8f0` 无名，需 S2 根因还原。**这是当前信息量最大且最可靠的方向。**
7. 平台：SPTM/TXM 镜像已提取且可反编译（`sptm.t8150.release.im4p`），PPL/SPTM 会挡住"改页表"这条路；代码签名需从 AMFI **数据面**绕过，不是改内核代码段。
8. 最省设备迭代的下一步：S2 根因还原（纯离线），把 57 个 dChk>0 收敛到 3-5 个可写 bug 陈述的目标。
9. **不建议现在上设备**。先离线完成「57 个候选 → 调用方反查 → 3–5 个有依据目标」（0 设备迭代）；`AppleM2ScalerCSCDriver` selector 11 是目前唯一有"实测可调用"证据的入口。
10. 定位：这是**漏洞研究进度**，不是可用越狱。缺 S2 之前，任何链设计都只是纸面。

---

## 0. 结论摘要

| 问题 | 答案 |
|---|---|
| 已确认的 4 个漏洞能否串成链？ | **不能**，一个都不提供内核原语 |
| 内核未修复节点怎么触达？ | 有两条真实通道：① 无门槛的 `/dev/null` devfs 路径；② 靠我们已有的 NetworkExtension entitlement 打网络栈 |
| 最可能卡死在哪？ | S2（内核内存破坏原语）与 MIE（`kalloc_type`）对利用形态的限制 |
| 当前最该做什么？ | 离线把 57 个 dChk>0 候选收敛成 3-5 条可写的 bug 陈述，再上设备 |

---

## 1. 事实底座（全部来自本工程实测，标注来源）

### 1.1 我们的位置与能力【已证实】

| 项 | 值 | 来源 |
|---|---|---|
| 设备 | iPhone 18,2 / iOS 27.0.1 (24A446) / `isProductionFused: true` | 项目背景 |
| 身份 | dev-signed app `com.example.ios27poc`，uid=501，自有沙箱 | `DEVICE-SURFACE.md` |
| entitlement 数 | **44**，与 embedded profile **完全一致**（无越权，故可正常安装） | 本次实测：`plutil` 对照 `/tmp/ents.plist` ↔ `embedded.mobileprovision` |
| `get-task-allow` | **false**（profile 与签名一致） | 同上 |
| IOKit 可打开服务 | **5 个**（type 0）/ 扫全 type 0..16 后更多 | `DEVICE-SURFACE.md`、`REACH-MAP-V2.md` |
| IORegistry | 1479 服务 / 327 类 | `DEVICE-SURFACE.md` |

### 1.2 关键 entitlement（本次首次系统核对）

```
com.apple.developer.networking.networkextension =
  [ packet-tunnel-provider, app-proxy-provider, content-filter-provider,
    dns-proxy, dns-settings, relay, url-filter-provider, hotspot-provider ]
com.apple.developer.networking.vpn.api
com.apple.developer.networking.multipath
com.apple.developer.networking.HotspotConfiguration
com.apple.developer.networking.wifi-info
com.apple.developer.kernel.extended-virtual-addressing
com.apple.developer.kernel.increased-memory-limit
com.apple.developer.kernel.increased-debugging-memory-limit
com.apple.developer.system-extension.install
```

**含义**：`packet-tunnel-provider` 允许我们创建 `NEPacketTunnelProvider`，从而：
- 建立 utun 接口，**读/写任意 IP 报文**
- 报文进入内核 IPv6/IPv4 栈（`ip6_input` → `frag6_input` / `nd6_*` / `icmp6_*`）

这是把网络攻击面从"远程/邻近"变成"本地 app 可控"的唯一手段，而**我们已经具备**。

### 1.3 27.0.1 内核侧未修复目标（公告对表）

13 条 Kernel CVE + AppleAVE2 4 条 + ANE 2 条等，见 `CVE-27.2.md` §一。

### 1.4 平台防护【已证实存在】

| 防护 | 证据 |
|---|---|
| SPTM（安全页表监视器） | `out/sptm.27.0.1.im4p` 已提取（1.26 MB arm64e EXEC），含 `uat_retype_in/out`、`VIOLATION_UAT_ILLEGAL_PAGE_TABLE`、`retyping from XNU_IOMMU but not to XNU_DEFAULT`（`METHOD-CALIBRATION.md` §5.2） |
| TXM（可信执行监视器） | `out/txm.27.0.1.im4p`，`TrustedExecutionMonitor_Guarded-217.0.2`；含 `com.apple.private.pmap.load-trust-cache`、`amfi-only-platform-code`、`can-load-cdhash` |
| MIE / `kalloc_type` | `CHAIN-TO-POC.md` §S6：「只能玩同 `kalloc_type` 内的复用；UAF 基本绝迹」 |
| 竞品已绕过 MIE | `INTEL.md` §7：Esser 确认基于 EMTE 的 MIE 没拦住（Calif 链） |

---

## 2. Q1：从应用沙箱出发，哪条路径能把已确认的漏洞串成链？

### 2.1 结论：串不起来

标准 iOS 越狱链有 6 个阶段。我们的 4 个漏洞逐一对照：

| 阶段 | 需要什么原语 | 我们的 bug 能提供吗 | 现状 |
|---|---|---|---|
| **S1** 用户态代码执行 | 任意原生代码 | 不需要 bug —— 我们本来就是 dev app | ✅ **已具备** |
| **S2** 内核内存破坏 | 内核 OOB write / UAF / 类型混淆 | ❌ 一个都不能 | ❌ **缺，且是唯一卡点** |
| **S3** 地址/对象泄漏 | 内核 OOB read 或可观测指针 | ❌（323148 越界读在 GPU 进程地址空间） | ❌ |
| **S4** 沙箱逃逸 | 改 `ucred` / sandbox label | 依赖 S2 | ❌ |
| **S5** 代码签名绕过 | AMFI 数据面写 | 依赖 S2 | ❌ |
| **S6** 持久化 | launchd + 可信可执行 | 依赖 S4/S5 | ❌ |

### 2.2 逐个漏洞的入链判定

| 漏洞 | 类别 | 为什么不能入链 | 来源 |
|---|---|---|---|
| CVE-2026-112695（WebCore checkmark UAF） | UAF | free/use 在**同一 C++ 调用链内同步完成**，中间无 JS 执行点 → 无法堆喷回收 | `ASSESSMENT-RW-AND-SANDBOX.md` §障碍1 |
| CVE-2026-113897（BroadcastChannel 竞态） | 竞态 DoS | 有跨线程窗口，但即使槽被重用也只是**读**到受控数据（潜在泄漏），不是写 | 同上 |
| bug 322033（JSC JIT 折叠） | 类型混淆 | 定性为**确定性错误常量**：`same2=true` 每次返回同一对象，喷堆无法回收 → 无悬垂指针、无常量池控制 → 无内存原语 | `POC-JSC-TYPECONFUSION-322033.md` §7 |
| bug 323148（WebGPU 越界取数） | OOB read | 发生在 **GPU 进程**，泄的是 GPU 地址空间，不是内核/WebContent | `POC-WEBGPU-OOB-323148.md` |

### 2.3 如果一定要用现有资产，唯一可能的形态【推断】

```
S1  ✅ dev app 原生代码
     ↓
S2' ⚠️ 用 dev app 直接打内核（绕过 WebKit 整条链）
     —— 这是真实越狱从自签 app 出发的标准做法，见 §3
```

即：**放弃 WebKit/WebContent 这条入口，改用 app 自身的 IOKit / socket 面**。
理由：WebKit 侧的每一个有内存破坏潜力的 bug（321608/319303/318331）都锁在 `jsc` shell 的同步 GC 内建后面（`DIRECTION-POST272-FIXES.md` §五，实测确认浏览器弱引用处理只在让出事件循环后发生）。

---

## 3. Q2：内核未修复节点怎么触达

### 3.1 先纠正任务前提：nexus 入口可达，但 skywalk 里没有洞

任务描述假设 `com.apple.net.nexus` 是被 108 处改动覆盖的入口。**实测否证**：

**(a) 真实控制名不是 `com.apple.net.nexus`**（kernelcache 字符串，两版一致）：
```
com.apple.nexus.kpipe          com.apple.nexus.netif
com.apple.nexus.netif.compat   com.apple.nexus.upipe
com.apple.nexus.utun.kpipe     com.apple.nexus.ipsec.kpipe
com.apple.nexus.flowswitch
com.apple.skywalk.nexus.{contexts,key,mib,port,port.info}
```

**(b) skywalk 的 108 处改动不含新检查**（本次复核，`SKYWALK-27.0.1-vs-27.2.md` §更正）：
```
改动函数对 108
条件分支数: 增加 0 | 减少 2 | 不变 106
合计 dChk 净变化: 0
```
改动实质 = 访问器内联（`ldr`→`ldp`）+ 一次 `and xN,xN,#~0x100`（清 flags bit8）。
**与 `CVE-KEXT-MAP.md` §五 的既有判断一致。**

**(c) skywalk 的 IOKit 类不面向普通 app**：其 entitlement 串只有
`com.apple.developer.driverkit.family.networking` + `IOServiceDEXTEntitlements`
→ 那是 **DriverKit 驱动**的门槛，不是 app 的。

**结论**：nexus 入口的价值不在 skywalk 自身，而在于它是**通往 `com.apple.kernel` 网络栈的本地报文通道**。真正的修补在 `com.apple.kernel`。

### 3.2 真修补在哪：dChk>0 的 57 个函数

`kfunc(27.0.1 → 27.2, com.apple.kernel)`：A=21792，B=21842，配对改动 **358** 个，其中 **57 个 dChk>0**（15.9%）。前 12 名：

| dChk | 27.0.1 偏移 | 27.2 偏移 | 尺寸 | 名字 |
|---|---|---|---|---|
| **6** | `0x3eef8f0` | `0x3f435e4` | 4776→4856 | — |
| **4** | `0x40969fc` | `0x40ec0f0` | 404→496 | — |
| **4** | `0x43adc18` | `0x44045c8` | 312→380 | — |
| 3 | `0x422962c` | `0x427f8b8` | 5264→5264 | — |
| 3 | `0x3dc9e08` | `0x3e1d0a4` | 3112→3128 | — |
| 3 | `0x3ee82bc` | `0x3f3beec` | 608→664 | `nat464_translate_64` |
| 3 | `0x3b5fdb8` | `0x3bafdd4` | 328→396 | — |
| 3 | `0x3b5ff00` | `0x3baff60` | 128→196 | — |
| 2 | `0x3e705bc` | `0x3ec3ae0` | 3828→3868 | — |
| 2 | `0x3f03d54` | `0x3f57d5c` | 1124→1204 | — |
| 2 | `0x3bba524` | `0x3c0b8a0` | 812→872 | — |
| 2 | `0x41a8624` | `0x41fe528` | 304→344 | `null_getnewvnode`※ |

对照：IPv6 栈那几个**不是**修补——
`frag6_input` dChk=**-4**、`tcp6_input` **-4**、`route6_input` **-4**、`kern_netif_queue_rx_enqueue` **-3**、`nd6_na_input` **0**。
→ 「utun 注入打 IPv6 栈」这条线**降级**（它们只是重构）。

### 3.3 路径 A：`0x41a8624` 的新增类型校验（**名字不可信，需先证身份**）

> ⚠️ **命名可信度警告**：该处被 `NAMED-CHANGED.md` 标为 `null_getnewvnode`，依据是 **KDK 符号的形状相似度 0.988**，不是符号表。
> 本次实测：`null_getnewvnode` / `nullfs` / `devfs_getnewvnode` / `null_vnop` 这些字符串在 **iOS kernelcache 里一条都不存在**。
> 因此「它是 devfs 的 /dev/null 处理函数」「`/dev/null` 可达」两项**均属【推断】，且证据薄弱**。
> **可以依赖的只有反汇编本身**：27.2 在该偏移新增了一次判空 + 一次取值范围校验。

**目标**：27.0.1 `0x41a8624` / VA `0xfffffe000b1b4624`；27.2 `0x41fe528`。

**差分（本次反汇编实测，这部分是硬证据）**：
```asm
27.0.1                                 27.2
mov  x25, x1                           mov  x24, x0
mov  x24, x0                           cbz  x1, fail          ★ 新增判空
adrp x0, ...                           ldrb w25, [x1, #0x71]  ; v_type
mov  w1, #0x8004                       sub  w8, w25, #3       ★
bl   alloc                             cmp  w8, #2            ★ (v-3)<2
mov  x20, x0                           b.hs fail              ★ 只允许 {3,4}
cbz  x25, skip                         ...
str  x25, [x20, #0x10]                 （随后才 alloc 并落字段）
ldr  w8, [x25, #0x74]
```

**可直接确认的语义**（不含推测）：
27.2 先 `cbz x1`（判空），再取 `[x1+0x71]` 的**字节**，`sub #3` 后 `cmp #2 / b.hs` → **该字节必须 ∈ {3,4}**，否则直接返回错误。
27.0.1 无判空、无范围校验，取到指针后立刻 `str x25,[x20,#0x10]` 并读 `[x25+0x74]`。

**推测部分（明确标注）**：
- 【推断·中】若 `+0x71` 是 vnode 类型字段，则 {3,4} = VBLK/VCHR（BSD vnode 枚举：VNON0/VREG1/VDIR2/VBLK3/VCHR4）→ **vnode 类型混淆**，与公告中未修复的 **Kernel 类型混淆 CVE-2026-112606** 同型
- 【推断·弱】入口为 devfs `/dev/null` —— **名字本身不可信（见上）**

**接口与权限**：
| 项 | 值 | 可信度 |
|---|---|---|
| 入口 | 待定（需在 `com.apple.kernel` 内对该 VA 做 `bl` 反查） | 【推断·弱】 |
| entitlement | 若为 devfs 路径则**不需要 entitlement** | 依赖上一行 |
| 替代 | `/dev/zero`、`/dev/random` 等同族节点 | 同上 |

**排序修正**：本条**不应**作为"第一跳"直接上设备。
必须先完成 §6 动作 2（调用方反查），才能判定它是否真可从 app 触达。
它目前的价值是：**57 个 dChk>0 候选里唯一有"新增校验"具体形态可读的一个**，可作为 S2 还原的样板。

### 3.4 路径 B：NetworkExtension → 网络栈（我们已有 entitlement）

**接口（实测字符串，两版一致）**：
| 层 | 名称 |
|---|---|
| socket | `socket(PF_SYSTEM=32, SOCK_DGRAM=2, SYSPROTO_CONTROL=2)` |
| name | `com.apple.nexus.kpipe`、`com.apple.nexus.netif`、`com.apple.nexus.upipe` |
| entitlement | `com.apple.developer.networking.networkextension` = `packet-tunnel-provider` ✅ **已持有** |

**通道**：
```
app → NEPacketTunnelProvider(appex) → XPC → nesessionmanager → nexus kctl → utun
                                                                    ↓
                                          注入的 IP 报文 → ip6_input → frag6/nd6/icmp6
```

**但**：目标函数 dChk ≤ 0（§3.2），**不是修补点**。
→ 路径 B 的价值降为：**数据分析/变体搜索**（用注入通道做运行时探针），不作第一跳。

**若缺 entitlement 的替代**：`com.apple.private.kernel-control`（无）；只能走"在已持权守护进程里拿到代码执行"的第二跳（`nesessionmanager` / `configd`）。

### 3.5 路径 C：`AppleM2ScalerCSCDriver` selector 11

| 项 | 值 | 来源 |
|---|---|---|
| 可打开 | `IOServiceOpen` type 0..16 **全部成功** | `REACH-MAP-V2.md` |
| selector 11 | 返回 0，**无需任何输入参数** | `DEVICE-SURFACE.md` §2 |
| 27.2 改动 | **34** 个配对改动，但多为 `dInsn≈0 + dChk=1`，形态与内联重构相似 | `REACH-MAP-V2.md` |
| 缺什么 | selector 11 语义未定位（kext 内 `cmp #0xb` 无命中 → 跳转表） | `DEVICE-SURFACE.md` §3 |

**判定**：唯一"无需授权的实际可调用内核入口"，但**尚未证明其改动含安全修补**。
优先级低于路径 A，因为路径 A 的改动已确认是校验。

### 3.6 路径 D：顶层无名候选（信息量最大，成本最高）

`0x3eef8f0`（dChk=6，+80 B）是本次最高分候选。无名 → 必须做 S2 根因还原：
1. 找被校验字段（`ldr w?, [x?,#imm]` 的 offset）
2. 反推原版缺失的不变式
3. 确定对象类型
4. 写"输入 → 缺检查 → 后果"三句话

### 3.7 已否证的路径（不要重做）

| 路径 | 否证依据 |
|---|---|
| ANE procedure 描述符 | CoreML/ANE 编译器在用户态强制 IO 计数上限；300 输入模型 85.7 ms 说明被 fallback 到 CPU（`CVE-27.2.md` §十） |
| AppleAVD 恶意视频 | kext 内 5 个改动全是内联重构（+88 B 那个把已有四项检查内联进调用者）→ 修复在 AEA 加密的用户态（`CVE-27.2.md` §八） |
| AVE 属性注入原始 VPS/SPS/PPS | 19 个候选键全 `-12900`；`NumberOfTemporalLayers>7` 只造成 DoS（`AVE-REACH.md`） |
| IOSurface 内核路径 | `IOServiceOpen` 成功但 selector 0–95 全 `0xE00002C2`；app 用的是用户态 broker（`IOSURFACE-FINDING.md` §6） |
| nat464 / NAT64 | 需设备作 NAT64 网关，普通 app 不可触发（`NETPATH-ANALYSIS.md` §可达性） |
| skywalk 自身 | 本次 dChk 复核：净变化 0 |

---

## 4. Q3：前置条件、PPL/SPTM、代码签名、持久化

### 4.1 各阶段前置条件

| 阶段 | 前置条件 | 我们缺什么 |
|---|---|---|
| S2 内核原语 | ① 沙箱可达入口 ② 可构造的违反不变式输入 ③ 能观测到 PC/寄存器受控 | ①②③ 中只有 ① 部分具备 |
| S3 泄漏 | 先有 S2 的 OOB read 或可利用的混淆读 | 全部 |
| S4 沙箱逃逸 | S2 给出内核任意写 | 全部 |
| S5 代码签名 | S2 + 能定位 AMFI 数据符号 | 全部 |
| S6 持久化 | S4 + S5 + 可写的 `/var/jb` | 全部 |

### 4.2 PPL/SPTM 会挡住哪一步【已证实存在，语义推断】

**挡住的**：
- 直接改页表把未签名页设为可执行 → SPTM 监控 UAT 重类型化，
  证据：`VIOLATION_UAT_ILLEGAL_PAGE_TABLE`、`retyping from XNU_IOMMU but not to XNU_DEFAULT`、
  `FTE %p should be held exclusive by sptm_retype()`
- 改内核代码段（KTRR/CTRR 类只读保护）

**不挡的**（因此是绕过重点）：
- 内核**数据段**写：`ucred.cr_uid`、`p_csflags`、sandbox label、AMFI 的内存态开关
- 进程自身的地址空间操作

**→ 所以代码签名绕过的正确路线是「改 AMFI/TXM 的数据面」，不是「patch 内核代码」。**

### 4.3 代码签名绕过

| 路线 | 说明 | 证据/状态 |
|---|---|---|
| AMFI 数据面开关 | 拿到内核写后改 `cs_enforcement_disable` 一类内存标志 | 【推断】标准做法，需符号定位 |
| TXM trustcache 注入 | TXM 暴露 `com.apple.private.pmap.load-trust-cache`、`can-load-cdhash`、外部 trust cache 模块加载 | 【已证实字符串存在】`METHOD-CALIBRATION.md` §5.2 |
| 走已签名进程执行 | 不绕签名，改为劫持已签名 daemon | 不需要 S5，但需要 S4 |

### 4.4 持久化

| 形态 | 要求 | 现状 |
|---|---|---|
| semi-tethered | 重跑 app 重放链 + `/var/jb` bootstrap + `launchctl bootstrap` | 需先有 S4/S5 |
| **untethered**（重启存活） | 引导链持久化 | `CHAIN-TO-POC.md` §S9 判"A19 上判死"；但 `INTEL.md` §7 记录 **Calif 已做到**，机制未知 —— 这是最大的未解问题，不要假设它做不到 |

---

## 5. Q4：风险与失败点、回退

### 5.1 最可能失败的环节（按概率降序）

| # | 失败点 | 概率 | 为什么 | 早期识别信号 |
|---|---|---|---|---|
| 1 | **S2 输入构造** | 很高 | 无符号、无结构体定义；`null_getnewvnode` 的调用方尚未确认 | S3 追不到 `bl` 调用者 → 该候选拔除 |
| 2 | **MIE 让原语不可用** | 高 | 越界写只能落在同 `kalloc_type` 分区；跨类型喷射被 MIE 挡住 | 崩溃显示目标对象与喷射对象不在同一 zone |
| 3 | **只能是 DoS** | 高 | 我们 4 个已确认漏洞全是这个结局 | 崩溃点 PC 稳定但寄存器不受输入影响 → 纯 panic |
| 4 | S3 KASLR | 中 | 需要额外泄漏 | — |
| 5 | 设备迭代成本 | 中 | 每次装配+启动+取日志约 1–2 分钟；崩溃只换 1–2 条信息 | 单轮信息产出 < 3 条即为低效 |

### 5.2 失败后如何回退

| 情形 | 回退动作 | 代价 |
|---|---|---|
| 候选拔除（S3 追不到入口） | 从 57 个 dChk>0 里取下一个；清单在 `out/kfunc` 输出可复现 | 0 设备成本 |
| 触发只导致 panic | 保留崩溃日志，回 S1 换候选；**不要在同一函数上反复调参** | 1 次设备重启 |
| 设备进入 panic loop | `devicectl` 重装 app（app 沙箱内操作不会持久污染内核态，重启即清） | 数分钟 |
| 喷射污染堆 | 每次实验用全新进程；不做跨轮状态复用 | 0 |

**安全边界**：所有实验在自有 app 沙箱内，最坏结果是内核 panic 重启，不涉及持久化改动。

---

## 6. Q5：按性价比排序的行动清单

**总原则：先把 57 个 dChk>0 收敛到 3–5 个"有调用方 + 有具体不变式"的目标，再上设备。**
当前任何直接在设备上试的行为都是浪费——这正是 `CHAIN-TO-POC.md` 标注的 S2 卡点。

| 序 | 动作 | 类型 | 设备迭代 | 预期产出 | 性价比 |
|---|---|---|---|---|---|
| 1 | **S2 收敛**：对 57 个 dChk>0 候选批量做"新增指令定位 → 被校验字段 → 一句话 bug 陈述" | 纯离线 | **0** | 3–5 条可写 bug 陈述 | ★★★★★ |
| 2 | **调用方反查**：对每个候选 VA 在 `com.apple.kernel` 内找 `bl` 引用，确认派发入口类型（syscall / IOKit external method / kctl） | 纯离线 | 0 | 每条候选的"能否 app 触达"判定 | ★★★★★ |
| 3 | 顶层 dChk=6 候选 `0x3eef8f0` 根因还原（+80 B、6 个新分支） | 纯离线 | 0 | 最高分候选定性 | ★★★★ |
| 4 | `AppleM2ScalerCSCDriver` selector 11 语义定位（跳转表）；**它有唯一"实测可调用"的入口证据** | 纯离线 + 1 次设备验证 | 1–2 | 是否可影响内核状态 | ★★★★ |
| 5 | 路径 A（`0x41a8624`）触发实验 —— **仅在动作 1/2 证明其可达后才做** | 设备 | 3–6 | 崩溃或否证 | ★★★（有前置） |
| 6 | 路径 B（utun 注入）作**运行时探针**而非攻击：用注入通道观察哪些网络函数被打到，反向补可达性证据 | 设备 | 2–3 | 可达性地图 | ★★★ |
| 7 | PPL/SPTM 审计（`sptm`/`txm` 镜像反编译，找 retype 状态机缺陷） | 纯离线 | 0 | 长期价值，与 S2 并行 | ★★ |
| 8 | 变体搜索：把 S2 找到的模式在 27.2 全 kext 横向扫 | 纯离线 | 0 | 可能发现同源未修补变体 | ★★ |

**节奏**：动作 1–3 全部离线、合计 0 设备迭代，即可把方向从"62 个模糊候选"压到"3–5 个有依据的目标"。
这一步的产出质量决定后面所有设备时间的价值。

---

---

## 6.5 ⚠️ 重大更正（2026-11-01，方向 A 实证）：`0x41a8624` 是 **bindfs**，与 `/dev/null` 无关

### 结论
该函数的身份由**字符串锚点**确认为 **`bindfs`**，不是 `null_getnewvnode`。
KDK 的形状匹配（相似度 0.988）**是错的**。

### 实证（`out/KERNEL-137-TRIAGE.md` §5，逐条反汇编）
27.2 版本 `0xb20a528` 新增：
```asm
ldrb w25, [x1, #0x71]      ; 源 vnode 的字节字段
sub  w8, w25, #3
cmp  w8, #2
b.hs ok                    ; 只接受 {3,4}
mov  w0, #0x2d             ; 否则 EOPNOTSUPP
```
并在 kauth 调用后向返回对象 `+0x72` 写半字 `0x1b`。
字符串锚点解析出 `"bindfs"`。

### 连带作废的推论
| 旧文档的说法 | 状态 |
|---|---|
| §5.1「入口为 devfs `/dev/null`」 | ❌ **作废**（与 devfs/nullfs/`/dev/null` 全无关系） |
| 摘要表「① 无门槛的 `/dev/null` devfs 路径」 | ❌ **作废** |
| `0x41a8624` 是可达的 S2 候选路径 | ❌ **作废**（bindfs 需 mount 权限，uid=501 沙箱无） |

### 因此
本文件原先「两条真实通道」的第 ① 条**不成立**。
剩下的可达面只有第 ② 条：**NetworkExtension → 网络栈**
（而网络栈函数的 dChk 全部 ≤ 0，见 `STATUS.md`）。

**这个更正把本文件给出的可达性评估整体下调一档。**

## 7. 本文件的自我限定

【已证实】= 工程内有实测数据或反汇编直接可见，已标注来源。
【推断】= 由证据推出但未经真机验证，逐条标了【推断】。

不确定项，明确列出：
1. **函数名可信度**：`NAMED-CHANGED.md` 的 36 个函数名全部来自 **KDK 形状相似度匹配**（0.94–1.000），不是符号表。
   本次实测 `null_getnewvnode`/`nullfs`/`devfs_getnewvnode`/`null_vnop` 在 iOS kernelcache 中**零命中** →
   **这批名字只能当"提示"，不能当事实**。引用时必须标注相似度。
2. `0x41a8624` 是否真由 `open("/dev/null")` 进入 —— **未验证**，需 §6 动作 2
3. `+0x71` 字节字段是否确为 `v_type` —— **未用 KDK/Diaphora 确认**，{3,4} 的语义解读基于 BSD 枚举推断
4. 57 个 dChk>0 与 13 条 Kernel CVE 的对应关系 —— **未建立**，无符号无法直接映射
5. MIE 对本设备（A19 / 27.0.1）的具体分区策略 —— 未实测
6. untethered 持久化机制 —— 竞品做到过（`INTEL.md` §7），机制未知

> ※ 该名字来自 KDK 形状匹配（0.988），iOS kernelcache 中无此字符串，**仅作提示**，详见 §3.3 与 §7.1。

---

## 8. 与前序文档的差异（避免混淆）

| 文档 | 前序结论 | 本文件 |
|---|---|---|
| `SKYWALK-27.0.1-vs-27.2.md` | 曾写"27.2 新增尺寸下界检查" | **已在该文档追加更正**：dChk 净变化 0，是内联误报 |
| `CVE-KEXT-MAP.md` §五 | skywalk 108 处全为内联重构 | ✅ 本文件复核**支持**该结论 |
| `NETPATH-ANALYSIS.md` | `nat464_translate_64` 有实质新检查 | ✅ 复核一致（dChk=3）；但仅 NAT64 网关可达 |
| `NETPATH-ANALYSIS.md` | IPv6 栈待细看 | ✅ 本文件补齐：`frag6_input`/`tcp6_input`/`route6_input` dChk **为负**，非修补 |
| `CHAIN-TO-POC.md` | 停在 S1→S2 交界 | ✅ 一致；本文件把 S2 的候选池从 358 收敛口径改为 **57 个 dChk>0** |
| `CVE-27.2.md` §十 | ANE 不可达 | ⚠️ `REACH-MAP-V2.md` 已修正为 `H1xANELoadBalancer` type 1/4 可打开；但 ANE IO 计数路径仍被编译器挡住 |
