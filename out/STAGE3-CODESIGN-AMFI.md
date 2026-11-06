# 阶段③：代码签名 / AMFI 数据面 —— 从「已有内核 r/w」出发的可执行设计

**日期**：2026-11-01
**范围**：方向 B / 第③阶段（S5 代码签名绕过 + PPL/SPTM 对抗 + 落地）
**前提假设**：S2 已成立，攻击者持**内核任意读写**（EL1 数据面），**不含**内核代码执行 / PAC 签名能力（两者的差别是本文的核心）。
**未做的事**：没有调用设备，没有修改 `out/` 以外任何文件。

---

## README（摘要，10 行）

1. **iOS 27 的代码签名不在 XNU 里了。** 校验、cdhash、entitlement 解析、trust cache 全部搬进 TXM（`txm.iphoneos.release.TrustedExecutionMonitor_Guarded-217.0.2`），XNU 只是**调用方**，只能通过 **40** 个 selector 的 `txm_kernel_call` 请求它做事（`grep -o "kTXMKernelSelector[A-Za-z0-9_]*" fw/xnu/bsd/kern/code_signing/txm.c | sort -u | wc -l` → 40；上一轮我写 34 是**计数脚本的 bug**：正则写成 `[A-Za-z]*` 会在数字前截断，7 个 `Image4*` selector 被并成 1 个，见 §9.5 开头）。
2. 因此工程内旧结论「改 AMFI 的内存态开关就能关代码签名」**在本设备上不成立**，本文给出源码级证据并作废该条。
3. 信任缓存（TC）在 SPTM 里的帧类型是 `TXM_SLAB_TRUST_CACHE` —— 属于 **TXM 独占的物理页类型**，XNU 侧连读都要走 TXM 查询接口，写不可能。TC 注入不是「改数据」，是「让 TXM 接受一个新条目」，需要 **Apple 签名的 image4 manifest**。
4. 唯一合法的 TC 载入入口 `load_trust_cache_with_type()` 需要 `com.apple.private.pmap.load-trust-cache` + 每类型的字符串值，且 **REM 一旦启用即永久拒绝**；我们的 app 不持该 entitlement。
5. `isProductionFused: true` ⇒ 设备跑的是 TXM **release** 变体（非 research），`/chosen/research-enabled` 为假，`disallowed loading ERM trust cache on the system` 生效 → 工程 TC（ERM/engineering）路线当场否决。
6. **页面级哈希校验仍留在 XNU**（`cs_validate_page` → `cs_invalid_page`），这是唯一还属于「普通内核数据」的签名相关面；但哈希槽本身在 TXM 拥有的内存里，且执行映射的授权由 TXM 按地址空间/VA 区间给出。
7. 我**否证**了两条看起来最像出路的路线：改 `pmap->txm_trust_level`（只有 KDP 读它，无策略消费者）、改 `cs_blob` 哈希槽（`csb_mem_kaddr` 注册后指向 TXM 内存）。
8. 纯 r/w（无调用能力）时，S5 的可行空间收窄为**数据面语义伪造**：`ucred` / sandbox label / `cs_flags`(CS_PLATFORM_BINARY) / `cs_blob` 的**非 PAC 字段**。要「运行新的未签名二进制」仍然过不去。
9. 不依赖内核 r/w 也能推进的部分：dev-signed helper 的合法能力上限（NetworkExtension 8 项）、描述文件/监督模式路径、开发者模式与 debugserver 的 TXM 侧门控、amfid/trustd 用户态面。
10. 持久化结论：`isProductionFused` 设备上**没有**可用的引导链持久化点；现实目标是 semi-tethered（重放链）+ 让「入口 app」自身长期存活。

---

## 0. 证据分级与本轮自证方法

本文每个论断带标签，四档：

| 标签 | 含义 | 例子 |
|---|---|---|
| **【V-D】** | 已证实·**设备镜像**（我在 `out/` 的 27.0.1 二进制里直接查到，附可复现命令） | `amfi interface is stale` 只在 CONFIG_SPTM 分支存在 |
| **【V-S】** | 已证实·**Apple 源码**（`fw/xnu`，tag `xnu-12377.1.9`；或项目内 `.orig` 原件） | `kern_trustcache.c.orig:163` `txm_load_trust_cache()` |
| **【V-P】** | 公开资料支持（本项目文档 / 公开越狱研究），未在设备上验证 | 竞品链的公开描述 |
| **【推断】** | 由证据推出，未验证；强的标「强」 | SPTM 用 context-id 绑定 ASID |

### 0.1 重要：本工程 xnu 树有两处**本地改造**，引用前必须区分

```bash
cd fw/xnu && git status --porcelain
#  M bsd/kern/kern_trustcache.c      ← 已被替换成 25 行 stub（"trust-cache functionality is inert"）
# ?? EXTERNAL_HEADERS/TrustCache/    ← 本地重建的 API.h（"Apple does not publish this header"）
```

- **`bsd/kern/kern_trustcache.c` 现在是 stub**；真源码在同目录 `kern_trustcache.c.orig`（1350 行，Apple 原件）。本文所有 TC 论断引用 **`.orig`**。
- **`EXTERNAL_HEADERS/TrustCache/API.h` 是重建桩**，里面 `#define kTCTypeStatic 0 / kTCTypeTotal 0 ...` 全是 `0`（见文件内 `/* AUTO-PATCH */` 段）。**不能从它读枚举值**。本文只把它当类型名来源。
- `txm.c` / `ppl.c` / `xnu.c` / `sptm/*` 未被修改（git 里干净），可直接当 Apple 源码引用。

### 0.2 我在设备二进制上做的验证（可复现）

```bash
KC=out/kern.27.0.1.macho
LC_ALL=C tr -c '[:print:]' '\n' < $KC | grep -E "TXM|txm"          # TXM glue 全量字符串
LC_ALL=C grep -a -c "amfi interface is stale" $KC                  # =1 → CONFIG_SPTM 分支被编译进来
LC_ALL=C grep -a -c "legacy trust caches are not supported" $KC    # =1 → txm_load_legacy_trust_cache() 的 panic
LC_ALL=C grep -a -c "attempted to overwrite TXM trust" $KC         # =1 → SPTM pmap（pmap_txm_set_trust_level）在位
LC_ALL=C tr -c '[:print:]' '\n' < $KC | grep "CODE SIGNING:"      # 页面级校验仍在 XNU
```

结论（**全部【V-D】**）：

| 事实 | 证据串 |
|---|---|
| 设备内核走 **TXM 后端**，不是 PPL 后端 | `amfi interface is stale` / `image4 interface not available` / `legacy trust caches are not supported on this platform` 三条只在 `#if CONFIG_SPTM` 分支里 |
| 设备内核有 **SPTM pmap**（不是 arm 老 pmap） | `attempted to overwrite TXM trust on the pmap: %p @%s:%d` |
| TXM 调用面在设备上活跃 | `TXM [Error]: CodeSignature: selector: %u`、`TXM [Error]: TrustCache: selector: %u`、`invalid number of arguments to TXM: selector: %u \| %u` |
| 设备树里有 TXM 节点 | `com.apple.txm`、`txm_bootstrap`、`TXM load address: %p` |
| **页面级 CS 校验仍在 XNU** | `CODE SIGNING: process %d[%s]: rejecting invalid page (phys#0x%x) at address 0x%llx ... (signed:%d validated:%d tainted:%d nx:%d...)` |
| `cs_blob` 仍是独立 zone | `cs_blob zone`、`cs_blob_count/…` |
| AMFI 是**注册进来的接口**，不是 kernel 内实现 | `_amfi_interface_register`、`amfi interface not available @%s:%d`、`amfi.c` |

提取完整性检查（避免又一次「截断当结论」）：`out/kern.27.0.1.macho` __TEXT_EXEC 段 `fileoff=0x298c90 filesize=0x8fb3d8`，文件总长 `0xccbe31`，**未截断**；`strings` 报的 `truncated` 只涉及 8 个 **size=0 的 PRELINK 段**（非 prelink 提取的正常现象）。

---

## 1. Q1：代码签名检查在内核里由谁做

### 1.1 三层结构（这是最容易用旧结论搞错的地方）

```
EL2 ┌─ SPTM  (sptm.t8150.release.im4p)      —— 页表/UAT 的唯一所有者
    │    · 维护 UAT 对象状态机，XNU 只能通过 sptm_uat_* / ioctl 请求
    │    · 帧类型（frame type）决定一个物理页"能干什么"
    │    · 有自己的 EXEC_MODE_*（按执行态切换可达帧类型）
    │
    │  ┌─ TXM  (txm.iphoneos.release.TrustedExecutionMonitor_Guarded-217.0.2)
    │  │    · 代码签名校验、cdhash、trust cache 存储与查询、entitlement 解析
    │  │    · 自己的 RO/RW 数据、自己的 malloc 页、自己的 TC slab
    │  │
EL1 └──┴─ XNU  (kernelcache.release.v54 / com.apple.kernel, 24A446)
         · 只保留：cs_blob 生命周期、页面哈希校验、csflags 策略、VM/VFS
         · 对 TXM 只能 "call"，不能 "write"
```

【V-D】SPTM 镜像里同时存在 `EXEC_MODE_TXM_DEFAULT` 与 `EXEC_MODE_XNU_DEFAULT / XNU_USER_DEFAULT / XNU_USER_JIT_RW / XNU_USER_TPRO_RW` —— SPTM 是**按执行态**而不是按地址范围来限制可达帧类型的。这解释了为什么「直接改 PTE」在 SPTM 上连入口都没有：XNU 根本不写 PTE。

### 1.2 `cs_blob` 的真实形态（【V-S】`bsd/sys/ubc_internal.h:106-165`）

```c
struct cs_blob {
    struct cs_blob  *csb_next;
    vnode_t          csb_vnode;
    void            *csb_ro_addr;
    /* group cs_cpu_info:   csb_cpu_type, csb_cpu_subtype */
    /* group cs_signer_info: csb_flags, csb_signer_type */
    off_t            csb_base_offset, csb_start_offset, csb_end_offset;
    vm_size_t        csb_mem_size;
    vm_offset_t      csb_mem_offset;
    void            *csb_mem_kaddr;          // ← 注册后可能指向 TXM 内存（见 §3.5）
    unsigned char    csb_cdhash[CS_CDHASH_LEN];
    const struct cs_hash *csb_hashtype;      // ← 普通指针
    int              csb_hash_pageshift, csb_hash_firstlevel_pageshift;
    const CS_CodeDirectory *csb_cd;          // ← 普通指针（指向 blob 内 CD）
    const char      *csb_teamid;
    const CS_GenericBlob *csb_entitlements_blob;      // raw blob
    const CS_GenericBlob *csb_der_entitlements_blob;
    void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_entitlements") csb_entitlements;  // ← PAC 签名
    unsigned     csb_reconstituted;
    /* group cs_blob_platform_flags: csb_platform_binary:1, csb_platform_path:1 */
    unsigned     csb_validation_category;
    uint64_t     csb_auxiliary_info;
#if CODE_SIGNING_MONITOR
    void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_csm_obj") csb_csm_obj;  // ← PAC 签名，指向 TXM 签名对象
    bool     csb_csm_managed;
    uint32_t csb_csm_trust_level;
#endif
};
```

三个必须先看清的点：

1. **`csb_entitlements` 是 PAC 签名指针，且对象在 RO 内存**。Apple 在字段注释里写得很直白（`ubc_internal.h:140-145`）：
   > "OSEntitlements pointer setup by AMFI. This is PAC signed in addition to the cs_blob being within RO-memory to prevent modifications on the temporary stack variable used to setup the blob."
   这是**专门针对「有人改 cs_blob 换 entitlements」写的对策**。【V-S】
2. **`csb_csm_obj` 同样 PAC 签名**，且其所有权在 TXM。换签名对象 = 换 cdhash = 需要 PAC 签名能力。
3. **`csb_mem_kaddr` / `csb_cd` / `csb_hashtype` 没有 PAC**（可用 r/w 改），但改它们能不能生效取决于 §3.5 的两条约束。

`cs_blob` 由 zone 分配（【V-D】zone 名 `cs_blob zone`），链表挂在 `struct ubc_info.cs_blobs`（`XNU_PTRAUTH_SIGNED_PTR("ubc_info.cs_blob")`，也是 PAC 指针）。

> **偏移说明**：`__xnu_struct_group` 在 `CONFIG_SUPPORTS_STRUCT_GROUPS` 下是匿名的联合/结构差异，**不同构建配置下偏移不同**。不要硬编码 `csb_flags` 的偏移。取值方法见 §7 动作 1。

### 1.3 AMFI 不再是 kext —— 它在 TXM 里

【V-D】`out/txm.27.0.1.macho` 里直接有 AMFI 的实现符号：

```
CTAmfiInitializeContextWithOptions
CTAmfiVerifyCMS
CTAmfiVerifyCertificateChain
amfi-only-platform-code
com.apple.amfid
```

【V-D】`out/kern.27.0.1.macho` 只有**消费端**：`_amfi_interface_register`、`_amfi_core_entitlements_register`、`amfi interface not available`、`amfi interface is stale: %u`。

【V-S】`kern_trustcache.c.orig:130-140`：`trust_cache_runtime_init()` 在 `CONFIG_SPTM` 分支下**先检查 `amfi != NULL` 且 `amfi->TrustCache.version >= 2`**，否则 panic。也就是说内核启动时必须已经有人把 AMFI vtable 注册进来 —— 在 SPTM 平台上这个"人"是 TXM bootstrap。

**结论（§9 已修正一半）**：`AppleMobileFileIntegrity.kext` **仍然存在，而且是 EL1 的 kext**（§9.0 我从 27.0.1 kernelcache 里把它提出来了）。"校验"（CMS / 证书链 / CDhash / TC）确实搬进了 TXM，但**entitlements 数据结构的实现（`OSEntitlements`、`CEValidateWithOptions`、`der_vm_*`）在 kext 里，跑在 EL1**。所以正确的说法是：**签名"由谁认证"在 TXM，"认证结果怎么用"在 XNU**。这一半在 §9 展开。

### 1.4 Trust cache 的归属：`TXM_SLAB_TRUST_CACHE`

【V-D】SPTM 的帧类型表里，TXM 独占的类型有：

```
TXM_DEFAULT  TXM_RO  TXM_RW  TXM_CPU_STACK  TXM_THREAD_STACK
TXM_ADDRESS_SPACE_TABLE  TXM_MALLOC_PAGE  TXM_FREE_LIST
TXM_SLAB_TRUST_CACHE          ← 信任缓存条目就住在这里
```

【V-S】`kern_trustcache.c.orig:81-95` 的注释是这个结构的官方描述：

> "The trust cache runtime is managed independently by TXM. All initialization work is done by the TXM bootstrap and there is nothing more we need to do here."
> `SECURITY_READ_ONLY_LATE(TrustCacheRuntime_t*) trust_cache_rt = NULL;`

即 **XNU 侧连 runtime 指针都是 NULL**（SPTM 构建下），完全靠 `txm_kernel_call(kTXMKernelSelectorQueryTrustCache, ...)` 问。

### 1.5 唯一还留在 XNU 的签名逻辑：页面哈希

【V-S】`bsd/kern/ubc_subr.c:6011 cs_validate_page()` → `cs_validate_hash()`，逐 4K 子区间比对 `csb_cd` 的哈希槽，产出 `validated / tainted / nx` 三个位图。
【V-S】`osfmk/vm/vm_fault.c:8196` 在**页入（page-in）时**调用它，把结果写到 `vm_page->vmp_cs_validated / vmp_cs_tainted / vmp_cs_nx`。
【V-S】`osfmk/vm/vm_fault.c:2923` 失败时 `reject_page = cs_invalid_page(vaddr, &cs_killed)` → 拒绝缺页，按 csflags 决定是否杀进程。
【V-D】设备内核含 `rejecting invalid page ... (signed:%d validated:%d tainted:%d nx:%d)` → 这条路径在 24A446 上活着。

**这是阶段③唯一真正的"数据面"落脚点**，也是 §3.5 讨论的战场。

---

## 2. Q2：信任缓存注入

### 2.1 合法路径全貌（【V-S】`kern_trustcache.c.orig:893-1035`）

```
用户态/kext → load_trust_cache[_with_type](type, img4_object, ext_manifest, aux_manifest)
  ├─ 参数校验（溢出 → panic）
  ├─ 从 img4 里拆 payload / manifest（img4if->i4if_version >= 15）
  ├─ 拒绝 type ∈ {kTCTypeStatic, kTCTypeEngineering, kTCTypeLegacy}
  ├─ 拒绝 type >= kTCTypeTotal
  ├─ ★ IOCurrentTaskHasStringEntitlement(
  │       "com.apple.private.pmap.load-trust-cache",
  │       TCTypeConfig[type].entitlementValue)      ← 每类型一个字符串值
  ├─ Cryptex1BootOS / BootApp 只允许各一次
  ├─ ★ restricted_execution_mode_state() == KERN_SUCCESS → 直接 KERN_DENIED
  │       "disallowed to load trust caches once REM is enabled"
  └─ #if CONFIG_SPTM → txm_load_trust_cache(type, payload, manifest, …)
```

TXM 侧（【V-S】`txm.c:163 txm_load_trust_cache()`）：

```
kmem_alloc(payload) + memcpy
kmem_alloc(manifest) + memcpy
txm_transfer_region(payload_addr, len)     ← ★ 页面所有权移交 TXM（SPTM 改帧类型）
txm_transfer_region(manifest_addr, len)
txm_kernel_call(LoadTrustCache, type, payload, len, manifest, len, 0, 0)
  ├─ 成功且 TXM 自己另分配 → 归还 payload 供 XNU 回收
  └─ 重复 → kTCReturnDuplicate
```

注意 **`txm_transfer_region`**：这不是拷贝，是**把 XNU 的页交给 TXM 并改帧类型**。移交之后 XNU 侧的地址（若有残留映射）不再可写。这是"数据面写入无效"的机制根源。

### 2.2 为什么「有 r/w」也不够

注入一个 TC 条目，TXM 需要的是：**一个通过 Image4 评估的 payload + manifest**。
【V-D】TXM 里对应的字符串是 `Image4: manifest evaluation: insufficient space for manifest hash`、`Image4: payload evaluation: insufficient space for payload hash`、`Image4: manifest evaluation: 'vnum' mismatch: build tuple %u` —— 完整的 img4 评估器在 TXM 内。

所以三条路线，只有第三条有讨论价值：

| 路线 | 需要什么 | 判定 |
|---|---|---|
| **T1 伪造 img4** | Apple 的 TC 签名私钥（personalization/manifest 签名） | 不可行【推断·强】 |
| **T2 打 TXM 的 Image4/TC 解析** | TXM 内的内存破坏或逻辑缺陷（当前无任何候选） | 未探索，长期项 |
| **T3 复用已存在的合法 TC** | 设备上已有的、由 Apple 签名的 TC（static boot TC / cryptex1 TC） | 只能"用"，不能"加" |

顺带否证一条常被误提的路线：**legacy trust cache module**（`load_legacy_trust_cache`）在 SPTM 平台上是 `panic("legacy trust caches are not supported on this platform")`（【V-S】`txm.c:251`，【V-D】字符串在设备内核中存在）。

### 2.3 `isProductionFused: true` 的具体影响

| 影响面 | 机制 | 证据 |
|---|---|---|
| TXM 是 **release** 构建 | 镜像标签 `txm.iphoneos.release.TrustedExecutionMonitor_Guarded-217.0.2` | 【V-D】 |
| research / extended-research 均为假 | `research_mode_enabled = txm_ro_data->buildType.research`（`kTXMKernelAPIVersion >= 11`）；`research configuration: %u` / `extended research configuration: %u` / `denying security-research-device configuration: %u \| %u` | 【V-S】`txm.c:626` + 【V-D】 |
| **工程/ERM TC 拒绝** | `disallowed loading ERM trust cache on the system`；`/chosen` 需 `research-enabled`、`sec-research-device-erm-enabled` | 【V-D】 |
| 开发者模式受 TXM 控制 | `developer mode enabled due to PCC research build` / `disabled due to PCC release build`；`txm_toggle_developer_mode` 是 TXM 调用且 `failure_fatal = true` | 【V-D】+【V-S】`txm.c:710` |
| 个性化（boot）限制 | 生产熔丝 ⇒ 只能装 Apple 个性化过的 iBoot/kernelcache，**research 变体无法启动** | 【推断·强】 |

### 2.4 CT / RR 与 `csm`/`amfi` 的 SHA 校验

- **CTRR / KTRR**（Code/Region Text Read-only）是**硬件**在 EL2/EL3 侧对内核代码段的保护。【V-D】SPTM 串里 `SPTM_XNU_CODE`、`xnu_ctrr_dispatch_table`、`Exceeded available number of xnu CTRR-protected frames` —— CTRR 帧由 SPTM 记账。**改内核代码段（patch 指令）不是"很难"，是没有写权限**。
- 反过来说：**本文全部路线都不需要改内核代码段**。这一点与 `CHAIN-DESIGN.md` §4.2 的判断一致，本轮补充的是机制级证据。
- `csm`/`amfi` 的 SHA：在 SPTM 构建下不存在"内核里存一份签名数据、定期自校验"的结构（`amfi` 是 vtable，`csm` 是 TXM 调用）。因此**没有可打的 SHA 自检**；相应地，也没有"改完数据骗过自检"的窗口。

---

## 3. Q3：PPL / SPTM 到底挡哪一步

### 3.1 先纠正层次：不要用 PPL 时代的结论套 SPTM

| 项 | PPL 时代（A12–A15） | **本设备（A19 / V54AP / SPTM）** |
|---|---|---|
| 监视器位置 | PPL 在 **EL1**，靠 APRR/权限域隔离，与 XNU 同特权级不同域 | SPTM 在 **EL2**，独立异常级 + 独立执行态 |
| 页表 | PPL 保护，XNU 仍持有/构造 PTE，PPL 检查 | **SPTM 独占**，XNU 只有 UAT 对象句柄，无 PTE 写路径 |
| CS 强制 | `pmap_cs` 在 PPL 里跑 | **`osfmk/arm64/sptm/pmap/pmap_cs.c` 只有 33 行占位**："Eventually all PPL code relating to code signing will be placed into this file." → 实际强制在 TXM |
| 保护单位 | 页表页 + PPL 代码/数据 | **物理帧类型（frame type）**，全系统统一 |

【V-S】`osfmk/arm64/sptm/pmap/pmap_ppl_interface.c` 里大量 `panic("%s: unsupported on non-PPL systems")` —— SPTM 构建下 PPL 入口是空壳。
【V-D】但设备内核仍有 `UAT_PPL_IOCTL_*` 字符串（`IOUAT: PPL map operation failed ...`）—— **名字是 PPL，实体是 SPTM**。看字符串判断"有没有 PPL"会误判，这是本轮的命名陷阱之一。

### 3.2 受保护（r/w 打不到）

| 对象 | 保护者 | 证据 |
|---|---|---|
| 页表页 / UAT 对象 / 根表 | SPTM（`XNU_PAGE_TABLE*`、`XNU_USER_ROOT_TABLE` 帧；`VIOLATION_UAT_ILLEGAL_TTE`、`ILLEGAL_PAGE_TABLE`、`ILLEGAL_MAP_FOUND_OCCUPIED_PTE`） | 【V-D】 |
| 信任缓存条目 | SPTM 帧类型 `TXM_SLAB_TRUST_CACHE` | 【V-D】 |
| TXM 的 RO/RW/堆/线程栈 | 帧类型 `TXM_RO / TXM_RW / TXM_MALLOC_PAGE / TXM_THREAD_STACK`，只在 `EXEC_MODE_TXM_DEFAULT` 可达 | 【V-D】 |
| 已注册的签名数据（`csb_mem_kaddr` 指向的那块） | `txm_transfer_region` 移交后归 TXM | 【V-S】`txm.c:434` |
| 内核代码段 | CTRR/SPTM（`VIOLATION_*` + `SPTM_XNU_CODE` 帧） | 【V-D】 |
| 内核 RO 段（`SECURITY_READ_ONLY_LATE` 全部变量） | RO zone + SPTM（`XNU_RO`/`XNU_ROZONE` 帧） | 【V-S】+【V-D】 |
| `csb_entitlements`、`csb_csm_obj`、`ui_cs_blobs` | **PAC**（地址多样性 + 字符串鉴别器），r/w 无法重签 | 【V-S】 |

### 3.3 不受保护（r/w 可改，且有意义）

| 对象 | 位置 | 能换来什么 |
|---|---|---|
| `ucred.cr_uid/cr_groups/cr_label` | XNU zone（普通） | root、去 sandbox label |
| `proc_ro->p_csflags` | XNU | `CS_PLATFORM_BINARY`(0x04000000)、`CS_GET_TASK_ALLOW`、`CS_DEBUGGED` 等**策略位** |
| `cs_blob` 的非 PAC 字段 | XNU zone | `csb_flags`、`csb_signer_type`、`csb_platform_binary`、`csb_csm_trust_level` |
| `vm_page->vmp_cs_validated / vmp_cs_tainted / vmp_cs_nx` | XNU | 让页面"看起来已验证"（效果见 §3.5） |
| `struct pmap` 自身的**普通字段** | XNU zone | 有限（见 §3.5 否证 1） |
| `amac`/MACF 标签、`task` 端口表 | XNU | 沙箱逃逸、给别的进程发 task 端口 |

### 3.4 会触发保护的操作（黑名单，别试）

- 对 `XNU_USER_EXEC` / `XNU_USER_JIT` 帧请求可写映射 → 触发重定类型并**断开所有既有映射**（`osfmk/arm64/sptm/pmap/pmap.c:5497-5511` 注释明确写了这一点：会 retype 回 `XNU_DEFAULT`，之后执行会重新 fault 并重新走 CS）
- 对 TXM 拥有的页做任何写 → `VIOLATION_FRAME_TYPE` / `VIOLATION_FRAME_PROTECTED` / `VIOLATION_FRAME_OWNER`
- 用别人的 ASID/句柄调 UAT 操作 → `VIOLATION_UAT_INVALID_CONTEXT_ID` / `ILLEGAL_ACTIVE_CTX_ID` / `ILLEGAL_SET_CTX_ID`（【推断·强】：SPTM 按核上活跃 context 校验，这挡住了"改 pmap 的 asid 去打别的进程页表"）
- 二次设置 pmap 的 TXM 信任等级 → `panic("attempted to overwrite TXM trust on the pmap")`（【V-D】设备内核有此串）
- **内核 panic 之后**再请求可执行映射 → TXM 直接拒绝：【V-D】`denying executable mapping as the kernel has panicked`。**这条对实验节奏影响很大：一次 panic 之后，本轮的"执行新代码"实验全部失效，必须重启。**
- REM（Restricted Execution Mode）启用后：TC 载入永久拒绝（【V-S】§2.1）

### 3.5 我否证的两条"看起来最像出路"的路线

#### 否证 1：改 `pmap->txm_trust_level` 提高信任等级 —— **无效**

【V-S】`osfmk/arm64/sptm/pmap/pmap.c`：`txm_trust_level` 只有 4 处引用 —— 初始化（2530）、写入（11580）、**KDP 读取（11595）**。全工程再无第二个消费者：

```bash
grep -rn "txm_trust_level" --include=*.c --include=*.h fw/xnu | grep -v BUILD
# txm.c:1492/1494/1500（txm_get_trust_level_kdp）、pmap.h:1027、pmap.c:2530/11575/11580/11595
```

即它是**给内核调试器看的诊断字段，不参与任何策略判断**。改它只会让 KDP 报告失真，不会让任何页变可执行。
（这条很值得记：它长得完全像"信任等级开关"，是典型的诱饵。）

#### 否证 2：改 `cs_blob` 的哈希槽让页哈希通过 —— **改不到**

【V-S】`ubc_subr.c:4286-4315`：`csm_register_code_signature()` 成功后，若 TXM 返回的地址与 `csb_mem_kaddr` 不同，XNU **释放自己那份**并对 TXM 的地址 `ubc_cs_blob_reconstruct()`，置 `csb_csm_managed = true`。而 `txm.c:1000` 在签名大于 `txm_managed_code_signature_size()` 时**先把页 `txm_transfer_region()` 给 TXM**。

两种情形都指向同一结论：**注册之后，XNU 读哈希槽的那块内存不归 XNU 写**。
（`csb_cd` / `csb_hashtype` 指针本身可以改，但改指针属于"另造一份 CD"，见下的残余空间。）

#### 残余空间（**唯一还开着的技术口子**）

`cs_validate_page()` 读的是 `csb_cd` / `csb_hashtype` **两个普通指针**。若能用 r/w 把 `csb_cd` 指向我们在**内核可写内存**里自造的 CodeDirectory（哈希槽填成我们想要的页内容的哈希），XNU 的页面校验就会通过。

但即使成功，收益上限是：
- 只能在**该 pmap 已被 TXM 关联的 VA 区间**内执行（关联按 `(pmap, addr, size)` 建立，见 `txm_associate_code_signature`）；
- 关联来自"这个进程 exec 的那个合法签名的二进制"，也就是**我们自己的 dev-signed app**。
- **结论：能得到的是"我们已经有的东西"（自己 app 里跑自己的代码），拿不到"跑一个未签名的、带平台 entitlement 的新二进制"。**

这就是阶段③的核心矛盾，写进结论。

---

## 4. Q4：不依赖内核 r/w 能做什么

按"能否独立产生价值"排序。全部不触碰设备（本文件不做设备验证）。

### 4.1 dev-signed helper：合法能力上限

已有 44 entitlement（`CHAIN-DESIGN.md` §1.2），其中有价值的：

| entitlement | 能做什么 | 边界 |
|---|---|---|
| `com.apple.developer.networking.networkextension`（8 项含 `packet-tunnel-provider` / `app-proxy-provider`） | 建 utun，注入/读取 IP 报文；做 DNS 代理、内容过滤 | 只能碰**自己进程的网络栈视图**，不能直接碰内核结构；已实测 IPv6 栈函数 dChk ≤ 0（`CHAIN-DESIGN.md` §3.2） |
| `com.apple.developer.networking.multipath` | 多路径 socket | 无内核面 |
| `com.apple.developer.kernel.extended-virtual-addressing` | 更大 VA | 只影响本进程 |
| `com.apple.developer.kernel.increased-memory-limit` / `increased-debugging-memory-limit` | 更大内存配额 | 只影响本进程 |
| `com.apple.developer.system-extension.install` | 装 System Extension（DriverKit/DEXT） | **iOS 上系统扩展不可用**；此 entitlement 在 iOS 侧无对应安装面【推断·强】 |
| `com.apple.developer.networking.HotspotConfiguration` | 配 Wi-Fi 热点 | 用户交互门控 |

**结论（口径要收）**：`CHAIN-DESIGN.md` §1.2 只列了 44 项里的 12 项，**剩下 32 项本工程没有留存 dump**（当时的 `/tmp/ents.plist` 已不在），因此不能说"44 项全无 CS 相关项"。可确认的是：与 CS 绕过直接相关的三项 —— `dynamic-codesigning`、`com.apple.private.cs.debugger`、`com.apple.private.pmap.load-trust-cache` —— **不在已列出的 12 项中**，而它们恰好是 §4.3 / §2.1 被判死的那三项。【待办：重取一次完整 entitlement dump，见 §7.2 动作 0】

### 4.2 描述文件 / MDM / 监督模式

| 路径 | 需要 | 现实性 |
|---|---|---|
| 安装配置描述文件（Web 描述文件） | 用户点击 + 设置里"已下载描述文件" | 只能改 VPN/Wi-Fi/证书/Web Clip，**不授予代码执行** |
| MDM 注册 | 用户/组织；监督模式需 Apple Configurator 或 ABM | 监督设备可**强制装 app、装 root CA、配 per-app VPN**；不能关 SIP/CS |
| 开发者模式（Developer Mode） | 设置里手动开启（TXM 记录状态） | 只放宽**调试**相关映射，不放宽 CS；见 4.3 |

**判定**：描述文件路径能给"长期存在的容器/网络钩子"，给不了代码执行。作为**投放与保活**手段有价值，作为 S5 替代品没有。

### 4.3 debugserver / 开发者模式：门控在 TXM，不在 XNU

【V-S】`developer_mode_enabled` 指向 **TXM 的 RW 数据**（`txm.c:585` `developer_mode_enabled = (bool*)txm_call.return_words[1]`），切换走 `kTXMKernelSelectorDeveloperModeToggle` 且 `failure_fatal = true`。
【V-D】TXM 里的判定串：`disallowed executable debug mapping`、`disallowed writable debug mapping due to developer mode`、`disallowed writable debug mapping due to address space`、`com.apple.private.cs.debugger`、`disallowed non-debugger initiated debug mapping`。

含义：
- **"debug 映射（可写可执行）"是存在的机制**，但每个映射请求都由 TXM 检查三件事：地址空间是否被标记 debugged、是否开发者模式、是否有 `com.apple.private.cs.debugger`。
- 我们的 app `get-task-allow = false`，也不持 `cs.debugger` ⇒ 连第一步都不满足。
- 想用 r/w 伪造 `CS_DEBUGGED` csflag：XNU 侧会去问 TXM（`txm_address_space_debugged`），entitlement 判定在 TXM 内 ⇒ **伪造无效**【推断·强】。

### 4.4 Network Extension 的权限边界（已实测，可复用）

- 我们可建 `NEPacketTunnelProvider` → `utun` → 内核 IP 栈，但**只在自己 app 的进程上下文**；
- `nesessionmanager` 是持有 `com.apple.private.network-extension` 的守护进程，**我们的 provider 是它的 XPC 客户端**；
- 这条通道的真价值：① 给内核网络栈喂**任意本地构造的报文**（探针/模糊测试输入）；② 观察哪些内核函数被打到（可达性地图）。**它不是 S5 的入口**。

### 4.5 用户态签名面（不需要内核 r/w 就能研究）

| 目标 | 为什么值得看 | 现在能做的离线动作 |
|---|---|---|
| `amfid` | 收到内核/taskgated 的 cdhash 校验请求；`com.apple.amfid` 服务 | 从系统卷取二进制，找它调 TXM/CS 的路径；看它是否仍是"用户态决策" |
| `trustd` | 证书/描述文件信任评估（`fw/deps/Security/trust/trustd/` 有源码） | 源码级审计，找"信任一个自定义根"的合法路径 |
| `installd` / `mobile_installation_proxy` | 装 app / 装描述文件 | 我们已用它装 app（`DEVICE-SURFACE.md`） |
| `libmis` / `CoreTrust` | 用户态签名校验（`fw/deps/libsecurity_codesigning`、`EXTERNAL_HEADERS/CoreTrust`） | 源码在手，可查"用户态有没有独立的信任判定" |

**这一组是本阶段最值得投入的离线方向**：如果用户态（amfid/trustd）仍有一条"决定谁可信"的分支，那么拿到其中任一进程的执行权就不必碰 TXM。

---

## 5. Q5：持久化

### 5.1 `isProductionFused` 上哪些持久化点存在

| 点 | 存在性 | 说明 |
|---|---|---|
| 引导链（iBoot/LLB/kernelcache 补丁） | **不存在** | 生产熔丝 + 个性化签名；这是 `CHAIN-TO-POC.md` §S9 判死的原因【推断·强】 |
| `/var/jb` bootstrap | 存在但需 root+可执行文件 | `/var` 可写；`launchctl bootstrap` 需要 root 与 launchd 的 XPC 授权 |
| LaunchDaemon（`/Library/LaunchDaemons`） | **不可写**（SSV 封印） | 需先关 SSV/改 rootfs，属 S4 之后 |
| 已安装的 dev app 自身 | **存在**（当前就有） | 描述文件有效期内 app 一直在；重启后用户点开即重放 → **semi-tethered 的现实形态** |
| 描述文件常驻 | 存在 | 可用于分发/保活 payload 载体（Web Clip、VPN 配置） |
| 系统扩展 / DEXT | iOS 无面 | 见 4.1 |
| NVRAM / boot-args | 需 `com.apple.private.iokit.nvram-write` + 生产熔丝下受限 | 不作为路线 |
| SEP/钥匙串持久化 | 不适用 | — |

### 5.2 工程结论

- **short term（现实的）**：semi-tethered。链 = dev app 重放 → S2 → 数据面提权 → 起用户态服务。app 与描述文件是唯一稳定的落脚点。
- **跨重启存活**：只有"入口 app 仍在 + 用户点一下"这一种；竞品（`INTEL.md` §7 记录的 Calif）做到的机制仍未知，**不要假设它做不到，但本文没有可复现机制**。
- **落地形态建议**：把"重放链"做成**一次点击、无交互、可幂等重试**；把状态放在 app 容器（`/var/mobile/Containers/Data/Application/…`，跨重启保留），重启后自动续。

---

## 6. Q6：风险排序、可回退性、变砖

按"最可能失败 → 代价"排序：

| # | 失败点 | 概率 | 失败后状态 | 可回退？ | 变砖？ |
|---|---|---|---|---|---|
| 1 | **r/w 无法升级为"调用能力"**（无 PAC 签名、无可控函数指针） | 很高 | 停在纯数据面 | 是（重启即清） | 否 |
| 2 | **TC 注入需要 Apple 签名** | 确定（不是概率） | 路线作废 | — | 否 |
| 3 | 改 `cs_blob`/`proc_ro` 触发一致性 panic | 高 | 内核 panic，**TXM 进入"拒绝新的可执行映射"状态**直到重启 | 重启 | 否 |
| 4 | 伪造 `csb_cd` 后页校验通过但关联区间不对 | 中 | 进程被 `cs_invalid_page` 杀掉 | 重启进程 | 否 |
| 5 | TXM 参数校验 panic（`invalid number of arguments to TXM`、`received excessive return words`） | 中 | panic | 重启 | 否 |
| 6 | 误写 TXM 拥有页 → `VIOLATION_FRAME_*` | 中 | SPTM 直接 panic（不是返回错误） | 重启 | 否 |
| 7 | 引导链尝试 | — | **变砖**（生产熔丝 + 个性化，刷回需 DFU+ipsw） | 需恢复模式 | **是** |

**风险铁律**：
1. 本阶段任何实验都**不要**碰 boot chain / iBoot / NVRAM 写入 —— 这是唯一能变砖的类别。
2. 每次实验前确认"上一轮没有 panic"：**panic 之后 TXM 拒绝新的可执行映射**（`denying executable mapping as the kernel has panicked`），此时任何"执行新代码"的观测都是假的。这条能直接制造假阴，与 `STATUS.md` §D 的教训同类。
3. 不要在同一个 panic 之后的状态里连续判读两次结论。

---

## 7. 结论与下一步

### 7.1 结论

**以当前掌握的信息，阶段③的可行性判断是：在「只有内核 r/w、没有内核代码执行与 PAC 签名」的前提下，S5（代码签名绕过）不可行；TC 注入在 `isProductionFused` 设备上被 TXM 的 Image4 与 SPTM 的 `TXM_SLAB_TRUST_CACHE` 帧类型双重封死；阶段③的现实形态只能是「数据面语义伪造（root/去沙箱/CS_PLATFORM_BINARY）+ 复用已签名二进制」，而不是「让未签名代码跑起来」。**

三条支撑：
1. 校验主体已迁入 TXM，XNU 只剩调用与页面哈希；`txm_kernel_call` 的 40 个 selector 里没有一个能让 r/w 变出"信任"（全部是 register/associate/query/toggle 类请求，入参校验都在 TXM 内）。
2. TC 的物理页类型 `TXM_SLAB_TRUST_CACHE` 使其在硬件层面对 XNU 不可写；`load_trust_cache_with_type()` 还叠了 entitlement + REM + 类型白名单三道门。
3. 页面哈希这条路虽然留在 XNU，但其收益被"TXM 只关联已签名二进制的区间"封顶为"跑自己的代码"。

### 7.2 可立即执行的离线动作（0 设备迭代）

| 序 | 动作 | 产出 | 成本 |
|---|---|---|---|
| 0 | **重取完整 entitlement dump**（44 项全量；当时的 `/tmp/ents.plist` 已丢），核对是否含 `dynamic-codesigning` / `com.apple.private.cs.debugger` / `com.apple.private.pmap.load-trust-cache` / `com.apple.private.security.*` | 把 §4.1 的口径从"12 项"补成"44 项定论" | 1 次设备只读操作 |
| 1 | **算 `cs_blob` 实际偏移**：`cs_blob zone` 串 → 找 zone 创建点 → 取元素大小；再反汇编 `ubc_get_cs_blobs` / `csblob_lookup` 的取字段指令，把 `csb_flags`/`csb_csm_trust_level`/`csb_platform_binary` 的偏移钉死 | 一张"可写字段 → 偏移"表（避免硬编码） | 0.5 天 |
| 2 | **枚举 XNU 侧仍读 `cs_flags` 的门**：`grep -rn "CS_PLATFORM_BINARY\|CS_GET_TASK_ALLOW\|CS_DEBUGGED\|CS_HARD" fw/xnu/bsd fw/xnu/osfmk`，逐条判"伪造该位能否换来新能力" | 数据面收益清单（决定阶段③是否值得继续） | 1 天 |
| 3 | **amfid / trustd 用户态审计**：查它们是否仍是"信任决策者"，尤其 `com.apple.amfid` 的 XPC 协议 | 一条不碰 TXM 的潜在路径 | 2–3 天 |
| 4 | **TXM double-fetch 审计**（承接 `METHOD-CALIBRATION.md` §5.3）：重点 `AccelerateEntitlements`（`txm.c:1610`，入参 `sig_obj`，返回 `CEQueryContext_t`）——若 TXM 在校验后二次读 XNU 内存，就是 r/w ⇒ 提权的桥 | 长期最高价值项 | 3–5 天 |
| 5 | **SPTM/TXM 27.0.1 ↔ 27.2 差分**（用现成 `kdiff`）：`sptm.t8150` / `txm.iphoneos` 两个镜像 | 找"27.2 修了什么"，反推 27.0.1 的可打点 | 1 天 |

> 动作 4 是我认为**唯一能在"只有 r/w"前提下真正突破 S5 的方向**：`txm_accelerate_entitlements` 把 TXM 侧的 `CEQueryContext_t` 交回 XNU 使用，指针存在 `cs_blob` 相关的内核结构里；如果这个上下文在 TXM 校验之后仍被 XNU 侧改动影响，或被 XNU 侧替换成另一个进程的上下文，就能直接拿到他人 entitlement。这条需要逐条读 TXM 反汇编确认，属于纯离线工作。

### 7.3 与工程既有结论的差异（避免混淆）

| 文档 | 旧表述 | 本文 |
|---|---|---|
| `CHAIN-DESIGN.md` §4.3 | 「AMFI 数据面开关：改 `cs_enforcement_disable` 一类内存标志」【推断】 | **作废**：SPTM 构建下 `code_signing_enabled` 是 `SECURITY_READ_ONLY_LATE` 且值来自 TXM RO 数据（`txm.c:585-600`），enforcement 在 TXM。改它不改变任何执行许可 |
| `CHAIN-DESIGN.md` §4.2 | 「内核数据段写：… AMFI 的内存态开关」 | 收窄为 §3.3 的清单；AMFI 的内存态**不在** XNU 数据段 |
| `METHOD-CALIBRATION.md` §5.2 | trustcache 操作面字符串清单 | 保留，补上：这些字符串说明"操作面在 TXM"，而不是"可以在内核里操作" |
| 工程内 "AMFI（内核扩展）" 表述 | AMFI 是 kext | SPTM 设备上 AMFI 实体在 TXM，内核只剩 vtable 消费端 |

---

## 8. 本文件的自证与未验证项

**已验证**：§0.2 的全部设备镜像串；§1.2/§1.5/§2.1/§3.5 的源码行号；§3.1 的 PPL 空壳与 SPTM 帧类型表。

**未验证（列出，避免被当成事实）**：
1. `xnu` 源码是 **12377.1.9**，设备是 **13432.2.10**。所有 `txm.c` 行号与 selector 名按 12377 给出；设备内核的 TXM panic 串带 `@%s:%d` 后缀，说明 **13432 的 txm.c 更新过**。结论层面我判断不受影响（结构性），但**逐行引用需以设备二进制为准**。
2. `TCTypeConfig[]` 的具体条目与 `entitlementValue` 字符串未取到（`TrustCache/API.h` 是本地重建桩，枚举值全 0）。只确认了 entitlement **名**与"每类型一个值"这一机制。
3. ~~没有提取 `AppleMobileFileIntegrity.kext`~~ → **§9 已提取**：`out/amfi.27.0.1.macho`（`com.apple.driver.AppleMobileFileIntegrity`，55,760 B）。据此确认 AMFI 是 EL1 kext，"校验核心在 TXM、数据实现 kext 里"这一半修正见 §9.0。
4. SPTM "按 context-id 绑定 ASID" 属【推断·强】（依据 violation 名：`ILLEGAL_ACTIVE_CTX_ID` / `ILLEGAL_SET_CTX_ID` / `INVALID_CONTEXT_ID`），未读反汇编确认。
5. `EXEC_MODE_*` 与帧类型的允许矩阵未还原（只知两者存在且 SPTM 按执行态限制）。
6. `panic 后拒绝可执行映射`的范围（是否只影响新进程/新映射）未确认，只知该判定在 TXM 内。
7. 全部结论**未经真机验证**（本任务禁止调用设备）。

---

## 附录 A：动作 0 已执行——entitlement 复核结果（主代理，2026-11-01 10:10）

子代理称 `/tmp/ents.plist` 已不存在，**实际仍在**（4170 B，2026-10-30 22:49）。
已复制到 `out/ents.plist` 作为持久副本。

### 总项数：44（与 `STATUS.md` 记录一致）

### 子代理要求核对的三项

| entitlement | 结果 |
|---|---|
| `dynamic-codesigning` | **无** |
| `com.apple.private.cs.debugger` | **无** |
| `com.apple.private.pmap.load-trust-cache` | **无** |

**→ 不存在任何代码签名特权捷径。S5 无法从 entitlement 侧绕过。**

### 与内核/调试相关的实际持有项（共 4 项）

```
com.apple.developer.kernel.extended-virtual-addressing   = true
com.apple.developer.kernel.increased-debugging-memory-limit = true
com.apple.developer.kernel.increased-memory-limit        = true
com.apple.developer.system-extension.install             = true
```

前三项只影响地址空间与内存配额上限，**不提供任何签名或内核写能力**。
第四项允许安装系统扩展，但系统扩展仍需 Apple 签名的 provisioning。

### 与网络相关的实际持有项（供 S4 方向参考）

```
com.apple.developer.networking.networkextension = Array (8 项)
com.apple.developer.networking.vpn.api
com.apple.developer.networking.multipath
com.apple.developer.networking.wifi-info
com.apple.developer.networking.HotspotConfiguration
```

### 复核结论
B 方向文档 §3「不依赖内核 r/w 能做什么」的假设**成立**：
我们手上没有任何能降低 S5 难度的 entitlement，
唯一的特权面是 NetworkExtension（面向 S4 的内核网络栈可达性，不是签名）。

---

# §9 double-fetch 深挖（第二轮：设备镜像反汇编）

> 本节全部证据来自 `out/txm.27.0.1.macho`、`out/amfi.27.0.1.macho` 的反汇编，以及 `out/kern.27.0.1.macho` 的字符串。
> **反汇编 VA 约定**（父代理提示的 `0xfffffe00` 前缀只适用于内核段）：
> - TXM 镜像基址 `0xfffffff017004000`（`__TEXT`），代码在 `__TEXT_EXEC` `0xfffffff017030000`
> - AMFI kext `__TEXT` `0xfffffe0007659fc0`、`__TEXT_EXEC` `0xfffffe00092241e0`（与内核同 `0xfffffe00` 前缀，但**是不同镜像**）
> - 用 `0xfffffe00` 去减 TXM 地址会得到负偏移；用 TXM 前缀去减内核地址同理。本节所有偏移均已按各自镜像基址核算。

## 9.0 先纠正我自己上一轮的一半结论（重要）

上一轮我写"AMFI 实体在 TXM，内核只剩 vtable 消费端"。**这半句是错的**，本轮已修正 §1.3。

我在 `out/kernelcache.27.0.1`（75 MB 已解压 fileset，301 个 kext）里找到了：

```
com.apple.driver.AppleMobileFileIntegrity   55,760 B
com.apple.kext.CoreTrust                    37,968 B
com.apple.security.AppleImage4              88,240 B
com.apple.security.sandbox               2,064,272 B
```

用 `tools/kext_extract.py` 提取后（`out/amfi.27.0.1.macho`，737 KB，需按段重算 section offset 才能反汇编，见 §9.8），AMFI kext 里的字符串直接说明**entitlement 引擎在 EL1**：

```
OSEntitlements.cpp
amfi.OSEntitlements
getOSEntitlementsFromProcSecure
copyOSEntitlements
CEValidateWithOptions
CEBuildIndexForContext
CEIndexSizeForContext
CESerializeXML
der_vm_bool_from_context / der_vm_data_from_context / der_vm_execute_match_bool …
"AMFI: attempted to reinitialize OSEntitlementsReadOnly ceCtx: %p" @%s:%d
"AMFI: attempted to reinitialize OSEntitlementsReadOnly data: %p" @%s:%d
"AMFI: attempted to reinitialize OSEntitlementsReadOnly identity: %p" @%s:%d
"AMFI: attempted to free OSEntitlements without invalidation" @%s:%d
"AMFI: failed OSEntitlements back-reference: %p | %p" @%s:%d
"AMFI: unexpected OSEntitlements adjustment with monitor" @%s:%d
"Not eligible for acceleration" / "runtime doesn't support acceleration"
```

**【设备镜像已证实】** 修正后的架构是：

| 环节 | 位置 | 依据 |
|---|---|---|
| CDhash / CMS / 证书链 / 信任缓存 | **TXM**（EL2 监视器） | `CTAmfiVerifyCMS` 等只在 TXM 镜像里 |
| entitlements 解析、匹配、脚本求值 | **AMFI kext（EL1）** | `der_vm_*`、`CEValidateWithOptions` 在 kext 里 |
| 签名对象（`sig_obj`）、CE 上下文的生产 | **TXM** | §9.1 |

**这就是本节的立足点**：如果 CE 上下文的生产在 TXM、而消费在 EL1 的 kext，那么"TXM 校验 → XNU/kext 使用"之间就存在跨特权级的**指针交接**，这正是 double-fetch 类问题生长的土壤。

## 9.1 Q1：`txm_accelerate_entitlements` 在设备镜像里的实现

### 9.1.1 定位方法（可复现）

```bash
# 1) 提取 TXM 的字符串及其 VA（按 __TEXT/__DATA_CONST 段映射）
python3 /tmp/txm_xref.py "entitle"     # → 0xfffffff0170053a4  "%s: entitlements not marked as accelerated"
# 2) 扫 adrp+add 对，反查 xref
python3 /tmp/xref2.py "accelerat|entitlements not marked"
#   → @0xfffffff0170354c8 ，函数头 0xfffffff017035164
```

三条 entitlement 相关串（`unable to evaluate for acceleration` / `unable to accelerate entitlements` / `entitlements not marked as accelerated`）**全部落在同一个函数** `0xfffffff017035164`，这就是设备上的 accelerate 实现体。

### 9.1.2 逐条读（关键指令）

```asm
; ---- 函数头 0xfffffff017035164  (x0 = sig_obj, x1 = out 指针) ----
fffffff017035180  mov  x20, x1            ; x20 = 出参 (&ce_ctx)
fffffff017035184  mov  x19, x0            ; x19 = sig_obj
fffffff01703519c  bl   0xfffffff017037054 ; 取锁 / 引用
fffffff0170351a0  ldrb w8, [x19, #0x18]   ; ★ sig_obj->flags
fffffff0170351a4  tbnz w8, #0, +0x1c      ; bit0 = "entitlements 已可用"
fffffff0170351a8  mov  w21, #0x26         ; 未标记 → 返回 0x26 (=38)
...
fffffff0170351c0  add  x0, x19, #0x28     ; sig_obj->entitlements 子对象
fffffff0170351d0  bl   0xfffffff017048344 ; 取 DER / 校验态
fffffff0170351d4  ldp  x0, x1, [x29, #-0x40]
fffffff0170351dc  bl   0xfffffff0170459fc
fffffff0170351e0  add  x0, x19, #0x28
fffffff0170351e4  add  x1, sp, #0x48      ; ★ 出参槽
fffffff0170351e8  bl   0xfffffff0170485e8 ; ← 生成 CEQueryContext
fffffff0170351ec  ubfx w9, w0, #8, #8     ; 返回码分级
...
fffffff01703529c  ldr  x8, [sp, #0x48]
fffffff0170352a0  cbz  x8, +0x8
fffffff0170352a4  str  x8, [x20]          ; ★★ 写回调用者的 ce_ctx
fffffff0170352c4  orr  x0, x22, x8        ; 拼返回码
fffffff0170352dc  retab
```

生成器 `0xfffffff0170485e8`（`CEQueryContext` 的来源）：

```asm
fffffff0170485e8  bti  c
fffffff0170485ec  ldrb w8, [x0, #0x29]    ; ★ 另一个"加速位"（对象 +0x51）
fffffff0170485f0  tbnz w8, #0, +0xc
fffffff0170485f4  mov  w0, #0x1040f       ; 未就绪 → 错误
fffffff0170485f8  ret
fffffff017048600  ...
fffffff017048618  bl   0xfffffff0170469dc
fffffff01704861c  str  x0, [x19]          ; 出参 = 下面这个函数的返回值
fffffff017048620  mov  w0, #0xf           ; =15 (CEQueryContextSuccess)
fffffff017048630  ret

; ★★ 决定性的一条：0xfffffff0170469dc
fffffff0170469dc  bti  c
fffffff0170469e0  ldrb w8, [x0, #0x110]   ; 就绪标志
fffffff0170469e4  add  x9, x0, #0x88      ; ★★★ 上下文地址 = 对象 + 0x88
fffffff0170469e8  tst  w8, #0x1
fffffff0170469ec  csel x0, x9, xzr, ne
fffffff0170469f0  ret
```

### 9.1.3 契约层（设备侧）

```asm
; 包装层 0xfffffff01703c570（唯一调用者）
fffffff01703c570  ... 
fffffff01703c588  bl   0xfffffff01703dc28 ; 取本次 kernel-call 结构
fffffff01703c58c  mov  x19, x0
fffffff01703c594  mov  x0, x20
fffffff01703c598  bl   0xfffffff01703774c ; 从入参解析出 sig_obj
fffffff01703c59c  add  x1, sp, #0x8
fffffff01703c5a0  bl   0xfffffff017035164 ; ← §9.1.2 的 handler
fffffff01703c5a8  cmp  x8, #0x28         ; 0x28 = 成功
fffffff01703c5b8  mov  w9, #0x1          ; 返回字数 = 1
fffffff01703c5bc  ldr  x10, [sp, #0x8]
fffffff01703c5c0  stp  x9, x10, [x19, #0x18]  ; ★ return_words[0] = 那个指针
```

**【设备镜像已证实】** `AccelerateEntitlements` 的设备实现返回 **一个 64 位字**，内容是 **`sig_obj->entitlements + 0x88`** —— 即 **TXM 拥有的对象内部的地址**，不是拷贝，不是 XNU 内存。

## 9.2 Q2：值拷贝还是传指针

| 档位 | 结论 | 依据 |
|---|---|---|
| **【源码支持】** | 是**指针** | `EXTERNAL_HEADERS/CoreEntitlements/CoreEntitlements.h:13`：`typedef struct CEQueryContext* CEQueryContext_t;` —— `CEQueryContext_t` 本身就是指针类型 |
| **【源码支持】** | XNU 只是把 return word 直接 cast | `txm.c:1624`：`*ce_ctx = (CEQueryContext_t)txm_call.return_words[0];` |
| **【设备镜像已证实】** | 该指针指向 TXM 对象内部 `obj+0x88` | §9.1.2 `0xfffffff0170469dc` 的 `add x9, x0, #0x88` |
| **【设备镜像已证实】** | 只有一个返回字，没有长度/校验字段 | `stp x9(=1), x10, [x19, #0x18]` |

**double-fetch 的第一前提成立**：跨越特权边界传递的是**裸指针**，生命周期不受接收方控制。

## 9.3 Q3：XNU 侧在哪读它，有没有窗口

### 9.3.1 XNU 自己不读（这是关键，且与直觉相反）

**【源码支持】** `bsd/kern/ubc_subr.c:4382 accelerate_entitlement_queries()`：

```c
CEQueryContext_t ce_ctx = NULL;                       // 栈上局部
ret = csm_accelerate_entitlements(cs_blob->csb_csm_obj, &ce_ctx);
...
ret = amfi->OSEntitlements.adjustContextWithMonitor(
        cs_blob->csb_entitlements, ce_ctx,            // ← 立刻原样交回 AMFI
        cs_blob->csb_csm_obj, signing_id, cs_blob->csb_flags);
```

`ce_ctx` **没有**被存进任何 `cs_blob` 字段，也没有被解引用，函数返回即消失。

**【源码支持】** 调用点 `ubc_subr.c:4875` 在 `cs_blob` 构建的第 2 阶段，注释明说："This must be done only after we know that the code signature pointers within the struct cs_blob aren't going to be shifted around anymore."

**结论：XNU 侧没有"校验→再用"的窗口。** 严格意义上的 double-fetch（同一块用户/共享数据被读两次）在 XNU 这一段**不成立**。

### 9.3.2 但 AMFI 把指针存下来了 —— 窗口转移到了 EL1 堆

**【设备镜像已证实】** AMFI kext 里有 `OSEntitlementsReadOnly` 结构，其 panic 文案逐字段点名：

```
"AMFI: attempted to reinitialize OSEntitlementsReadOnly ceCtx: %p"    ← ceCtx 是持久字段
"AMFI: attempted to reinitialize OSEntitlementsReadOnly data: %p"
"AMFI: attempted to reinitialize OSEntitlementsReadOnly identity: %p"
```

三行文案证明 `OSEntitlementsReadOnly` 有 `{data, ceCtx, identity}` 三个只写一次的字段，构造函数在重复初始化时 panic。**`ceCtx` = 那个指向 TXM 内存的裸指针，被长期保存在 EL1 堆对象里。**

**【设备镜像已证实】** entitlement 的求值确实在 EL1 发生（同一个 kext 内有 `der_vm_execute_match_bool` / `CEValidateWithOptions` / `CEError` 全套）。

所以问题从"double-fetch"变成了"**长生命周期句柄替换**"：
> 攻击者拿内核 r/w，把 `OSEntitlementsReadOnly.ceCtx` 改指向自己伪造的 CE 上下文（内核堆里），下一次 `queryEntitlementBoolean("…")` 就会对伪造的 DER 求值 → 任意 entitlement 通过。

### 9.3.3 XNU 里所有"TXM 指针交给 XNU 用"的点，以及为什么只有 ceCtx 值得打

```bash
grep -n "return_words\[0\]" fw/xnu/bsd/kern/code_signing/txm.c
```

| 行 | selector | XNU 拿到什么 | XNU 的指针变量存放处 | 可被 r/w 重定向？ |
|---|---|---|---|---|
| 579 | `GetLogInfo` | 日志页（字符串） | `txm_log_page`（`SECURITY_READ_ONLY_LATE`） | 否（RO 页） |
| 607/608 | `GetCodeSigningInfo` | `txm_rw_data`、`developer_mode_enabled` | 同上，RO 页 | 否 |
| 610 | `GetCodeSigningInfo` | `txm_ro_data` | 同上 | 否 |
| 692 | `GetSecureChannelAddr` | 物理地址（不当指针用） | — | — |
| 819/872 | `Register/TrustProvisioningProfile` | 不透明 handle | 调用栈 | 否 |
| 984 | `SetupNestedAddressSpace` | 地址 | 调用栈 | 否 |
| 1040 | `RegisterCodeSignature` | `sig_obj` 句柄 | `cs_blob->csb_csm_obj`（**PAC 签名**） | 否（PAC） |
| 1096 | `RegisterCodeSignature` | `signature_addr` → XNU 经它读签名 | `cs_blob->csb_mem_kaddr`（**无 PAC**） | **是**（见 §9.6 附注） |
| 1147 | `UnregisterCodeSignature` | 待回收地址 | 调用栈 | 否 |
| 1181 | `RegisterAddressSpace` | `txm_addr_space` | `pmap->txm_addr_space` | 是，但用途受限 |
| 1556 | `AcquireSigningIdentifier` | `const char*` → 当 C 串用 | 调用栈 | 否 |
| 1605 | `ResolveKernelEntitlementsAddressSpace` | 内核 entitlement 指针 | 调用栈 | 否 |
| **1624** | **`AccelerateEntitlements`** | **`CEQueryContext_t`** | **AMFI 的 `OSEntitlementsReadOnly+0xd8`（可写堆对象，无 PAC）** | **是 —— 见 §9.6.2** |

**【推断·强】** 表中 12 项里，11 项的指针要么是 RO 页里的常量、要么是 PAC 保护的、要么是即用即弃的栈变量；**只有 `ceCtx` 是"无 PAC 的裸指针 + 长期存活 + 在堆上 + 每次 entitlement 查询都要解引用"**。它是这套设计里唯一同时满足四个条件的交接点。

补充一条反面证据（表明 XNU 对 TXM 内存只读）：`txm.c:630` `num_static_trust_caches = os_atomic_load(&txm_metrics->trustCaches.numStatic, relaxed)` —— XNU **读**由 TXM 递增的计数器，全工程没有任何一处 XNU 往 `txm_rw_data` 写。**【源码支持】**

## 9.4 Q4：触发条件（谁能走到 accelerate）

| 问题 | 结论 | 依据 |
|---|---|---|
| 是否需要特殊 entitlement？ | **不需要**。不是 entitlement 门控 | `ubc_subr.c:4875` 在 `cs_blob` 第 2 阶段无条件调用；`ubc_subr.c:4388` 只在 `CODE_SIGNING_MONITOR` 下生效 |
| 什么时候会走？ | **每个带 entitlements 的签名，在 `cs_blob` 构建时各走一次** | 同上；`csb_csm_obj == NULL` 或无 entitlement 时退回 `adjustContextWithoutMonitor` |
| 我们的 app 能否触发？ | **能**。44 项 entitlement + dev 签名 → TXM 注册签名对象 → 必然走到 | 【推断·强】：由上一行逻辑闭合；设备侧 `cmds` 检查 `sig_obj->flags` bit0 而非调用方身份 |
| TXM 侧的额外门槛 | `sig_obj->entitlements` 的 +0x51 bit0 与 +0x110 bit0 必须已置位（"已被标记可用"），否则返回 0x26 / 0x1040f | 【设备镜像已证实】§9.1.2 |

**要点**：这条路径**不看调用方是谁**，只看"签名对象是否就绪"。所以"我们的 app 能不能触发"不是问题所在；问题在于触发之后拿到的那根指针能不能被改写（§9.6）。

## 9.5 Q5：40 个 selector 全表与交接点分类

> **先纠一个计数错误（上一轮的）**：我上轮用 `grep -o "kTXMKernelSelector[A-Za-z]*"` 得到 34，并写进了 README 与 §7.1。这个正则在数字前截断，7 个 `Image4*` selector 被折叠成 1 个 `kTXMKernelSelectorImage`。正确计数：
> ```bash
> grep -o "kTXMKernelSelector[A-Za-z0-9_]*" fw/xnu/bsd/kern/code_signing/txm.c | sort -u | wc -l   # → 40
> ```
> README 与 §7.1 已同步改为 40。**结论不受影响**（多出来的 6 个都是 Image4 nonce/release-type 类，无指针交接），但"34"这个数字在项目里出现过，这里明确作废。

### 9.5.1 全表（40 项）与分类

图例：**A** = 无返回 / 只返回状态；**B** = 返回不透明句柄或地址（XNU 不解引用）；**C** = **返回 TXM 内存指针且 XNU 会读**；**D** = 判定类（返回 bool/状态）

| # | selector | 类 | 说明 |
|---|---|---|---|
| 1 | `AccelerateEntitlements` | **C** | → `OSEntitlementsReadOnly+0xd8`（本节主角，§9.6.2） |
| 2 | `AcquireSigningIdentifier` | **C** | → `const char*`（TXM 内的签名标识串），XNU 直接当 C 串用（`txm.c:1556`） |
| 3 | `AddFreeListPage` | A | 内存池维护 |
| 4 | `AllowInvalidCode` | A | 开关，无数据面 |
| 5 | `AllowJITRegion` | A | 授权 JIT 区间，判定在 TXM 内 |
| 6 | `AssociateCodeSignature` | A | 关联，无返回数据 |
| 7 | `AssociateDebugRegion` | A | 同上 |
| 8 | `AssociateJITRegion` | A | 同上 |
| 9 | `AssociateKernelEntitlements` | A | 同上 |
| 10 | `AssociateProvisioningProfile` | A | 同上 |
| 11 | `AuthorizeCompilationServiceCDHash` | D | bool |
| 12 | `AuthorizeLocalSigningCDHash` | D | bool |
| 13 | `DeveloperModeToggle` | A | 开关 |
| 14 | `DisassociateProvisioningProfile` | A | — |
| 15 | `EnableRestrictedMode` | A | 开关 |
| 16 | `EnterLockdownMode` | A | 开关 |
| 17 | `GetCodeSigningInfo` | **C** | → `txm_rw_data` / `developer_mode_enabled` / `txm_ro_data` 三个指针（§9.3.3 表 607/608/610） |
| 18 | `GetLocalSigningPublicKey` | B | 取本机签名公钥（作为数据拷贝或只读常量，XNU 不当堆指针用） |
| 19 | `GetLogInfo` | **C** | → TXM 日志页（RO 字符串页） |
| 20 | `GetSecureChannelAddr` | B | 物理地址，不当指针解引用 |
| 21 | `Image4Dispatch` | A | Image4 请求转发，参数由 XNU 给、校验在 TXM |
| 22 | `Image4GetExports` | B | 返回 Image4 导出表指针（XNU 只转发给 Image4 kext） |
| 23 | `Image4GetNonce` | B | 非数字指针（`img4_nonce_t*`），XNU 拷贝使用 |
| 24 | `Image4RollNonce` | A | — |
| 25 | `Image4SetBootNonceShadow` | A | — |
| 26 | `Image4SetNonce` | A | — |
| 27 | `Image4SetReleaseType` | A | — |
| 28 | `MatchCompilationServiceCDHash` | D | bool |
| 29 | `ReconstituteCodeSignature` | B | 重建签名，返回句柄 |
| 30 | `RegisterAddressSpace` | B | → `txm_addr_space`（存 `pmap`，用途受限） |
| 31 | `RegisterCodeSignature` | **C** | 第一个返回字 = `sig_obj`（PAC 存于 `cs_blob->csb_csm_obj`）；第二个 = 签名数据地址（→ `csb_mem_kaddr`，**无 PAC**，§9.6.3） |
| 32 | `RegisterProvisioningProfile` | B | → `profile_obj` |
| 33 | `ResolveKernelEntitlementsAddressSpace` | **C** | → 内核自身 entitlement 指针（`txm.c:1605`） |
| 34 | `SetLocalSigningPublicKey` | A | — |
| 35 | `SetupNestedAddressSpace` | B | 返回地址 |
| 36 | `TrustProvisioningProfile` | B | → `profile_addr` |
| 37 | `UnregisterAddressSpace` | A | — |
| 38 | `UnregisterCodeSignature` | B | 返回待回收地址（`txm.c:1147`） |
| 39 | `UnregisterProvisioningProfile` | A | — |
| 40 | `ValidateCodeSignature` | A | 校验，无数据面返回 |

**统计**：A 类 **21**、B 类 **10**、C 类 **6**、D 类 **3**，合计 **40**（对上表逐行计数）。分类按"XNU 是否 deref + 是否落地存活"人眼判断，三个边界项（`GetLocalSigningPublicKey` / `Image4GetExports` / `Image4GetNonce`）即使改判为 C 类，也不满足 §9.5.2 的 (ii)(iv)，结论不变。

### 9.5.2 为什么 C 类 6 个里只有 `AccelerateEntitlements` 值得打

判据四条，必须同时满足：**(i) XNU 会把指针存起来跨调用存活；(ii) 存的位置是普通内核堆（不是 `SECURITY_READ_ONLY_LATE` 页）；(iii) 存储/读取不加 PAC；(iv) 每次判定都要解引用它。**

| C 类交接点 | (i) 存活 | (ii) 堆 | (iii) 无 PAC | (iv) 高频解引用 | 可打？ |
|---|---|---|---|---|---|
| `GetLogInfo` | √ `txm_log_page` | ✗ RO 页 | — | 只读日志 | 否 |
| `GetCodeSigningInfo` | √ `txm_ro_data` 等 | ✗ RO 页 | — | √ 参与 CS 策略 | 否（RO 页写不了） |
| `AcquireSigningIdentifier` | ✗ 即用即弃 | — | — | — | 否 |
| `ResolveKernelEntitlementsAddressSpace` | ✗ 即用即弃（`csm_resolve_os_entitlements_from_proc` 内） | — | — | √ | 否（不落地） |
| `RegisterCodeSignature`（签名地址） | √ `csb_mem_kaddr` | √ 在 `cs_blob`（堆） | √ 无 PAC | √ 页校验时读 | √ 但收益封顶（§9.6.3） |
| **`AccelerateEntitlements`** | **√ 存进 `OSEntitlementsReadOnly`** | **√ 堆对象（0xf0 B）** | **√ 明文 `ldr`（§9.6.2b）** | **√ 每次 entitlement 查询** | **√ 收益最大** |

**结论**：`AccelerateEntitlements` **不是唯一**的交接点，但它是唯一**四条全中**的那个；`csb_mem_kaddr` 是第二个（§3.5 已记），收益被封在"执行自己已签名代码"。

## 9.6 判定

### 9.6.1 能否升级成**代码签名绕过**？→ **不能**

三道独立的闸，任一道都足够：

1. **TXM 不看 entitlement。** 信任缓存载入（`load_trust_cache_with_type`）在 XNU 侧确实用 `IOCurrentTaskHasStringEntitlement` 检查 —— 这一道伪造 entitlement 可以过 —— 但紧接着 `txm_load_trust_cache()` 把 img4 交给 TXM，由 TXM 的 Image4 评估器验签（`Image4: payload evaluation: insufficient space for payload hash` 等）。**【源码支持】+【设备镜像已证实】** 伪造 entitlement 只买到"排队资格"。
2. **JIT / debug 映射的判定在 TXM。** `txm_allow_jit_region()` / `txm_associate_debug_region()` 是独立 selector，TXM 内部自行解析签名与 entitlement（TXM 里就有 `com.apple.private.cs.debugger` 字面量）。**【设备镜像已证实】**
3. **代码签名校验本身**（`ValidateCodeSignature`）根本不接受来自 XNU 的 entitlement 数据。

### 9.6.2 能否升级成 **entitlement 伪造**？→ **结构上成立，且最后一处 PAC 疑点已排除**

#### (a) `ceCtx` 的确切位置与"只写一次"语义【设备镜像已证实】

`OSEntitlementsReadOnly` 用 `0xf0`（240）字节的堆对象承载，构造时按 `(offset, size)` 从栈上模板逐段拷入：

```asm
; 构造函数（片段）：分配 + 逐段拷贝
fffffe0009238804  mov  w2, #0xd0        ; ← data 字段
fffffe0009238808  mov  w4, #0x8
fffffe000923880c  bl   0xfffffe000924f9a8     ; 通用"拷入对象"helper(x0=zone,x1=obj,x2=off,x3=src,x4=len)
...
fffffe00092388c4  mov  w2, #0xd8        ; ★← ceCtx 字段
fffffe00092388c8  mov  w4, #0x8
fffffe00092388cc  bl   0xfffffe000924f9a8
```

**`ceCtx` 在对象 `+0xd8`**（8 字节），旁边是 `data`(`+0xd0`)、`identity`(`+0xe0`)；`+0x48` 起还有 `0x88` 字节的一段拷贝（高度疑似 `struct CEQueryContext` 的**按值副本**，见 (c) 的边界说明）。

"只写一次"由 panic 保护 —— 实测校验指令就在存储前一条：

```asm
fffffe000923888c  ldr  x8, [x19, #0xd8]   ; 已有值？
fffffe0009238890  cbnz x8, 0xfffffe00092388e4   ; 有 → panic "attempted to reinitialize ... ceCtx"
```

#### (b) 读取侧**没有** PAC 认证【设备镜像已证实】—— 这是决定性证据

全 kext 里对 `[obj+0xd8]` 的读取点：

```asm
; 读点 1（访问器，尾调用把它交出去）
fffffe00092246e8  ldr  x0, [x0, #0xd8]     ; ← 普通 ldr，无 autda
fffffe00092246ec  cbz  x0, +0x1c           ; NULL → 返回 0xe00002c9
...
fffffe0009224704  b    0xfffffe000923281c  ; 带着 x0 走

; 读点 2（entitlement 判定函数，"取不到 ceCtx 即拒绝"）
fffffe0009224748  ldr  x21, [x0, #0xd8]    ; ← 普通 ldr，无 autda
fffffe000922474c  cbz  x21, 0xfffffe00092247bc     ; ceCtx==NULL → w19 = 0xe00002c9 (not permitted)
fffffe0009224758  bl   0xfffffe000924f698         ; 取当前 task
fffffe000922476C  add  x2, x29, #-0x21
fffffe0009224770  bl   0xfffffe0009231f8c         ; 用字符串求值，结果写 [x29-0x21]
```

对照：AMFI 在同一镜像里对**别的**字段用了地址多样化 data-PAC（`pacda x16, x17`，x17=字段地址，鉴别器 `0x6ae1/0xe1e/0xe123/0xcda1/0x73db/0x3a87/0x8f99/0xc8a2/0x2bad/0x2e4a`，全 kext 共 **669** 条 `pacd*/autd*`）。也就是说 **"没上 PAC"不是因为整个 kext 不用 PAC，而是这一处确实没上**。

再加上 §9.0 的 `"AMFI: failed OSEntitlements back-reference: %p | %p"` 说明反引用另有 PAC 校验 —— 也就是说 Apple 在这里做了分层保护，但 `ceCtx` 本身按**明文指针**存取。

#### (c) 攻击链（据此重写，原"待定"已消除）

```
1. r/w 读 our_proc → p_ro → p_cs_blob           （只读，不伪造 PAC 指针）
2. 读 cs_blob->csb_entitlements → OSEntitlements 对象（+0x10 处的 PAC 反引用可读）
3. 定位 OSEntitlementsReadOnly 基址 → 记下 +0xd8 的 ceCtx 值 V
4. 在内核堆上布局：
     fake_ctx = 拷贝 V 指向的 0x88 字节结构（V 指向 TXM 内存，XNU 可读）
     把 fake_ctx 里的 DER 指针/长度改成指向自造的 entitlements blob
     自造 blob = 合法 DER，含 "com.apple.private.pmap.load-trust-cache" 等键
5. r/w 写 object+0xd8 = &fake_ctx          ← ★ 无 PAC，可直接写
6. 触发一次 entitlement 查询 → EL1 的 der_vm_* 对自造 DER 求值 → 通过
7. 用伪造的 entitlement 去过 XNU 侧的门（IOKit IOCurrentTaskHasStringEntitlement 等）
```

**边界与保留**：
- 第 4 步"原样拷贝 0x88 字节"是关键技巧 —— 它绕开"必须自己造一个自洽 der_vm_context"的难题（`CERuntime` 指针等都在原结构里）。**【推断·强】**
- 若 `+0x48` 那段确实是**按值副本**（构造时 `mov w2,#0x48; mov w4,#0x88` 拷贝），那么查询很可能读副本而不是 `+0xd8` 的指针 —— 此时**直接改 `+0x48` 那段副本更省事**（同样无 PAC）。两条路都不需要伪造 PAC，区别只在于改哪个偏移。**这一点是本节唯一未闭合的细节。**
- 未做真机验证（本节禁止调用设备）。

### 9.6.3 附注：另一个**已确认无 PAC** 的交接点（§9.3.3 表中 1096 行）

`cs_blob->csb_mem_kaddr` 无 PAC，XNU 经它读签名 blob（`csb_cd`、哈希槽都在里面）。这就是我在 §3.5 标为"残余空间"的那条：r/w 可以把 `csb_mem_kaddr`/`csb_cd` 指向内核里自造的 CodeDirectory，让 `cs_validate_page` 通过。
但**收益上限仍然是"跑自己已签名的代码"**（TXM 只关联已签名二进制的 VA 区间），对 S5 **无用**。§9.1.3 的设备侧契约（`RegisterCodeSignature` 只把 TXM 侧的 `sig_obj` 句柄交回、签名数据面由 TXM 自己持有）再次确认了这一点。

### 9.6.4 一句话回答任务书的判定

> **这条路径不能在「已有内核 r/w、无内核代码执行」的前提下把 r/w 升级成代码签名绕过**——TXM 在信任缓存载入、JIT 映射、调试映射三处都不消费 XNU 侧的 entitlement，伪造 entitlement 只买到"排队资格"，最终仍要过 TXM 的 Image4/签名校验（§9.6.1）。
>
> **但它**可以**把 r/w 升级成 entitlement 伪造**：`CEQueryContext_t` 是裸指针（§9.2），XNU 自己不读只转交（§9.3.1），AMFI kext 把它明文存在 `OSEntitlementsReadOnly+0xd8`（§9.6.2a），读取点用普通 `ldr`、**无 `autda`**（§9.6.2b），对象在可写的内核堆上 ⇒ r/w 可把它重定向到自造的 CE 上下文，EL1 的 `der_vm_*` 会对伪造 DER 求值。
>
> 剩余未闭合项只有一处：查询走的是 `+0xd8` 指针还是 `+0x48` 的按值副本（决定改哪个偏移，两条路都不需要伪造 PAC）。**真机未验证（本轮禁止调用设备）。**
>
> 对项目主线的净收益：**§8 的 S5 判定不变（不可行）**；新增的是一条"r/w → 平台级 entitlement"的旁路，价值在于 IOKit / task 端口面，而不在代码签名面。

## 9.7 下一步（全部离线，按性价比排序）

| # | 动作 | 判据 | 成本 |
|---|---|---|---|
| ~~1~~ | ~~判定 `ceCtx` 字段是否 PAC~~ → **本节已完成**：`ceCtx` 在 `+0xd8`，写入走通用拷贝 helper、读取点 `0x2246e8` / `0x224748` 均为**普通 `ldr`、无 `autda`** ⇒ 路径成立 | 已判定 | — |
| 2 | 交叉验证 `getOSEntitlementsFromProcSecure`：它对 `proc → cs_blob → OSEntitlements` 是否二次校验（若二次校验用 PAC 后引用，则即使改了 ceCtx 也会先失败） | 高 | 0.5 天 |
| 3 | **闭环最后细节**：确认查询读的是 `+0xd8` 的指针还是 `+0x48` 的按值副本（决定改哪个偏移）；顺带解析 `0xfffffe0009231f8c`（求值函数）与 `0xfffffe000924ec48`（对象取用）的入参 | 决定性 | 1 天 |
| 4 | 顺带：`ResolveKernelEntitlementsAddressSpace`（内核自身 entitlement）与 `AcquireSigningIdentifier` 这两个 C 类交接点做同样的 PAC 检查 | 低 | 0.5 天 |

## 9.8 本节工具链（复现用）

```bash
# 1) 解压 kernelcache（本机 27.0.1 的 payload 是 LZFSE 全 bvx2 未压缩块，但块边界需按 LZFSE 语义走；
#    工程里已有解压产物，直接用）
ls out/kernelcache.27.0.1        # 75 MB fileset，301 kext

# 2) 列 fileset / 提取 kext
python3 -c "import sys;sys.path.insert(0,'tools');import kdiff;d=kdiff.load('out/kernelcache.27.0.1');[print(n,hex(f),s) for f,s,n in kdiff.slices(d) if 'FileInt' in n]"
python3 tools/kext_extract.py out/kernelcache.27.0.1 \
        --kext com.apple.driver.AppleMobileFileIntegrity --out out/amfi.27.0.1.macho

# 3) 修复 section offset（提取器只重定位了段，section 的 offset 还是旧的；
#    否则 llvm-objdump 报 "offset field of section 0 ... extends past the end of the file"）
#    规则：new_sect_off = new_seg_fileoff + (sect_addr - seg_vmaddr)，同时丢弃 __LINKEDIT

# 4) 反汇编
OD=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump
$OD -d --no-show-raw-insn out/amfi.clean.macho > /tmp/amfi.dis   # 43,480 行

# 5) 字符串→VA→xref
python3 /tmp/amfi_tool.py "adjustment with monitor|reinitialize OSEntitlementsReadOnly"
```

**踩过的坑（写下来省下一次）**：
1. `llvm-objdump` 的行格式是 `地址:` + **空格** + `\t` + 指令；正则写成 `:\t` 会静默匹配 0 行（我第一次的 xref 扫描就是这样空转的）。
2. TXM 的 VA 前缀是 `0xfffffff0…`，内核/kext 是 `0xfffffe00…`；混用会得到负数偏移。
3. `out/txm.27.0.1.macho` 里搜 `TXM_SLAB_TRUST_CACHE` 是 0 命中 —— 那是 **SPTM** 镜像的帧类型字符串（父代理已核实，本轮再次确认）。
4. 提取出来的 kext 不能直接 `nm`/`objdump`：`__LINKEDIT` 指向共享 kextcache，必须重建最小 LC_SEGMENT_64 集合。
