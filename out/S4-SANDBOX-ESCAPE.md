# S4 —— 沙箱逃逸：从「有具体机制」推进到「每一步钉死」

## README（10 行）

1. 本文接 `STAGE3-CODESIGN-AMFI.md` §9 这条线，只处理 **S4（沙箱逃逸）**，不动 S5（判定不变：不可行）。
2. 全部结论来自 `out/amfi.clean.macho`（265,920 B，`com.apple.driver.AppleMobileFileIntegrity` EL1 kext）的 **指令级反汇编 + Ghidra 反编译**，辅以 `fw/xnu` v12377 源码。
3. **本轮推翻了上一轮的地基**：`ceCtx` 不在 `+0xd8`。`+0xd8` 是 `identity`（strdup 出来的 C 字符串）；`ceCtx` 在 **`+0xd0`**，且它指向对象体内 **`+0x48`** 的按值副本。
4. 因此「答错全盘皆错」的那一问，答案是**第三条路**：查询读的是 **`+0xd0` 的指针**，而该指针**按构造指向 `+0x48` 的 0x88 字节按值副本**。两条旧假设的偏移都错了。
5. 求值侧使用的 `ceCtx+0x08/+0x10/+0x30/+0x38` **全是裸 `ldr`/`str`，路径上没有任何 `autda`**。
6. 但**对象指针本身是 PAC 签名的**（`autda #0x8b90` + `xpacd` 自检 + `brk #0xc472`）——「重指 cred 字段」这条路死了，「改对象内容」这条路活着。
7. 所有内核侧 entitlement 门禁（`IOTaskHasEntitlement` / `IOCurrentTaskHasEntitlement`）**全部汇聚到这一个对象**，这是 S4 的兑现面。
8. 伪造 entitlement **不能**改沙箱标签（`cr_label` 是另一套、且 PAC 保护）。
9. 所以 S4 = 「伪造 entitlement 打开内核门禁」，**不等于**「解除 seatbelt 约束」；后者仍缺一步（§3.3）。
10. 前提仍是 **S2（内核 r/w）**。在没有 r/w 的情况下，本文第 5 节给出唯一残余路径，并说明它为什么不是利用路径。

证据标记：**【镜像】**= 设备镜像指令级已证实；**【源码】**= `fw/xnu` v12377 源码支持（设备为 13432，版本差已标注）；**【推断】**= 推理，未证实；**留白** = 没证据，不填。

---

## 0. 本轮更正清单（先读这一节，避免把旧结论继续往下带）

| # | 上一轮的说法 | 本轮结论 | 依据 |
|---|---|---|---|
| C1 | `ceCtx` 在 `OSEntitlementsReadOnly+0xd8` | **错**。`+0xd8` 是 `identity`（`char *`，strdup 得到）；`ceCtx` 在 **`+0xd0`** | 【镜像】构造函数 `0xfffffe0009238860` 在 `+0xd8` 上：`ldr x8,[x19,#0xd8]` + `cbnz` → panic `"…reinitialize OSEntitlementsReadOnly identity: %p"`；另一函数在 `+0xd0` 上：`ldr x8,[x19,#0xd0]` + `cbnz` → panic `"…ceCtx: %p"`。panic 串自己说明了字段名 |
| C2 | 读取点是「裸 `ldr`，无 `autda`」 | **成立，但读的是 `[obj+0xd0]`，不是 `[obj+0xd8]`** | 【镜像】`0xfffffe0009239e60: ldr x0,[x1,#0xd0]`，紧接 `bl 0xfffffe00092417f8` |
| C3 | 对象 0xf0 字节 | **成立**，且字段布局已由编译器类型编码钉死 | 【镜像】`thunk_EXT_FUN_8011000003c43dd8(DAT_…8129d58, 0xf0, payload)`；`__cstring` 里的 ObjC 类型编码（见 §1.2） |
| C4 | 「有 r/w 就能把 `+0xd8` 重定向到自造上下文」 | **方向对，落点错，且多一道硬约束**：`+0xd0` 可以改，但改 **cred 里指向该对象的那个指针**需要 DA key | 【镜像】`0xfffffe000922df5c: movk x17,#0x8b90,lsl#48` / `autda` / `xpacd` / `brk #0xc472` |

**一句话**：上一轮把 `identity` 当成了 `ceCtx`，因此「伪造 +0xd8」这条路即使做出来也只会破坏一个日志用字符串。真正的落点在 `+0xd0` / `+0x48`。

---

## 1. Q1（地基）：查询读的是 `+0xd8` 的指针，还是 `+0x48` 的按值副本？

### 1.1 结论

**两者都对，也都错——正确表述是三段式：**

```
proc → cred → [cred+0x78]  ← PAC 签名的对象指针（outer OSEntitlements）
                 ↓ outer+0x10
            payload（0xF0 字节，kalloc_type 类型隔离堆）
                 payload+0xD0  ← ★ 裸 ldr 读出的指针，按构造 == payload+0x48
                 ↓
            payload+0x48  0x88 字节的 _CEContext（按值副本）
                 ↓
            CE 求值：der base = *(ceCtx+0x08)、der len = *(ceCtx+0x10)、索引 = *(ceCtx+0x30)/*(ceCtx+0x38)
```

- 查询**确实读指针**，但读的是 **`payload+0xd0`**（【镜像】）。
- 该指针**由构造代码写成 `payload+0x48`**（【镜像】见 §1.3 的 `copy(…, 0xd0, &(payload+0x48), 8)`），所以实际求值的**是按值副本**。
- 也就意味着：**改对象内容（`+0x48` 起 0x88 字节）和改指针（`+0xd0`）两条路都通**，且都只需要普通 8 字节写入，**不需要伪造 PAC**。

### 1.2 `_OSEntitlementsReadOnly` 的确切字段（编译器类型编码，【镜像】）

`__cstring @ 0xfffffe0007662f42` 里有一条完整的 Objective-C 运行时类型编码串，原文：

```
v16@?0r^{_OSEntitlementsReadOnly=^{OSEntitlements}{CEQueryContext={der_vm_context=^{CERuntime}
{CEAccelerationContext=^{CEAccelerationElement}Q}QBB(?={ccder_read_blob=**}{?=**})}B}
{_CEContext={_CEContextInfo=CI}{_CEElement={?=*Q}{?=Q{?=*Q}}}^{_CEElementIndex}Q
{CEQueryContext={der_vm_context=…}B}B}^{_CEContext}*{?=^{__SC_GenericBlob}}{?=BB}}8
```

字段顺序（1 指针 + 2 聚合 + 1 bool + 1 指针 + 1 字符串指针 + 2 匿名聚合）：

| 字段 | 类型 | 实测偏移 | 证据 |
|---|---|---|---|
| 1 | `OSEntitlements *`（回指 outer，用于 `"failed OSEntitlements back-reference"` 校验） | `+0x00` | 【镜像】`0xfffffe00092385cc`: `if (*payload != outer) panic` |
| 2 | `CEQueryContext` | `+0x08`，拷入 **0x40** 字节 | 【镜像】`copy(zone, payload, 0x08, src, 0x40)` @`0xfffffe00092387f0` |
| 3 | `_CEContext` | `+0x48`，拷入 **0x88** 字节 | 【镜像】`copy(zone, payload, 0x48, src, 0x88)` @`0xfffffe00092387e8` |
| 4 | `bool` | 落在 `+0xD0` 之前的对齐空隙 | 【推断】 |
| 5 | `_CEContext *ceCtx` | **`+0xD0`** | 【镜像】`copy(zone, payload, 0xD0, &(payload+0x48), 8)` |
| 6 | `char *identity` | **`+0xD8`** | 【镜像】strlen→kalloc→memcpy→`copy(…,0xD8,…,8)`；panic 串 `identity: %p` |
| 7 | `struct { __SC_GenericBlob * }` | `+0xE0` | 【推断】（类型编码 + 后续字段位置反推） |
| 8 | `struct { bool, bool }` | `+0xE8` | 【推断】 |

合计 `0xEA`，按 8 字节对齐 → **`0xF0`**，与 `thunk_EXT_FUN_8011000003c43dd8(zone, 0xf0, payload)` 的尺寸校验参数**完全吻合**（【镜像】）。

**`_CEContext`（0x88）的内部布局 —— 已完整闭合，可直接当施工图**（【镜像】+ 类型编码交叉验证）：

| 偏移（相对 `ceCtx` = `payload+0x48`） | 字段 | 证据 |
|---|---|---|
| `+0x00` | `_CEContextInfo { char; int; }` | 类型编码 |
| **`+0x08`** | **`_CEElement` union 首字 = DER base 指针** | 【镜像】`0x9241860`: `der_base = *(ulong*)(ceCtx+0x08)` |
| **`+0x10`** | **DER length** | 【镜像】`der_len = *(long*)(ceCtx+0x10)`；`end = der_base+der_len` |
| `+0x18` | 容器迭代哨兵（`0x2000000000000011` / `-0x5ffffffffffffff0`） | 【镜像】`FUN_fffffe000923feb0` 要求等于二者之一，否则返回 10 |
| `+0x30` | `_CEElementIndex *`（索引数组） | 【镜像】`idx = *(long*)(ceCtx+0x30)`；为 0 则走线性扫描 |
| `+0x38` | `Q` 索引条目数 | 【镜像】`*(long*)(ceCtx+0x38)` |
| `+0x40` | `CEQueryContext`（0x40 字节，内含 `der_vm_context`） | 【镜像】构造时 `copy(payload+0x08, param_2+0x40, 0x40)` —— 源正好是 `_CEContext+0x40`，长度正好 0x40 ⇒ 该成员就在 `+0x40` 且 sizeof = 0x40 |
| `+0x80` | `bool` 有效位 | 【镜像】`0x9241720`: `if ((*(ctx+0x80) & 1) == 0) return 6`；`0x924157c`/`0x9241408` 写它 |

**⇒ 尺寸自洽性检查全绿**：`0x08 + 0x28(_CEElement) = 0x30` → idx@0x30 → `Q`@0x38 → `CEQueryContext`@0x40 (0x40) → `bool`@0x80 → sizeof = **0x88**。
**⇒ 上一版遗留的「类型编码差 8 字节」疑虑已消除**：`CEQueryContext` = **0x40**，`_CEContext` = **0x88**，两者都不需要"抹平"；构造里 0x40 / 0x88 两个立即数与字段边界逐一对上。
**⇒ 副产物**：`payload+0x08` 与 `payload+0x48+0x40` 是同一个 `CEQueryContext` 的**两份拷贝**（一份独立、一份嵌在 `_CEContext` 里）。改 DER 源时**两份都可改，但只有 `+0x48` 这一份被查询使用**（查询走 `*(payload+0xd0)`）。

### 1.3 查询路径逐条指令（全部 VA 用 `0xfffffe00…` 前缀，勿与 TXM 的 `0xfffffff0…` 混用）

**Step 1 — 入口（`queryEntitlementBooleanWith…` 族）** `0xfffffe0009231f8c`：

```asm
fffffe0009231f8c:  bti  c
fffffe0009231fa4:  mov  x19, x2                 ; out bool
fffffe0009231fa8:  mov  x21, x1                 ; entitlement 字符串
fffffe0009231fac:  bl   0xfffffe000922e014      ; ★ x0 = proc（未改写，直接前传）→ 取 OSEntitlements 对象
fffffe0009231fb0:  cbz  x0, 0xfffffe0009231fec  ; 失败 → 0xe00002f0
fffffe0009231fb8:  mov  x1, x21
fffffe0009231fbc:  bl   0xfffffe0009239ca0      ; ★ 真正的布尔查询
fffffe0009231fc0:  strb w0, [x19]               ; 写结果
fffffe0009231fe4:  mov  w0, #0x0                 ; 返回 KERN_SUCCESS
```

**Step 2 — proc→cred→对象** `0xfffffe000922e014` → `0xfffffe000922df3c`：

```asm
fffffe000922df50:  cbz  x0, <log "called with NULL cred">
fffffe000922df54:  ldr  x16, [x0, #0x78]!       ; ★ 对象指针，基址自增后 x0 = &cred->field
fffffe000922df58:  mov  x17, x0
fffffe000922df5c:  movk x17, #0x8b90, lsl #48   ; 修饰符 = 字段地址 ⊕ 0x8b90
fffffe000922df60:  autda x16, x17                ; ★ 认证
fffffe000922df64:  mov  x17, x16
fffffe000922df68:  xpacd x17                     ; 再剥离
fffffe000922df6c:  cmp  x16, x17
fffffe000922df70:  b.eq 0xfffffe000922df78
fffffe000922df74:  brk  #0xc472                  ; ★ 不带签名 → panic
fffffe000922df7c:  bl   0xfffffe0009231e94      ; safeMetaCast(ptr, OSEntitlements meta)
```

> **这是本轮第二重要的发现**：`cred+0x78` 是 **PAC 签名 + `xpacd` 双检**的槽位。把 cred 里这个指针改成自造对象 **不是写 8 字节就完事**，需要 DA key 生成合法签名。纯 r/w 做不到。
>
> **版本差警告**：`fw/xnu` v12377 的 `struct ucred`（`bsd/sys/ucred.h:143-181`）在 `NGROUPS=16` 下算出 `cr_label` 恰好在 `+0x78`。**不要据此把 `cred+0x78` 认成 `cr_label`**：设备 13432 上该槽位解出来的对象带 vtable（`+0x20` retain / `+0x28` release 虚调用，见 `0xfffffe000922e044-0xfffffe000922e060`），`safeMetaCast` 到 `OSEntitlements` 元类成功 —— 它是 OSA 对象，不是裸 `struct label *`。**【镜像】对【源码】偏移的否决，记在这里。**

**Step 3 — payload 取用 + 回指校验** `0xfffffe00092385cc`：

```c
local_28 = *(long **)(outer + 0x10);          // payload
thunk(zone_id, 0xf0, payload);                // ★ 尺寸校验 0xf0
if (*payload != outer)  panic("failed OSEntitlements back-reference: %p | %p");
return payload;                               // ★ 返回 payload
```

**Step 4 — 读 ceCtx（关键的那一条 `ldr`）** `0xfffffe0009239e28`：

```c
*(u16 *)(...) = 1;                                 // 默认结果
if (*(long *)(payload + 0xd0) != 0) {              // ★★ 裸读 +0xd0，无 autda
    key = *(long *)(ctx + 0x30);                   // entitlement 名（PAC 签过，进来之前已认证）
    st  = FUN_fffffe00092417f8(*(long *)(payload + 0xd0), key, &res);   // ★★ 求值
    if (!st) st = FUN_fffffe0009240858(&res, 1);   // 取布尔 + 与期望值比对
}
```

对应反汇编（同族查询位点，每种查询各一份，全 kext 共 **20 处** `[xN,#0xd0]`，其中 10 处是 `ldr x0,[x1,#0xd0]` 形态）：

```asm
fffffe0009239e60:  ldr  x0, [x1, #0xd0]      ; ★ ceCtx
...
fffffe0009239728:  ldr  x0, [x1, #0xd0]
fffffe00092399ac:  ldr  x0, [x1, #0xd0]
fffffe0009239b50:  ldr  x0, [x1, #0xd0]
fffffe000923a1bc:  ldr  x0, [x1, #0xd0]
fffffe000923a5b8:  ldr  x0, [x1, #0xd0]
fffffe000923a854:  ldr  x0, [x1, #0xd0]
```

**Step 5 — CE 求值内核** `0xfffffe00092417f8` → `0xfffffe0009241860`：

```c
// 0x92417f8(ceCtx, key, out)
len = strlen(key);
if (key + len < key) brk 0x5519;            // -fbounds-safety 溢出检查
FUN_fffffe0009241860(ceCtx, &key, out);
```

```c
// 0x9241860(ceCtx, key, out)   —— 全部字段裸读
idx = *(long *)(ceCtx + 0x30);              // ★ 索引数组指针
if (idx == 0) return FUN_fffffe000924052c(ceCtx + 8, key, out);   // 线性扫描路径
if (*(long *)(ceCtx + 0x38) != 0) {         // 索引条目数
    ... 二分查找 ...
    der_base = *(ulong *)(ceCtx + 0x08);    // ★ DER 起始
    der_len  = *(long  *)(ceCtx + 0x10);    // ★ DER 长度
    item     = der_base + (entry >> 32);
    end      = der_base + der_len;
    if (end < item || item < der_base) brk 0x5519;   // 边界检查（用裸值直接比）
    FUN_fffffe000923e4c4(&item, &out);      // der_vm_construct
}
```

**结论（【镜像】，可直接当施工图）**：
- DER 基址/长度 = `ceCtx+0x08` / `ceCtx+0x10`，**裸 8 字节**。
- 索引 = `ceCtx+0x30`（指针）/ `ceCtx+0x38`（条数），**裸 8 字节**；把 `+0x30` 置 0 即走线性扫描 `FUN_fffffe000924052c`。
- 边界检查用裸值比较（`-fbounds-safety` 的 `brk 0x5519`），**不做任何 PAC 认证**。`|0xc8a2…` 那段 `(a^b)&0xffc0000000000000` 只在顶位不一致时才触发，对同一区域的规范内核指针是**空操作**。

### 1.4 `+0xd8` 到底是什么（三条独立证据，防止再被误认）

1. **panic 串自证**：`0xfffffe000923888c: ldr x8,[x19,#0xd8]` 的失败分支跳到 `0xfffffe00092388f8`，加载 `0xfffffe0007662c26` = `"AMFI: attempted to reinitialize OSEntitlementsReadOnly identity: %p"`。而 `+0xd0` 的失败分支加载 `0xfffffe0007662b96` = `"…ceCtx: %p"`。
2. **写入形态**：`+0xd8` 的写入路径是 `strlen(src)` → `kalloc(len+1, 0x8004)` → `memcpy(…, len+1)` → `copy(payload, 0xD8, &ptr, 8)`。这是**字符串**，不可能是 CE 上下文。
3. **使用形态**：`0xfffffe0009224718` 等处把它当「非空即已初始化」的标记用（`ldr x21,[x0,#0xd8]; cbz x21 → "%s: target is not AppleMobileFileIntegrity object"`），从不进入 `der_vm_*`。

> 全 kext `[xN,#0xd8]` 命中 27 处，其中 15 处是 **vtable 偏移**（`ldr x8,[x16,#0xd8]!`，前面紧跟 `autda`），与字段无关；真正的字段访问只有 9 处，全部是 identity 的初始化/判空。

### 1.5 三个可写落点与推荐

| 落点 | 写入量 | 需要 PAC？ | 副作用 | 评价 |
|---|---|---|---|---|
| **A. `payload+0x08` / `payload+0x10`**（DER 基址/长度） | 16 字节 | 否 | 无（其余字段保持原值，`+0x30` 建议同时置 0 走线性路径） | **推荐**。最小、最稳、不破坏任何结构 |
| B. `payload+0x48` 全量 0x88 字节 | 0x88 | 否 | 需自己重建整个 `_CEContext`（含 `+0x00` 的 runtime 哨兵） | 可行但没必要，风险高 |
| C. `payload+0xD0` 改成自造结构 | 8 字节 | 否 | 要另找可写内核内存放 0x88 字节上下文 | 可行，无优势 |

**A 是首选**：只改两个字段，`_CEContext` 里那两个 `0x2000000000000011 / -0x5ffffffffffffff0` 哨兵、`+0x18` 的解析态、`+0x80` 的有效位全部保持原值，`FUN_fffffe000923feb0` 的容器迭代前置检查继续通过。

### 1.6 伪造 DER 的形状要求（【镜像】+【源码】）

`FUN_fffffe000923e4d0`（`der_vm_construct`）是标准 DER TLV 解析器：读 tag 字节、长度（短/长形式，长形式最多 8 字节且首字节非 0、长度必须 ≥0x80）、要求 `[ptr, ptr+len]` 落在 `[start, end]` 内，越界 `brk 0x5519`。

线性扫描路径 `FUN_fffffe000924052c(ceCtx+8, key, out)` 走 `FUN_fffffe000923feb0` 迭代容器子项，逐项回调 `FUN_fffffe00092405b4` 做键比较。因此最小伪造 blob：

```
30 <len>                                  ; SEQUENCE（顶层容器）
   30 <len2>                              ;   子项 SEQUENCE
      0C <n> "com.apple.private.xxx"      ;     UTF8String 键
      01 01 FF                            ;     BOOLEAN TRUE
```

只要 `ceCtx+0x08/0x10` 指向这块内存即可。**这块内存必须落在内核可读区**，且位置我们可控（r/w 阶段的常规做法：管道缓冲区 / `setxattr` 名字 / `kalloc` 后回读地址）。

---

## 2. Q2：伪造什么 entitlement 才真能出沙箱

### 2.1 关键结构事实：所有内核门禁只有一个汇聚点

【源码】`fw/xnu/iokit/bsddev/IOKitBSDInit.cpp:1589-1615`：

```c
boolean_t IOTaskHasEntitlement(task_t task, const char *entitlement) {
    ...
    proc_t proc = (proc_t)get_bsdtask_info(task);
    kern_return_t ret = amfi->OSEntitlements.queryEntitlementBooleanWithProc(proc, entitlement);
    return ret == KERN_SUCCESS;
}
```

而 `queryEntitlementBooleanWithProc` 就是我们 §1 追到底的 `0xfffffe0009231f8c` → `0xfffffe0009239ca0` → `0xfffffe0009239e28` → `*(payload+0xd0)`。

**⇒ 结论【镜像】+【源码】：改掉 `ceCtx` 的 DER 源，就对「整台设备上所有 `IOTaskHasEntitlement` / `IOCurrentTaskHasEntitlement` 调用点」同时生效。** 没有第二个 entitlement 求值引擎。

XNU 里这些调用点数量级（仅 `fw/xnu` 源码，不含 kext）：`IOTaskHas*` / `IOCurrentTaskHas*` 命中 **60+ 处**，分布 `bsd/vfs`、`bsd/kern`、`iokit/Kernel`、`osfmk`。

### 2.2 候选逐个核实

| 候选 | 内核侧消费者 | 位置 | 伪造后能过哪道门 | 判定 |
|---|---|---|---|---|
| **（通配）任意字符串 entitlement** | `IOTaskHasEntitlement` | `IOKitBSDInit.cpp:1595` | 所有内核侧 entitlement 判断 | ✅ **这是真正的杠杆** |
| `…` → IOKit UserClient 类级门槛 | `IOTaskHasEntitlement(owningTask, requiredEntitlementString)` | `iokit/Kernel/IOUserClient.cpp:4549` | 打开 **Info.plist 里 `IOUserClientEntitlementsKey` 指定的特权 UserClient 类** | ✅ **S4 主兑现面** |
| `…` → IOKit 每 selector 门槛 | `IOCurrentTaskHasEntitlement(dispatch->checkEntitlement)` | `iokit/Kernel/IOUserClient.cpp:6653` | **`IOExternalMethodDispatch` 表里带 `checkEntitlement` 的每一个外部方法** | ✅ **S4 主兑现面** |
| `com.apple.private.cs.debugger` | `IOCurrentTaskHasEntitlement` | `bsd/kern/code_signing/ppl.c:410` | 允许 `region_addr != PAGE_SIZE` 的 debug 映射（PPL 判定的 debugger 关联） | ✅ 有效，但只在「映射已建立」的场景加分 |
| `com.apple.private.pmap.load-trust-cache` | `IOTaskHasEntitlement` | `osfmk/arm/pmap/pmap.c:13053` | pmap 层信任缓存装载 | ⚠ 只买到「排队资格」，TXM 侧还要过（S5 已否证） |
| `com.apple.private.security.no-sandbox` | **XNU 只有 macOS 分支** | `bsd/kern/kern_exec.c:7960`，整段在 `#if XNU_TARGET_OS_OSX` 内 | **iOS 上没有任何内核分支读它** | ❌ **出局**（iOS 内核不消费） |
| `com.apple.private.security.container-required` | **XNU 源码 0 命中** | — | 由用户态 `libsystem_secinit` / container manager 在 exec 时读 | ❌ **出局**（不是内核门禁，且只在 exec 时读） |
| `platform-application` | **XNU 源码 0 命中**；字符串位于 `com.apple.security.sandbox` kext | kernelcache 内 `com.apple.security.sandbox` 切片 | seatbelt 在**贴标签时**（exec）消费 | ❌ **对已运行进程无效**（事后伪造不回溯）【推断】 |
| `task_for_pid-allow` | **XNU 源码 0 命中**（只在 `tests/*.plist` 出现）；`task_for_pid_posix_check()` 用的是 **uid/gid + `P_SUGID`**，不查 entitlement | `bsd/kern/kern_proc.c:5602-5670` | `task_for_pid` 不会因此放行；字符串位于 sandbox kext ⇒ 由用户态 taskgated 链路消费 | ❌ **出局**（伪造拿不到 tfp） |
| `com.apple.private.amfi.can-load-cdhash` | **AMFI kext 自己** | `0xfffffe0009224718` | 「修改编译服务信任缓存」这一条外部方法；需要另一个已初始化的 AMFI 实例（`[obj+0xd8] != 0`） | ⚠ 只在打 AMFI UserClient 时有意义，与本条链正交 |
| `com.apple.private.amfi.can-execute-cdhash` | AMFI kext（字符串 `0xfffffe000765bed3`，另有 `"AMFI: can-execute-cdhash is disabled by system configuration"`） | AMFI `__cstring` | 控制「能否按 cdhash 执行」；同一 kext 内还有 `"AMFI: can-execute-cdhash code in non-entitled context."` | ⚠ 有效但受系统配置开关二次限制，且执行侧还有 TXM |

### 2.3 最小增量集合（结论）

**增量不是一个固定的 entitlement 列表，而是「任意字符串」**——因为门禁是 `IOTaskHasEntitlement(task, "字符串")`，字符串由调用点给出，我们伪造 DER 时想写什么就写什么。

所以最小增量集合应表述为：

```
Δ = { 任意调用点所需的 entitlement 名 }         // 无需预先枚举
```

但**为了「出沙箱」这个具体目标**，真正能带来越界能力的只有下面这一组（按性价比排序）：

1. **IOKit UserClient 类级 entitlement**（`IOUserClient.cpp:4549`）—— 这直接决定「我们能不能拿到一个有特权的 UserClient」。这是 S4 之后所有后续工作的入口，**优先级最高**。
2. **IOKit `IOExternalMethodDispatch.checkEntitlement`**（`:6653`）—— 决定「拿到之后能不能调那些被挡的 selector」。
3. **`com.apple.private.cs.debugger`**（`ppl.c:410`）—— 边际增益，需要已有映射。
4. 其余（`no-sandbox` / `container-required` / `platform-application` / `task_for_pid-allow`）**全部出局**，理由见上表 —— 它们要么不是内核门禁，要么只在 exec 时读，要么根本不存在于 iOS 内核。

> **不要写「最小 5 项 entitlement」这种话。** 正确的说法是：**一个 DER 改写点，覆盖全部内核门禁；具体写哪些名字由目标决定。**

---

## 3. Q3：那些门禁真的可达吗；伪造能不能改沙箱标签

### 3.1 可达性：可达，而且是「全局可达」

- 触发形态：**任意** `IOTaskHasEntitlement` / `IOCurrentTaskHasEntitlement` 调用点，包括
  - 我们的 app 自己发起的 `IOServiceOpen`（→ `:4549` 的类级门）
  - 我们的 app 自己发起的 `IOConnectCallMethod`（→ `:6653` 的 selector 级门）
  - `csops` 之外的 VFS 门（`vfs_syscalls.c` 里 20+ 处）
- 这些调用都在**当前任务的上下文**里跑，读的是**我们进程自己的 cred → 我们自己的 OSEntitlements**，正是我们改的那个对象。
- **⇒ 可达性没有疑问。** 这是 S4 最干净的一段：不需要跨进程、不需要时序、不需要额外前置。

### 3.2 伪造 entitlement **不能**改沙箱标签 —— 三条硬约束

**约束 1：两套数据面完全分离。**
- entitlement 面：`cred+0x78`（PAC 签名）→ OSEntitlements 对象 → `payload+0xd0` → `_CEContext`。
- 沙箱标签面：`ucred->cr_label` 是 `struct label *`，源码里带 **`OS_PTRAUTH_SIGNED_PTR_AUTH_NULL("ucred.cr_label")`**（`bsd/sys/ucred.h:173`）—— 同样是 PAC 保护。seatbelt 的检查（`sandbox_check`）走 MACF hook，取的是标签里的 profile，**不调 `IOTaskHasEntitlement`**。
- 两条链路在 §1 追踪的整条路径上**没有任何交叉点**。改 `+0x08/+0x10` 不会碰到 `struct label`。

**约束 2：标签是「贴」上去的，不是「查」出来的。**
- seatbelt 的 profile 在 exec 时由 `libsystem_secinit`（用户态）依据**当时的** code signature entitlements 选定并 `sandbox_init()`。
- 事后改 entitlement 不回溯。**要换标签必须重新 exec**，而 exec 又回到 S5（TXM 校验）——S5 判定不变：不可行。

**【源码】** 唯一在 XNU 里与「不贴沙箱」相关的分支是 `kern_exec.c:7960`，且整段包在 `#if XNU_TARGET_OS_OSX` 里，iOS 内核不编译进这条路径。

**约束 3：能改标签的地方都锁在 PAC 后面。**
- `cred+0x78` 的对象指针：`autda #0x8b90` + `xpacd` + `brk #0xc472`（【镜像】§1.3 Step 2）。
- `cr_label` 本身：源码标了 `OS_PTRAUTH_SIGNED_PTR_AUTH`。
- 纯 r/w 没有 DA key，写不出合法签名。

### 3.3 所以 S4 还差哪一步

**S4 严格意义上的产出是「任意内核侧 entitlement」，不是「脱离 seatbelt」。**

要做到真正的「沙箱外文件/网络/端口访问」，还差：

| 缺口 | 说明 | 现状 |
|---|---|---|
| G1 | 把「有特权的 entitlement」兑换成「有特权的**事实**」——即用 §2.2 的 IOKit 门去打开一个能读内核内存 / 驱动硬件的 UserClient | **可做**，只需枚举目标 UserClient 类的 Info.plist 门槛（离线可从 kernelcache 的 kext Info.plist 得到） |
| G2 | 或者：用 entitlement 门换取一个**已在沙箱外**的服务的 Mach port（`mach-lookup` 在 seatbelt 里被 profile 挡，但若目标服务本身不查标签只查 entitlement，则可由 G1 的 UserClient 转手） | **需逐服务核实，未做** |
| G3 | 真正的 seatbelt 逃逸（改标签） | **卡死**：需重新 exec（S5）+ PAC（无 key） |

**⇒ 「S4 完成」的正确判据是 G1 闭合：伪造 entitlement → 打开一个此前打不开的特权 UserClient → 该 UserClient 的外部方法给我们内核读能力或设备访问能力。** 这条路径**不需要** G2/G3。

---

## 4. Q4：写入侧的现实性

### 4.1 write-once 保护的确切形式

**保护在构造函数里，是纯软件分支，没有硬件/SPTM 参与。**

`_OSEntitlementsReadOnly::setContext` 族，函数 `0xfffffe000923877c`：

```asm
fffffe0009238798:  ldr  x19, [x0, #0x10]      ; payload
fffffe000923879c:  add  x8, x19, #0x48
fffffe00092387a0:  stp  xzr, x8, [sp, #0x20]  ; 出参槽，第 2 字预置为 &payload+0x48
fffffe00092387a4:  ldr  x8, [x19, #0xd0]      ; ★ 读 ceCtx
fffffe00092387a8:  cbnz x8, 0xfffffe000923883c   ; ★ 非空 → panic
...
fffffe0009238850:  adrp x0, 0xfffffe0007662000
fffffe0009238854:  add  x0, x0, #0xb96       ; = 0xfffffe0007662b96
fffffe0009238858:  bl   0xfffffe000924f558   ; ★ panic("AMFI: attempted to reinitialize
                                             ;          OSEntitlementsReadOnly ceCtx: %p" @%s:%d)
```

同族三个字段、三个 panic 串，一一对应：

| 字段 | 检查指令 | panic 串 VA | 串内容 |
|---|---|---|---|
| `+0x10`（outer→payload） | `0xfffffe0009238728: cbnz x8` | `0xfffffe0007662b4d` | `…reinitialize OSEntitlementsReadOnly data: %p` |
| **`+0xD0`（ceCtx）** | `0xfffffe00092387a8: cbnz x8` | `0xfffffe0007662b96` | `…reinitialize OSEntitlementsReadOnly ceCtx: %p` |
| `+0xD8`（identity） | `0xfffffe000923888c: ldr/cbnz` | `0xfffffe0007662c26` | `…reinitialize OSEntitlementsReadOnly identity: %p` |

**形式**：`if (field != NULL) panic(...)`。`panic` 走 `0xfffffe000924f558`（非 `brk`、非 SPTM 陷门），是普通内核 panic 路径。

### 4.2 内核 r/w 能不能绕过它 —— **能，彻底能**

三条理由，逐条：

1. **它是「构造期」检查，不是「使用期」检查。** 查询路径（§1.3 Step 4/5）**没有任何一个字节**会去验证 `+0xD0` 是否为 NULL 之外的约束，也不会重跑构造。写内存直接落在使用侧，检查永不执行。
2. **落点 A（推荐）根本不碰被保护的字段。** 我们写 `payload+0x08` / `payload+0x10`（DER 基址/长度），这两个字段**没有 write-once 检查**（构造里是 `copy(...)` 无条件写）。`+0xD0` 保持原值，panic 分支永不进入。
3. **即使要改 `+0xD0`（落点 C），也只是 memset 之外的普通 store。** 保护只存在于"再初始化"函数里；直接 `*(u64*)(payload+0xd0) = X` 不会触发任何检查。

**⇒ write-once panic 对本威胁模型**（内核 r/w）**不构成障碍，它只防「正常代码路径重复初始化」这类 bug，不防内存写。**

### 4.3 堆区与类型隔离 —— 哪些证实，哪些留白

**已证实【镜像】**：
- 分配点是**按 zone id 的 typed allocation**，不是通用 `kalloc(size)`：

  ```asm
  adrp x20, 0xfffffe0008129000
  ldrh w0, [x20, #0xd58]        ; ★ 16 位 kalloc_type zone id（kext 本地 zone_id_t 变量 @0xfffffe0008129d58）
  mov  x1, #0x8004
  bl   0xfffffe000924f998       ; typed alloc
  ...
  ldrh w0, [x21, #0xd58]        ; 同一 zone id
  ... bl 0xfffffe000924f9a8     ; typed 区域拷贝（0x48/0x88/0xD0/0xD8 四段都走这里）
  ```
- 该 kext 存在 `__kalloc_type`（0xF80 B）与 `__kalloc_var`（0x1400 B）两个段，`__DATA_CONST` 各 186 / 310 个非零字 —— 即该 kext 声明了成组的 `kalloc_type_view`。
- 尺寸校验 `thunk(zone_id, 0xf0, payload)` 把 zone 与 0xF0 绑定在一起。
- 相关字符串：`amfi.OSEntitlements`（`0xfffffe000765ea10`）、`iokit.OSEntitlements`（`0xfffffe0007662ae8`）。

**留白（明确不填）**：
- **具体 zone 名称**：`__kalloc_type` / `__kalloc_var` 记录里的 `kt_name` 指针是**链式 fixup token**（如 `0x00200000_0065699a`），而本镜像的 `LC_DYLD_CHAINED_FIXUPS` / `LC_SYMTAB` 已在提取时被剥离（`nsyms = 0`）。**无法从现有产物解出 zone 名字**。我不拿 `amfi.OSEntitlements` 硬套。
- **是否 ZSS 隔离**：`fw/xnu` v12377 的 `osfmk/kern/{zalloc,kalloc}.h` 里 **`ZSS` 0 命中**；该标记属于设备特有版本，源码不可作证。**未证实。**

**能给的可操作判断【推断】**：
- 该对象在**类型隔离的专用 zone** 内，不在通用 `data`/`kalloc.240` 里。含义很具体：
  - ✗ **不能**用「相邻通用堆对象的溢出」去够它；
  - ✗ **不能**用「同尺寸通用分配」去占位（type isolation 会把不同 site 分到不同 zone）；
  - ✓ 但**可以整 zone 扫描**：zone 里所有元素都是 0xF0 的同类对象，用 `payload+0xd0 == payload+0x48` 这个自指关系 + `payload+0x00` 回指 + `payload+0x08` 的非零 DER 指针，判定成本极低。**这是 r/w 阶段定位目标对象最省事的办法**（也绕开了 `cred+0x78` 的 PAC 问题，见 §1.3）。

### 4.4 对利用形态的实际限制（MIE / kalloc_type 层面）

1. **S2 的 exploit 原语必须能「写到指定地址」，不能只是「相邻对象破坏」。** 类型隔离让"结构化"的 overflow 基本不可用于命中本对象；需要的是 arbitrary write，或 zone 内的可控写入。
2. **0xF0 的尺寸是固定锚点**：zone 内全部同类，尺寸校验 `0xf0` 会在构造时把尺寸不符的对象打掉。**伪造时不要动 payload 的尺寸语义**（落点 A 天然满足）。
3. **回指校验是真实约束**：`if (*payload != outer) panic("failed OSEntitlements back-reference")`。若采用落点 C（自造 payload），必须把 `+0x00` 写成真正的 outer 地址，否则 `0xfffffe00092385cc` 直接 panic。**落点 A 不涉及这个风险。**
4. **不要碰 `+0x10`**：那是 `data` 的 write-once 检查位；破坏它会让下次构造 panic（我们本来就不会再构造，但会污染其他进程的路径——不, 每个进程独立对象。仍建议不碰）。

---

## 5. Q5：不依赖内核 r/w 的可能性

**结论：没有可用的非 r/w 路径。明确地「只能靠 r/w」。** 下面把每一条可能的旁路都过一遍，并给出否证依据，而不是一句"没有"。

| 假设路径 | 是否成立 | 依据 |
|---|---|---|
| 该对象由用户可控数据创建，创建时把用户数据拷进去了 | **部分成立，但不构成漏洞** | 【镜像】`+0x48` 的 0x88 字节来自 **TXM 的 CE 上下文**，`+0x08` 来自它 `+0x40`；两者都不是用户直接可控。用户唯一间接影响的是**自己签名里的 entitlement DER**（见下） |
| 用户能通过某个 API 让 AMFI 重建/重指该对象 | **否** | 【镜像】重初始化会 `cbnz` → `panic`。没有"替换"API，只有"崩溃"路径 |
| UAF 导致对象被重用 | **未发现** | 【镜像】`+0x00` 回指校验 + `+0x10`/`+0xD0`/`+0xD8` 三重 write-once，加上 `"AMFI: attempted to free OSEntitlements without invalidation"` / `"unexpected OSEntitlements adjustment"` 两组 panic 串，说明 Apple 对生命周期做了专门加固。**我没找到 UAF，但这不等于不存在——留白** |
| 用户态 API 直接改 `DEQueryContext`（如 `csops`） | **否** | 【源码】`csops` 的 `CS_OPS_ENTITLEMENTS_BLOB` / `DER_ENTITLEMENTS` 走 `csblob_os_entitlements_get(blob)`（`bsd/kern/kern_proc.c:3765,3800-3803`），读的是 **cs_blob 里的原始 blob**，不经过 CE 上下文。改 CE 不会改 `csops` 的输出，反之亦然 |
| exec 一个新进程让 entitlement 重新求值 | **是重新求值，但值不变** | 重新求值只会把**同一份**签名 DER 再解析一遍。要让它变，还是得改内存 |
| **在签名阶段就把 entitlement 写进自己的 DER** | **这才是唯一的"无 r/w"路径，但它不是漏洞** | 我们**本来就控制**自己 app 的 entitlement DER（`out/ents.plist` 那 44 项就是这么来的）。限制不在内存，而在 **profile/描述文件**：`platform-application`、`com.apple.private.security.*`、`task_for_pid-allow` 这类**不接受任何描述文件授予**。所以这条路的上限是"换一个更肥的 profile"，与 S4 无关 |

**⇒ 唯一无 r/w 的"影响"是签名期可控，但它被授权体系而非内存机制卡住，因此不构成 S4 的可行路径。S4 只能用内核 r/w。**

**注意一个容易被忽略的点（对施工有用）**：`cred+0x78` 虽然是 PAC 签名的，但**"读"不需要 key**。真正需要 key 的是"用"。因此：
- 若要顺着 cred 走，需要 PAC strip —— 是否可行取决于该 build 的 VA 宽度，**本文未在真机验证，标记未闭合**；
- 若走 §4.3 的 **zone 扫描**，则完全不需要 strip。**推荐后者。**

---

## 6. S4 距离可执行还差什么（清单）

### 6.1 前提链（按执行顺序）

| # | 前提 | 状态 | 说明 |
|---|---|---|---|
| P1 | **内核 r/w（S2）** | ❌ **未闭合** | 所有 S4 工作的绝对前提。当前 S2 仍缺（STATUS §O.5） |
| P2 | 从 `proc` 找到 `cred`，读出 `cred+0x78` | ⚠ **可行但需处理 PAC** | 【镜像】`autda #0x8b90` + `xpacd` + `brk 0xc472`。**读值可以，解引用需要 strip；本文未验证该 build 的 VA 宽度** |
| P2' | **（替代 P2）扫描 AMFI typed zone 定位 0xF0 对象** | ✅ **技术路线已定，未执行** | 判据：`payload+0xd0 == payload+0x48`、`payload+0x00` 回指、`payload+0x08` 非零。**不需要 PAC strip** —— **推荐走这条** |
| P3 | 对象是 `_OSEntitlementsReadOnly`（0xF0）且 `+0xD0` 非空 | ✅ **已闭合** | 尺寸校验 `0xf0`、字段布局、`+0xD0`/`+0xD8` 语义全部指令级证实（§1.2/§1.3） |
| P4 | 求值路径使用 `ceCtx+0x08/+0x10` 作为 DER 源，且无 PAC | ✅ **已闭合** | §1.3 Step 5；`brk 0x5519` 边界检查用裸值比较；`_CEContext` 全字段偏移已对齐（§1.2 表），含 `+0x18` 哨兵 `0x2000000000000011` / `0xa000000000000010`（`FUN_fffffe000923feb0` 读 `[x0+0x10]`，调用点为 `x0=ceCtx+8`）——**落点 A 不碰它，故哨兵恒过** |
| P5 | 找到一块**内核可读、内容可控**的内存放伪造 DER | ❌ **未闭合（工程量）** | r/w 之后的标准动作（管道缓冲 / xattr / `kalloc` 回读）。**本文未选型** |
| P6 | 构造出能被 `der_vm_construct` 接受的 DER blob | ✅ **格式已定，未实测** | §1.6 的 `SEQUENCE{ SEQUENCE{ UTF8 key, BOOLEAN TRUE } }`。**未在设备上跑过解析器** |
| P7 | 写入 `payload+0x08` / `payload+0x10`（+ 可选清零 `+0x30`） | ✅ **写入方案已定** | 16 字节，绕开全部 write-once 检查（§4.2） |
| P8 | 用 `IOTaskHasEntitlement` 验证生效 | ⚠ **验证方法已定，未执行** | 最省事的探针：调一个受 `IOUserClient.cpp:4549` 保护的 `IOServiceOpen`，看返回值从 `kIOReturnNotPrivileged` 变成成功 |
| P9 | **G1：把 entitlement 兑换成实际能力** | ❌ **未闭合（选型未做）** | 需要枚举 kernelcache 里各 kext 的 `IOUserClientEntitlementsKey` / `checkEntitlement`，挑一个"开了就等于拿到内核读/设备访问"的类。**本文只确认了门存在，没有挑具体目标** |
| P10 | 改沙箱标签（真正的 seatbelt 逃逸） | ❌ **卡死** | 需重新 exec（S5，不可行）+ PAC（无 key）。§3.2 |

### 6.2 一句话状态

- **已闭合**：P3、P4、P6（格式）、P7、P2'（路线）。
- **未闭合**：P1（S2）、P5（内存选型）、P6（实测）、P8（实测）、P9（目标选型）、P2（PAC strip 的可行性）。
- **卡死**：P10。

### 6.3 本轮的方法学留痕（避免下次重犯）

1. **panic 串是字段名的第一手证据，不要靠偏移猜。** 上一轮把 `identity` 当 `ceCtx`，代价是整条链的落点错位。
2. **`[x16,#0xd8]!` 这种带 `!` 的 `ldr` 是 vtable 偏移，不是结构体字段。** 全 kext 27 处 `#0xd8` 里 15 处是虚调用；把它们算进"字段访问"会污染结论。
3. **拷贝长度比类型编码可信。** ObjC 类型编码可能来自相邻 build；`copy(dst,off,len)` 的立即数是本镜像的真值。
4. **`0x8004` / `0x5ede` / `0x8b90` 这类常量先当"标记"读，不当"边界"读。**
5. **版本差必须写进结论**：v12377 的 `cr_label=0x78` 在 13432 上**不成立**，硬套会得出完全错误的架构判断。

---

## 7. 最后一句直答

**在「已有内核 r/w」的前提下，S4 能做——但"S4"的产出必须重新定义。**

- **能做的是**：伪造任意内核侧 entitlement。路径已钉死到指令级：
  `R/W → 定位 0xF0 的 _OSEntitlementsReadOnly（zone 扫描，靠 +0xD0==+0x48 自指识别）→ 写 payload+0x08/0x10 指向自造 DER → 全系统所有 IOTaskHasEntitlement 调用点按我们的 DER 求值`。
  这条链上**没有 PAC、没有 write-once 障碍、没有时序窗口**，唯一剩下的工程项是「在内核里找一块可控内存放 DER」和「挑一个值得打开的特权 UserClient」。
- **不能做的是**：改沙箱标签。`cr_label` 与 entitlement 是两套数据面，标签在 exec 时贴、事后不回溯；换标签要么重新 exec（撞 S5，不可行），要么写 PAC 保护的指针（无 DA key）。
- **所以**：S4 的终态是 **「拿到了任意 entitlement ⇒ 能打开此前打不开的内核/IOKit 门」**，而**不是**「进程脱离了 seatbelt」。把前者当后者写，就会重演本工程已经犯过六次的那种误判。
- **并且**：这一切仍然压在 **S2 未闭合** 之上。S4 做得再实，也只是「等 r/w 落地即可执行」的状态，不解除 S2 这道门。
