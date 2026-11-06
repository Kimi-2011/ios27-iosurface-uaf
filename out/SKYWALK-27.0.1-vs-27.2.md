# IOSkywalkFamily：27.0.1 → 27.2 函数级差分

**日期**：2026-11-01 00:10
**样本**：`out/skywalk.27.0.1.macho` (826,848 B) / `out/skywalk.27.2.macho` (827,744 B)
**提取**：`python3 tools/kext_extract.py out/kc.27.0.1.full --kext com.apple.iokit.IOSkywalkFamily --out ...`
（注意：`--kext` 要写**全限定名**，写短名会 IndexError）

## 一、段尺寸对比

| 段 | 27.0.1 | 27.2 | 差异 |
|---|---|---|---|
| `__TEXT` | 0x5e10 | 0x5e10 | 相同 |
| `__TEXT_EXEC` | 0x43600 | 0x43714 | **+0x114 (276 B)** |
| `__DATA` | 0x924 | 0x924 | 相同 |
| `__DATA_CONST` | 0xc9a0 | 0xc9a0 | 相同 |
| `__LINKEDIT` | 0x73029 | 0x73291 | +0x268 |

`__cstring` / `__os_log` **完全一致（282 条，零差异）** → 修复**不新增校验消息**，是纯代码逻辑改动。

## 二、方法（可复用）

盲目全文件字符串 diff 会被数据段噪声淹没（实测新增"字符串"全是二进制垃圾）。
正确的两步：

1. **只取 `__cstring`/`__os_log` 段**，按 VA 范围经段映射回文件偏移（绕开重建 kext 里损坏的 section fileoff）
2. **函数级差分 + 指令归一化**：
   - 函数起点用 **`BTI c`**（`5f 24 03 d5`）识别 —— 2132 个，与实际 2165 个吻合
     ⚠️ 不能用 `PACIASP`(`d503233f`)；内核用 **`PACIBSP`** = `7f 23 03 d5`，且只覆盖 1392 个（漏掉叶子函数）
   - 归一化：把 `#imm` 记为 `#I`、`0x...` 记为 `A`，再哈希
     （kext 整体加载地址变了，含 ADRP/ADD 的函数字节全变，不归一化会导致 1392 个函数"全部改动"的假象）

**校验**：归一化后差分得出 **108 个改动函数**，与既有 `kdiff.py` 的 108 **完全一致**。

## 三、差分结果

- 函数总数：2132（两版相同）
- 改动函数：**108**
- 其中**指令数增加**的：96 个

### 3.1 统一的清位改动：107 / 108

| 新增指令 | 次数 |
|---|---|
| `and xN, xN, #0xfffffffffffffeff` | **107** |

即**清除某 64 位字段的 bit 8（0x100）**，几乎每个改动函数都做一次。

### 3.2 新增的尺寸下界检查

| 新增 `cmp` 立即数 | 次数 |
|---|---|
| `#1` | 158 |
| `#0x3c` (60) | 47 |
| **`#0x54` (84)** | 41 |
| `#2` / `#5` | 24 / 16 |
| `#0x6c` (108) / `#0x5c` (92) | 7 / 7 |
| `#0x11` (17) | 4 |

`0x3c / 0x54 / 0x5c / 0x6c` 构成一组结构尺寸阈值。

### 3.3 典型函数逐条对比（A `0xa2f67b4` → B `0xa344b18`）

```asm
27.0.1                          27.2
bti c                           bti c
mov x8, x0                      mov x8, x0
mov w0,#0x2bf / movk …#0xe000   （同）
ldr x9,[x8]                     ldp x12,x10,[x8]        ; 合并加载
ldr w9,[x9,#0x20]               ldp w11,w9,[x8,#0x10]   ; w11 = u32@this+0x10
cmp w9,#1                       ldr x8,[x8,#0x18]       ; this->f18
b.ne fail                       ldr x13,[x8,#8]         ; u64@f18+8
                                and x13,x13,#~0x100      ; ★ 清 bit8
ldr x9,[x8,#0x18]               str x13,[x8,#8]          ; ★ 回写
ldr x9,[x9,#0x10]               ldr w12,[x12,#0x20]
cmp x9,#1                       cmp w12,#1 / b.ne fail
b.ne fail                       ldr x8,[x8,#0x10]
                                cmp x8,#1 / b.ne fail
                                cmp w11,#0x54            ; ★ 新增下界
                                b.lo fail                ; ★ 不足 0x54 拒绝
```

## 四、安全含义

### 已证实（反汇编直接可见）
1. 27.2 在 107 个函数里统一**清除某个字段的 bit 8**
2. 27.2 在多个入口新增**描述符尺寸下界检查**（0x3c / 0x54 / 0x5c / 0x6c）

### 推断（需进一步验证）
- **bit 8 = 存活/在用标志**。27.0.1 在释放路径上没清这一位 → 对象释放后仍被判为"可用" → **UAF**。
  这与 27.2 公告里 IOKit/网络类 CVE 多为竞态/UAF 相符。
- **尺寸下界缺失** → 27.0.1 接受小于结构体真实尺寸的描述符，随后按完整结构读字段 → **越界读/写**。
  这正是公告措辞「improved bounds checking」对应的形态。

### 可达性（关键，尚未验证）
字符串显示对外暴露的是 IOKit 类 + nexus 接口：
```
IOSkywalkInterface / IOSkywalkNetworkInterface / IOSkywalkEthernetInterface
IOSkywalkNexusDomainProvider / IOSkywalkNetworkNexusDomainProvider
site.kern_nexus_netif_llink_init / kern_nexus_netif_llink_qset_init
```
`kern_nexus_*` 表明走 **nexus 内核控制 socket**（`com.apple.net.nexus`），
用户态经 Network.framework 编程 → **原理上 app 沙箱可达**。
但「108 个改动函数里哪些属于 nexus kctl 路径」**尚未定位**，这是下一步的核心问题。

## 五、工具局限

- 符号表已剥离（`nsyms=0`），无 `LC_DYLD_EXPORTS_TRIE` → **无法给函数命名**，只能按 VA 与结构偏移描述
- `LC_FUNCTION_STARTS` 存在，但其 `dataoff` 指向原 kernelcache 偏移，在重建 kext 中映射失败 →
  改用 `BTI` 扫描，得到 2132/2165（98.5% 覆盖）

---

## 六、可达性追查结果（00:30）：skywalk 无法直接触达

### 6.1 skywalk 自身没有用户客户端
```
skywalk.27.2.macho 中含 "UserClient" 的字符串：0 条
```
→ app **不能** `IOServiceOpen` 它。

### 6.2 nexus kctl 不在 skywalk 里
```
com.apple.net.nexus    : 未找到
com.apple.nexus        : kernel 本体 file 0x1daf8
kern_nexus             : kernel 本体 file 0xad876
```
nexus 的 kctl 注册在 `com.apple.kernel`，skywalk 只提供 `IOSkywalkNexusDomainProvider` 等 IOKit 类。

### 6.3 上游 Wi-Fi 驱动不在本 kernelcache
扫描 301 个 kext，**无** `AppleBCMWLANCore` / `AppleOLYHAL` / `IO80211Family`。
唯一的 skywalk 引用者就是它自己。

### 6.4 结论
**在现有样本下，skywalk 的可达链无法完成追踪**：
app → Network.framework → kernel nexus kctl(com.apple.kernel) → ??? → skywalk
中间那一环（Wi-Fi 驱动 / nexus 分发）**不在本 kernelcache 中**。

要继续必须有完整的 fileset（含 Wi-Fi kext），否则这条线**无法评估**，
不建议继续投入。108 个改动函数的审计价值仍在（若日后拿到完整样本可直接复用本次差分器）。

## 七、并行目标：AppleH16ANEInterface（CoreML 可达）

用同一差分器跑 ANE，改动量级远大于 skywalk：

```
改动函数对：155（指令增加的 85 个）
最大一个：0xfffffe0008d27af8 (195 条) → 0xfffffe0008d1ed20 (646 条)  +451 条 / +1804 B
```

新增代码特征：
- `cmp` 立即数仅 `#1 ~ #7`（不像边界检查）
- 访存偏移集中在 `0x428 / 0x430 / 0x438 / 0x440`（8 字节步长，疑似记录数组）与 `0x4228`

**判定：暂不认定其为安全修复**——形态更像新增数据结构处理。
需要先恢复结构语义才能定性，否则会重复 AVE 那种误判。

---

# ⚠️ 更正（2026-11-01 00:20）：撤回"新增尺寸下界检查"的结论

## 复核方法与结果

对本文件第三节识别出的 108 个改动函数，逐个统计**条件分支指令数**
（`b.cond` / `cbz` / `cbnz` / `tbz` / `tbnz` / `csel` / `csinc`）在两版间的变化：

```
改动函数对 108
条件分支数: 增加 0 | 减少 2 | 不变 106
合计 dChk 净变化: 0
```

## 结论修正

| 先前写的 | 实际 |
|---|---|
| 27.2 在多个入口「新增描述符尺寸下界检查」 | ❌ **错**。没有任何函数新增条件分支 |
| `cmp #0x3c / #0x54 / #0x5c / #0x6c` 是新增校验 | ❌ **错**。它们是**新内联的访问器**带进来的比较，分支结构原本就有 |
| 27.2 统一清 bit 8 + 加尺寸检查 | ✅ 只有「清 bit 8」成立 |

**根因**：我的统计口径是「B 中出现了、A 中该函数内没有的 `cmp` 立即数」。
内联（`ldr`→`ldp`、访问器展开）会把别处的比较搬进本函数，
于是被误计为"新增"。**这是内联重构的经典误报形态。**

## 与既有结论的一致性

`CVE-KEXT-MAP.md` §五早就写明：IOSkywalkFamily 的 108 处改动
**全部是访问器内联重构，dChk=0，无安全修补**。本次复核**支持该结论**，
推翻的是我昨天的过度解读。

## 对攻击链设计的含义（重要）

- 108 处改动 = `getMetaClass`/`retain` 一类访问器内联 + 一次 flags bit8 清除
- **不含可利用的检查缺失**
- → IOSkywalkFamily **不能作为打分基础的第一跳来源**
- → 但 nexus 内核控制入口（`com.apple.nexus.*`）本身**仍然是可达的**，
  价值在于「通往 `com.apple.kernel` 里 IPv6 栈的本地报文注入通道」，
  而不是 skywalk 自身的差分

## 方法学教训（新增第 4 条）

4. **判定"新增检查"必须看条件分支数（dChk），不能看立即数出现与否。**
   内联会把比较搬进函数体，制造"新增立即数"的假象。

---

# ⚠️ 更正（2026-11-01 01:40）：第三节「尺寸下界检查」的结论是错的

## 错在哪

我原文写「27.2 给 ~96 个入口统一加了 `*(this+0x10) >= 0x54` 的下界检查」，
并据此推断 27.0.1 存在越界读/写。**这个结论不成立。**

## 正确判据：dChk（条件分支数变化），不是立即数

对 108 个改动函数逐个统计条件分支（`b.cond/b.lo/b.hi/cbz/cbnz/tbz/tbnz/csel/csinc/csinv/csneg`）：

```
改动函数对 108
dChk > 0 : 0
dChk = 0 : 106
dChk < 0 : 2
净 dChk  : -15
```

**没有任何一个函数增加了条件分支。** 那些 `cmp #0x3c/#0x54/#0x5c/#0x6c` 是
**新内联的访问器**带进函数体的，不是新增校验。

## 根因

我的口径是「B 中出现、而 A 中该函数没有的立即数」。
内联（inlining）会把别处的比较搬进函数体，于是被误判为「新增检查」。
**这个口径在存在内联/重排时会系统性误报。**

## 后果

- `IOSkywalkFamily` 的 108 处改动**全部是访问器内联，无安全修补**
- 该 kext **不能作为任何漏洞打分的基础**
- `CVE-KEXT-MAP.md` §五 的原始判断是对的，我后来的「新发现」是倒退

## 方法学教训（新增第 4 条）

> 判定「是否新增安全检查」**必须看 dChk**（条件分支增量）。
> 看新增立即数、看新增指令、看字符串增量都会误报——
> 内联会把别处的代码搬进来，字符串增量会被数据段噪声淹没。
> 本工程已因口径问题误判三次：AVE 的 0x1888（日志当索引）、
> AVD 的 0xD84（字符串偏移当字段）、本次 skywalk（内联当校验）。

## 现存的正确结论（用 dChk 复核过）

| 目标 | 改动函数 | dChk>0 | 净 dChk | 判定 |
|---|---|---|---|---|
| IOSkywalkFamily | 108 | **0** | −15 | 无安全修补 ✗ |
| AppleAVD | 6 | **1** | +3 | 真修复（`0x8707cf0` dChk=+5）✓ |
| AppleH16ANE | 155 | **42** | −106 | 真修复（最大 dChk=+34）✓ |
| com.apple.kernel | 358 | 57 | — | 真修复 ✓ |
