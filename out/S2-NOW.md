# S2 攻关现状 — 总指挥结算

> README（10 行）
> 1. 本文是 S2（内核内存破坏）攻关的当前结算，取代此前所有中间结论。
> 2. 方法已突破：**字符串差分**能定位补丁（AVE2、DCP 两发两中，均为原始字节计数 0→1）。
> 3. 但**还没拿到任何可利用原语**。已定位 ≠ 可利用。
> 4. `AppleAVE2Driver` 已证**结构性不可达**（type 0..255 穷举，`rc(t)==rc(t%16)`）。
> 5. `IOSurface` 的 `+0xf1` 守卫：注册侧可达（sel 17），**注销侧不是 selector，内部路径**。
> 6. census 的分母是错的：`IOSurface` 实为 **60 个 selector**，不是 120。
> 7. 新发现：**`AGXAcceleratorG18P` type 33 是另一个 user client**，能进到权限检查。
> 8. `AppleSEPKeyStore` 全 170 个 selector 审完，**阴性**（5 类模式全部反证）。
> 9. 距离可用 PoC 仍很远；下面第 6 节直说差什么。
> 10. 所有数字可复查，产物路径见第 7 节。

---

## 1. 靶子记分板

| 靶子 | 可达性（真机实测） | 补丁定位 | 原语 | 状态 |
|---|---|---|---|---|
| **AppleAVE2Driver**（5×OOB write） | ❌ type 0..255 全失败 | ✅ 3 个具名检查函数 + 5 个调用点 | ❌ | **此路不通** |
| **AppleAVD** | ❌ 256 个 type 全 `NotPrivileged` | — | ❌ | 权限层就挡死 |
| **IOMobileFrameBuffer**（AppleCLCD2） | ✅ 0..255 全部可开 | ✅ 双管状态机全套 | 未证 | **在查**（race） |
| **IOSurface**（CVE-2026-112477） | ✅ type=0，实为 60 个 selector | ✅ `+0xf1` 守卫 | 未证 | 注册可达，**注销不可达** |
| **AppleM2ScalerCSCDriver** | ✅ type 0..255 全开 | ⚠️ 主题是**资源生命周期**不是边界 | ❌ | **本轮审完，阴性** |
| **Apple Neural Engine** | ✅ type=1/4 | ❌ 27.2 改动是 Exclave 架构新增，非边界检查 | ❌ | 降级 |
| **IOHIDFamily** | ✅ ×28 | ❌ 锁检测未覆盖（认不出 `IORecursiveLock*`） | ❌ | **未覆盖，非阴性** |
| **com.apple.kernel** | ✅ 系统调用面 | 部分（2 处真加锁） | ❌ | 6 条 UAF 无指纹 |
| **AppleSEPKeyStore** | ✅ 0..255 | — | ❌ | **阴性**（审计完成） |
| **AGXAcceleratorG18P** | ✅ type 1 / **33** / 65537 | 未做 | ❌ | **新面** |

---

## 2. 方法结论（这几条比单个靶子重要）

### 2.1 字符串差分是找补丁的最快路径
补丁常带新的 panic / 日志文案。两发两中：
- AVE2：`AVE_HEVC_CheckVPSExtBounds` / `AVE_Client_CheckMCTFInfo` / `AVE_Client_CheckLRMEInfo`，27.0.1 均为 0 次
- DCP：`establish_dual_pipe_pairing` / `teardown_dual_pipe_pairing` / `rejected swap_start`，27.0.1 均为 0 次

而且带出**断言的字面表达式**，等于直接给出被检查的字段名。

### 2.2 跨版本函数配对：只有一种方法被证实
| 配对法 | 结果 | 死因 |
|---|---|---|
| 指令序列掩码签名 | 14,348 对 / 0 差异 | **补丁本身插指令 → 被修的函数必然掉出配对集** |
| 字符串交叉引用 | IOSurface 配对 0 | 只有 133/1330 函数引用字符串，且互相重叠 |
| **序号对齐 + 长度校验** | **1,328/1,330 长度全等** | **可用** |

### 2.3 dChk（条件分支计数）有结构性盲区
| 苹果修复措辞 | 编译产物 | dChk 可见 |
|---|---|---|
| improved bounds checking | 新增 `cmp`+`b.hi` | ✅ |
| improved memory management (UAF) | 新增 `bl` retain/release | ❌ |
| improved locking (race) | 新增 `bl` lock/unlock | ❌ |

公告 141 条里 **17 条**落在「看不见」那一列。**此前所有「dChk=0 所以没补丁」的结论作废。**

### 2.4 census 的分母有两类结构性漏检
1. 只扫数据段的 `IOExternalMethodDispatch` 记录数组（24 字节步长）
2. **单个 34 KB 内联大函数**（`AppleSEPKeyStore` 的 169 个 handler 全内联，被当成「函数间空隙」）

### 2.5 ★ 已证伪：532 张「代码段派发表」不是派发表

**我此前把 `DISPATCH-SWEEP.md` 的 532 个 `ldrsw`+`adr`+`add`+`br` 点当成 census 的第三类盲区，这个判断是错的。**

判据（由 M2Scaler 审计提出，我在全内核验证）：

| 表项目标处的指令 | 含义 |
|---|---|
| `bti c` | **可被 `blr` 调用** → 函数入口 → 可能是真 handler |
| `bti j` | **只被 `br` 跳转进来** → 同一函数内的分支标号 → `switch` 的 case 体 |

全 581 个扫描点、**17,206 个表项**的结果：

```
bti j  17,206
bti c       0
```

**零个 `bti c`。** 逐 kext 也是 100%：`com.apple.kernel` 8,197、`IOHIDFamily` 1,032、`M2Scaler` 946、`PPMCPMS` 780、`H16ANEInterface` 484、`IOMobileGraphicsFamily` 454、`apfs` 364、`sandbox` 296、`SEPCredentialManager` 293、`JPEGDriver` 238、`AppleSEPKeyStore` 214……

**结论：这 532 张表全部是 C `switch` 被 lower 成跳转表的产物，背后没有任何隐藏的 selector 面。** 这条路作废，`S2-NOW.md` 早期版本里的「census 重合度 0 = 漏检」说法一并作废。

---

## 3. IOSurface `+0xf1` 这条线的确切边界

**已确证**：
- 27.2 在注销时置 `[obj+0xf1]=1`（`#802`），在注册时检查（`#799`），命中返回 `0xE00002D8`
- 27.0.1 **两处都没有** → 注销后重新注册**完全放行且返回 0**
- 注册侧 handler = **selector 17**，`stIn=24`，`IOServiceOpen(IOSurface, type=0)` 后可直接调
- 崩溃点候选 `0xb3d115c`（`node+0x10` 销毁）= `ldr x8,[x0]; ands x0,x8,#-4; b.eq; bl 0xabbfa68` → **释放 `node+0x10` 持有的引用**

**已否证 / 未证**：
- ❌ **注销侧 `0xa34b2dc` 不是任何 selector 的 handler**（120 行 census 里 0 条命中）→ 内部 teardown 路径
- ⚠️ `#802` 释放的只是 **node**，不释放 node 引用的 surface → **不能声称 UAF**
- ⚠️ 要触发「注销→再注册」，得让 surface 在注销后仍可用；这需要持有引用

**结论**：机制清楚，**但缺一环**——注销路径的用户可达性未证。这一环不补上，这条线不能升级为原语。

---

## 4. census 数据质量修正

`IOSurface` 的「120 个 selector」是**虚高**：

| 项 | 数 |
|---|---|
| census 报告 | 120 |
| 实际 | **60**（sel 0..59） |
| 后半 60..119 与前半逐项相同 | 仅 37/60 |
| 后半里 `handler=0xfffffe000a34aa64`（`return 0xE00002E2` 不支持桩） | **23 个** |

写点：`0xa34aa64` = `mov w0,#0xe00002e2; movk w0,#0xe000,lsl#16; ret`。

**此前标注的「疑似未拆分的双表」现在结案：是 over-read，不是双表。**

---

## 4.5 M2Scaler 审计结果（阴性，但给出方向修正）

`AppleM2ScalerCSCDriver`（可达，type 0..255 全开）本轮全审：

- **32 张表全部是编译器 `switch` 跳转表**，不是 selector 派发表（见 §2.5）
- **本 kext 根本没有 `IOExternalMethodDispatch` 记录数组**；`__DATA_CONST` 是 9,774 个 chained 指针组成的 vtable 海
- 真实 selector 面形态是 `switch(w1)`，12/32 张符合 externalMethod 的 ABI，**但可达性未证**（全是虚调用，`bl` 直接调用者为 0）
- 全 10,262 个函数中，**无一函数可证读 `structureInputSize`（`+0x38`）**
- 唯一候选 T1/T2/T3（`0x9082c8c` / `0x90f1ac8` / `0x9100b1c`）入口**无条件写 `[x2+0x1088]`**，全函数无尺寸比较；但这三个函数在 27.2 里**指令序列完全相同**（Apple 没修），且结构来源未证

**方向性修正（有价值）**：27.2 对 M2Scaler 的改动主题是**资源生命周期**——新增字符串是 `reclaiming PIODMA command`、`reclaimed %u PIODMA command(s)... refCount now %u`、`deferring arena release during flush`、`command %u sequence list spans two requests`，xref 落在 4 个**新增函数**上。**不是边界检查。** 若此 kext 有被修的内存破坏，更可能在新增的回收/引用计数逻辑（UAF / 重复释放），这一块**未审**。

**反假阳性记录**：`Histogram bin count (%d)` → `(%ld)` 只是 printf 宽度更正，检查本身是无符号 `cmp #8 / b.ls`，两版都正确，不作为安全修复。

---

## 5. 真机可达面（type 0..255 全量）

| 扫描范围 | 尝试次数 | 可开服务 | 可开类 | (服务,type) 组合 |
|---|---:|---:|---:|---:|
| type 0..3（旧） | 5,876 | 85 | 17 | 100 |
| type 0..15 | 23,504 | 85 | 17 | 161 |
| **type 0..255（全量）** | **376,064** | **85** | **17** | **1,362** |

- 靠 `type>3` 才能打开的服务：**0 个**
- 但 `(服务,type)` 组合数 **100 → 1,362（13.6×）**，每个组合是独立 user client 实例
- **`AGXAcceleratorG18P` type 33 是另一个子类**：selector 2 返回 `NotPrivileged`（type 1 同位是 `BadArgument`），哨兵位也不同
- **type 是位域编码**：AGX 另有 type `65537 = 1|0x10000`
- `AppleKeyStore` / `AppleCLCD2` / `AppleJPEGDriver` / `AppleM2ScalerCSCDriver`：`newUserClient` **不看 type**，0..255 全开

返回码更正：`0xE00002C2`=`BadArgument`，`0xE00002E2`=`NotPermitted`，`0xE00002BD`=`NoMemory`。

---

## 6. 距离可用 PoC 差什么（直说）

**差三步，每一步都不小：**

1. **一个真正可达的破坏点**。目前最接近的是 IOSurface 的 `+0xf1`，但它缺「注销侧可达」这一环；DCP 的 race 还在读。**没有这一步，后面都是空谈。**
2. **把状态机不一致转成内存破坏**。即使 `+0xf1` 那一环补上，`#802` 只释放 node；要变成越界写/UAF 需要 node 引用了什么被重复释放 —— 未读到。
3. **绕过 iOS 27 的利用硬化**。PAC（`autda`/`autibsp` 全在）、SPTM、`kalloc_type` 类型隔离、TXM。**这一层的难度不低于前两步。**

**另外必须说清楚**：即使 S2 打通，**S5（代码签名）在 iOS 27 上是架构性堵死的**——签名验证已移到 TXM，`dynamic-codesigning` / `cs.debugger` / `pmap.load-trust-cache` 三个 entitlement 我们一个都没有。所以「挖到能越狱的漏洞」这个目标，**光有 S2 不够**。

---

## 7. 产物索引

| 文件 | 内容 |
|---|---|
| `out/ADVISORY-iOS-27.2.md` | 公告整理版（141 条 / 163 CVE / 65 组件） |
| `out/KERNEL-UAF-SIG.md` | kernel 锁差分 + IOSurface 双表结案 |
| `out/IOSURFACE-F1.md` | `+0xf1` 守卫完整分析 |
| `out/AVE2-PATCH-LOCATED.md` | AVE2 三个检查函数 + 5 个调用点 |
| `out/AUDIT-SEPKEYSTORE.md` | 170 个 selector 全审（阴性） |
| `out/DISPATCH-SWEEP.md` | 532 个代码偏移派发点 |
| `out/UCALL-BASELINE.md` | type 0..255 全量可达性 |
| `out/reach.json` | 实测可达面（1,469 服务 × 256 type） |
| `out/v2701/` `out/v272/` | 8 个 kext 双版本对照 |
| `tools/lzfse_dec` | lzfse 解压器 |
| `tools/cdiff.py` | 调用目标差分 |

---

*结算时间：2026-11-01 11:40 (Asia/Shanghai)*
