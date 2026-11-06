# 工具学坑（会重复咬人的那些）

> README（10 行）
> 1. 本文记录**已被复现**的工具/方法陷阱，每条都咬过至少一次。
> 2. 开工前读一遍，能省几小时。
> 3. 所有条目都有具体的失败现象，不是理论警告。
> 4. 出现新坑就追加，不要另起文件。
> 5. 修复工具时同步更新对应条目。
> 6. 数字以本文为准，早于此的错误结论作废。
> 7. `tools/kseg.py` 是目前唯一可信的 VA↔fileoff 映射。
> 8. 判据纪律见第 4 节，那是假阳性的主要来源。
> 9. 跨版本配对见第 5 节，只有一种方法被证实可用。
> 10. 最后更新：2026-11-01。

---

## 1. VA ↔ fileoff 映射

### 1.1 `kdiff.slices()` 的 size 是错的
它用「下一个 entry 起点 − 本 entry 起点」当 size，**最后一个 entry 吃掉 63 MB**。
后果：拿它做 offset→kext 反查，会把全内核的命中错误归类（已复现：1,453 个 `BadArgument` 命中全被归到 `tmpfs`）。

**用 `tools/kseg.py`**，它按 `LC_SEGMENT_64` 的 `(fileoff, filesize)` 建索引（27.0.1 共 1,510 段 / 301 kext）。

### 1.2 `kext_extract.py` 不重写 `section_64.offset`
提取出的 Mach-O 里 section 偏移**仍指向原 kernelcache**。任何按 section 取表的代码读到 `None` 或垃圾。

**绕过：VA↔off 只走 segment，绝不用 section。**

### 1.3 `LC_FILESET_ENTRY` 是 `0x80000035`
不是 `0x1F`。而且 `fileoff` 在 `+16`（不是 `+8`），名字在 `+id_off`。
用错得 **0 个 entry**，且不会报错。

### 1.4 `LC_FUNCTION_STARTS` 是 `0x26`
`0x80000034` 是 **chained fixups**。用错得 0 个函数。

### 1.5 段大小要取 `min(vmsize, filesize)`
`vmsize` 常大于 `filesize`（bss 部分不在文件里）。只用 `vmsize` 会读到文件外。

---

## 2. 指针与数据

### 2.1 chained fixup 解码
```python
va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)
```
**绝不** `if v >> 63: continue` —— arm64e / 内核的 auth 指针最高位常为 1，这样写会滤掉全部。

### 2.2 kext 镜像与 kernelcache 的 `__DATA_CONST` 不一致
镜像里某些位置**全零**，cache 里同 VA 有数据。
**代码段用镜像，数据段必须用 `out/kc.*.full`。**

### 2.3 `md.disasm()` 遇到不可解码的 4 字节就停
一个 716 指令的函数可能只解出 299 条。
**必须重同步扫描**：每次前进 4 字节，能解就收，解不出就跳过。

---

## 3. 结构性误判（最贵的错误）

### 3.1 ★ 532 张「代码段派发表」不是派发表
`ldrsw`+`adr`+`add`+`br` 形态的表，判据是**表项目标处的指令**：

| 表项目标 | 含义 |
|---|---|
| `bti c` | 可被 `blr` 调用 → 函数入口 |
| `bti j` | 只被 `br` 跳进来 → **同一函数内的 switch case** |

全 581 个扫描点、17,206 个表项：**`bti j` 17,206，`bti c` 0**。
⇒ 这 532 张全是 C `switch` 被 lower 成跳转表的产物。**「census 第三类盲区」不成立。**

### 3.2 ★ 「stride 0x30 / 函数在 +0x08」的表大部分是假阳性
`IOExternalMethod` 记录确实是 48 字节、函数指针在 `+0x08`（AGX 表 A @ `0x7f20938` 已验证）。
但**不能只凭「指针指向 `bti c`」就认定**：必须加**计数合法性**（`+0x10..+0x2c` 必须是 8 个小整数）。

| | 加过滤前 | 加过滤后 |
|---|---|---|
| 表数 | 2,297 | **685** |
| 项数 | ~20,000 | **769** |

过滤前 `AppleMobileDispH18P-DCP` 报「230 项」，**实际 0 项**——那 230 项全是 `{ptr, fn, ptr, ptr, ...}` 别的结构。

### 3.3 `AppleSEPKeyStore` 是单个 34 KB 内联大函数
169 个 handler **全部内联在一个函数里**，census 把它当成「函数间空隙」，一个 selector 都看不到。

### 3.4 ★ 大步长采样会**混叠**小步长表
按 stride `0x30` 去扫一个实际是 stride `0x18` 的表时，会采到 `{P₁,C,P₂, P₁',C',P₂'}` 这种**同一三元组重复两遍**的形态，看起来完全像合法的 48 字节记录。

识别方法：**同一行里出现完全重复的三元组 ⇒ 真实步长是它的一半。**
```
80202abe03d7f48c 000c000300000006 8010bcad04138ea8  80202abe03d7f48c 000c000300000006 8010bcad03dc5760
└──────────── 0x18 ─────────────┘ └──────────── 0x18 ─────────────┘  ← 同一个表项
```
后果：`out/extmethod_tables.json` 里那 685 张「stride 0x30 表」有相当一部分是 0x18 表的混叠。

### 3.5 chained fixup 基址**是**全局常数（这条曾被我误判）
`0xFFFFFE0007004000 + (word & 0xFFFFFFFF)` 对 `com.apple.kernel` 和 kext **都成立**。
我曾因为算错一次把它当成「按 image 变化」，**该假设已被证伪**，不要改。

### 3.6 `sysent` 位置**仍未找到**（三种方法全失败）
`mov w0,#0x4e; ret`（`ENOSYS`）在 `com.apple.kernel.__TEXT_EXEC` 有 15 处（`0xb09d5ec` 起，间隔 12 字节），但**零个数据指针指向它们**。

三次失败尝试，别再重复：
1. **`sy_narg` 指纹**（`idx 1..7 = 1,0,3,3,3,1,4`，即 `exit/fork/read/write/open/close/wait4`）：stride ∈ {0x20,0x28,0x30,0x38} × narg 偏移 ∈ {0,4,8} 全组合，**0 命中**
2. **字符串 `sysent` / `kern_sysent` / `syscallnames`**：**0 处**（release 内核已剥）
3. **字符串 `unix_syscall` xref**：1 处（`0xfffffe00070b9aef`），仅 2 个引用点（`0xb262a50` 是参数拷贝辅助、`0xb26e060` 是字节数组解析循环），**都不是 `unix_syscall64`**

候选待验：`0x7eaee80`（`__DATA_CONST`，**stride `0x18`**，约 558 项，记录形态 `{fn, count, fn₂}`，见 3.4 的混叠说明）。
**下一步锚点建议**：别再猜步长，从 `sleh_synchronous` / `handle_svc` 那条异常入口链顺下来找表装载点。

### 3.7 `__LINKINFO` 有符号名但**没有地址**
`com.apple.kernel.__LINKINFO`（`0xfffffe000b9c4000`，298,280 B）是一个 **binary plist**：
```
SymbolsSets[9] → {CFBundleIdentifier, CFBundleVersion, Symbols[{SymbolName}]}
```
- `com.apple.kpi.bsd` 874 个、`com.apple.kpi.iokit` 2263 个、`com.apple.kpi.libkern` 878 个…共 5,000+ 个 KPI 名字
- **只有名字，没有任何地址字段** ⇒ 无法恢复 address→name
- 用途有限：可以确认某个 KPI 名字存在，但不能定位它

### 3.8 `OSMetaClass` 类名指针**找不到**
对 `AppleCLCD2` / `IOMobileFramebufferShim` / `IOSurface` / `AGXAcceleratorG18P` 四个类名字符串，在**全部 DATA 段**里按以下四种编码扫描：绝对地址、chained fixup（`KB+low32`）、low32 独立匹配、`rel32±`，**全部 0 命中**。

结论：iOS 27 的 `OSMetaClass` 不持有指向 `__TEXT` 里那份类名字符串的直接指针。**别再用「类名 xref」去定位 vtable。**



---

## 4. 判据纪律（假阳性的主要来源）

1. `ubfiz → cmp xN,wN,sxtw → csel 0x2bad` 是**范围闸不是容量闸**
2. 「乘法常数 + 移位异或 + 容量掩码」= 哈希函数，不是边界检查
3. `[MEM+…]` 位移成等差数列 = **结构体重排**；跨版本必须先钉住整体位移量
4. 带 `!` 的 `ldr x8,[x16,#0xd8]!` 是 vtable 预索引，不是字段读
5. `[x,#0x550]` 这类偏移**同时被当普通成员用**，不能当 vtable 槽判别器
6. **只统计一层 `bl` 会漏**：被 `b` 尾调、被虚表调用的都看不见（已咬两次）
7. `printf` 宽度更正（`%d`→`%ld`）**不是安全修复**
8. 「读到 `structureInputSize(+0x38)`」要手读确认，自动扫描必假阳性

---

## 5. 跨版本配对的唯一可用方法

### 5.1 已证伪的两条
| 方法 | 失败现象 |
|---|---|
| 指令序列掩码签名 | 补丁本身插指令 ⇒ **被修的函数必然掉出配对集**，「0 差异」是假象 |
| 字符串交叉引用 | 只有少数函数引用字符串，IOSurface 上配对数为 **0** |

### 5.2 可用的那条：**长度序列对齐 + 立即数集合 Jaccard 验证**
1. 取两版 `LC_FUNCTION_STARTS` 的长度序列
2. `difflib.SequenceMatcher` 对齐（**注意**：只在插入点会漂移）
3. 对每个候选配对算**立即数集合的 Jaccard 相似度**，`< 0.5` 一律否决

实效：
- `com.apple.kernel` 相似度 **0.9787**，等长块覆盖 **21,353 / 21,793 = 98.0%**，配对 **21,769 / 21,793 = 99.9%**
- Jaccard 否决了 112 个错配（其中就包括一个「332→5360、Δcond +208」的诱人假阳性，两个函数开头栈帧完全不同）

### 5.3 什么时候不能用
**某 kext 在两版之间函数总数变化较大时会整体漂移**：
- `AGXG18P` 27.2 多 21 个函数 ⇒ 纯序号对齐只有 11.7%，长度序列对齐后 4 个真 handler 仍全部配错
- 此时唯一可用的键是**语义槽位**（按表/槽号配对），配完 19/19 槽 counts 全同

### 5.4 内核函数配对覆盖率对比
| 方法 | 覆盖率 |
|---|---|
| A 早期的「调用目标多重集」 | 27%（363/1324） |
| **长度序列 + Jaccard** | **99.9%（21,769/21,793）** |

---

## 6. 动态探针纪律

### 6.1 返回码映射（按 `IOReturn.h`）
| 值 | 名 |
|---|---|
| `0xE00002C2` | `kIOReturnBadArgument` |
| `0xE00002C7` | `kIOReturnUnsupported` |
| `0xE00002E2` | `kIOReturnNotPermitted` |
| `0xE00002BD` | `kIOReturnNoMemory` |
| `0xE00002C1` | `kIOReturnNotPrivileged` |

### 6.2 哨兵判据：先测 selector 4095
| 哨兵返回 | 能否量出上界 |
|---|---|
| `Unsupported` | ✅ 能 |
| `BadArgument` | ❌ **不能**——整个 selector 空间全返回 `BadArgument`，「handler 存在」与「不存在」不可区分 |

不给 `BadArgument` 兜底的类编造上界。

### 6.3 「第一个 `Unsupported` 就是上界」会失效
`AppleCLCD2` 的 `Unsupported` 出现在有效区间**内部**（sel 1,2,36–40,45,46,76），之后 `BadArgument` 一直到 255。返回码**非单调**。

### 6.4 type 是位域不是序数
`AGXAcceleratorG18P` 有 type `1`、`33`、`65537 = 1|0x10000`。扫描只到 0..3 会完全看不到 type 33（那是另一个 user client 子类）。

### 6.5 每类实际可打开类型数（27.0.1 / 24A446 实测）
`AppleKeyStore` / `AppleCLCD2` / `AppleJPEGDriver` / `AppleM2ScalerCSCDriver`：`newUserClient` **不看 type**，0..255 全开。
实测上界：`M2Scaler` = **12**、`AGX` type 1/65537 = **56**、`AppleCLCD2` = **非单调，无单一上界**。

---

## 7. 已确认不可达（不要重复投入）

| 目标 | 阻断原因 | 证据 |
|---|---|---|
| `AppleAVE2Driver` | 256 个 type 全失败，`rc(t)==rc(t%16)` 逐条成立 | 2³² 内无新残类 |
| `AppleAVD` | 256 个 type 全 `NotPrivileged` | 权限层挡死 |
| `AppleM2ScalerCSCDriver` | 无 `IOExternalMethodDispatch` 数组；32 张表是 switch | 946/946 `bti j` |
| `AGX` 自有面 | 15/15 记录 `checkScalarInputCount=0`、`checkStructureInputSize=0` | 内核派发前就拒掉输入 |
| `AppleSEPKeyStore` | 170 selector 全审，无 `structureInput` 面 | 阴性 |
| `AppleJPEGDriver` | sel 8 的 4 字节尺寸翻转是**假信号**：handler 在 `ldr x0,[x0,#0xe0]; cbz` + `ldrb w8,[x1,#0x108]; tbz` 之后返回 `0xE00002BC`(=`kIOReturnError`)，**驱动没 ready，没走到读那 4 字节之后** | 见 `0x90164a8` |
| `AppleM2ScalerCSCDriver` 的 12 张 `switch(w1)` | 不是 selector 派发表——每个 case 把 `w1` 重写成常量（4/8/0x10/0x1b/0x55/0x5b）再尾调，且先 `stp xzr,xzr,[x0]; str xzr,[x0,#0x10]` 清零 24 字节输出结构，是**属性取值分发** | 见 `0x906af88` |

### 7.1 已确认不是 handler 的形态
`bti j` + `mov w1,#常量` + `b 共同尾调` ⇒ 属性取值器（property getter）。
共同尾调形如 `ldr x8,[x0,#8]; cmp x1,x8; b.ls` → `lsl x1,x1,#4` → 按 16 字节元素扩容的向量。


---

## 8. 动态探针（harness/fuzz2）的坑

### 8.1 ★ 串行派发队列被一次挂死永久占住 ⇒ 之后**所有**调用假超时

第一版把每次 `IOConnectCallMethod` 都派发到**同一个** `DISPATCH_QUEUE_SERIAL`。
`AGXAcceleratorG18P` sel 55 挂死后那条 block 永不返回，队列被永久占住：
**后续 11 个类、几百条用例全部记成 `TIMEOUT`**，看起来像设备整体挂了，实际是探针自锁。
`IOSurfaceClose` 也救不回来 —— 那条 block 还在队列里等。

修复：超时后**丢弃并新建队列**（`gQ = dispatch_queue_create(...)`），弃掉那一条和它的线程。
同一批修复前后：`70 条 / 13.1s`（几乎全是超时）→ **`4,459 条 / 0.2s`**。

### 8.2 超时后**不要** `IOServiceClose` 那条 conn

另一条线程还卡在里面，close 会把对象释放掉 → 自伤 UAF。弃 conn、换新队列即可；
一个 selector 一个 conn、用完即关，本来就不会把僵尸 conn 留在表里。

### 8.3 用例 key 必须包含内容，否则所有变体塌成一条

第一版 `keyOf` 只有 `class|type|sel|form|size|mut|scv|outcap|pass`，缺 `struct_in_hex`：
18 个 hex 变体在 `(class,type,sel,size,mut='-',pass=0)` 上**共用一个 key**，
只有第一个跑到，其余被判「已完成」跳过 —— 表面「跑了 192 条」，实际每个 hex 只落 1 次。
**改了 key 方案 ⇒ 旧进度全部作废**，必须 `RESET=1` 重跑并归档旧 ndjson。

### 8.4 `IOConnectMethodScalarIScalarO` 在 arm64 上不存在

`IOKitLib.h` 把它整段放在 `#if !defined(__LP64__)`（第 1474 行起，到 1640 的 `#endif`）。
arm64 上写这行直接 `call to undeclared function` 编不过。
现代设备只有 `IOConnectCallMethod` / `CallScalarMethod` / `CallStructMethod` / `CallAsyncMethod`。

### 8.5 输出容量是独立一维，而且**非零即拒**

`structureOutputSize` / `scalarOutputCount` 取 `1/8/4096` 时，多个 selector（含已证明内容敏感的
`M2Scaler` sel 7）一律 `kIOReturnBadArgument`。任何把 `out=4096` 写死的探针都会把整轮结果打成假阴性。
`AppleCLCD2` 的 11 个 selector 也是同样的塌陷。

### 8.6 设备被另一条战线共享时的三个硬坑

1. **容器 ID 每次变**：对方重装会换 `Data/Application/<UUID>`（见过 `72030EBA` / `58A51C4D` / `713D39A6`）并清掉 `tmp/`。
2. **launch 假成功**：`devicectl process launch` 报成功，但起来的是**对方的 App**（同一个 bundle id）。
   判据：**launch 后先看自己的 log 文件有没有新内容**。
3. **设备掉线**：`unable to locate a device matching the requested device identifier (ecid_...)`，
   `list devices` = `unavailable`，此时 install / launch / copy 全失败。轮询到 `available` 再继续，不要当自己的 bug 追。

对策：每次启动前 `BUILD=1` 重装自己的包；启动前把上一批 ndjson push 回设备做断点续跑（幂等）。

### 8.7 `IOServiceOpen` 的 `type` 是**掩码**，不是序数

41 个 type × 39 个类实测：`AGXAcceleratorG18P` 接受 1 / 33 / 65537(`0x10001`) / 131073(`0x20001`)，
后两者的 257 个 selector 返回值与 type 1 **逐条一致**（含 sel 22 内部 `Unsupported`、sel 55 挂死）；
`0x10000` / `0x20000` / `0x20002` / `0x8000` / `0x10000000` 全拒 ⇒ 门控只看**低字节**。
所以「新 type 可开」不等于「新面」，必须拿 selector 表逐条比对才能判定别名。

---

## 坑 N+1：内核缓存的数据段里**没有裸指针**，是 chained fixups（2026-11-01）

**症状**：对 `com.apple.kernel` 的 `__DATA_CONST` 直接按 64 位裸值搜索「某函数地址」，永远返回 0 命中。

**实测**：
```
com.apple.kernel __DATA_CONST  165,831 槽   裸值落在 0xfffffe0007..~0xfffffe000c.. 区间: 0 个 (0.0%)
```

**原因**：指针以 `dyld_chained_ptr_64_rebase` 编码存放：
```
target : bits 0..35    (36 位，相对 image base 的偏移)
next   : bits 51..62
bind   : bit 63        (1 = 绑定到导入符号，不是 rebase)
```

**正确解码**：`va = 0xfffffe0007004000 + (w & 0xFFFFFFFFF)`（`BASE` = 项目 KB_BASE 未滑动基址）。

**验证（必须做，否则全是假阴性）**：
```
解码后落在内核镜像内的比例: 157,784 / 186,311 = 84.69%   ← 方法成立
```

**抽样 120,775 个 `__DATA_CONST` 槽位的落段分布**：
```
BIND            71,437   59.1%   ← 导入符号，启动时解析，静态不可见
?               37,659   31.2%   （落在已知段范围外，需再查）
__TEXT           7,563    6.3%
__DATA           1,701    1.4%
__DATA_CONST     1,356    1.1%
__TEXT_EXEC      1,059    0.9%   ← 只有这些是「直接指向代码」的 rebase
```

### 两个直接后果

1. **跨 kext / 跨内核的引用，59% 是 BIND**，目标由启动时解析 ⇒ **静态搜索必然 0 命中，这不是"没有引用"**。
2. 因此**「零引用 ⇒ KPI 导出 / 死代码」这个推论只在同 kext 内成立**。跨 kext 的必须走 chained-fixups 的 imports 表（ordinal → 符号名）才能定。

### 已作废的结论

- 「IOSurface 的 `0xa34b2dc` / `0xa3338cc` / `0xa346364` 零引用 ⇒ KPI 导出」—— **方法不成立，结论无依据**（可能仍是 KPI，但没被证明）。
- 「AppleAVD `0x86b49d0` 零引用 ⇒ 不可达」—— 同上。
- 所有基于「数据槽 PAC 掩码搜索 = 0」的可达性判定，**一律需要重做**。

### 正确的下一步

要建立跨 kext 可达性，必须解 `LC_DYLD_CHAINED_FIXUPS` 的 **imports 表**（ordinal → 符号名）。这是唯一能拿到跨 kext 符号级引用的静态途径。

---

## 位运算读错：`BIC` 被读成「允许这几位」

**症状**：把 `bic w9, #0xC0, w1` 读成「`w1` 只允许 `0xC0` 这几位」，并据此推出
「后续抽 bit9/bit10 的代码变死代码」，连锁作废两条推论。

**真值表**：`BIC Wd,Wn,Wm` = `Wd = Wn AND NOT Wm`。
`w9 = 0xC0 & ~w1`，`cbnz w9 → 拒绝` 非零 ⇔ `0xC0` 里有一位不在 `w1` 中
⇔ **`w1` 必须同时置位 bit6/bit7（`w1 & 0xC0 == 0xC0`，必备位）**。

**规则**：读 `BIC` / `TST` / `ANDS` / `BFXIL` 这类位运算，**先写出真值表再下结论**。
「允许哪些位」和「必须含哪些位」是相反的结论，一个字符之差。

## 「这个对象是什么」的判定顺序

**先看 `+0x00` 是不是 PAC 签名的 vtable 且被 `autda` + `blraa` 调用。**

```
是  -> 内核 C++ 对象（libkern / IOKit 基类族），不要按 BSD 结构体去猜
否  -> 再看字段布局（+0x00 指向自身结构 / 偏移组合 / 原子字段）
```

比按偏移猜可靠得多。判据出处：`0xb348450` 的 `ldr x16,[x0]` / `autda x16,x17` / `blraa x8,x16`。

## `movz` 被 capstone 显示成 `mov`

**症状**：按 `x.mnemonic == 'movz'` 匹配「构造某个大常量」的指令，**全库零命中**，
而字节级扫描同一个常量却有 1651 处。

**原因**：`MOVZ Wd,#imm16,lsl #0` 是 `mov` 的规范别名，capstone 优先显示 `mov`。
只有 `movz` 带非零 `lsl` 时才显示成 `movz`。

**规则**：做指令形态匹配时，`mov` / `movz` **两个助记符都要接受**，
或者干脆按 **32 位编码**匹配（`movz w`: `(w & 0x7F800000) == 0x52800000`；
`movk w,lsl#16`: `(w & 0x7FE00000) == 0x72A00000`）。按助记符单挂 `movz` 必得假阴性。

## 形态签名扫描必须先跑已知正例

**症状**：写了「全库三件套形态扫描」，定义成「同一函数内同时有 `strb` 写标记和
`ldrb` 读门在同一归一化偏移」，跑完 301 个 kext —— **已知正例 IOSurface `+0xf1` 没命中**。

**原因**：`+0xf1` 的真实形态是**跨函数配对** —— 一个函数写标记，另一个函数读门，
同一结构体字段。写成「同一函数内」就必然漏掉唯一的正例。

**规则**：形态扫描**先跑正例再跑全库**。正例不命中 = 扫描定义错了，
此时全库输出一律作废，不许拿来下「没有第二处」的结论。
（这是本项目第三次栽在「搜索返回 0 却不先验方法」上。）

## 序列对齐的元素键不能容忍不了内容变化

**症状**：想找出「新增函数」，用 `(size, 归一化 body 的 sha1)` 做序列元素跑
`difflib.SequenceMatcher`，得到 3996 插入 / 3946 删除 —— 而函数数只净增 50。

**原因**：精确 body 哈希要求「一个字节都没变」才认得出是同一函数。
**改过一条指令的函数全部被读成「删除 + 插入」**，噪声是信号的 80 倍。

**规则**：找新增函数时，序列元素键要**粗**：

```
键 = (体积 // 32, 前 6 条指令的助记符序列)
```

这样 body 内部变化不影响对齐，只有真正凭空多出来的才成为纯插入段。
实测同一份数据：精确哈希 3996 个 vs 粗键 **54 个**（净增 50，对得上）。
**判据：插入数 − 删除数 必须与函数数差值吻合，否则方法就是错的。**

## chained fixups 解码：位宽 + 撒网式扫描，两个错叠在一起

**背景**：本项目早期得出「数据段槽里 59.1% 是 BIND，跨 kext 引用静态不可见」，
这个结论压了后面至少四轮判断。**它是两个错误叠加的产物，已撤回。**

**错一：target 位宽。**

```
通用 arm64e 布局  target = bits 0..35
本机真实格式     pfmt = 8 = DYLD_CHAINED_PTR_64_KERNEL_CACHE
   target    : bits 0..29   (30 位)
   cacheLevel: bits 30..31  ( 2 位)   <- 被 36 位方案吞进 target
   diversity : bits 32..47
   addrDiv   : bit  48
   key       : bits 49..50
   next      : bits 51..61  (11 位)
   isAuth    : bit  62      (没有 bind 位)
```

用 36 位解，`cacheLevel` 被当成目标地址的一部分 ⇒ **解出的 VA 全错 ⇒ 搜索恒返回 0**。

**错二：把 `__DATA_CONST` 每个 8 字节字都当 chained 指针。**

chained fixups 是**稀疏的** —— 只有 starts 表登记过的槽才是指针，其余是普通数据
（长度、常量、整数）。对这些垃圾值取 `(w>>63)&1`，自然约一半为 1。
**那不叫 BIND，那叫随机。**

**规则**：
1. 先读 `dyld_chained_starts_in_segment.pointer_format`，**按格式查位宽表**，不要套通用布局。
2. **只遍历 starts 表登记的槽**，绝不对整个段做「每个 8 字节都是指针」的扫描。
3. 正例验证必须包含一个**已知有多处引用**的目标（本项目用 `0xb348450`，命中 12 槽）。
4. `imports_count == 0` 且格式无 bind 位时，**不存在跨 kext bind** —— 这不是「不可见」，是没有。

## vtable 归属不能靠「连续同 kext 指针段」

`__DATA_CONST` 里的指针在 chained fixups 下**天然连续**（链按页串），
vtable 之间的边界不体现为链中断。所以「一段连续同 kext 指针」不等于一个 vtable
（实测 IOSurface 那段有 188 项，不可能是单个 vtable）。

**正确做法**：靠 `OSMetaClass` / 类名字符串引用定位 vtable 起点，
再由起点算槽序号。**没有起点就不要报「第几项」**。

## 坑 N+2：函数指针表指向 `bti c`，不指向函数体

arm64e 上函数入口是 `bti c`，但**函数体第一条实质指令在它之后 4 字节**。
`IOExternalMethodDispatch` / vtable 里的指针指向的是 **`bti c` 本身**。

按「函数体首条指令地址」去搜数据槽，会得到 0 命中 —— 本项目里
`wrapA 0xa3498f8` 因此一度被判「零引用、不可达」。

**正确做法**：两种地址都搜（`addr` 与 `addr-4`），或者直接以 `bti c` 的位置作为函数标识。

**实例**：
```
wrapA  bti c 在 0xa3498f4   <- 表里存的是这个
       函数体  在 0xa3498f8
按 0xa3498f8 搜 -> 0 命中（错）
按 0xa3498f4 搜 -> 命中 off 0x137bcb8（对）
```
