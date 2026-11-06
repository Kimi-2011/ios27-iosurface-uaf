# AUDIT-AGX-TYPE33 — AGXAcceleratorG18P type 33 审计

> **README（10 行）**
> 1. 目标：`AGXAcceleratorG18P` 的 **type 33**（真机扫描新发现、旧 type 0..3 扫描不可见的另一 user client 子类）。
> 2. 样本：`out/v2701/AGXG18P.macho`（27.0.1）与 `out/v272/AGXG18P.macho`（27.2）。**未标版本的地址一律为 27.0.1。**
> 3. 函数边界：`LC_FUNCTION_STARTS` + ULEB128 delta，base=`__TEXT` vmaddr；自证：首项 == `__TEXT_EXEC` vmaddr。27.0.1 = 3,421 函数 / 27.2 = 3,442 函数，两版**自证均通过**。
> 4. 指针解码：`va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)`，**从不**用 `if v>>63: continue` 丢项。
> 5. 结论一：AGX 的 `externalMethod` 是 **`0xfffffe00084f1fb4`**（52 B，纯转发），位于 vtable `0x7f207b0`；它一次都不碰 `args`，这就是"`cmp w1,#N` + `ldr [x2,#0x10]` + `ldr [x2,#0x30]` 零命中"的原因。
> 6. 结论二：AGX 自有的 selector 面是 **`0x100..0x112` 共 19 槽（15 个有 handler，4 个空）**，步长 0x30、fn 在 +0x08；真机探针扫的 `0..15 / 4095` **完全没进这块空间**。
> 7. 结论三：表 A 全部 15 条记录的 `checkScalarInputCount=0`、`checkStructureInputSize=0` ⇒ 内核在派发前就拒掉任何输入，**该面不存在用户可控的索引/长度/计数**。仅 selector `0x107` 解引用 args 内一个指针（读 3 个 u64、不读计数位）——**留白，不判漏洞**。
> 8. 交叉版本：表 A 19/19 槽 counts 与长度全同、12/15 handler 逐字节相同、另 3 个归一化后相同（纯重定位）⇒ **audited 面在 27.0.1→27.2 未变**。
> 9. 27.2 唯一实质新增：`AGXUMASyncNodeCommandDescriptor::prepare(uint32_t)`，含 `array[index]` 只做 32 位溢出守卫、**无上界检查**；但从被审面 3 层调用图不可达 ⇒ 记为后续目标，不当成本轮结论。
> 10. 方法学纠错两条（可复用）：`tools/kext_extract.py` 不重写 `section_64.offset`；`kdiff.slices()` 的 size 用"下一个起点差"导致 offset→kext 映射全错。详见 §0。

---

## 0. 方法与工具学（两条会直接导致错结论的坑）

### 0.1 提取出的 Mach-O：section 偏移是陈的

`tools/kext_extract.py` 只补丁了 segment `fileoff`、`LC_FUNCTION_STARTS`、`LC_SYMTAB`，**没有重写 `section_64.offset`**。
后果：`__const` 的 `section.offset` 仍指向原始 kernelcache（例如 `0x1f2aaa0` 远超切片长度），任何按 section 取数据表偏移的代码读到 `None` 或垃圾。
本轮处理：`tools/agx.py` 的 `va2off/off2va` **只走 segment**（`seg.foff + (va - seg.vm)`），并在注释里记录该前提。

### 0.2 `kdiff.slices()` 不能用来做 offset→kext 映射

`slices()` 的 size 取"下一个 entry 的 fileoff 起点差"，最后一个 entry（`com.apple.filesystems.tmpfs`）因此吃掉 63 MB 尾巴。
用它做映射时，**全内核 1,453 个 `kIOReturnBadArgument` 命中全部被归到 tmpfs**（44/73/1453 三个错误码全部 100% 落在一个 kext 上）——明显的信号错误。
正确做法：建 **segment 级** `(fileoff, filesize) → (kext, segname, vmaddr)` 索引（27.0.1 共 1,510 段），offset 命中后 `va = vmaddr + (off - fileoff)`。校验点：AGX `__TEXT_EXEC` file `0x14ad960` → vm `0xfffffe00084b1960`，与切片头一致。
修好后的分布才有意义（`NotPrivileged` 44 处里 AGX 占 **3** 处，全部落入同一个函数，见 §3）。

### 0.3 跨版本函数配对：任务单给的两条路都不成立

- **序号对齐 + 长度校验**：27.2 多出 21 个函数，插入点之后全体移位；实测可配对 714 条，其中 2,707 条长度不一致无法配对，而表 A 的 4 个真 handler 全部配到**错误**函数（如 `0x84f14d4`(2108 B) 被配到 `0x8509eec`(16 B)）。
- **整段平移对齐**（`__TEXT_EXEC` delta `0x18000`）：3,421 个函数里只有 **38** 个能在 27.2 找到"平移 + 同长"对应，其中 16 个字节完全相同。整个 kext 是重新排布的，不是平移。

⇒ 可行的配对键是**语义槽位**（派发表槽号），并用 counts/长度作闸门。见 §4，19/19 槽全对上、extra 字段逐一相等，属于自证式配对。

---

## 1. 问题一：AGX 真正的 `externalMethod` 在哪？

### 1.1 位置与形态

```
0xfffffe00084f1fb4  (52 B)  ← AGX 的 externalMethod override
  bti c
  cmp  w1, #0x107                       ; selector == 0x107 ?
  adrp x8, #0xfffffe0007f20000
  add  x8, x8, #0xcc8                   ; &B[1]
  csel x4, x0, x4, eq                   ; target      = this
  csel x3, x8, x3, eq                   ; dispatch    = 0xfffffe0007f20cc8
  adrp x8, #0xfffffe0007f35000
  ldr  x8, [x8, #0x7d8]                 ; __got → 类引用（父类 vtable 地址点）
  add  x6, x8, #0x550
  ldr  x16, [x8, #0x550]                ; 父类 externalMethod
  movk x17, #0xb352, lsl #48
  braa x16, x17
```

**它一次都不读 `x2`（args）**，只做两件事：selector==0x107 时把 `dispatch` 换成 `B[1]` 并把 `target` 换成本对象，然后把一切原样转交父类。
这就是"按 `cmp w1,#N` + `ldr x?,[x2,#0x10]` + `ldr x?,[x2,#0x30]` 找 AGX `externalMethod` 全 0 命中"的**结构性原因**——不是没找到，而是 AGX 的这个 override 本来就不碰参数。真正读 args 的是**内核的 `IOUserClient::externalMethod`**，它拿 `getTargetAndMethodForIndex` 返回的记录做计数校验后才调 handler。

### 1.2 为什么能确定它属于同一个 user client 类

- `externalMethod` 作为数据出现在 **`0x7f207b0`**（全二进制仅此一处）；
- `getTargetAndMethodForIndex` 出现在 **`0x7f20820`**（全二进制仅此一处）；
- 两者相差 `0x70` = **14 个 vtable 槽**，而两处尾调代码用的槽位移恰好是 `0x550` 与 `0x5c0`，差也是 `0x70` ⇒ 同一张 vtable，槽位一致，互相印证。

### 1.3 `0x550` 不能当判别器（纠错）

`[x,#0x550]` 全 kext 有 **351** 处——`0x550` 同时也是普通结构成员偏移。而 `[x,#0x5c0]` 只有 **4** 处，其中只有 `0xfffffe00084f0a54` 是 `getTargetAndMethodForIndex` 的尾调：
`0x84b1b9c`(5944 B)、`0x84f0a54`(100 B)、`0x853689c`(5748 B)、`0x856ca00`(1744 B)。
⇒ **AGX kext 内只有一个 `getTargetAndMethodForIndex` override**，也就是只有一张自建派发表。

### 1.4 27.2 的对应

`0xfffffe000850aef4`，结构完全相同，`cmp w1,#0x107` → dispatch = **`0x7f34cf8`**（= B 基址 `0x7f34cd0` + 0x28，即 B[1]）。

---

## 2. 问题二：type 33 的 selector 面有多大？有哪些 handler？

### 2.1 表 A：`getTargetAndMethodForIndex`（`0xfffffe00084f0a54`，100 B）

```
bti c
str  x0, [x1]                 ; *targetP = this
sub  w8, w2, #0x100           ; index = selector - 0x100
cmp  w8, #0x12                ; bound 0x12
b.hi fallback
mov  w9, #0x30
adrp x10, #0xfffffe0007f20000
add  x10, x10, #0x938         ; 表基址 = 0xfffffe0007f20938
umull x9, w8, w9
cmp  x9, w9, sxtw             ; 乘法溢出守卫
add  x8, x10, w9, sxtw
add  x16, x10, x9
movk x16, #0x2bad, lsl #48
csel x8, x8, x16, eq          ; 溢出 → 毒指针
ldr  x9, [x8, #8]             ; 取 fn
cbz  x9, fallback             ; fn==0 → 落回父类
mov  x0, x8
ret
fallback: 父类 getTargetAndMethodForIndex（槽 0x5c0，disc 0xbdaa）
```

- 记录布局：**步长 0x30（48 B）**，`fn` 在 **+0x08**，counts 在 `+0x10/+0x18`，另有 `+0x20/+0x28` 两个附加字段。
- 注意 `w8 = selector-0x100` 是**范围门**（`cmp w8,#0x12`），不是容量门——`umull`+`cmp`+`csel 0x2bad` 才是容量/溢出门。

### 2.2 表 A 逐槽（19 槽，selector `0x100..0x112`）

| sel | handler | 长度 | counts (sIn,stIn,sOut,stOut) | extra(+0x20,+0x28) |
|---|---|---|---|---|
| 0x100 | `0x84f1de0` | 52 | (0,0,3,0) | (0,152) |
| 0x101 | `0x84f1dac` | 52 | (0,0,3,0) | (0,160) |
| 0x102 | `0x84f1d78` | 52 | (0,0,3,0) | (0,456) |
| 0x103 | `0x84f1d44` | 52 | (0,0,3,0) | (0,32) |
| 0x104 | `0x84f1d10` | 52 | (0,0,3,0) | (0,16) |
| 0x105 | `0x84f14d4` | 2108 | (0,0,3,0) | (72,72) |
| 0x106 | `0x84f14a0` | 52 | (0,0,3,0) | (0,8) |
| 0x107 | — | — | 空 | 由 `externalMethod` 特判接管 → `B[1]` |
| 0x108 | — | — | 空 | — |
| 0x109 | `0x84f0ff0` | 1200 | (0,0,3,0) | (8,8) |
| 0x10a | `0x84f0fbc` | 52 | (0,0,3,0) | (0,16) |
| 0x10b | `0x84f0fac` | 16 | (0,0,3,0) | (16,16) |
| 0x10c | `0x84f0f9c` | 16 | (0,0,3,0) | (16,0) |
| 0x10d | `0x84f0b54` | 1096 | (0,0,3,0) | (8,8) |
| 0x10e | — | — | 空 | — |
| 0x10f | `0x84f0b20` | 52 | (0,0,3,0) | (0,32) |
| 0x110 | `0x84f0aec` | 52 | (0,0,3,0) | (8,0) |
| 0x111 | — | — | 空 | — |
| 0x112 | `0x84f0ab8` | 52 | (0,0,3,0) | (0,432) |

**自证**：`0x107` 在表 A 里是空的、而 `externalMethod` 恰好特判 `0x107` —— 两条独立证据对同一个槽给出同一解释。
（`0x108/0x10e/0x111` 是真空：`externalMethod` 不特判它们，`getTargetAndMethodForIndex` 会因 `fn==0` 落回父类。）

### 2.3 handler 分类（按是否接触 args）

逐个扫 15 个 handler 的 `[x?, args_offset]` 读写（偏移表用项目实测值：`+0x10` async 指针、`+0x18` scalarInput packed、`+0x20` scalarInput64、`+0x30` structureInput、`+0x38` structureInputSize、`+0x48` scalarOutput、`+0x50` scalarOutputCount、`+0x58` structureOutput、`+0x60` structureOutputSize）：

- **11 个是转发 thunk（16–52 B）**：`ldr x16,[x0]; autda; add #imm; ldr x8,[x16]; braa` —— 只是跳到本类 vtable 的另一槽（`+0x5e8 / +0x5f0 / +0x628 …`），**完全不碰 args**。
- **3 个纯输出 getter**：
  - `0x105`(2108 B) 读 `args+0x40`(descriptor)、`+0x48`、`+0x50`、`+0x58`、`+0x60`；
  - `0x109`(1200 B) 读 `+0x48`、`+0x60`；
  - `0x10d`(1096 B) 读 `+0x48`、`+0x50`、`+0x60`。
- **1 个解引用 args 内指针**：`0x107` → `B[1]` = `0x84f1fe8`(228 B)，见 §3.2。

### 2.4 与真机观测的接口（重要）

真机 `reach.json` 的探针 selector 是 **0..15** 与 **4095**；AGX 自建面是 **0x100..0x112**，两者**不相交**。
所以真机看到的 `type 1 → BadArgument×16（哨兵 Unsupported）` / `type 33 → selector 2 NotPrivileged`、`sentinel 4095 → BadArgument`，**全部产生于父类的 `getTargetAndMethodForIndex` + 内核的计数校验**，不是 AGX 表 A 的行为。
换言之：**"selector 2 返回 NotPrivileged" 无法用表 A 解释，本轮不解释它**（见 §3.4 的留白）。

---

## 3. 问题三：type 33 里有没有用户可控的内核内存破坏？

### 3.1 表 A：结构性否定（这是本轮最硬的结论）

15 条记录的 `checkScalarInputCount = 0`、`checkStructureInputSize = 0`。
内核 `IOUserClient::externalMethod` 在调 handler 前按记录做四项计数校验：调用方一旦传入任何 scalarInput / structureInput 就会被 `0xE00002C2` 拒掉，handler 根本进不去。
⇒ 表 A 的 15 个 handler **拿不到任何用户字节**；3 个真 handler 只写 scalarOutput / structureOutput。
⇒ 该面**不存在用户可控的索引、长度、计数**，也就没有 OOB / 整数溢出 / 未校验索引的入口。**否定，且是结构性的，不依赖逐个函数读完**。

### 3.2 selector `0x107`（`0x84f1fe8`）：唯一有指针解引用的地方

```
ldr  x21, [x2, #0x10]          ; args+0x10 → 指针型 async 字段
cbz  x21, fail                 ; 只判 NULL
ldr  x20, [x0, #0x120]
ldr  x0, [x20, #0x168]; bl lock
ldrb w8, [x20, #0x170]; tbz w8, #0, ok
   ... unlock ; add w19,w19,#7 ; ret 0xE00002C9
ok:
ldp  x1, x2, [x21]             ; 读 [x21] , [x21+8]
ldr  x3, [x21, #0x10]          ; 读 [x21+0x10]   ← 共 24 字节
add  x0, x20, #0x128
bl   0x858806c                 ; (obj+0x128, u0, u1, u2)
```

- 事实：**读完 24 字节，全程没有读 `+0x18`/`+0x28` 一类计数位**，也没有和任何 bound 比较。
- 事实：该字段是**指针型**（因为紧接着被 `ldp/ldr` 解引用）。项目 `AUDIT-IMAGE-VIDEO.md §0.4` 把 `+0x10` 标为 `asyncWakeTarget`（依据是 H16Cam sel6 `ldr x4,[x2,#0x10]` 把它当整数用）——**两种用法并存于同一偏移**，说明该偏移在不同调用路径下语义不同（同步路径给整数 wake target、异步路径给引用数组指针），仅凭现有样本无法定死。
- ⇒ **留白**：这是否构成越界读，取决于内核侧 `is_io_connect_*_method` 给该缓冲分配的**固定容量 vs 用户给定 count**。本轮未读 `com.apple.kernel` 的该函数，**不判定为漏洞，也不排除**。下一步只需一处证据：`com.apple.kernel` 里 `IOExternalMethodArguments.asyncReference` 的拷贝缓冲大小是常量还是 `asyncReferenceCount`。

### 3.3 27.2 新增：`AGXUMASyncNodeCommandDescriptor::prepare(uint32_t)`

字符差分（27.2 新增 10 条 / 消失 3 条；其中非签名串 7 条，含 1 条编译时间戳）：

```
+ AGXUMASyncNodeCommandDescriptor
+ site.AGXUMASyncNodeCommandDescriptor
+ agxk_uma_sync_node_command.cpp
+ virtual IOReturn AGXUMASyncNodeCommandDescriptor::prepare(uint32_t)
+ mmuReqsThreshold
+ DSF Pause Timeout
+ Oct 13 2026 21:05:45          （编译时间戳）
- Aug 13 2026 21:42:13
（另 4 条超长 1/2 数字串是 kalloc_type 的签名序列，只有一位变化）
```

沿新增签名串反查，落到 `0xfffffe0008596184`（956 B，vtable 槽 `0x7f42c28` 唯一引用），断言三件套自证身份：

```
格式  @0x713bd6c  "AGXk: %s:%d:%s: !!! queue->getFreeEntries() < AGXK_MAX_KSM_KICK_QUEUE_ENTRIES_PER_CMD"
文件  @0x713bdc3  "agxk_uma_sync_node_command.cpp"
行    #0x7d = 125
函数  @0x713bde2  "virtual IOReturn AGXUMASyncNodeCommandDescriptor::prepare(uint32_t)"
```

带下标访问的那段：

```
ldr  x8,  [x19, #0x10]
ldr  w9,  [x19, #0x3fc]              ; index（u32 字段）
add  x8,  x8, #0x11, lsl #12
add  x8,  x8, #0x798                 ; array = pDev + 0x11798
lsl  x9,  x9, #3
cmp  x9,  w9, sxtw                   ; 只做 32 位乘法溢出守卫
add  x10, x8, w9, sxtw
add  x16, x8, x9
movk x16, #0x2bad, lsl #48
csel x10, x10, x16, eq
ldr  x8,  [x10]                      ; q = array[index]     ← 无上界检查
add  x9,  x8, #0x44
ldar w9,  [x9]
ldr  w10, [x8, #0x10]
sub  w9,  w10, w9
and  w9,  w9, #0xffff
cmp  w9,  #4
b.ls panic                           ; 触发上面那条断言
```

- **无上界检查是真的**（只有 `umull`/`sxtw` 那条 32 位溢出守卫，形式和表 A 的容量门一样，但这里后面没有 bound 比较）。
- **但本轮不算它是 type 33 的漏洞**：`index` 来自 `[x19,#0x3fc]`，该偏移在 27.2 全 kext 只有 **1 处写入**（`0xfffffe00084f8d00 str w1,[x20,#0x3fc]`，27.0.1 里该偏移 0 处写入 ⇒ 是新对象布局），其上游是否为用户可控**未证**；且从被审方法面出发做 3 层调用图 BFS：

  | 入口 | 3 层内可达函数数 | 是否可达新 `prepare` |
  |---|---|---|
  | sel 0x105 | 69 | 否 |
  | sel 0x107 | 7 | 否 |
  | sel 0x109 | 9 | 否 |
  | sel 0x10d | 17 | 否 |

  ⇒ **不可达，落在本轮被审面的爆炸半径之外**。记为后续目标（配套问题：`[x19,#0x3fc]` 的赋值来源）。

### 3.4 关于 `NotPrivileged`：找到了门，但没接上链路（留白）

全内核 `return kIOReturnNotPrivileged` 共 44 处，AGX 占 **3** 处，且**全部落在同一个函数** `0xfffffe00084f0948`（268 B）：

```
w0 = 0xE00002C1                        ; 默认返回值就是 NotPrivileged
ldrb w8, [x21, #0x130]                 ; 缓存位
tbnz w8, #0, skip_check
ldr  x0, [x21, #0x120]
adrp x1, #0xfffffe000712c000
add  x1, x1, #0x163                    ; 字符串 → "com.apple.internal.display-params-access-privileged"
bl   0x8587f2c                         ; entitlement 检查
tbz  w0, #0, deny                      ; 不满足 → strb wzr,[x21,#0x130]; ret NotPrivileged
  ... 取锁、cset 缓存、解锁
deny: ret 0xE00002C1
[转发路径] ldr x8,[x21,#0xf8] ; 经 [x8+0x388] 对象 vtable+0xe8 做 runAction(fn=0x84cc968, ...)
[空指针] 返回 0xE00002C9
```

- 身份：一个**特权门 + 序列化 wrapper**，entitlement = `com.apple.internal.display-params-access-privileged`（同页字符串里还有 `AGXDeviceUserClient`、`site.AGXDeviceUserClient`、`AGXDiagnosisReport`）。
- 它以数据地址 `0x7f20850` 出现在一段连续 code 指针串里（形态像 vtable 槽，但 vtable 身份见 §5.6 的保留），**不是派发表项**；`bl` 直接调用者 **0** 个。
- ⇒ **留白**：真机 selector 2 的 `NotPrivileged` 走的不是表 A（探针范围不相交），本轮**没有证据**把 selector 2 接到这个门上。同时，AGX 字符串里只出现 **1** 个 user client 类名（`AGXDeviceUserClient`），但"没有名字"≠"没有类"（只有用了 `kalloc_type` 的类才会留名），所以"type 33 = 另一个 user client 类"这条假设**仍然开放**，未证否也未证实。

---

## 4. 27.0.1 → 27.2 交叉版本差分（按语义槽位配对）

- 段增量：`__TEXT +0x4000`、`__TEXT_EXEC +0x18000`、`__DATA_CONST +0x14000`、`__DATA +0x58000`、`__LINKEDIT +0x5c000`。
- 表 A 基址：`0x7f20938` → **`0x7f34968`**（注意不是简单平移 `+0x14000`，多了 0x30 ⇒ 表前插了一条 0x30 记录，与 B 表同步位移一致）。
- **19/19 槽**：counts 全同、extra 全同、handler 长度全同。
- handler 体：**12/15 逐字节相同**；`0x105 / 0x109 / 0x10d` 字节不同但**归一化（抹掉 PC 相对立即数）后完全相同**、指令数一致（527/527、300/300、274/274）⇒ 纯重定位，不是逻辑改动。
- `externalMethod` 特判 `0x107` 与 `B[1]`：27.2 = `0x850aef4` / `0x7f34cf8`，`0x84f1fe8 → 0x850af28`（归一化 57/57 相同）。
- 唯一实质 delta = §3.3 的新 UMA sync 类。

**结论：被审的 AGX 方法面在 27.0.1→27.2 完全没变；27.2 的改动落在审计面之外的新类上。**

---

## 5. 留白清单（明确不主张的）

1. **selector 2 → `NotPrivileged` 的归属**：表 A 不可达该 selector；仅知道存在一个 entitlement 门 `0x84f0948`，链路未接上。
2. **type 1 / type 33 / 65537 的类映射**：AGX 内只有 1 个 `getTargetAndMethodForIndex`、1 个 `externalMethod` override、1 个留名的 user client 类；`newUserClient` 本轮**未定位**（`cmp w3` 候选里 0 命中 `1/0x21`，ctor→caller 反查 29 条也没有一条做 `{1,33}` 校验）。type 的位域语义（`1`、`0x21`、`0x10001`）仍只是观测事实。
3. **`args+0x10` 的缓冲边界**：见 §3.2，需读 `com.apple.kernel` 的 `is_io_connect_*_method`。
4. **`0x3fc` 索引的上游可控性**：见 §3.3。
5. 表 A 的 `extra(+0x20,+0x28)` 字段语义（`(72,72)`、`(0,456)` 这类值）未定；已知它与 40 字节记录"多出的 16 字节"位置重叠，但本 kext 里不全为 0，说明不是同一版结构。
6. `0x7f20850` 起的连续代码指针串被判定为 vtable 槽（8 字节步长、全是 code 指针），但**未**验证其 address point 的 `offset_to_top/typeinfo` 形态（`-0x10` 是带签名的数据指针而非 0），因此"它是 AGXDeviceUserClient 的 vtable"只是**强倾向**，不是定论。

---

## 6. 复现命令

```bash
cd tasks/ios27-chain-poc/tools
# 函数边界自证 + 表 A 解码
python3 -c "import agx;m=agx.MachO('../out/v2701/AGXG18P.macho');print(m.selfcheck())"
# 全内核错误码分布（必须用 segment 级映射，不能用 kdiff.slices）
python3 - <<'PY'
import pickle,bisect
d=open('../out/kc.27.0.1.full','rb').read(); segs=pickle.load(open('/tmp/kc_segs.pkl','rb'))
PY
# 27.2 表 A 基址确认
python3 -c "
import agx;m=agx.MachO('../out/v272/AGXG18P.macho')
import pickle;ins=pickle.load(open('/tmp/agx272_ins.pkl','rb'))
print([hex(a) for a,(mn,op) in ins.items() if mn=='sub' and 'w2, #0x100' in op])"
```
