# AUDIT-GRAPHICS-SURFACE — 27.0.1 图形 / Surface 子系统内存破坏审计

1. **靶子**：`com.apple.iokit.IOSurface`（29,360 B）、`com.apple.iokit.IOGPUFamily`（48,384 B）、`com.apple.AGXG18P`（88,160 B）、`com.apple.driver.DiskImages.UDIFDiskImage`（14,736 B）。
2. **判据**：「27.0.1 里这段能不能越界」，不看 27.2 修没修（差分对「两边都有的洞」结构性失明）。
3. **方法**：从 `out/kc.27.0.1.full`（75 MB fileset，301 kext）按全限定 bundle id 提取 → 修复 section offset → `llvm-objdump` → 字符串/xref/模式扫描。
4. **结论先说**：**本轮没有确证 app 沙箱可达的内核内存破坏**。~~无 `IOExternalMethodDispatch` 表可依~~ —— **该前提第四轮已被推翻**：IOGPU 的派发表找到了（§6.7），共 140 条记录；AGX / UDIF 的派发是 switch 跳表（§6.2），不适用同一判据。§5 给出精确的未审计清单。
5. **最有价值的副产物**：这批 kext 的**代码指针是可解的** —— 解码式 `va = 0xfffffe0007004000 + (q & 0xFFFFFFFF)`，四个 kext 全部校验通过（§0.2/§0.2.1）。**第四轮修正**：`__DATA_CONST` 里大量 code 指针带 `bit63=1`（arm64e auth-rebase），旧扫描把 `v>>63` 当非法过滤掉了，导致误报"只有 34 个 rebase 槽"与"无 vtable"。真实图景：**代码指针解得出（含 auth 形态），导入符号名彻底没有**（`imports_count=0` 仍成立）。
6. **硬化正证据**：全 4 个 kext 共 340 处 `mul`、~180 处 `lsl`，**没有一处**是"先算尺寸再直接调函数且中间无上界/溢出检查"（§0.3）。
7. **IOSurface 的属性校验读到了指令级**：类型宽度、上界、2 的幂、**32 位求和溢出**四类检查都在（§1.3）。
8. **IOGPU 拿到了完整方法名清单**（16 个 `s_*` 方法），并确认 `group_add/remove_resources` 有显式 count-overflow panic 守卫（§2.2）。
9. **UDIF 降级**：纯解析器但不是 app 沙箱可达（走 DiskImages 用户客户端，需特权），按「沙箱可达」判据排最后（§4）。
10. **禁止项**：本轮未调用真机；所有 VA 为静态镜像地址，`0xfffffe00…`（kext）与 `0xfffffff0…`（TXM/SPTM）不可混用。
11. **第二轮补充（§6.1–6.5）**：selector 派发**解出来了** —— 不是数据段指针数组，而是 `__TEXT_EXEC` 里的 `ldrsw`+`adr`+`br` PC 相对偏移表。AGX 五张跳表全解（66/15/18/51/17 项），**全部有上界**；IOGPU 21 个方法名→地址全映射。上一轮"扫不到跳表"是扫描器 bug，已在 §0.4 标注作废。
12. **第三轮补充（§6.6）**：sel 3 / sel 4 候选**闭合为降级出局** —— `x2` 在 12 个 case 里只当 32 位标量（无一处解引用）⇒ 非 `externalMethod`、无类型混淆；`base` 是堆结构体数组（记录 696/376 字节，无 `ldraa` 无屏障）不是 MMIO；函数在以五种编码搜遍 75 MB 后**零静态引用**且其页从未被 `adrp` ⇒ 不是虚函数、拿不到入口。
13. **第四轮补充（§6.7）**：找到 IOGPU 的 `externalMethod`（`0xa024d94`）与**四张真派发表**（56+56+14+14 条，共 140 条 `IOExternalMethodDispatch` 记录全部解码）；含一个此前未发现的**第二个 user client**（`0xa024e4c`，14 个 selector）。声明 vs 实现核对：**0 条不一致**；自动判据报的 2 条经手读全部推翻（假阳性率 2/2，已写入文档）。同时纠正两处自我假阴性：`bit63=1` 的 auth 指针被旧扫描过滤掉、`mov w?,#0x18`+`umull` 形态未被旧正则捕获。
14. **第五轮补充（§8）**：AGX 的 vtable **存在** —— `__DATA_CONST.__const` 里 3463 个 auth-signed 代码指针（解码 `va = 0xfffffe0007004000 + (q & 0xFFFFFFFF)`，不判 bit63）。§0.2.1「无 vtable」与 §6.6.3「`0x851cfd4` 不是虚函数」**作废**，后者改为"是虚方法（槽 `0x7f228c8`），但 `count` 调用方未定"。命令/记录解析审了三条路径：`idx=len/stride` 有 `ensure_capacity` 守卫（负结果）、`0x84f8bb4` 的 count 循环**无自身上界**但 caller 未定、`0x8556cf0` 有 `cmp/b.hi`（负结果）。**AGX 的 `externalMethod` 与 submit handler 本轮未定位**，真正的 tagged-union 解析器在 IOGPU（`0xa0528cc`，17 项，type 有上界，逐条长度校验未读）。
15. **第六轮补充（§9）**：`0x8558c18` 的 `b.ls` **定性**——不是容量校验、也不是固定常数比较，而是 `rec2->f1 <= j`（记录字段 vs 内层循环下标）。顺带纠正上一轮「`[x2,#0x30]` 是参数结构字段」：`x2` 实为 `X + i*56`，是 56 字节记录数组的第 i 条。**两处无上界索引**（`buffer[k]`、`X + buffer[k]*56`）已定位，但 `X` 的记录数与字节表来源静态追不到，标为缺一环。

---

## §0 方法与工具

### 0.1 提取与反汇编（可复现）

```bash
# 1) 枚举 fileset
python3 - <<'EOF'
import sys; sys.path.insert(0,'tools'); import kdiff
d=kdiff.load('out/kc.27.0.1.full')
for fo,sz,name in kdiff.slices(d):
    if any(k in name.lower() for k in ('iosurface','iogpu','agx','udif')): print(name, sz)
EOF

# 2) 按全限定名提取（必须全限定，短名会失败）
python3 tools/kext_extract.py out/kc.27.0.1.full \
        --kext com.apple.iokit.IOSurface --out out/iosurface.kext.macho

# 3) 修复（提取器只重定位段，section.offset 仍指向共享 cache，objdump 会拒读）
python3 tools/fix_kext.py out/iosurface.kext.macho out/iosurface.macho

# 4) 反汇编
OD=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump
$OD -d --no-show-raw-insn out/iosurface.macho > /tmp/iosurface.dis
```

`fix_kext.py` 做三件事：`section.offset = seg.fileoff + (sect.addr - seg.vmaddr)`；丢掉共享的 `__LINKEDIT`；给 `__TEXT_EXEC` 每个节置 `S_ATTR_PURE_INSTRUCTIONS`（否则 objdump 只反汇编 `__text`，`__auth_stubs`/`__exc` 全丢，扫描会漏）。AGX 的 `__DATA` 有 zerofill 节超出段长度，需 clamp。

### 0.2 指针编码（重要，纠正一条流传的假设）

`__DATA_CONST` 里的槽位形如 `0x00100000_033253e4`：

| 位域 | 含义 |
|---|---|
| `[0:36)` | rebase 目标，单位是**内核 cache 的文件偏移** |
| `[51:62)` | 链式 next（stride = 4 字节；`0x0010…` ⇒ next=2 ⇒ 隔 8 字节） |
| `[63]` | bind 位，1 = 符号绑定（静态读不出目标） |

解析：`va = 0xfffffe0007004000 + target`。该基址在四个 kext 上**全部自洽**（每个 kext 的每个段都满足 `vmaddr - cache_fileoff = 0xfffffe0007004000`）。

```bash
python3 tools/kaudit.py out/iosurface.macho ptr 0x3cef8     # -> rebase 0xfffffe000a3293e4
```

统计：IOSurface 的 `__DATA_CONST` 共 0x6528 字节，节构成 `__mod_init_func` 0x90 / `__mod_term_func` 0x90 / `__const` 0x46f8 / `__kalloc_type` 0xd00 / `__kalloc_var` 0xaa0 / `__auth_got` 0x4a0 / `__got` 0xd0。**rebase 到 `__text` 的槽位只有 34 个，且全部落在 `__mod_init_func`/`__mod_term_func`。**

### 0.2.1 没有符号绑定可用（实测，纠正一条也会误传的假设）

`__got`(26) + `__auth_got`(148) = 174 个导入槽，它们在**加载期**由符号绑定填充，静态是空的。绑定表本来应该在：

```bash
# 内核 cache 根头的 LC_DYLD_CHAINED_FIXUPS
python3 - <<'EOF'
import struct
d=open('out/kc.27.0.1.full','rb').read()
ver,starts,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',d,0x4a80000)
print(count, fmt, symbols)      # -> 0 1 0x576
EOF
```

结果：**`imports_count = 0`** —— 整个 collection **没有任何符号绑定**（所以 `__DATA_CONST` 里那些"看起来像 bind"的 `0xffffffff00000000` 只是数据常量，不是指针槽，别数它）。再看每个 kext 切片自己的符号表：`LC_SYMTAB.nsyms = 0, strsize = 1`，`LC_DYSYMTAB` 只有 `nindirectsyms` 非零（IOSurface=322、IOGPU=472），而它指向的字符串表是空的。

**推论【设备镜像已证实】：这批 kext 的导入符号名在 kernelcache 里被彻底剥离，静态无法还原 `IOMalloc`/`copyin`/`IOBufferMemoryDescriptor::withOptions` 这类调用的名字。** §0.3/§5 里凡是需要"认导入函数叫什么"的判据，本轮都作废。

### 0.3 硬化扫描（全 4 kext）

| kext | `mul` | `madd` | 未检查 mul→call | 未检查 lsl→call |
|---|---|---|---|---|
| IOSurface | 22 | 5 | **0** | **0** |
| IOGPUFamily | 38 | 5 | **0** | **0** |
| AGXG18P | 277 | 156 | **0** | **0** |
| UDIFDiskImage | 3 | 0 | **0** | **0** |

判据：`mul/madd` 之后 12 条指令内出现调用，且这 12 条里**没有** `umulh/smulh/cmp/cset/ccmp/tbnz/tbz/b.hi/b.lo/b.cs/b.mi` 任何一条 ⇒ 记为未检查。结果 0。

读法（守纪律）：**这不证明没有整数溢出**。它只说明"编译器把 `__builtin_mul_overflow` 的检查发出来了"这一类路径没有被漏掉；溢出仍然可能发生在 ①检查之后又被改写、②检查用的上限本身来自用户输入、③`mul` 之后先存内存再取用。§5 列了针对这三类的后继动作。

### 0.4 为什么没有 selector→函数的映射（三条路都试过了）

`IOExternalMethodDispatch` 表要求的形态是 24 字节记录（8 字节 code ptr + 4×`uint32`）。尝试与结果：

| 尝试 | 结果 |
|---|---|
| 扫 `__DATA_CONST` 里 24 字节记录（code ptr + 4 个小整数） | **0 条**。该段里 rebase 到 `__text` 的槽只有 34 个，全是 `__mod_init/term_func` |
| 扫"bind 指针 + 4 整数"（以为派发表是 bind 编码） | 全部是数据常量误命中；`imports_count=0` 后此法作废（§0.2.1） |
| 扫跳转表（`br x?` 前 5 条出现 `ldrsw` / `add x?,x?,w?,`） | 首轮报 **0 命中**，**该结论已作废**：回看窗口太窄（实际间隔 7 条）+ `br\tx` 匹配写法不一致。修正后命中 IOSurface 0、IOGPU 1、AGX **5**、UDIF 8（含 5 条 memcpy 尾部）。见 **§6.1** |
| 扫"按 `args->selector`（`[x?,#4]`）取值" | 3 处命中，但全是结构体字段（如 surface 的 plane 相关字段），**不是** selector |

**关键 API 事实**：`IOUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *args, ...)` 的 **selector 走 `w1`，不在 `args+0x4`**。改按 `w1` 扫：IOSurface 切片共 **1023 个函数**，其中 65 个在前 70 条指令里有 ≥3 次 `cmp/sub w?, w1, #imm`，集中在 `0xfffffe000a33eb54`–`0xfffffe000a33ebd4` 一带（cmp 数 3→5 递增，像内联展开的 ladder）。**这 65 个里哪个是 `externalMethod` 无法确认**（没有 vtable / 没有调用者信息可对照）。

结论：**这批 kext 的请求派发静态不可定界**。本报告的入口分析因此改为「字符串 → 方法名 → 语义」，而不是「selector 号 → 代码」。§2.2 在 IOGPU 上这条走得最远。

---

## §1 IOSurface（`com.apple.iokit.IOSurface`）— 最高优先

### 1.1 镜像事实【设备镜像已证实】

| 项 | 值 |
|---|---|
| slice 大小 | 29,360 B |
| `__TEXT` | vm `0xfffffe0007a18790`，`__cstring` 0x33b7、`__os_log` 0x3779 |
| `__TEXT_EXEC.__text` | vm `0xfffffe000a3257c0`，size **0x3461c**（214 KB，约 5.4 万条指令） |
| `__auth_stubs` | 0xfffffe000a359ddc，0x940（导入桩，`blraa`） |
| 用户客户端类 | `IOSurfaceRootUserClient`（字符串 `0xfffffe0007a1b53f`），实现文件 `IOSurfaceRootUserClient.cpp` |
| 可达性 | **无 entitlement 门槛**：任何 app 用 `CVPixelBuffer` / Metal / `IOSurfaceCreate` 即建 surface |

已确认存在的相关类：`IOCoreSurfaceRoot`、`IOSurfaceSharedEventListener`、`IOSurfaceSharedEvent`、`IOSurfaceSharedEventNotificationPort`、`IOSurfaceFenceTransaction.cpp`。

### 1.2 属性键（说明用户能控制哪些字段）

`__cstring` 里成体系出现的键：`IOSurfaceWidth` / `Height` / `BytesPerRow` / `BytesPerElement` / `BitsPerElement` / `ElementWidth` / `ElementHeight` / `PixelFormat` / `AllocSize` / `Offset` / `PlaneInfo` / `PlaneOffset` / `PlaneWidth` / `PlaneHeight` / `PlaneBytesPerRow` / `PlaneElementWidth` / `PlaneElementHeight` / `PlaneBitsPerElement` / `Address` / `AddressRanges` / `CacheMode` / `BufferTileMode` / `YCbCrMatrix` / `TimingInfo` / `GPUTimes` …

即：**width/height/bpp/rowbytes 组合、plane 数量与偏移表**这两类历史高发面，用户态全部可写。

### 1.3 校验读到了指令级（本节的实质内容）

`0xfffffe000a32c820`–`0xfffffe000a32c8b8` 是属性采纳循环的一轮，逐条读：

```asm
fffffe000a32c820  ldur x8, [x29, #-0x68]      ; 从（未序列化后的）字典取出的值
fffffe000a32c824  lsr  x9, x8, #32            ; ★ 宽度检查：值必须装得进 32 位
fffffe000a32c828  cbnz x9, 0xfffffe000a32dedc ;    超出 → 走错误路径
fffffe000a32c82c  str  w8, [x26, #0x4]        ; 采纳到 surface 结构 +0x4

fffffe000a32c834  ldr  w8, [x26, #0x4]
fffffe000a32c838  cbz  x8, 0xfffffe000a32d9b4 ; ★ 非零检查
fffffe000a32c83c  cmp  x8, #0x400             ; ★ 上界：必须 < 0x400
fffffe000a32c840  b.hs 0xfffffe000a32da38     ;    越界 → 错误
fffffe000a32c844  add  x9, x8, #0x3ff
fffffe000a32c848  tst  x9, x8                 ; ★ 2 的幂检查（x8 ∈ {1,2,4,…,0x200}）
fffffe000a32c84c  b.ne 0xfffffe000a32da68

fffffe000a32c850  ldr  x9, [sp, #0x78]        ; 另一个 64 位输入
fffffe000a32c854  ldur x9, [x9, #0x8]
fffffe000a32c858  ldr  w10, [x26, #0x10]      ; 结构里已有的偏移/尺寸字段
fffffe000a32c85c  add  x8, x9, x8             ; ★ 求和
fffffe000a32c860  add  x8, x8, x10            ; ★ 再求和
fffffe000a32c864  lsr  x8, x8, #32            ; ★★ 32 位求和溢出检查
fffffe000a32c868  cbnz x8, 0xfffffe000a32da98 ;     溢出 → 错误

fffffe000a32c880  tbz  w0, #0x0, 0xfffffe000a32c898
fffffe000a32c884  ldur x8, [x29, #-0x68]
fffffe000a32c888  lsr  x9, x8, #16            ; ★ 16 位宽度检查（字段 +0x24 是 u16）
fffffe000a32c88c  cbnz x9, 0xfffffe000a32dedc
fffffe000a32c890  strh w8, [x26, #0x24]

fffffe000a32c89c  ldr  w9, [x26]              ; ★ 一致性：+0 ≥ +0x24
fffffe000a32c8a0  cmp  w9, w8
fffffe000a32c8a4  b.lo 0xfffffe000a32dac8     ;    不满足 → 错误
```

**判读**：这一轮属性采纳同时做了 ①类型宽度（`lsr #32` / `lsr #16`）、②上界（`cmp #0x400`）、③2 的幂（`tst` 惯用法）、④**32 位求和溢出**（`lsr #32; cbnz`）、⑤跨字段一致性（`cmp w9,w8`）。这与"IOSurface 属性字典随便填就能打穿"的旧印象相反 —— 至少这条路径是逐字段设防的。

### 1.4 与 surface 描述符相关的其它已核实点

- `0xfffffe000a32cb54` 附近有 `udiv` + `mov w9,#-1; cmp x10,x9` 形态 ⇒ **除法/乘加后再做 64 位溢出比较**（同样是 `__builtin_*_overflow` 的产物）。
- 全 kext 的变址访问（`ldr/str x?, [x?, x?, lsl #3]`）共 21 处"启发式未设防"，逐一回读后**全部是常量上界的展开循环**（`0x1a8`/`0x98`/`0x330`/`0x48`/`0xa` 等步长），没有一处是用户标量当下标。**这是假阳性，不记为发现。**

### 1.5 还没做的（IOSurface）

见 §5 第 1–4 项。核心缺口：`IOSurfaceRootUserClient` 的 16 类请求（create/release/lock/unlock/set_value/plane 相关）无法静态定界，因为它走 bind 派发表。

---

## §2 IOGPU（`com.apple.iokit.IOGPUFamily`）

### 2.1 镜像事实【设备镜像已证实】

`__TEXT_EXEC.__text` vm `0xfffffe000a01b390`，size **0x437c0**（277 KB）；`__cstring` 0x61b3；`__DATA_CONST.__const` 0x6fd0。
用户客户端：`IOGPUDeviceUserClient`，另有 `site.struct IOGPUDeviceUserClientPrivate`（kalloc_type 名）。

### 2.2 完整方法清单（本节最硬的产出）

`__cstring` 里成组出现**带完整签名的调试串**，等于把用户客户端的方法表交出来了：

```
s_new_command_queue            s_delete_command_queue        s_new_resource
s_submit_command_buffers       s_create_vniodesc             s_create_io_command_queue
s_destroy_io_command_queue     s_set_io_notification_queue   s_submit_io_commands
s_create_io_command_buffer     s_destroy_io_command_buffer   s_try_cancel_io_command_buffer
s_perform_io                   s_io_command_buffer_complete  s_io_command_buffer_barrier_complete
s_group_add_resources          s_group_remove_resources
s_async_signal_mtlLateEvalevent  s_query_mtlLateEvalevent
```

格式统一为 `static IOReturn IOGPUDeviceUserClient::s_xxx(IOGPUDeviceUserClient *, void *, IOExternalMethodArguments *)` —— 即它们是 `IOExternalMethodAction`，与 `IOExternalMethodDispatch` 表里的函数指针同型。**这 19 个名字就是 selector 表的语义清单**（顺序未定，见 §5-5）。

### 2.3 count-overflow 守卫确实存在

两条 panic 串直接点名：

```
"add_group_resources_fast() count overflow"      @0xfffffe0007996007
"group_add_resources_trap() count overflow"      @0xfffffe0007997258
```

xref（`tools/kxref.py`）定位到 panic 桩 `0xfffffe000a05e094` / `0xfffffe000a05e3fc`，其调用者：

| panic 桩 | 调用点 | 所在函数 |
|---|---|---|
| `0xfffffe000a05e094` | `0xfffffe000a02cdd4` | `0xfffffe000a02cdc8` |
| `0xfffffe000a05e094` | `0xfffffe000a02ce94` | `0xfffffe000a02ce88` |
| `0xfffffe000a05e3fc` | `0xfffffe000a035ba8` | `0xfffffe000a035850` |

读法（守纪律）：**"调用者=0"、桩函数体只有一条 `bl panic` ≠ 守卫缺失**；它只说明守卫的**冷路径被拆成了独立桩**，热路径上的 `cmp/b.hs` 才是判据。本节只证明"存在显式 count 溢出守卫"，**不**证明每个 `count * size` 都被覆盖 —— 后者见 §5-6。

相邻函数 `0xfffffe000a02cdf8` 里另有一段：

```asm
fffffe000a02cdf8  cbz  w1, panic
fffffe000a02cdfc  mov  w8, #0xfffffff
fffffe000a02ce00  cmp  w1, w8
fffffe000a02ce04  b.hs panic            ; ★ 上界 0xFFFFFFF
fffffe000a02ce08  retab
```

即同一路径上还有"计数必须 < 0xFFFFFFF"的显式上限。

### 2.4 `replace_backing_ranges_locked` 值得跟

字符串 `IOReturn IOGPUSysMemory::replace_backing_ranges_locked(task_t, mach_vm_address_t, uint64_t)` 与 `replace_backing_bytes_locked(...)`：**入参是 task + 地址 + 长度**，属于"用户给的地址/长度直接进内核映射操作"的形态。**未审计**（§5-6）。

---

## §3 AGX（`com.apple.AGXG18P`）

### 3.1 镜像事实【设备镜像已证实】

| 项 | 值 |
|---|---|
| slice | 88,160 B（在 fileset 里登记的大小）；`__TEXT_EXEC.__text` size **0xd630c**（878 KB，22 万条指令） |
| `__TEXT.__const` | 0x430c（与其它 kext 不同：这里 const 在 `__TEXT` 里） |
| `__cstring` | 0xfccf |
| 用户客户端 | `AGXDeviceUserClient`（仅此一个类名字符串命中） |
| 提取瑕疵 | `__DATA` vmsize 0x6318 但 filesize 被 clamp 到 0x4000（zerofill 超出），4 KB 的 `__DATA` 尾部不在文件里 |

### 3.2 状态：仅完成扫描，未完成审计

- 硬化扫描：277 `mul` / 156 `madd`，**0** 处未检查 mul→call。
- `umulh` 命中多为"除常数"惯用法（如 `umulh x8, x8, #0xaaab…` = ×1/3），**不是**溢出检查，别误记为硬化。
- 类名/方法名串几乎全被剥离（只有 `AGXDeviceUserClient`），无 §2.2 那样的方法签名清单。
- **结论：AGX 是这批里最大的一块面（878 KB 代码），也是本轮最没审的一块。** 按"沙箱可达"它确实可达（Metal），但 22 万条指令无符号盲审在本轮预算内不可行。

---

## §4 UDIF（`com.apple.driver.DiskImages.UDIFDiskImage`）

- `__TEXT_EXEC.__text` vm `0xfffffe000a09a740`，size **0xb75c**（47 KB）；`__TEXT.__const` 0x3058；`__cstring` 仅 0x2b0（解析器里字符串极少，符合"纯二进制解析"）。
- 硬化扫描：3 `mul` / 0 `madd`，0 未检查。
- **可达性判定：不是 app 沙箱可达。** 要走到这个 kext 需要 DiskImages 用户客户端路径（挂载磁盘映像），普通 app 拿不到。按任务书的"沙箱可达"判据，它排在最后。
- 历史上 UDIF 的问题多在 `blkx` 表（用户给的 sector 数 × 512 求偏移），本轮**未审计**（§5-8）。

---

## §5 未审计清单（按性价比）

| # | 目标 | 具体动作 | 判据 / 为何重要 |
|---|---|---|---|
| 1 | **拿到 vtable / 派发表** | 它们**不在 kext 切片里**（§0.4 已证实）。改动方向：①从 `corecrypto`/`kernel` 侧的 `OSMetaClass` 注册表反推（类名串在 __cstring，注册时被引用）；②用 `nm`-级别的外部符号源（`kernelcache` 的 `__LINKEDIT` 保留区 / 苹果的 kext 符号库存档）对齐；③退而求其次：按 §2.2 的**方法名字符串**逐个 xref 到"引用该名字的函数"，用 panic/`IOLog` 的调用点反推方法体 | 决定后面 6 项能否做 |
| 2 | IOSurface `set_surface_handle` | 字符串 `"asked to set handle %08x that was not free: %p"`（`0xfffffe0007a1b90f`）说明存在**按用户 handle 索引的表**；找到该表的容量检查与索引来源 | 典型的"索引直接取自 scalar，无上界" |
| 3 | IOSurface plane 表 | `PlaneInfo` 是数组；查 `planeCount` 与 `planeOffset[]` 的容量校验、`AllocSize` 与 `max(planeOffset+planeSize)` 的比较 | 历史高发：plane 数 × 每 plane 偏移越界 |
| 4 | IOSurface lock/unlock | 引用计数与 `lockCount`/`useCount` 的饱和处理 | 竞态/UAF 面，非静态可完全判定，需真机 |
| 5 | IOGPU selector 顺序 | 用 §2.2 的 19 个名字，在 bind 解析完成后按 imports 序号还原派发表顺序 | 决定"哪个 selector 号打哪个方法" |
| 6 | IOGPU `s_group_add_resources` | 读 `0xfffffe000a035850` 全函数：`count` 来源（scalar 还是 struct 字段）、`count * 8` 的溢出检查点、目的地数组容量 | count 型越界的最佳候选 |
| 7 | IOGPU `replace_backing_ranges_locked` | `IOAddressRange *` 数组 + `uint32_t` 计数从哪来、是否校验落在本 task 的映射内 | "用户地址/长度直接进映射操作" |
| 8 | UDIF `blkx` 解析 | sector 数 × 512 的偏移计算、run count 循环上界 | 解析器经典面（但可达性差） |
| 9 | AGX（整块） | 878 KB 无符号，需先解 bind 表拿到 vtable，再按 `AGXDeviceUserClient` 的方法集分工 | 本轮最大空白 |
| 10 | 全 4 kext 的 `copyin` 长度一致性 | 需先解 bind（`copyin` 是导入符号）；当前无法定位调用点 | 任务书五类里的第四类 |

**方法论提醒（给下一个人）**：
- `instr` 正则必须写 `^([0-9a-f]{16}):\s+`，objdump 的行是 `地址:` + 空格 + `\t`，写成 `:\t` 会静默 0 命中。
- kext VA 前缀 `0xfffffe00…`，TXM/SPTM 是 `0xfffffff0…`；混用得负偏移。
- 提取出的 kext 不能直接 `nm`/`objdump`：共享 `__LINKEDIT` 与陈旧 `section.offset` 都会让它报 "truncated or malformed"。
- 「函数边界」只能靠 `pacibsp`/`bti c` 且前一条是 `ret/b/nop` 推断；对 `__exc`（panic 桩）会切出一堆 5 行的假函数 —— **看到只含一条 `bl panic` 的"函数"，那是冷路径桩，不是调用者**。

---

## §5b 直答（第一轮范围：IOSurface / IOGPU / UDIF）

> **这批（IOSurface / IOGPU / AGXG18P / UDIF）里，本轮没有确证任何一处「app 沙箱可达的内核内存破坏」。**

具体到四个靶子：

- **IOSurface** —— 唯一一条我读到指令级的用户可控解析路径（属性采纳循环 `0xfffffe000a32c820`）**是逐字段设防的**：类型宽度、上界、2 的幂、32 位求和溢出、跨字段一致性五类检查齐备；变址访问全部是常量上界循环。**没有发现越界。**
- **IOGPU** —— 拿到了 19 个方法名与两处 count-overflow 守卫的存在性证据，但**没有**把任何一个 `count`/长度字段追到内存操作，因此**既不能报有、也不能报没有**。
- **AGXG18P** —— 878 KB 代码、无方法名、无符号，**本轮实质未审**。
- **UDIF** —— 47 KB 解析器，但**不是沙箱可达**，按判据降级。

**所以正确的表述是：在已审到的范围内没有洞；而已经审到底的范围只覆盖了 IOSurface 的一条属性路径。** 把这句话读成"这批是安全的"会是本轮最容易犯的错（差分失明的同构错误：审计盲区 ≠ 无洞）。

**下一步最该做的一件事**：解开 bind 表（§5-1）。它一次性解锁 §5 里的第 1、2、5、6、7、9、10 项 —— 也就是这批里几乎所有还开着的口子。

---

## §6 AGX 专项审计

### 6.1 派发解出来了 —— 是代码段里的 PC 相对偏移表（不是数据段指针数组）

你的提示是对的，而且**我上一轮报的「0 命中」是扫描器 bug**，不是事实。两个 bug：

1. 回看窗口取 5 条，实际惯用式是 `cmp → csneg → adrp → add → ldrsw → adr → add → br`，间隔 **7 条**；
2. 判定里写成 `br\tx`，而 objdump 的行是 `地址:` + 空格 + `\t` + 助记符，`strip()` 之后 `br` 与 `x16` 之间是**制表符**，正则写死了字面量 `\t` 在部分路径上不匹配。

修正后的判据（三连）：

```asm
cmp  x16, #BOUND
csneg x16, x16, xzr, ls        ; 越界则索引钳到 0（csel 版本用于 unsigned）
adrp x17, TABLE_PAGE
add  x17, x17, #TABLE_OFF
ldrsw x16, [x17, x16, lsl #2]  ; ★ 32 位有符号相对偏移
adr  x17, .+8                  ; ★ 相对基址是这条 adr 自身
add  x16, x17, x16
br   x16                       ; ★ 间接跳转
```

表项 = `TABLE[i]`，目标 = `adr_addr + (int32)TABLE[i]`。因为存的是**相对偏移**而不是指针，它不需要 chained-fixup 编码、也不需要符号名 —— 正好绕开 §0.2.1 的死路。

全 4 kext 全部跑过（`python3 tools/kaudit.py <kext>.macho tables <dis`，已并入工具）：

```
iosurface   （无）
iogpu       br 0xfffffe000a05292c  table=0xfffffe000a053e40  bound=0x10  n=17
agx         br 0xfffffe00084b8218  table=0xfffffe00084b82d4  bound=0x41  n=66
            br 0xfffffe00084f77d0  table=0xfffffe00084f88b4  bound=0x0e  n=15
            br 0xfffffe000851d034  table=0xfffffe000851ec44  bound=0x11  n=18
            br 0xfffffe000853364c  table=0xfffffe00085336e0  bound=0x32  n=51
            br 0xfffffe0008572f38  table=0xfffffe000857472c  bound=0x10  n=17
udif        br 0xfffffe000a0a0668  table=0xfffffe000a0a0cdc  bound=0x0a  n=11
            br 0xfffffe000a0a0d90  table=0xfffffe000a0a1554  bound=0x0a  n=11
```

（UDIF 另外 6 条 `br x17` 是 `memcpy`/`memmove` 的内联尾部跳转，无 `ldrsw`+`adr` 三连，已被这个判据正确排除。）

### 6.2 AGX 的五张跳表（全部解出，全部有上界）

| # | `br` 地址 | 表地址 | 项数 | 索引来源 | 上界检查 |
|---|---|---|---|---|---|
| 1 | `0xfffffe00084b8218` | `0xfffffe00084b82d4` | 0x42（66） | **`w1`** | `cmp w1,#0x41` → `b.hi 0x84b8224` |
| 2 | `0xfffffe00084f77d0` | `0xfffffe00084f88b4` | 0x0f（15） | **被调函数返回值** `w0` | `cmp w0,#0xe` → `b.hi 0x84f7774` |
| 3 | `0xfffffe000851d034` | `0xfffffe000851ec44` | 0x12（18） | **`w1`** | `cmp w1,#0x11` → `b.hi 0x851e610` |
| 4 | `0xfffffe000853364c` | `0xfffffe00085336e0` | 0x33（51） | **`w1`** | `cmp w1,#0x32` → `b.hi 0x85336d4` |
| 5 | `0xfffffe0008572f38` | `0xfffffe000857472c` | 0x11（17） | **`w8-0x10`**（w8 ∈ [0x10,0x20]） | `sub w16,w8,#0x10; cmp w16,#0x10` → `b.hi 0x8574700` |

**五张表全部在 `br` 之前做了上界检查**，越界一律落到 default（表里对应项本身也指向同一个 default 目标）。这一类（表驱动派发）在 AGX 里**没有越界跳转面**。

三张按 `w1` 派发的（#1/#3/#4）形状高度一致：`this` 在 `x0`，索引在 `w1`，第三参在 `x2`，且都有 `strb wzr, [x2]`（把某个输出字节清零）—— 典型的 `f(self, op, out*)` 或 `f(self, selector, args*)`。

### 6.3 深读 #3：`0xfffffe000851cfd4`（bound 0x11，18 项，12 个 live case）

派发本身：

```asm
0xfffffe000851cfd4  pacibsp / sub sp,sp,#0x90 / 存 x19-x28,x29,x30
0xfffffe000851cff8  mov  x19, #0            ; 默认返回值
0xfffffe000851cffc  cmp  w1, #0x11          ; ★ selector 上界
0xfffffe000851d000  b.hi 0xfffffe000851e610 ;    越界 → default
0xfffffe000851d004  mov  x20, x2            ; ★ 第三参 → x20（下文见）
0xfffffe000851d008  mov  x22, x1            ; selector 另存
0xfffffe000851d00c  mov  x25, x0            ; this
0xfffffe000851d010  ldr  x28, [x0, #0xcb8]  ; this→字段
0xfffffe000851d014  mov  w16, w1
...                (6.1 的三连)
0xfffffe000851d034  br   x16
```

12 个 live selector 与目标（表 `0xfffffe000851ec44`，基址 `adr 0xfffffe000851d02c`）：

| sel | 目标 | 该 case 做的事（摘要） |
|---|---|---|
| 0 | `0xfffffe000851d038` | `x27 = [this+0x2e0] + 0xb50` → 汇合 |
| 1 | `0xfffffe000851d0cc` | `x27 = [this+0x2e0] + 0x9c8` → 汇合 |
| 2 | `0xfffffe000851d070` | `x27 = +0x2b94`，`x26 = +0x2acc` → 汇合 |
| 3 | `0xfffffe000851d144` | **`x27 = base + 0x18 + count*696`** ← 见下 |
| 4 | `0xfffffe000851d184` | **`x21 = base + 0x8 + count*376`** ← 见下 |
| 8 | `0xfffffe000851d094` | `x27 = +0xa80` |
| 9 | `0xfffffe000851d0e8` | `x21 = +0x22c8`，`[sp+0x10] = +0x22c0` |
| 11 | `0xfffffe000851d118` | `ldr w10,[base+0xc75+8]!`；`x21 = (w10==0) ? base+0xc79 : base+0xc75+8`（**按字段值二选一**） |
| 12 | `0xfffffe000851d1e4` | `x21 = +0x2e60`，`[sp+0x10] = +0x2e58`，`[sp+8] = [x28+0x64]` |
| 14 | `0xfffffe000851d1c4` | `x27 = +0x2d24` |
| 16 | `0xfffffe000851d054` | `x27 = +0x27d6` |
| 17 | `0xfffffe000851d0b0` | `x27 = +0x2fe4` |

（`base` 恒为 `[[this+0x2e0]]`；`0x2bad` 是**毒化魔数**，见下。）

**sel 3 / sel 4 是本节唯一带乘法索引的两个 case，逐条读 sel 3：**

```asm
0xfffffe000851d144  bti  j
0xfffffe000851d148  mov  x21, #0
0xfffffe000851d14c  stp  xzr, xzr, [sp, #0x8]
0xfffffe000851d150  mov  x26, #0
0xfffffe000851d154  ldr  x8, [x25, #0x2e0]     ; base 对象
0xfffffe000851d158  mov  w9, #0x2318
0xfffffe000851d15c  add  x8, x8, x9            ; base += 0x2318
0xfffffe000851d160  mov  w9, #0x2b8            ; ★ 元素大小 696
0xfffffe000851d164  umull x9, w20, w9          ; ★ x9 = (u64)w20 * 696
0xfffffe000851d168  add  x9, x9, #0x18         ; + 0x18
0xfffffe000851d16c  cmp  x9, w9, sxtw          ; ★ 是否装得进 int32
0xfffffe000851d170  add  x27, x8, w9, sxtw     ; 截断版指针
0xfffffe000851d174  add  x16, x8, x9            ; 全 64 位版
0xfffffe000851d178  movk x16, #0x2bad, lsl #48 ; ★ 打上 0x2bad 高位
0xfffffe000851d17c  csel x27, x27, x16, eq     ; 装得进→截断版；装不进→毒化指针
0xfffffe000851d180  b    0xfffffe000851d210
```

判读（守纪律，逐条说明我据什么下这个判断）：

- `cmp x9, w9, sxtw` + `csel ... eq` **不是**"溢出就报错"，而是**二选一**：装得进 `int32` 就用 `base + sext32(off)`；装不进就返回一个高位带 `0x2bad` 的指针，后续经 `autda`/`ldraa` 认证必失败 → 主动 fault。也就是说**只有"超出 int32 范围"才被拦**（`0x2bad` = 有意毒化，"2 bad"）。
- 因此**没有针对对象真实容量的上界检查**：只要 `0x18 + count*696 < 2^31`（即 `count < ~3.08e6`），算出来的 `x27` 就是一个"合法形状"的指针，可以偏离 `base` 最多约 2 GB。
- sel 4 同构，只是元素大小 376（`0x178`）、基址偏移 `0x2920`、加数 `0x8`。

**这就构成了一个候选越界原语**（`base + count*elemsize`，count 无容量上界），但**本轮无法闭合**两个前提，所以不记为发现：

1. **`count` 是谁给的？** 它是第三参 `x2`（`0xfffffe000851d004 mov x20, x2`，且这是全函数里**唯一**一次写 `x20`；我逐条验证过 0x851cfd4–0x851d240 区间的所有 `w20/x20` 写入，只有这一条）。若 `x2` 是 `IOExternalMethodArguments *`，把它的低 32 位当计数是荒谬的 —— 所以**证据倾向于 `x2` 是 32 位标量计数**，即这个函数不是 `externalMethod`，而是内部 `f(self, op, count)` 派发器。
2. **`base` 是什么？** `[[this+0x2e0]] + 0x2318`。AGX 的这个对象有多大、这块是 kalloc 堆还是固件/MMIO 映射，本轮未定。

**未能闭合的原因**：`0xfffffe000851cfd4` 在整个 75 MB kernelcache 里**零静态引用**（`bl`/`b` 目标 0 处；把 `va-KB` 的低 32 位当 qword/低 32 位两种形式全文件搜，也是 0 处）。它只能经 `braa`（PAC 寄存器间接调用）到达，而 vtable 不在切片里（§0.2.1）。`__DATA` 的尾段 0x2318 字节在 cache 里就是 `filesize=0x4000 < vmsize=0x6318` 的 zerofill，也不在文件里。

### 6.4 顺带解出的：IOGPU 21 个方法名 → 地址（这次是真映射）

上一轮我以为拿不到 selector→函数，是因为我把 `s_*` 签名字符串当成了"panic 桩"就放过了。**其实那些字符串正是被方法体自己引用的**（`require()`/`IOLog` 里带函数名），所以 `kxref` 的 `字符串 → 引用它的函数` 直接给出方法地址：

| 地址 | 方法 | 地址 | 方法 |
|---|---|---|---|
| `0xfffffe000a022274` | `s_new_command_queue` | `0xfffffe000a0236ac` | `s_submit_io_commands` |
| `0xfffffe000a022578` | `s_delete_command_queue` | `0xfffffe000a023918` | `s_create_io_command_buffer` |
| `0xfffffe000a02260c` | `s_new_resource` | `0xfffffe000a0239d4` | `s_destroy_io_command_buffer` |
| `0xfffffe000a02299c` | `s_submit_command_buffers` | `0xfffffe000a023a90` | `s_try_cancel_io_command_buffer` |
| `0xfffffe000a022d78` | `s_async_signal_mtlLateEvalevent` | `0xfffffe000a023b4c` | `s_perform_io` |
| `0xfffffe000a022eb4` | `s_query_mtlLateEvalevent` | `0xfffffe000a023bf4` | `s_io_command_buffer_complete` |
| `0xfffffe000a023194` | `s_create_vniodesc` | `0xfffffe000a023c98` | `s_io_command_buffer_barrier_complete` |
| `0xfffffe000a0232f4` | `s_create_io_command_queue` | `0xfffffe000a023d58` | `s_group_add_resources` |
| `0xfffffe000a0234d8` | `s_destroy_io_command_queue` | `0xfffffe000a023ee8` | `s_group_remove_resources` |
| `0xfffffe000a02355c` | `s_set_io_notification_queue` | | |

地址随源码顺序单调递增，**selector 编号大概率就是这张表的顺序**（0 = `s_new_command_queue` … 17 = `s_group_remove_resources`），但这只是排序推断，未与派发表核对。

**`s_group_add_resources` / `s_group_remove_resources` 的边界检查是对称的**（这正是"兄弟函数有没有同等加固"的检验）：

```asm
; s_group_add_resources 0xfffffe000a023d58
0xfffffe000a023d8c  ldr  x8,  [x2, #0x20]   ; args->scalarInput
0xfffffe000a023d90  ldr  w23, [x8]          ; A = sc[0]
0xfffffe000a023d94  ldr  w21, [x8, #0x8]    ; B = sc[1]
0xfffffe000a023d98  ldr  x0,  [x2, #0x40]   ; structureInputDescriptor
...
0xfffffe000a023e14  ldr  w0,  [x25, #0x38]  ; 无 descriptor 时取 structureInputSize
0xfffffe000a023e18  ldr  x24, [x25, #0x30]  ; structureInput
0xfffffe000a023e20  cmp  x0, x21, lsl #2    ; ★ 输入长度 ≥ B*4（add：每项 4 字节）
0xfffffe000a023e24  b.lo 0xfffffe000a023e40 ;   不够就退
0xfffffe000a023e38  bl   0xfffffe000a0428f4 ; add_group_resources_fast(this->[0x120], A, buf, B)

; s_group_remove_resources 0xfffffe000a023ee8
0xfffffe000a023fb0  cmp  x0, x21, lsl #3    ; ★ 同一位置，remove 是 B*8（每项 8 字节）
0xfffffe000a023fb4  b.lo 0xfffffe000a023fd0
0xfffffe000a023fc8  bl   0xfffffe000a0429fc ; group_remove_resources(...)
```

**读法**：两个兄弟函数在**同一条指令位置**做**同一形状**的长度比对，只有元素宽度不同（4 vs 8），完全对应当题语义。**"一个加固了、兄弟没加固"这个形态在这里不成立。** 这是负结果，但是有指令级证据的负结果。

`ldr w23,[x8]` / `ldr w21,[x8,#8]` 没有自己检查 `scalarInputCount`——但这一层由 `IOUserClient::externalMethod` 在调用前按派发表条目声明的 `checkScalarInputCount` 强制，属框架责任；若某条派发记录声明为 0 而方法体仍读 `sc[0]`，那才是问题（**未核对**，见 §6.5）。

### 6.5 AGX 这条面上本轮没闭合的

1. **`AGXDeviceUserClient::externalMethod` 到底是哪一个函数。** AGX 没有 IOGPU 那样的方法签名字符串（`__cstring` 里只有 `AGXDeviceUserClient`、`site.AGXDeviceUserClient` 两个类/kalloc 名），所以 §6.4 那条路走不通。三个按 `w1` 派发的函数（#1/#3/#4）都可能，但 #3 的第三参语义指向"计数"而非"args 指针"，反而更像内部派发器。
2. ~~**`count` 的用户可控性。**~~ **已闭合为否定**（§6.6.1）：`x2` 在 12 个 case 里只当 32 位标量用、从不被解引用 ⇒ 不是 `IOExternalMethodArguments *`。仍未定的是**调用方是谁**（§6.6.3：函数零引用、不可达），只能靠动态断点。
3. ~~**`base` 的归属。**~~ **已闭合**（§6.6.2）：堆/结构体数组（记录 696 / 376 字节），不是 MMIO；`x27` 是裸指针，无 PAC。
4. **`s_*` 派发声明与实现是否一致。** 需要把 IOGPU 的 `IOExternalMethodDispatch` 表（当前不在切片里）与 §6.4 的 21 个方法体比：某条记录声明 `checkScalarInputCount=0` 而实现读 `sc[1]` ⇒ 内核栈/参数区越界读。这是**当前最便宜、最可能出结果**的一条。

---

### 6.6 sel 3 / sel 4 闭合实验（三个判别实验，结论：**降级出局**）

#### 6.6.1 实验一：同表兄弟的 `x2` 语义（判别"计数 vs 指针"）

先纠正一个我上一轮的**范围错误**：我把 `0xfffffe000851cfd4` 当成一个小函数读，实际它是 **2308 条指令**（`0xfffffe000851cfd4` – `0xfffffe000851f3e4`，以 `retab` 收尾，前一条是 `add sp,sp,#0xb0`，起点确认为独立函数）。

在这 2308 条里，**所有**涉及 `x2/w2/x20/w20` 的指令只有这些：

| 地址 | 指令 | 性质 |
|---|---|---|
| `0x851cfec` | `stp x20, x19, [sp, #0x70]` | 保存被调用者寄存器 |
| `0x851d004` | `mov x20, x2` | **全函数唯一一次写 x20** |
| `0x851d164` | `umull x9, w20, w9` | sel 3：当**计数** |
| `0x851d1a4` | `umull x9, w20, w9` | sel 4：当**计数** |
| `0x851d220` | `str w20, [sp, #0x4]` | 汇合点：按 **32 位标量**溢出保存 |
| `0x851e3c0` | `ldr w10, [sp, #0x4]` → `umull x26, w10, #0x178` | 取回后当**计数** |
| `0x851e4cc` | `ldr w8, [sp, #0x4]` → `mov w20, w8` | 取回后当**计数** |

**全函数 12 个 live case 里，没有任何一处解引用 `x2`**（没有 `ldr ..., [x20, #off]`、没有 `ldrb`、没有 `[x2, #off]`）。汇合点把它当 32 位值 `str w20, [sp,#4]` 溢出，之后两次读回**都是喂给 `umull`**。

按你给的判据：**12 个 case 全部把 `x2` 当标量 ⇒ 倾向证实 ⇒ 候选降级。** 同时这也排除了"sel 3/4 把指针当计数用"的类型混淆 —— 不存在不一致，因为没有别的 case 解引用它。

签名因此是 `f(self, op, count)`（`x0`=对象、`w1`=op/selector、`w2`=32 位计数），**不是 `IOExternalMethodArguments *`**，也就**不是 `externalMethod`**。

#### 6.6.2 实验二：`base` 是堆还是 MMIO

| 检查项 | 结果 | 含义 |
|---|---|---|
| `autda`/`autdb`/`autia`/`autib` | 函数内 **127 处 `autda`**，但**没有一处作用于 `x27`/`x21`/`x26`** | 函数整体在堆对象上工作（`x19` 等），但这三个派生指针本身是**裸指针** |
| `ldraa`/`ldrab`/`pacda` | **0 处** | `x27`/`x21`/`x26` 不经 PAC 认证，直接解引用 |
| `dsb`/`dmb`/`isb` | **0 处**（全 2308 条） | 不像 MMIO 访问序列 |
| 访问形态 | `ldr w0, [x27, #0x4c]`、`#0x50`、`#0x80`、`#0x48`、`#0x70`、`#0x74`、`#0x88`、`#0x8c`、`#0x90`、`#0x94`、`#0x78`、`#0x7c`、`#0x24`、`#0x28`、`#0x34`、`#0x38`、`#0x3c`、`#0x44`、`#0x54`… | 偏移非均匀、全 32 位宽、全部落在 696（0x2b8）字节内 ⇒ **结构体字段**，不是寄存器组 |

**结论**：`x27` 指向**内存里的结构体数组**中的一条记录（记录大小 696 / `sel 4` 是 376），`base = [[this+0x2e0]] + 0x2318`（`sel 4` 是 `+0x2920`）。**是堆/内核内存，不是 MMIO。** 因此若真越界，性质是读内核内存，不是打硬件寄存器。

顺带修正上一轮的说法：我写"毒化指针经 `autda` 必 fault"是**错的** —— `x27` 根本不做 PAC。真实机制是：`movk x16,#0x2bad,lsl#48` 造出一个**带 0x2bad 高位标记的非规范/毒化地址**，随后 `ldr w0,[x27,#off]` 直接访存 → 毒化指针一解引用就 fault。**它是一道"int32 范围"闸，不是容量闸。**

#### 6.6.3 实验三：零静态引用（五种编码全试）

| 编码假设 | 搜索值 | 全 75 MB cache 命中 |
|---|---|---|
| VA 低 32 位 | `0x0851cfd4` | **0** |
| KB 偏移（rebase 目标） | `0x01518fd4`（原写 `0x151cfd4`，同值） | **0** |
| 相对 `__TEXT_EXEC` | `0x0006b674` | **0** |
| 相对 `__TEXT` | `0x013f9e94` | **0** |
| `adrp` 目标页 `0x851c000` / `0x851d000` | — | **0 处** |

另外做了一次**扫描器自检**：拿 `com.apple.driver.AppleMobileFileIntegrity`（必然有 ObjC 类元数据）跑同一个"data 段里的 code 指针"扫描，结果 **7 个，全部是 `__mod_init_func`/`__mod_term_func`**。所以"这批 kext 的 data 段里没有 code 指针"是**这批 kernelcache 的普遍形态**，不是我的扫描器坏了 —— 但也意味着**"地址被取过"这条证据链在本项目里根本不可用**，无法用它来判定函数是不是虚函数。

**综合（该段已被 §8.1 部分推翻，保留原文以便对照）**：`0x851cfd4` 既没有 `bl`/`b` 指向它，也没有任何形式的存储指针指向它，连它的页都没被 `adrp` 过 ⇒ 当时判为"不是虚函数"。

> **§8.1 更正**：这条**错了**。搜索时用了 `if v >> 63: continue`，把 arm64e auth-signed 指针全部过滤掉了。放开 bit63 后，`0x851cfd4` **确为虚方法**，vtable 槽 `0xfffffe0007f228c8`（AGX 的 `__DATA_CONST.__const` 里共有 3463 个这类代码指针）。因此本节结论只保留两条腿：**`x2` 是 32 位标量**（12 个 case 无一解引用，成立）与 **`base` 是堆结构体数组**（无 `ldraa`、无屏障、记录 696/376 字节，成立）；"函数不可达"这条撤回。**降级出局的判定维持，但理由变为：`count` 的调用方仍未定，而"不可达"不再是理由之一。**

#### 6.6.4 判据复盘：这个"缺容量闸"到底严不严重

把 sel 3 的完整语义写出来：

```c
// 推测签名：f(self, op, count)   count 是 32 位标量
rec_t *r = (rec_t *)((char *)self->dev + 0x2318 + 0x18 + count * 696);   // sel 3
rec_t *s = (rec_t *)((char *)self->dev + 0x2920 + 0x08 + count * 376);   // sel 4
... 若该偏移装不进 int32 → 指针被 0x2bad 毒化 → 后续 ldr 直接 fault
```

- **有**：int32 范围闸（毒化）。
- **没有**：`count < 数组元素个数` 的容量闸。
- 因此只要 `count` 落在 `[0, ~3.08e6]`（`0x18 + count*696 < 2^31`），算出的指针"形状合法"，可以偏离 base 最多约 2 GB，随后 `ldr w0, [r + 0x4c]` 之类的**读**会落在任意内核内存上。

**但这不构成 app 沙箱可达的发现**，因为缺的那一环是 `count` 的来源：全函数无引用、不可达，我拿不到任何一条"用户态 → 这个 `w2`"的路径。

---

---

### 6.7 声明 vs 实现一致性核对（`checkScalar*` / `checkStructure*`）

#### 6.7.0 先纠一个前提：`0xa053e40` 不是派发表

你让我核对的那张 IOGPU 表（`br 0xa05292c table=0xa053e40 bound=0x10`）是**代码段里的 switch 跳转表**，不是 `IOExternalMethodDispatch` 数组：索引来自 `ldr w24,[x8],#8` 再 `sub w16,w24,#2`（结构体首 u32），表项是 32 位相对偏移。用它核对 `checkScalarInputCount` 是范畴错误。

真正的派发表在别处。定位手段是**运行时乘 24**：

```asm
mov  wN, #0x18
umull xM, wSEL, wN     ; ← 24 字节一条记录
adrp x10, TABLE_PAGE
add  x10, x10, #OFF
```

**这里我又踩了一次自己的坑**：上一轮我扫"24 字节步长索引"用的是 `mul/madd #0x18` 和相邻 `lsl #3`+`lsl #4`，**漏掉了 `mov w?,#0x18` + `umull` 这个形态**，所以当时报"四个 kext 全 0 命中"是假阴性。修正后：IOGPU **10**、AGX **6**、IOSurface **1**、UDIF **0**。

#### 6.7.1 IOGPU 的 `externalMethod` 找到了：`0xfffffe000a024d94`

```asm
0xa024d94  bti c
0xa024d98  w8 = 0xe00002c2                 ; 默认错误码
0xa024da0  ldrb w9, [x0, #0x100]
0xa024da4  tbz  w9, #0, 0xa024e24          ; 标志位关 → 直接返回
0xa024da8  cmp  w1, #0x37                  ; ★ selector 上界 = 0x37（56 条）
0xa024dac  b.hi 0xa024e30                  ; 越界 → 走 super::externalMethod
0xa024db0  ldr  x9, [x2, #0x10]            ; args->asyncReference
0xa024db4  cbnz x9, 0xa024e28              ; 不支持 async
0xa024db8  ldrb w8, [x0, #0x103]           ; ★ 表选择标志
0xa024dc0  umull x9, w1, #24               ; sel*24
0xa024dc4  adrp x10, 0x82f6000 / add #0x9f0 ; ★ 表 A = 0xfffffe00082f69f0
0xa024de0  adrp x10, 0x82f6000 / add #0x4b0 ; ★ 表 B = 0xfffffe00082f64b0
0xa024dfc  tst  w8, #1
0xa024e00  csel x3, x11, x12, ne           ; dispatch = (flag&1) ? A[sel] : B[sel]
0xa024e04  x8 = *(0x82fe000+0xa78)         ; 类对象
0xa024e10  x16 = [x8 + 0x550]
0xa024e14  x4 = x0                          ; target = this
0xa024e20  braa x16, x17                    ; super::externalMethod(sel, args, dispatch, this, NULL)
```

**并且顺带发现了第二个 user client**：同页的 `0xa024e4c` 是另一个 `externalMethod`，`cmp w2, #0xd`（selector 在 **w2**，14 条），表 `0x82f7080` / `0x82f6f30`（同样双表，同一个 `flag&1` 选择）。它的 14 个目标全部落在 `0xa0240e8`–`0xa0248b8`，正好覆盖 §6.4 里那批 `t_signal_shared_event` / `t_wait_shared_event` / `t_signal_mtl_event` / `t_wait_mtl_event` —— 即**事件/通知用的第二个 user client**。

#### 6.7.2 解出来的声明值

`IOExternalMethodDispatch` = `{action@0, sc_in@8, st_in@12, sc_out@16, st_out@20}`，条数 24。指针字段是 arm64e auth-rebase（bit63 置位、target 在 bits[0:32)），解码 `va = 0xfffffe0007004000 + (ptr & 0xFFFFFFFF)` —— 破案的关键还在于：**我先前扫"data 段里的 code 指针"报 0，是因为把 bit63=1 的 auth 指针全过滤掉了。**

表 A（56 条）关键几条：

| sel | 目标 | sc_in | st_in | sc_out | st_out |
|---|---|---|---|---|---|
| 6 | `0xa022274` `s_new_command_queue` | 0 | `0xffffffff`(variable) | 0 | 16 |
| 7 | `0xa022578` `s_delete_command_queue` | 1 | 0 | 0 | 0 |
| 8 | `0xa02260c` `s_new_resource` | 0 | `0xffffffff` | 0 | `0xffffffff` |
| 25 | `0xa02299c` `s_submit_command_buffers` | 4 | `0xffffffff` | 1 | 0 |
| 26 | `0xa022c2c` | 1 | 12 | 1 | 0 |
| 35 | `0xa02306c` | 2 | 0 | 0 | 0 |
| 27–54 | `0xa0240d8`（共享多路器） | 0–3 | 0/24/`0xffffffff` | 0–2 | 0 |

`0xffffffff` = `kIOUCVariableStructureSize`，单独看待（尺寸由调用方声明、实现自验）。表 B 与 A 在 **21、27–34、36–54** 上不同（两套变体）。表 C/D（14 条）**全部声明为 0**。

#### 6.7.3 核对结果

判据（比追用户可控性硬得多，因为不需要证明可达）：
- 声明 `sc_in = n` ⇒ 框架只拷 n 个 scalar；实现若读 `scalarInput[i]` 且 `i >= n` ⇒ **越界读内核缓冲**；
- 声明为 0 ⇒ 实现不得解引用 `args->scalarInput`；
- 同理 `sc_out` / `st_in` / `st_out`。

| 表 | 记录数 | 核对方式 | 不一致 |
|---|---|---|---|
| A（56） | 56 | 严格寄存器追踪：`ldr xR,[x2,#0x20]` → 传播 `mov`/`add #imm`，遇非传播写即作废；统计最大索引 | **0** |
| B（56） | 56 | 同上 | **0** |
| C（14） | 14 | 声明全 0，只需看是否解引用 `[x2,#0x20/0x30/0x48/0x58]` | **0** |
| D（14） | 14 | 同上；D[4..7] 与 C[4..7] 目标不同，两条都扫了 | **0** |
| 合计 | **140** | | **0** |

**必须交代我自己这套扫描器的假阳性**：严格追踪版报出 2 条（B[28]、B[29]），**逐条手读后两条都是假阳性**：

- B[28] → `0xa022d78`：实际读的是 `ldr x1,[x2,#0x48]`（`scalarOutput`，声明 `sc_out=2`，索引 0，**在界内**），不是 `scalarInput`；
- B[29] → `0xa022dac`：`ldr x8,[x2,#0x20]; ldr w1,[x8]`，声明 `sc_in=1`，索引 0，**在界内**。

即：**假阳性率 2/2（100%）**，全部来自寄存器被复用后未及时作废。所以"0 条不一致"这个结论的证据强度，靠的是**手读**这 2 条 + 声明为 0 的 28 条走的是"是否解引用"这种不依赖索引推算的粗判据；中间那 110 条只有自动判据、没有逐条手读。

**因此诚实的表述是**：在 140 条记录中，**没有任何一条的证据强到可以称为发现**；自动判据报出的 2 条经手读全部推翻；粗判据覆盖的 28 条（C+D）全部干净；余下 110 条仅有自动判据支撑。

#### 6.7.4 AGX / IOSurface / UDIF 这条路不通

- **AGX**：`mov w?,#0x18` + `umull` 有 6 处，但**没有一处是 24 字节派发表索引**。抽查最像的 `0x84cdc88`：`cmp w19,#0x2; cset w22,eq; umull x9,w22,#24; add x10,x8,x9; add x23,x10,x20,lsl #3` —— 索引是 `(w19==2)?1:0`，落在 `[x21+0x48 + sel*24]`，是**内部 24 字节记录数组**，不是 user-client 派发表。AGX 的 5 张表是 switch 跳表（§6.2），**不适用本判据**。
- **IOSurface**：1 处（`0xa328b8c`），本轮未展开。
- **UDIF**：0 处；它的 2 张表也是 switch 跳表。

---

## §8 AGX 命令缓冲区解析

### 8.1 开工先纠一条会误导后续所有判断的错误

前几轮我写「这批 kext 的 `__DATA_CONST` 里没有代码指针 / 没有 vtable / `0x851cfd4` 不是虚函数」。**全错。** 错因是扫描时用了 `if v >> 63: continue`，把 **arm64e auth-signed 指针**（bit63 = 1，target 在 bits[0:32)）当成非法值过滤掉了。

修正解码式（与 `.dump` 里的普通 rebase 同一形式，只是不再判 bit63）：

```
va = 0xfffffe0007004000 + (q & 0xFFFFFFFF)
```

实测 AGX：`__DATA_CONST.__const` 里有 **3463 个** 代码指针（`__mod_init_func` 119、`__mod_term_func` 93、`__DATA.__data` 1）。抽样 `q = 0x8011c597014f4bb4 → 0xfffffe00084f8bb4`，高 32 位的 `0x8011c597` 是 key/addrDiv/diversity，**不是**目标。

**后果一**：§0.2.1「`imports_count=0` ⇒ 全 cache 无符号绑定 + 无 vtable」的后半句作废（前半句仍成立）。
**后果二**：§6.6.3 那条「`0x851cfd4` 零静态引用 ⇒ 不是虚函数」作废 —— 它**是**虚方法，vtable 槽 `0xfffffe0007f228c8`。§6.6 的「降级出局」结论**只剩两条腿**（`x2` 是 32 位标量、`base` 是堆结构体数组），「不可达」这条腿撤回。

被 vtable 引用的 `cmp w1,#N` 派发器（AGX）：

| 函数 | bound | vtable 引用处 | 引用数 |
|---|---|---|---|
| `0x84b81c0` | 0x41 | `0x7f25e18` `0x7f26dc0` `0x7f27ce0` `0x7f294e8` | 4（基类方法被 4 个子类继承） |
| `0x850f170` | 0x10 | `0x7f22f08` | 1 |
| `0x851070c` | 0x0f | `0x7f22300` | 1 |
| `0x8514ae0` | 0x64 | `0x7f22e08` | 1 |
| `0x851cfd0` | 0x11 | `0x7f228c8` | 1 |
| `0x85335f4` | 0x32 | `0x7f26e08` | 1 |
| `0x856a5e8` | 0xff | — | **0**（仍未定） |

### 8.2 但是：AGX 的 `externalMethod` 本体这一轮**没定出来**

对上面 6 个候选逐个扫 `IOExternalMethodArguments` 的特征偏移（`+0x20 / +0x28 / +0x30 / +0x38 / +0x40 / +0x48 / +0x50 / +0x58 / +0x60`），**6 个全部 0 命中**。也就是说这 6 个都不把 `x2` 当 args 解引用 —— 与 §6.6 对 `0x851cfd4` 的判定一致（`x2` 是标量），但结论是：**按 `cmp w1,#N` 找 AGX 的 `externalMethod` 这条路走不通**，AGX 的 user-client 方法入口要么在别的形态（vtable slot 转发 / `getTargetAndMethodForIndex`），要么这些 `w1` 派发器全都不是 user-client 层。

因此下面 8.3–8.5 审的是**AGX 里被我实际读到的三条"从缓冲/记录算索引"的路径**，不是 Metal command buffer 本体；**AGX 的 submit handler 本轮没能定位**。这一点必须先说清，避免"没找到"被读成"没有"。

### 8.3 路径一：`idx = len / stride` —— 有容量守卫（负结果，机制明确）

函数 `0xfffffe000854874c`（276 条指令），核心 24 条：

```asm
0x85487cc  bl   0x85892cc            ; w0 = getLen(obj x20)（PAC 桩，非本地函数）
0x85487d0  mov  w22, w0              ; ★ len（来自对象/描述符，不是用户直接写）
0x85487d4  ldr  w23, [x21, #0x48]    ; ★ stride
0x85487d8  ldr  x0,  [x21, #0x40]
0x85487dc  bl   0x8587ccc            ; 取锁
0x85487e8  bl   0x85499d8            ; ★ 容量守卫，见下
0x85487ec  tbz  w0, #0x0, bail       ; 返回 0 → 退出
0x85487f0  udiv x8, x22, x23         ; ★ idx = len / stride
0x85487f4  ldr  x9, [x21, #0x28]     ; ★ 记录数组基址
0x85487fc  umull x10, w8, #24
0x8548800  add  x10, x10, #0x10      ; rec = base + 0x10 + idx*24
0x8548804  cmp  x10, w10, sxtw       ; int32 范围闸（毒化 0x2bad）
0x8548814  csel x11, x11, x16, eq
0x8548818  umsubl x22, w8, w23, x22  ; ★ rem = len - idx*stride
0x854881c  ldr  x0, [x11]            ; ★ 取记录里的指针
0x854882c  autda x16, x17
0x8548838  blraa x8, x16             ; 虚调用 [x0]->[0x98]
0x854883c  add  x22, x0, x22, lsl #3 ; 结果 + rem*8
```

**`0x85499d8` 就是那个容量守卫**，读出来是 `ensure_capacity`：

```asm
0x8549a00  ldr  w24, [x0, #0x20]     ; counter
0x8549a04  cmp  x1, x24              ; ★ 请求长度 vs 现有容量
0x8549a08  b.hs grow                 ; 不够 → 去增长
0x8549a0c  mov  w0, #1               ; 够 → 返回 1
...
0x8549a40  ldr  w8,  [sp, #0xc]
0x8549a44  ldr  w9,  [x20, #0x20]
0x8549a48  add  w24, w9, w8
0x8549a4c  str  w24, [x20, #0x20]    ; counter += chunk
0x8549a50  cmp  x19, x24             ; ★ 循环直到 counter >= len
0x8549a54  b.lo 0x8549a0c
```

**结论**：`idx = len/stride` 之前 `len` 已被"容量 ≥ len"保证，`idx` 因此落在 `capacity/stride` 内；记录数组按 24 字节步长。**这条有校验，不构成越界**。这是负结果，但机制读到指令级，可留作后续对照。

（`.4e0` 变体 `0xfffffe000856aafc` 同构，逐条比对一致。）

### 8.4 路径二：记录表布局函数 `0xfffffe00084f8bb4` —— **循环无自身上界**

这是本轮唯一出现"从结构体读 count、直接当循环次数写数组"的地方：

```asm
0x84f8be0  ldr  x8, [x1, #0x10]      ; ★ array = args_struct->array
0x84f8be4  str  wzr, [x8, #0x14]     ; 先把 [0].field14 清零
0x84f8be8  ldr  w9, [x1, #0x18]      ; ★ count = args_struct->count
0x84f8bec  cmp  w9, #0x2
0x84f8bf0  b.lo 0x84f8c50            ; count < 2 → 跳过循环
0x84f8bf4  sub  x10, x9, #0x1        ; 迭代次数 = count-1
0x84f8bf8  mov  w11, #0x1            ; i = 1
0x84f8bfc  add  x12, x11, x11, lsl #1 ; i*3
0x84f8c00  lsl  x13, x12, #3          ; i*24
0x84f8c04  sub  x13, x13, #0x18       ; (i-1)*24
0x84f8c08  add  x14, x8, x13          ; rec[i-1]
0x84f8c1c  ldp  w14, w13, [x14, #0x10] ; 读 {size, off}
0x84f8c20  add  w13, w13, w14
0x84f8c24  add  w13, w13, #0x3f
0x84f8c28  and  w13, w13, #0xffffffc0 ; align 64
0x84f8c40  str  w13, [x14, #0x14]     ; ★ 写回 rec[i-1].field14
0x84f8c44  add  x11, x11, #0x1
0x84f8c48  subs x10, x10, #0x1
0x84f8c4c  b.ne 0x84f8bfc
0x84f8c50  sub  w9, w9, #0x1
0x84f8c58  umull x9, w9, #24
0x84f8c70  ldp  w24, w20, [x10, #0x10] ; 读最后一条 rec[count-1]
0x84f8cb0  lsl  w8, w8, w25            ; 对齐位移来自全局，不是用户
0x84f8cc4  and  w20, w9, w8            ; align_up(last.size + last.off, 1<<w25)
```

**数据流**：`count = [x1+0x18]`、`array = [x1+0x10]` → 循环 `count-1` 次，第 i 次写 `array[(i-1)*24 + 0x14]` → 最后读 `array[(count-1)*24 + 0x10..0x18]`。

**问题就一句**：这个循环**没有任何一处把 `count` 和数组真实容量比较**。它唯一的"闸"是 32 位乘法的毒化（`umull` + `cmp sxtw` + `0x2bad`），即 §6.3 已证的 **int32 范围闸，不是容量闸**。

**但我不能把它记成发现**，缺的是：`x1` 是谁给的。该函数被 **2 个 vtable 槽**（`0x7f22080`、`0x7f22d40`）引用 ⇒ **它是虚方法，可达性成立**；但它在本 kext 内**零 `bl` 调用者**（`grep 0xfffffe00084f8bb4 agx.dis` → 0 命中），说明调用方在别的 kext 或经 `braa` 到达，`count` 是否经过校验无从静态判定。

顺便：`[x1+0x10]` / `[x1+0x18]` 这两个偏移**恰好与 `IOExternalMethodArguments.asyncReference / asyncReferenceCount` 同址**，但本函数不读 `+0x20/+0x30/+0x38` 等任何其它 args 字段，且 `x1` 在函数内被当"带 array+count 的描述符"，所以**倾向它是内部结构，不是 args**。这一点标为**未定**，不拿它当证据。

### 8.5 路径三：`0xfffffe0008556cf0` 附近 —— 有界，负结果

```asm
0x8556cf4  and  w16, w15, #0xf
0x8556cf8  cbnz w16, 0x8556d44      ; ★ 低 4 位必须为 0
0x8556cfc  add  w8, w12, w17, lsr #4
0x8556d00  cmp  w8, w14
0x8556d04  b.hi 0x8556d40           ; ★ 上界检查
0x8556d0c  cbnz w11, 0x8556d4c
0x8556d14  sub  w16, w9, #0x1
0x8556d18  umull x16, w16, #24      ; idx = w9-1
0x8556d38  ldrb w14, [x2]           ; 读到 0 就退出
```

两道检查（对齐 + `cmp`/`b.hi`）都在索引之前。**有校验。**

### 8.6 真正属于"命令缓冲区解析"的那一段在 IOGPU，不在 AGX

你在任务里假设 AGX 有这个解析器。实际情况：**AGX 侧本轮没定位到**（§8.2），而我上一轮在 IOGPU 里解出的 `0xfffffe000a0528cc` 才是 tagged-union 命令解析器：

```asm
0xa0528cc  ldr  w24, [x8], #0x8     ; ★ 取 u32 type，指针前进 8
0xa0528d0  sub  w16, w24, #0x2      ; type-2
0xa0528d4  cmp  w16, #0x10          ; 上界 0x10（17 项）
0xa0528d8  b.hi default             ; ★ 越界走 default
           ... ldrsw + adr + br     ; 17 项跳表 @0xa053e40
           sub  x21, x2, x8          ; 剩余长度
```

**已证**：type（用户字节）→ 减 2 → 与 0x10 比较 → 越界进 default；跳表 17 项全解（§6.2 表）。**未证**：每条命令体内部是否检查"剩余长度 ≥ 该命令所需"，即 `sub x21, x2, x8` 后的逐条校验。这一段**本轮未读**，明确列入未审计。

---

## §9 `0x8558c18` 用户缓冲区解析

**范围**：`0xfffffe00085587f8`–`0xfffffe0008559430`（782 条指令）中的解析循环 `0x8558b44`–`0x8558c34`。全部手工逐条读，没有自动结果。

### 9.1 先纠正上一轮我写错的一句

上一轮我写「`[x2,#0x30]` 是子类自定义参数结构的缓冲区字段」。**读完整函数后这是错的**：`x2` 不是参数结构，而是**一个 56 字节记录数组里的第 i 条记录的地址**：

```asm
0x8558b78  lsl  x16, x9, #6          ; i<<6
0x8558b7c  sub  x16, x16, x9, lsl #3 ; = i*56
0x8558b80  add  x2, x12, x16         ; ★ x2 = X + i*56   ← 每条循环重新赋值
```

`x12` 才是数组基址（`0x8558b54  ldp x12, x13, [x13, #0x18]`）。所以 `[x2,#0x30]` 是**记录内偏移 0x30 的字段**（记录 56 字节，这是倒数第二个 8 字节槽），`[x2,#0x1]` / `[x2,#0x2]` 是记录内的两个 u8 计数。

### 9.2 `b.ls` 两个操作数的来源链（逐跳）

```asm
0x8558b9c  mov  x5, #0               ; j = 0
0x8558b94  ldrb w4, [x2, #0x1]      ; ★ j 的上界 = record->f1（u8）
0x8558ba0  ldr  x6, [x3, #0x10]
loop_j:
0x8558c04  ldr  x7, [x6, x5, lsl #3]; j-th 指针
0x8558c08  cbz  x7, next_j
0x8558bcc… x5 += 1; cmp x5, x4; b.eq next_i
```

```asm
0x8558c18  ldr  x21, [x2, #0x30]    ; buffer = record->f0x30
0x8558c1c  ldrb w22, [x21, x20]     ; ★ b = buffer[k]，k = x20
0x8558c20  lsl  x16, x22, #6
0x8558c24  sub  x16, x16, x22, lsl #3  ; = b*56
0x8558c28  add  x23, x12, x16       ; ★★ rec2 = X + b*56
0x8558c2c  ldrb w16, [x23, #0x1]    ; ★★★ 左操作数：rec2->f1
0x8558c30  cmp  w16, w5, uxtb       ; ★★★ 右操作数：w5 = j（内层循环下标）
0x8558c34  b.ls 0x8558c80           ; if rec2->f1 <= j → 走失败路径
```

- **左**：`rec2->f1`，`rec2 = X + (buffer[k]) * 56` —— 依赖一个**从缓冲区读出来的字节**做索引。
- **右**：`w5` = 内层循环下标 `j`，上界是 `record->f1`（`0x8558b94`）。
- 两侧都是 `uxtb` 后的 8 位值，**没有任何一处与"缓冲区字节数"或"数组元素个数"相关**。

### 9.3 直答

> **都不是。`b.ls` 既不是真实容量校验，也不是固定常数比较。**

它是**记录字段之间的一致性比较**：`rec2->f1 <= j` → 失败。语义上像"校验被引用记录的下标范围覆盖了当前 j"。

**因此它不保护任何内存访问**：三处解引用全部发生在它之前 —— `[x23,#0x1]`（0x8558c2c）、`[x21,x20]`（0x8558c1c）、以及 `[x20]`/`[x20,#0x8]` 那组位图更新。

### 9.4 顺着读出来的两处**无上界索引**（缺一环，不是发现）

| # | 指令 | 索引来源 | 基址 | 之前有无容量检查 |
|---|---|---|---|---|
| 1 | `0x8558c1c  ldrb w22, [x21, x20]` | `k = x20`，上界 `record->f2`（u8） | `x21 = record->f0x30` | **无**（只 `cbz` 了计数非零） |
| 2 | `0x8558c2c  ldrb w16, [x23, #0x1]` | `b = buffer[k]`，**任意 8 位值** | `X + b*56` | **无**（唯一的 `cmp` 在其后） |

第 2 处是重点：**一个从缓冲区读出的字节，被直接乘以 56 当作记录索引**，上界 255 ⇒ 最远 `X + 255*56 + 1 = X + 14281`。若 `X` 的记录数少于 256 条，这里就是越界读。

**缺的那一环**（因此不升级为发现）：
1. `X` 的记录数没有静态确定 —— `x12` 来自 `ldp x12, x13, [x13, #0x18]`，`x13` 再往上是一串 `[xN+0xcb0]` 之类的结构体字段链，本 kext 内追不到分配点。
2. `record->f0x30` 指向的字节缓冲区**由谁填充**未定。若它由内核生成且值恒 `< 记录数`，第 2 处安全；若它来自用户提供的描述符，则不安全。
3. 该缓冲区的**容量**与 `record->f2`（u8，最大 255）之间**没有发现任何比较** —— 这一点是确定的，但只覆盖第 1 处索引。

### 9.5 可达性

**不判死。** 上一轮说它「不是标准 args」，那只说明它不是 `externalMethod`，**不说明不可达**：`x2` 是记录数组指针、`x0` 是 this，函数在 `0x8558938` 还有一条 `x0/x1/x2` 原样转交的尾路（`b` 到别处），说明它是被上层方法调用的内部例程。本 kext 内对 `0x85587f8` 的静态引用数：自动扫描 **未手读**，不作为结论。

**一句话**：`b.ls` 已经定性（非容量校验，比较的是 `rec2->f1` 与循环下标 j）。剩下能把它变成发现的唯一缺口是「`X` 有多少条记录 + `f0x30` 那个字节表由谁写」—— 这两点静态追不到，需要符号或动态断点。

---

## §7 直答（AGX）

> **AGX 这条面上，本轮没有确证任何一处用户态可控输入导致的内核内存破坏。**

分开说，避免把"审了没有"和"没审到"混起来：

- **审了、并且是否定**：AGX 的**表驱动派发**。五张跳表全部解出（66/15/18/51/17 项），`br` 之前**全部**有 `cmp wN,#BOUND; b.hi default` 上界检查，没有越界跳转面（§6.2）。IOGPU 的兄弟函数加固对称性也是否定结论（§6.4）。
- **审了、候选已闭合为否定**：`0xfffffe000851cfd4` 的 sel 3 / sel 4。三个判别实验（§6.6）做完后的结论是**降级出局**：
  1. `x2` 在全部 12 个 case 里**只当 32 位标量**用（唯一一次写入是 `mov x20,x2`，唯一一次溢出是 `str w20,[sp,#4]`，两次读回都喂 `umull`），**没有任何 case 解引用它** ⇒ 不存在类型混淆，签名是 `f(self, op, count)`，**不是 `externalMethod`**；
  2. `base` 是**堆/结构体数组**（无 `ldraa`/无屏障/偏移非均匀全 32 位读，记录大小 696 或 376），不是 MMIO；所谓"毒化"是 int32 范围闸，不是容量闸；
  3. ~~该函数在五种编码下**零静态引用** ⇒ 不是虚函数，取不到任何入口。~~ **该条已被 §8.1 推翻**：放开 `bit63` 后它是虚方法，vtable 槽 `0xfffffe0007f228c8`。
  
  只剩两条腿，仍足以降级：`x2` 是 32 位标量（无一处解引用）+ `base` 是堆结构体数组 + 无容量闸但只有 int32 范围闸。**`w2` 的调用方仍无法静态确定**（本 kext 内零 `bl`，只能经 vtable/`braa`，而 vtable 所属类未解出）。要闭它得动态断点或符号源。**在此之前，它不是发现。**
- **没审到**：AGX 878 KB 里除 §6.2 的 5 张表 + §8.3–8.5 的三条路径之外的绝大部分。AGX 的 `externalMethod` 与 Metal submit handler **本轮未定位**（§8.2：6 个 `cmp w1,#N` 候选全部不读 `IOExternalMethodArguments` 的任何特征偏移）。真正的 tagged-union 命令解析器在 **IOGPU**（`0xa0528cc`），属另一 kext。

一句话给下一个接手的人：**AGX 的派发不是障碍了（跳表可解、上界齐全），障碍是"用户数据怎么进到那些 `w1` 派发器"。** 先解 `AGXDeviceUserClient` 的 externalMethod，比继续盲扫 878 KB 划算一个数量级。

## §7b 直答（声明的入参量 vs 实现实际读的量）

> **没有。140 条派发记录，0 条「声明允许的入参量小于实现实际读的量」。**

- 核对范围：IOGPU `externalMethod`（`0xa024d94`，56 条 × 2 张表 = 112）+ 第二个 user client（`0xa024e4c`，14 条 × 2 张表 = 28），**合计 140 条**。
- 自动判据报出 2 条疑似（B[28]、B[29]），**逐条手读后全部推翻**（都是读 `scalarOutput` 或索引 0 在界内）。
- 声明全 0 的 28 条（C/D 两表）：**没有任何一条解引用 `args->scalarInput/scalarOutput/structureInput/structureOutput`**。
- 覆盖不到：AGX（5 张表是 switch 跳表，不适用本判据）、UDIF（同）、IOSurface 的 1 处 `umull #24`（未展开）。
- 顺带的正面产物：**IOGPU 的 `externalMethod` 与全部 140 条声明的原始值已解出**，表 A/B/C/D 地址分别是 `0xfffffe00082f69f0`、`0xfffffe00082f64b0`、`0xfffffe00082f7088`、`0xfffffe00082f6f38`（后两者需 +8 对齐才是记录起点）。

## §8 直答（AGX 命令缓冲区解析）

> **没有。本轮没有确证任何一条「从用户字节读出的长度或索引，在进入内存操作之前没有经过容量校验」的路径。**

但必须把账算清楚，因为这一轮的覆盖比前几轮窄：

**读了、且有明确校验机制（负结果，指令级可复现）**

1. `idx = len / stride` 路径（`0xfffffe000854874c`，另 `.4e0` 变体 `0x856aafc` 同构）：`len` 在任何索引计算之前先过 `0xfffffe00085499d8`，该函数是 `ensure_capacity` —— `cmp x1, [x0+0x20]; b.hs` 进入增长循环，直到 `counter >= len` 才返回 1。**校验存在。**
2. `0xfffffe0008556cf0` 一带：索引前有 `and w16,w15,#0xf; cbnz → bail`（对齐）与 `cmp w8,w14; b.hi → bail`（上界）。**校验存在。**

**读了、但缺一环，不能称发现**

3. `0xfffffe00084f8bb4`：`count = [x1+0x18]`、`array = [x1+0x10]`，循环 `count-1` 次写 `array[(i-1)*24 + 0x14]`，**循环体内没有任何 `count` vs 容量 的比较**，唯一闸门是 int32 毒化（范围闸，非容量闸）。但它是**虚方法**（vtable 槽 `0x7f22080` / `0x7f22d40`），本 kext 内**零 `bl` 调用者**，`x1` 的来源与 `count` 是否在校验后传入**无从静态判定**。缺的就是这一环。

**没读到（明确留白，不是"没有"）**

4. AGX 的 `externalMethod` 与 Metal 命令提交入口 —— 6 个 `cmp w1,#N` 候选（含 4 个被多个 vtable 引用者）逐个扫 `IOExternalMethodArguments` 特征偏移（`+0x20/+0x28/+0x30/+0x38/+0x40/+0x48/+0x50/+0x58/+0x60`），**全部 0 命中**，说明按"`cmp w1,#N` + 读 args"找 AGX 的 user-client 方法入口这条路不成立。AGX 的 submit handler 本轮**没有定位到**。
5. IOGPU 的 tagged-union 解析器（`0xfffffe000a0528cc`）里，`type` 的上界已证（`sub w16,w24,#2; cmp w16,#0x10; b.hi default`，17 项），但 `sub x21, x2, x8`（剩余长度）之后的**逐命令长度校验没读**。

**读了哪几条、总共多少条**：AGX 侧 3 条（§8.3 两条同构算 2 条、§8.4 一条、§8.5 一条），其中 2 条判为有校验、1 条判为缺一环；IOGPU 侧 1 条（解析器外壳），只到分派层。**合计 4 条路径、5 个函数体（276 / 183 / 4 / 183 / 1 条指令级），无一条可升级为发现。**

给下一个接手的人：**别再按 `cmp w1,#N` 找 AGX 的 externalMethod 了**（§8.2 已证否）。现在已知的锚是那 3463 个 vtable 代码指针（§8.1）—— 从 vtable 布局反推类，再从类的 `externalMethod` 槽（`IOUserClient` 的固定槽位）取，是唯一还可能走通的路。
