# AGXAcceleratorG18P 用户客户端外方法面（iOS 27.0.1）

> 可达性由真机实测确认（`out/SERVICE-MATRIX.md`）：
> `IOServiceOpen("AGXAcceleratorG18P", task, type=1)` → `KERN_SUCCESS`。
> **这是本 app 能打开、且此前完全未审计的最大内核面。**

## 0. 一句话

**`IOGPUDeviceUserClient` 外方法表共 168 条（两张表 112 + 56），
其中 21 条的输入或输出长度是 `0xFFFFFFFF`（wildcard ⇒ IOKit 完全不校验）。
去重后 8 个 handler，其中一个 handler 的输入和输出**双双 unchecked**。**

## 1. 表在哪、怎么看

派发表**不在** `__DATA_CONST`，在 `__DATA`；**stride 是 24，不是 40**。

```
起 off 0x12f24b0  ->  table A, 112 条
起 off 0x12f29f0  ->  table B,  56 条
条目布局:
  +0   handler  (chained ptr, 指向 bti c)
  +8   { scalarIn,  structIn  }   各 32 位
  +16  { scalarOut, structOut }   各 32 位
0xFFFFFFFF = wildcard = 不校验
```

**为什么之前扫出 0 张表**：本项目所有扫描器都按 **stride 40** 写，
按 40 解这张表会得到垃圾（`sOut=15679416` 之类）。
`IOSurface` 的表确实是 40（`IOExternalMethodDispatch2022` 形态），
`IOGPUFamily` 是 24（经典形态）。**两种并存，扫描器必须都试。**

## 2. wildcard 条目（去重后的 8 个 handler）

| handler | stIn | stOut | 说明 |
|---|---|---|---|
| `0xa02260c` | **wild** | **wild** | **输入输出双双不校验 —— 最高优先级** |
| `0xa022274` | **wild** | 16 | 输入不校验 |
| `0xa0228c0` | 0 | **wild** | 输出不校验 |
| `0xa02299c` | **wild** | 0 | 输入不校验 |
| `0xa0236ac` | **wild** | 0 | 输入不校验 |
| `0xa023d58` | **wild** | 0 | 输入不校验 |
| `0xa023ee8` | **wild** | 0 | 输入不校验 |
| `0xa0240d8` | **wild** | 0 | 输入不校验（占 4 个槽：101/108/109 等） |

selector 索引（table A）：`6, 8, 22, 25, 45, 52, 53, 62, 64, 78, 81, 101, 108, 109`

## 3. `0xa02260c` 开头（已反汇编）

```
0xa02260c  bti c
0xa02262c  mov  x22, x2            ; args
0xa022634  mov  w19, #0x2c2 ; movk #0xe000,lsl#16   ; 默认返回 BadArgument
0xa02263c  ldr  x23, [x2, #0x58]   ; structureOutput 指针
0xa022640  ldr  x0,  [x2, #0x40]   ; 一个对象指针
0xa022644  cbz  x0, 0xa0226bc      ; 为空则走默认失败
0xa022648  ldr  x16, [x0]          ; 取 vtable
0xa022654  autda x16, x17          ; 认证（PAC）
0xa022658  ldr  x8, [x16, #0xe8]!  ; 方法 +0xe8
0xa02265c  mov  w1, #0x1000
0xa022664  blraa x8, x16           ; 调过去，w1=0x1000 (4096)
```

**注意 `ldr x0,[x2,#0x40]`：本 kext 用的 args 字段集与 IOSurface 不同**
（IOSurface 用 `+0x30` 作 structureInput）。**不要跨 kext 套用同一份字段映射。**

## 4. 还没做的

1. `0xa02260c` 到底往 `structureOutput` 写多少字节、写到哪些偏移
2. `w1=0x1000` 是不是一个未校验的「要写多大」参数（**若调用方可控 → 直接是内核堆溢出**）
3. 其余 7 个 handler 的写量与偏移
4. 少量 `structureOutputSize` 值下的实际行为（真机）

## 5. 工具坑（新增）

- **stride 不是常数。** 24 与 40 两种派发表并存。只写一种必然漏掉整片 kext。
- **wildcard `0xFFFFFFFF` 才是「不校验」的准确信号**，
  而不是 `0`。`0` 表示「必须正好 0 字节」，也是强校验。
  本项目此前把 `0` 当成「未校验」，方向搞反了。
- `IOExternalMethodArguments` 的字段偏移 **按 kext 不同而不同**，必须逐 kext 反推。

---

# 6. 闭环（第 9 轮）：wildcard 不等于不校验 —— **负面**

## 6.1 `0xa02260c` 拆到底

```
0xa02263c  ldr  x23, [x2, #0x58]      ; structureOutput 指针
0xa0226cc  cmp  x3, #0x58             ; 输入侧 >= 0x58
0xa0226d0  ccmp x23, #0, #4, hs       ; 输出指针非空
0xa0226e8  bl   0xa024ec4             ; 转发
```
`0xa024ec4` 原样转发到 `0xa0414b0`（x1/x2/x3/x4 全传）。

`0xa0414b0` 里**有完整的双向校验**：
```
0xa0414e0  cmp  x3, #0x58
0xa0414e4  b.lo 0xa0419e4             ; 输入不足 -> BadArgument

0xa0414ec  ldr  w8, [x4]              ; 声明输出大小 (args+0x60)
0xa0414f4  ldr  w9, [x0, #0x22c]      ; 驱动侧所需
0xa0414f8  add  x9, x9, #0x58
0xa0414fc  cmp  x9, x8
0xa041500  b.hi 0xa0419e4             ; 不够 -> BadArgument
```

**⇒ 输出长度在真正写入前被 `[args+0x60]` 校验，越界写在构造上不成立。**

## 6.2 这一条推翻了我上一轮的判据

上一轮我把「派发表里 `stOut=0xFFFFFFFF`」当作「不校验」。
**错的。** wildcard 只是说 IOKit 这一层不管，**handler 自己在内部拿 `[args+0x60]` 比**。

于是「8 个 wildcard handler 是风险目标」这个假设**在原理上就不成立**，
它们的展开大概率会像 `0xa02260c` 一样各自有校验。

## 6.3 为什么这么多次都是假阳性：同一个盲区

本项目所有「未校验」结论都来自**同一个缺陷**：
检测器只跟 `b` 尾调用，**不跟 `bl`**。
真实代码把校验放在被调函数里（本例 `0xa0414b0`），于是全被判成「未校验」。

```
IOSurface      长度校验在 callee 0xa34bc34   -> 误判
IOGPU 0xa02260c 长度校验在 callee 0xa0414b0  -> 误判
```

**结论：只要检测器不跟 `bl`，「某 handler 不校验长度」这个结论就不可用。
必须停止用「是否出现对 size 字段的读」当判据。**

## 6.4 下一个判据（换方向，不再修同一个检测器）

真正值得查的类别不是「外层长度没校验」，而是：

> **输入缓冲区内部自带长度/偏移/计数，handler 拿它当下标或偏移用，
> 而外层只校验了缓冲区总大小。**

这类漏洞不受 `[args+0x38]` 校验保护 —— 外层大小是对的，坏的是内部字段。
典型形态：`ldr w9,[x1,#k]` 之后直接 `add x8,x1,x9` / `ldr x0,[x8]`，中间没有 `cmp`。

**下一轮查这个类别，范围限定在真机实测可达的 7 个服务内。**

---

# 7. 一个尚未解决的疑点（第 11 轮）

那两张表（`__DATA_CONST` 里 112 + 56 条）**找不到任何引用**：

```
adrp+add 引用            0
adrp+ldr 未查
chained 槽指向它们       0
完整 8 字节地址          0 处
低 32 位地址             0 处
fileoff / data-relative / page-relative 偏移   均 0 处
```

**两种解释：**
1. 它们是 live 表，但引用方式是 PAC 签名后的指针（原值不等于裸地址），我的搜索都够不着；
2. 它们是**死拷贝 / 模板**，真正的分发表在别处。

**条目本身是"像真的"**：handler 落在 `__TEXT_EXEC` 且偏移合理，计数是 64/536/8/16/32 和 wildcard，
不是随机数据。

**结论：静态无法定论。** 用真机调 selector 来判定——
如果返回 `0xE00002C7 Unsupported` 就说明该 selector 不存在（表是死的）；
如果返回别的码，表就是活的。这就是 `out/GPU-PROBE.md` 要做的事。

---

# 8. 真机判定（第 11 轮结果，含一处勘误）

## 8.1 表死活：已闭合

真机扫 selector 0..167，**只有 0..55 存在**，56..167 全部 `0xE00002C7 Unsupported`
（dispatcher 层就拒，一次都没进 handler）。

### 关于 A/B 两表的关系（我先误判过一次，这里更正）

我一度写「报告说 B 表是活的，是标签错了」。**核实后：我错了。**

```
A 前 56 条与 B 前 56 条逐位相同的:  28 / 56
前 12 条完全一致（0xa021ee8, 0xa021ffc, 0xa022030, 0xa022100,
                  0xa022134, 0xa022210, 0xa022274, ...）
```

两张表**在前段大量重叠**。所以：
- 「sel 0..55 = A.idx 0..55」和「那 56 条就是 B 表」**描述的是同一批 handler**
- 两种说法都对，不构成矛盾

**操作上唯一重要的事实：活着的 selector 是 0..55，共 56 条。**

交叉验证：
```
sel 0  -> 0xa021ee8  stOut=64   真机 oc/sc 显示 64B    ✓
sel 2  -> 0xa022030  stOut=536  真机 536B（全表最大）   ✓
sel 8  -> 0xa02260c  双 wildcard 两遍均 BadArgument    ✓
```

**有效面从 168 条缩到 56 条。**
`0xa0240d8`（A 表里占 28 个槽的 stub）落在 idx 101/108/109 → **不可达，降级**。

## 8.2 真机返回码分布

```
SUCCESS          14   sel 0,1,2,3,4,5,16,17,19,21,23,28,41,42
Unsupported     113
BadArgument      35
NotPrivileged     3   sel 32,33,34
NoMemory          1   sel 12
其它              2
```

## 8.3 三个高价值点

1. **sel 0/1/2/3/4/5/16/17/19/21 返回 SUCCESS 且往调用方缓冲区拷数据**
   （64/64/536/8/32/16/8/4/24/48 字节）。**缓冲区内容尚未 dump。**
   → 这是本项目从未开始的 **S3（信息泄露）** 的现成入口。**最高优先级。**
2. **sel 8 需要 `stIn=0x58(88)` 才可能进到 `0xa0414b0`** —— 真机只试了 0 和 1 字节。
   88 及更大值**还没试过**。
3. `sel 55` 让内核调用永久阻塞（handler `0xa0240cc`，三次独立复现，150s 看门狗收尾），
   **不是 panic**。属 DoS 级，与 S2 同类，价值有限。

## 8.4 静态结论被真机钉死

sel 8 用 0 字节和 1 字节都回 `BadArgument` ⇒ §6.2 的「wildcard≠不校验，
handler 内部有 `cmp x3,#0x58`」**实测成立**。

---

# 9. GPU 面结论：挖干了（第 12 轮）

## 9.1 一条会影响所有后续 harness 的规则

**这个 kext 的派发校验是「精确相等」，不是 `>=`。**

```
scalarOut 必须 == 声明值（多数是 0）
structOut 必须 == 声明值
放大任一个 -> kIOReturnBadArgument(0xE00002C2)
```

实测：14 个 selector 按声明原值传 → **14/14 SUCCESS**；
把 structOut 放大到 4096（scalarOut 保持精确）→ **14/14 BadArgument**。

**这条解释了前几轮 sel 8 的 BadArgument**：它声明 scalarOut=0，之前传了 64，
死在校验层，根本没进 handler。**不是 handler 拒绝。**

> 写进规则：**任何走 wildcard/声明契约的调用，scalarOut 与 structOut 都必须精确等于声明值。
> 想探越界只能靠「声明什么就传什么」之后看 handler 内部怎么写，不能靠放大缓冲区。**

## 9.2 测试 A 结果：没有内核地址

14/14 SUCCESS，dump 全文在 `out/GPU-DUMP.md`。摘要：

| selector | 内容 | 价值 |
|---|---|---|
| 0 | 64B 小整数位域（`0x4340`, 2, `0x4000`, `0x80000000`） | 无 |
| 1 | 64B，`"AGXG18P"` | 无（固件名） |
| 2 | 536B：32B 头 + **125 条 u32 偏移表 8,12,…,508** | 无（偏移表） |
| 3, 21 | 全 0 | 无 |
| 17 | u32=1 | 无 |
| 5, 16, 19 | `0x1310xxxx`/`0x1410xxxx` 时间戳/计数器 | 无 |
| 23 | scalar 0 | 无 |
| 28, 42 | `0x14100e38`/`0x14100e5c` 单调计数器 | 无 |
| **4** | `0x000001049b0000` / `0x0000010487c000`，16KB 页对齐 | **用户态 VA** |

**sel 4 的两个值随进程 ASLR 平移**（复跑变成 `0x104ab4000`/`0x104aa8000`），
基址在 `0x100000000` 之上 ⇒ **iOS 用户态地址，不是内核地址，拿不到 slide。**

**结论：14 个 selector 全部无内核指针、无 PAC 指针；
声明长度之后的字节全 0，无越界写。**

## 9.3 测试 B：sel 8 走不通，且不是尺寸问题

scalarOut 改成 0 后**全部越过校验**，错误码变成 `kIOReturnNoResources(0xE00002BE)`，
**16/16 完全一致**：

```
(stIn, stOut) = (0x58,0x80) (0x58,0x200) (0x58,0x800) (0x58,0x1000)
                (0x60,·) (0x100,·) (0x400,·)          -> 全 0xE00002BE
```

stIn 从 0x58 加到 0x400、stOut 从 0x80 加到 0x1000，**kr 一动不动**。

读法：确实进了 `0xa02260c`，卡在 `0xa0414b0` 的 `声明 >= [x0+0x22c] + 0x58` 门槛上，
而 `[x0+0x22c]` 是**驱动侧自己填的**，不是调用方能撬的。
大概率要求先有成功的 init selector 或 GPU 已通电/有 surface。

**这条线不要再投入。**

## 9.4 最终判定

**AGX GPU 用户客户端这条面，到此挖干：**
- 56 个 selector 全部枚举
- 14 个成功的全部 dump，无内核信息泄露
- 唯一的地址泄露是用户 VA（无价值）
- sel 55 永久阻塞（DoS 级，与 S2 同类）
- sel 8 被驱动侧状态卡住，尺寸撬不动
- sel 32/33/34 卡 entitlement（本 app 无相关授权）

**S3（信息泄露）在这条面上不成立。**
