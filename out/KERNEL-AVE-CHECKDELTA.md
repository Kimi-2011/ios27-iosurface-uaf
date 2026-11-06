# AppleAVE2 内核校验增量：27.0.1 缺失的边界检查（实证）

**日期**：2026-10-31 22:50
**方法**：对 `ave.27.0.1.macho` / `ave.27.2.ga.macho` 做字符串增量 + 指令级字段读取点扫描

---

## 一、27.2 给 AppleAVE2 新增了 21 条校验消息

用 Python 直扫 Mach-O（macOS `strings` 对 kext 返回 0，必须自己扫）：

```
27.0.1 字符串 7255 | 27.2 字符串 7312 | 新增 127（其中校验类 21）
```

新增校验（节选，全部指向码流参数集解析）：
```
HEVC VPS count is out of range
HEVC VPS vps_max_layers_minus1 is out of range
HEVC VPS num_add_layer_sets is out of range
HEVC VPS layer_id_in_nuh is out of range
HEVC VPS highest_layer_idx_plus1 sum is out of range
HEVC VPS layer-set total / output-layer-set total is out of range
HEVC VPS extension layer/OLS counts are out of range
HEVC SPS / PPS / RPS count is out of range
AVC PPS count / AVC log2_max is out of range
HEVC log2_max_pic_order_cnt_lsb_minus4 is out of range
MCTF strength count out of range
invalid MB/CTU stats firmware buffer
number of sub layer is out of range
iRefNum is out of range
```

这些字段全部来自**压缩码流**，且对应公告中 AVEVideoEncoder 的 6 条越界 CVE
（112705 / 112689 / 112470 / 112469 / 112468 / 112466），此前只分析了 1 条（且是自伤 DoS）。

## 二、指令级证据：27.0.1 缺校验

扫描 `LDR (immediate, 32-bit)` 指令，按字段偏移统计读取点：

| 字段 | 27.0.1 读取点 | 27.2 读取点 | 27.2 含检查 |
|---|---|---|---|
| **0x1888** | **2** | 10 | ✅ `cmp w8,#6; b.hi` → 错误路径 |
| 0x27f8 | **0** | 10 | ✅ `cmp w8,#0xf; b.hi` |
| 0x2c10 | **0** | 10 | ✅ `cmp w8,#0x10; b.hi` |
| 0x27f4 | **0** | 10 | ✅ `cmp w8,#0x3f; b.hs` |

27.2 校验块原文（`0xfffffe00087c51b0`）：
```asm
ldr w8, [x20, #0x1888]
cmp w8, #6
b.hi #error
ldr w8, [x20, #0x27f8]
cmp w8, #0xf
b.hi #error
ldr w8, [x20, #0x2c10]
cmp w8, #0x10
b.hi #error
```

27.0.1 对应位置（`0xfffffe000878de54`）**无任何比较**：
```asm
ldr w8, [x21, #0x1888]
cbz w23, #...
stp x19, x8, [sp, #0x30]     ← 直接使用
```

## 三、必须说清的两个限制

### 限制 1：偏移跨版本可能漂移
0x27f8 / 0x2c10 / 0x27f4 在 27.0.1 **从未被读取**，说明这可能是 27.2 新加的字段，
而不是"27.0.1 用了但没检查"。结构体增大 → 偏移整体漂移 → 直接比偏移不可靠。

**唯一可信的是 0x1888**：两版都读，27.2 加检查、27.0.1 没有。

### 限制 2：0x1888 在 27.0.1 的用途不是数组索引
```asm
ldr w0, [x21, #0x1888]
bl  FUN_fffffe00088cedac      ← 作为函数参数
```
是"传参"而非"索引"。要证明是 OOB 必须先恢复结构体语义 + 定位它最终索引的数组。

## 四、方法学死路（已复现确认）

AVE 的日志走**运行时消息表**，代码不直接引用格式字符串：
```
'vps_max_layers_minus1 is out of range' VA=0xfffffe0007308fca  引用数=0
```
→ 字符串 xref 定位法对 AVE 完全无效（Ghidra 与自建 ADRP+ADD 扫描器均 0 命中）。

## 五、结论

| 事项 | 状态 |
|---|---|
| 27.2 新增 21 条码流校验 | ✅ 实证 |
| 0x1888 在 27.0.1 无校验、27.2 有 | ✅ 实证 |
| 该缺失导致内核越界写 | ❌ **未证明**（用途未定性） |
| app 能把构造的 VPS 送进内核 | ❌ **未打通**（此前 19 个属性键全 -12900） |

**这是目前最接近"内核越界"的线索，但它还不是一个可用漏洞。**
从"发现缺校验"到"能触发的内核 OOB"还差两步：恢复结构体语义、打通输入通道。
而打通输入通道这一步，之前已经把 18 个 app 可设属性全试完了。

---

## 五、修正（2026-11-01 00:25）：0x1888 的读取点是日志，不是索引

跟随 `FUN_fffffe00088cedac` 与调用点反汇编后，两条判断都要改：

### 5.1 27.0.1 并非完全不校验 0x1888
`FUN_fffffe00088cedac` 本身**就是校验函数**：
```asm
cmp  w0, #4
mov  w8, #-0x3ea
csel w0, wzr, w8, lo     ; w0 < 4 → 0，否则 -0x3ea
ret
```
所以 `< 4` 的边界检查在 27.0.1 **已经存在**，只是位于被调函数内。

### 5.2 但该读取点的用途是日志，不是数组索引
27.0.1 `0xfffffe000878de54`：
```asm
ldr  w8, [x21, #0x1888]
cbz  w23, ...
stp  x19, x8, [sp, #0x30]      ; 塞入栈上参数数组
adrp x8, #0xfffffe00072ea000
add  x8, x8, #0x152            ; 取格式串
mov  w9, #0x1d9
stp  x9, x8, [sp, #0x20]
adrp x0, #0xfffffe00072ff000
add  x0, x0, #0xadf
stp  x22, x8, [sp]
b    #0xfffffe000878e048       ; → 日志函数
```
**这是日志格式化**，`0x1888` 作为 printf 参数使用。
→ 「0x1888 未校验导致越界」这一推断**不成立**，此前结论作废。

### 5.3 为什么所有读取点看起来都像日志
正是第四节说的「运行时消息表」：AVE 不引用格式串，而是把参数打进数组再交给统一日志函数。
这导致 **字符串 xref 定位法 0 命中**，同时**也把真实的数据流读取点伪装成日志点**。
两者用同一种代码形态，无法靠反汇编形态区分。

### 5.4 结论
AVE 这条线的可挖掘性**被显著下调**。要在 AVE 上继续，必须先解决
「如何区分日志参数与真实索引」这个问题——目前没有可靠方法。
建议把 AVE 从高优先级列表移出。
