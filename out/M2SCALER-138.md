# M2ScalerCSCDriver `+0x138` 字节门 —— 完整分析

对象：`com.apple.driver.AppleM2ScalerCSCDriver`
方法：27.0.1 / 27.2 提取出的 kext（`out/v2701/` `out/v272/`），`tools/fdiff.py` 划函数边界 + capstone 反汇编。
纯静态，未碰设备。

---

## 0. 先纠正一个前提

你在指令里说「写侧 `0xfffffe0009142840` … 它是不是 teardown？」「一读一写」。

**这个前提不成立。** `0x9142840` 不是写侧，它也是**读侧**，而且是个 **6920 字节**的大函数 ——
它是 CSC 参数**字典构建器**，里面成片引用这些字符串：

```
ProcessName / SourceWidth / SourceHeight / SourcePixelFormat
DestinationWidth / DestinationHeight / DestinationPixelFormat
Rotation / SourceRGB / SourceYCbCr / SourceCompressedPlane%u
ReshapingLUT / MMRCb / MMRCr / ChromaUpSample
DivideAlphaFirst / MultiplyAlphaFirst
```

即「把一次颜色空间转换的参数打成字典/日志」。两个门函数都是**诊断/遥测路径**，不是 teardown。

真正的**写侧**是另外两个函数（见 §2）。

---

## 1. Q1：`+0x138` 是哪个对象的字段

**是 CSC 子对象自己的失效字节。** 访问形态在 27.2 里高度统一（15 处）：

```asm
ldr  x8, [self, #0x50]      ; CSC 子对象指针
cbz  x8, out
ldrb w9, [x8, #0x138]       ; ← 失效字节
tbz  tbnz w9, #0, ...
add  x8, x8, #0x130         ; ← 与它相邻的资源/载荷字段
```

结构推断：

```c
struct M2ScalerCSCObj {          // 由 self->0x50 指向
    ...
    /* 0x100 */ void *res100;     // teardown 时释放
    /* 0x120 */ void *res120;
    /* 0x130 */ void *payload;    // 诊断时要打印/格式化的东西
    /* 0x138 */ uint8_t invalid;  // ← 新增的失效字节
    /* 0x164 */ uint32_t x164;
    /* 0x168 */ uint32_t state;   // 2 = 活
};
```

`self` 本身是 scaler 服务对象，它还有 `+0xcb4`（一个诊断限流计数器，上限 `0x3d = 61`）。

---

## 2. Q2：写侧在哪、是不是 teardown

**两个写点，都在 27.2 新增（27.0.1 侧 `+0x138` 一次都没被写过）：**

### 2.1 `0xfffffe00090e1698` —— **是 teardown**

```
 24  mov  x19, x0
 28  mov  w8, #1
 32  strb w8, [x0, #0x138]     ; ← 先打失效标记
 36  ldr  x0, [x0, #0x100]
 40  cbz  x0, out
 44  bl   ...                  ; 然后才释放 +0x100
 52  mov  x0, x19
 56  bl   ...
 64  ldr  x0, [x19, #0x100]
 68  ldr  x16, [x0]            ; 走 vtable 继续销毁
```

**先置 `invalid=1`，再释放 `+0x100`。** 这就是「improved state handling」的标准形态：
把「对象已失效」这件事在释放**之前**记录下来，让并发读者能看见。

### 2.2 `0xfffffe00090e1240` —— 初始化/复位（清零）

```
 20  str  w2,    [x0, #0x164]
     str  xzr,   [x0, #0x120]
 36  strb wzr,   [x0, #0x138]   ; ← invalid = 0
 40  mov  w8, #2
 44  str  w8,    [x0, #0x168]    ; state = 2（活）
```
调用者：`0x90e148c`、`0x90e1a18`。

所以生命周期是：**构造清 0 → 使用 → teardown 置 1 → 释放**。

---

## 3. Q3：读侧在什么路径上、命中后返回什么

**不返回任何错误码。** 命中（`invalid == 1`）时它**不去解引用 `+0x130`**，改成打印字符串 `"(unknown)"`。

直接证据 —— 读门 A `0xfffffe000912b940` 只有 268 字节，全文如下（节选关键段）：

```
 40  ldr  w8, [x1, #0xcb4]      ; 诊断限流计数
 44  add  w8, w8, #1
 48  str  w8, [x1, #0xcb4]
 52  cmp  w8, #0x3d             ; 每 61 次才真的打一次
 56  b.lo skip
 64  ldr  x8, [x1, #0x50]       ; 子对象
 68  cbz  x8, out
 76  ldrb w9, [x8, #0x138]      ; ← 门
 80  tbz  w9, #0, 0x...b9b0     ; 未失效 -> 走 112
     ; ---- 已失效：只拼 "(unknown)"，完全不碰 x8 ----
 84  adrp x8, "(unknown)"
 92  ldp  q0, q1, [x8]
 96  stp  q0, q1, [sp]          ; 64 字节拷到栈上
108  b    join
     ; ---- 未失效（112）： ----
112  ldr  x0, [x8, #0x130]      ; ← 读资源指针
140  cbz  x0, join
144  bl   ...                   ; 格式化
168  mov  w0, #2 / mov w1, #8 / bl 0x90a3374
196  bl   0x91c42ac             ; 上报
204  cbnz w0, ... / str wzr, [x19,#0xcb4]   ; 复位计数
```

**结论：这是「诊断打日志时不要碰已释放对象」的修复。** 没有错误返回、没有拒绝路径，
只有一次「改读常量字符串」。

读门 B `0x9142840`（6920 字节那个字典构建器）同理，门在 `+0x74`：
`ldrb w9,[x8,#0x138]` / `tbnz w9,#0, →0x91428dc`（跳到填 `(unknown)` 的分支）。

---

## 4. Q4：两侧能否从 selector 到达

### 4.1 census 里 M2Scaler **只有两行**

```
sel 0   handler 0xfffffe0009099b40   sIn=0 stIn=0 sOut=0 stOut=0
sel 1   handler 0xfffffe000909b33c   sIn=0 stIn=0 sOut=3 stOut=0
```

这两行和我们实测对不上：我们动态扫到 M2Scaler **sel 7 / 9 / 11 有真实行为**（`NoMemory` / `NoMemory` / `SUCCESS`），
但 census 没收录 ⇒ **census 对 M2Scaler 是不完整的**，不能拿它判「不可达」。

### 4.2 静态调用图在 IOCommandGate 处断掉

从两个 census handler 做 BFS（含 `b` 尾调用），只能覆盖 **3 个 / 1 个** 函数，一个门函数都到不了。
原因不是不可达，而是 IOKit external method 的 handler 普遍长这样：

```
20  adrp x0, ...        ; 分配一个上下文
28  mov  w1, #0x178
32  bl   ...            ; IOMalloc
48  mov  x1, x20
52  bl   ...            ; 设置
56  adrp x16, ...       ; 取 action 表
```

然后经 `IOCommandGate::runAction(gate, actionFn, ...)` 间接调用 —— **action 函数地址不是 `bl` 立即数**，
静态图必然断在这里。

门函数的静态调用者：

| 版本 | 读门 A | 读门 B |
|---|---|---|
| 27.0.1 | `0xfffffe0009176fc8` | **无** |
| 27.2 | `0xfffffe00091be69c` | **无** |

两个门函数都**没有取地址（`adrp+add`）引用**，读门 B 连 `bl` 调用者都没有 ⇒ 只能经
虚派发（`ldr x8,[x16,#slot]; blraa`）进入。

**结论（如实）：静态不可判。** 要判定必须解 `runAction` 的 action 表，本轮没做。
但有一条我们自己的**动态**证据可用 —— 见 §6。

---

## 5. Q5：27.0.1 上有没有不经门的路径

**有，而且很多。** 这是本次最硬的发现：

| | 27.0.1 | 27.2 |
|---|---|---|
| `self->0x50` → 子对象 → `+0x130` 的访问点 | **14 处 / 10 个函数** | 6 处 / 5 个函数 |
| 其中带 `+0x138` 门 | **0** | **2** |
| `+0x138` 的字节写 | **0 处** | 2 处 |
| `+0x138` 的字节读 | 2 处（且基对象是 `[x0+0x18]`，另一个结构） | 13 处 |

27.0.1 里这 10 个函数是：

```
0xfffffe0009060888  0xfffffe00090885f4  0xfffffe00090b9878  0xfffffe00090ba1b4
0xfffffe00090ba5d0  0xfffffe00090dcf58  0xfffffe00090dd654  0xfffffe00090e42a0
0xfffffe00090fb14c  0xfffffe0009142118
```

**全部是无条件解引用**：拿到 `self->0x50` 后直接 `add x8,x8,#0x130` / `ldr x,[x8,#0x130]`，
中间没有任何状态检查。

⇒ **27.0.1 上：teardown 先释放 `+0x100`/`+0x130`，诊断路径仍会去读它**。
这正是「race condition + improved state handling」的形状 ——
和 IOSurface `+0xf1` 那条**完全同族**（那也是一读一写、27.0.1 侧 0 处）。

**差别**：IOSurface 那条是**安全门**（命中返回 `0xE00002D8` 拒绝）；
M2Scaler 这条是**日志门**（命中改打 `(unknown)`）。
所以 M2Scaler 这条的失败模式是 **panic（在日志路径里踩 UAF）**，不是拒绝服务以外的能力 ——
与 CVE-2026-112501 的「unexpected system termination / DoS」吻合。

---

## 6. 完整调用链（能确定的部分 + 断点标出）

```
[用户态] IOConnectCallMethod(conn, sel, ...)
   │
   ├─ census: sel 0 → 0x9099b40   sel 1 → 0x909b33c        ← 只有这 2 个被收录
   ├─ 我们实测: sel 7 / 9 / 11 也有真实 handler                ← census 缺失
   │
   ▼
[IOCommandGate::runAction(gate, actionFn, ...)]              ← ★ 静态图在这里断掉
   │   （actionFn 不是 bl 立即数，也找不到 adrp+add 取地址）
   ▼
 未定位的 action 函数
   │
   ├── bl → 0x91be69c  (27.2) / 0x9176fc8 (27.0.1)           ← 读门 A 的唯一静态调用者
   │        └── bl → 读门 A  0x912b940(27.2) / 0x90e42a0(27.0.1)
   │                └── 检查 / 打印 "(unknown)" 或解引用 +0x130
   │
   └── 虚派发 → 读门 B  0x9142840(27.2) / 0x90fb14c(27.0.1)   ← 无静态调用者
            └── 检查 / 构建参数字典

teardown 侧（无调用者，也是虚派发）：
   0x90e1698  置 +0x138 := 1  →  释放 +0x100
   0x90e1240  清 +0x138 := 0  →  state := 2   （调用者 0x90e148c / 0x90e1a18）
```

**断点只有一个：IOCommandGate 的 action 表。** 把它解开，§6 的链就补全了。

---

## 7. 与 S2（IOSurface `+0xf1`）的对照

| | IOSurface `+0xf1` | M2Scaler `+0x138` |
|---|---|---|
| 27.0.1 侧出现次数 | 0 | 0（写）/ 2（读，另一对象） |
| 27.2 新增 | 1 读 + 1 写 | 13 读 + 2 写 |
| 门的作用 | **拒绝**：命中返回 `0xE00002D8` | **降级**：命中改打 `(unknown)` |
| 触发面 | external method（有 selector，我们动态打穿过） | 诊断/遥测路径（限流 61 次一次） |
| 失败模式 | 崩溃 | 崩溃 |
| 可达性 | **已实测可达** | 未定（卡在 runAction） |

M2Scaler 这条的触发密度低（每 61 次诊断才真的解引用一次），但**它不需要我们猜 selector**——
只要能把「诊断频繁触发 + 并发 teardown」这个状态撞上。

---

## 8. 下一步要解开的那一个结

**IOCommandGate action 表。**
方法：在 `0x9099b40` / `0x909b33c` 里跟到 `runAction` 的调用，把 actionFn（`x1`/`x2`）的地址解出来；
若走的是 `IOCommandGate::runAction(this, action, owner, arg0..3, &returnValue)` 的 C++ 重载，
actionFn 通常由 `adrp+add` 装进寄存器后传入 —— 我在门函数本身没找到取地址引用，
所以要往**上一层**（handler → 未定位的 action）找。

没做的部分我不填：**M2Scaler 的门函数到底挂在哪个 selector 上，目前不知道。**

---

## 9. 边界声明

- 「`+0x138` 是失效字节」「teardown 先置位再释放」「读侧打 `(unknown)`」—— **这三条有指令级证据**，见 §2 §3。
- 「CSC 子对象」「`self->0x50` 指向它」—— **结构推断**，依据是 15 处访问形态统一 + 相邻字段 `+0x130`/`+0x100` 的生命周期。
- 「对应 CVE-2026-112501」—— **高度相似的推断，未证实**。
- 「可达性」—— **未知**，静态被 runAction 截断，动态我们没跑过 M2Scaler 的诊断路径。
