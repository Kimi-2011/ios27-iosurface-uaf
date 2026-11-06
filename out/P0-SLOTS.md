# P0：正确解码后的槽命中与 vtable 归属

工具：`tools/vtscan.py`（新增）。**只收录 starts 表登记的真实槽**，target = bits 0..29。
正例：`0xb39e868`（= `0xb348450`）→ **12 槽**，方法成立。

---

## 1. 六个函数的槽命中（两版对照）

| 27.0.1 | 27.2 | 函数 | 27.0.1 槽数 | 27.2 槽数 | 位置 |
|---|---|---|---|---|---|
| `0xa34b2dc` | `0xa3996c4` | teardown 本体 | **1** | **1** | IOSurface `__DATA_CONST` |
| `0xa3338cc` | `0xa381c9c` | surface dealloc 遍历入口 | 0 | 0 | — |
| `0xa346364` | `0xa394744` | #802 摘节点 | 0 | 0 | — |
| `0xa34ff48` | 未配对 | 崩溃点所在函数 | 0 | — | — |
| `0xa3460f0` | `0xa3944c0` | register | 0 | 0 | — |
| `0xa3461f4` | 未配对 | deregister | 0 | — | — |

**关键事实：`teardown 本体` 是这六个里唯一进入函数指针表的，且两版都是恰好 1 个槽（稳定）。**

槽位置：
```
27.0.1  fileoff 0x137b658
27.2    fileoff 0x1391f08
```

## 2. vtable 归属 —— **未定**（我不能回答那个决定性问题）

槽所在的连续同 kext 指针段：

```
27.2  0x1391c50 .. 0x1392228   共 188 槽
teardown 槽 0x1391f08 是第 87 项（0 基）
```

**但 188 槽不可能是单个 vtable。** 原因是**`__DATA_CONST` 里相邻指针在 chained fixups 下天然是连续的**
—— 链是按页串起来的，vtable 之间的边界不体现为「链中断」。所以「连续同 kext 指针段」**不等于** vtable。

**⇒ 无法据此判定它是 `clientClose` / `stop` / `free` 中的哪一个。**
那个决定性问题的答案（`IOServiceClose` 会不会走到它）**这一轮没能拿到**。

### 正确做法（下一轮）

vtable 起点要靠 **`OSMetaClass` 引用或类名字符串**定位，而不是靠指针连续性：

```
1. 在 __DATA_CONST 里找指向 OSMetaClass / 类名 cstring 的槽
2. 类元数据对象通常紧邻或包含指向 vtable 的指针
3. 由类元数据 -> vtable 起点 -> 槽序号 -> 知道是哪个人造方法位
```

**这条没做。** 我不能拿「第 87 项」去猜方法名。

## 3. `0xb348450` 的 12 个槽（顺带）

12 槽 / 8 kext，全在 `__DATA_CONST`。**同样没有做 vtable 边界判定**，
所以「它是 IOCommandGate 族」仍是**形态推断 + 符号名巧合**，不是结论。

## 4. `w1 & 0xC0` 的 `attemptAction` 假设 —— 未验

父提的假设：`0xb348450` = `IOCommandGate::attemptAction(this, void*, void*, void*, void*)`，
`w1` 是第二个 `void*`。

**现状**：`w1` 在函数里被 `ands w8,w1,#0x600` 与 `bic w9,#0xC0,w1` 两处当**位域**用 ——
如果是 `void*` 指针，不会这样用。**所以这个假设与指令证据不符**，倾向否。
但 `attemptAction` 的 `int` 型参数版本是存在的，**不能完全排除**。

**验证没做**（要解 `bl 0xb347e20` 的语义和 `+0x88` 计数器用途）。写未定。

## 5. 这一轮的净收获

```
✅ 六个函数的引用计数从「方法作废、未知」变成「确定值」：1 / 0 / 0 / 0 / 0 / 0
✅ teardown 是唯一有函数指针引用的，且两版一致
❌ vtable 归属未定 —— 卡在没有 vtable 边界判定方法
❌ 因此「IOServiceClose 会不会走到 teardown」仍未答
```

**S2 的下一枪要不要打，这一轮没给出答案。** 差的是 vtable 边界定位。

---

# 附录：零值复核（父要求「先验 0 是不是真 0」）

## 复核方法

两步互相独立，且**结论完全一致**：

1. **链表扫描**（只走 starts 表登记的真实槽）
2. **原始全文件扫描**：对所有 8 字节对齐字取 `w & 0x3FFFFFFF` 比对
   —— 随机命中的概率约 **2⁻³⁰**，方法本身数学上可靠
   （注意：这与当年错的「撒网 + bind 位」不同，用的是 30 位掩码，不是高位随机位）

正例：`0xb348450` 两法都 **12 处**；`0xa34b2dc` 两法都 **1 处**。
**⇒ decoder 正确，下面的 0 是真 0。**

## 代码引用（补充维度）

| 函数 | 数据槽 | `bl`/`b` 调用者 | 取地址 |
|---|---|---|---|
| `register 0xa3460f0` | 0 | **2** | 0 |
| `deregister 0xa3461f4` | 0 | **2** | 0 |
| surface dealloc 遍历入口 `0xa3338cc` | 0 | **7** | 0 |
| #802 摘节点 `0xa346364` | 0 | **1**（来自 teardown `+0xb0`） | 0 |
| **teardown 本体 `0xa34b2dc`** | **1** | **0** | 0 |

27.2 侧完全同构（`0xa3944c0` 2 处 / `0xa381c9c` 7 处 / `0xa394744` 1 处来自 `0xa3996c4+0x34` / `0xa3996c4` 数据槽 1）。

## 两条结论

### 1. IOSurface **不用** `IOExternalMethodDispatch` 表

`register` / `deregister` 都是**直接 `bl` 调用**、**零数据槽、零取地址**。
⇒ 外方法派发是**手写 selector switch**，不是 `IOExternalMethodDispatch` 结构表。
**父预期「handler 应该在 dispatch 表里有引用」不成立 —— 不是 decoder 的问题，是这个 kext 不用那种表。**

### 2. teardown 本体是**纯虚派发**：0 直接调用、1 个函数指针槽

```
bl/b 调用者   0
取地址        0
数据槽        1（IOSurface __DATA_CONST）
自身内部      调 #802 摘节点（+0xb0）
```

**「零直接调用者 + 一个 vtable 槽 + 内部做节点摘除」= 析构/终止类虚方法。**

### 3. 由此得到一个不依赖 vtable 归属的结论

`IOServiceClose` 之后的路径会依次走 `terminate()` → `stop()` → `free()`，并调用 `clientClose()` ——
**这三个候选方法全部在 close 路径上。**

⇒ **无论那个槽是 `clientClose` / `stop` / `free` 中的哪一个，`teardown 本体` 都经由 `IOServiceClose` 可达。**
vtable 归属只决定**它在线序里的先后**（是否在端口失效之前），**不决定可达性**。

**这与父的判断一致：决定性问题由 `rc1` 回答，vtable 是解释性补证。**

---

# 附录二：vtable 归属尝试（方法 2 / 3）—— 部分成功

## 确定拿到的

**`IOSurfaceRootUserClient` 的类构造点找到了**：函数 `0xa39704c`

```asm
bti c ; pacibsp
adrp x1, #0xfffffe0007a28000
add  x1, x1, #0xb2f          ; "IOSurfaceRootUserClient"
adrp x2, #0xfffffe000839a000
ldr  x2, [x2, #0x108]        ; 父类元类
mov  w3, #0x148              ; sizeof = 0x148
bl   #0xfffffe000a3a8414     ; 元类构造
adrp x16, #0xfffffe0008396000
add  x16, x16, #0x238
add  x16, x16, #0x10
mov  x17, x0 ; movk x17, #0xcda1, lsl #48
pacda x16, x17               ; 签名 vtable 指针
str  x16, [x0]               ; 存进对象 +0x00
retab
```

**⇒ `IOSurfaceRootUserClient` 的 vtable 虚表项起始 VA = `0xfffffe0008396248`**（`__ZTV + 0x10`，Itanium ABI）。

## 一个确定的负结果

teardown 槽的 VA：

```
__DATA_CONST: vm=0xfffffe0008393c88  fo=0x138fc88  fsz=0x6528
槽 fileoff 0x1391f08  ->  VA 0xfffffe0008395f08
```

**`0x8395f08` < `0x8396248`，相差 0x340 = 104 个槽。**

**⇒ teardown 本体不在 `IOSurfaceRootUserClient` 的 vtable 里。**
它属于**同 kext 的另一个类**的 vtable（本 kext 至少还有 `IOSurface`、`IOSurfaceSharedEvent`、
`IOSurfaceSharedEventListener`、`IOSurfaceSharedEventNotificationPort`、
`IOFenceTransaction`、`IOSurfaceSharedEventReference` 等，均已从 cstring 确认存在）。

## 这条负结果的直接含义

**teardown 不是 `IOSurfaceRootUserClient` 的方法 ⇒ 它不太可能是 `clientClose` / `stop` 那类
「用户客户端关闭」方法。** 更像某个内部类（`IOSurface` 本体或 shared-event 系）的析构/终止虚方法。

**⇒ 上一份里「close 三个候选全在路径上」的说法要收紧：那个槽可能根本不在这三个候选里。**
父指出的区分是对的，而且比父预想的更不利于 S2：**它可能压根不是 close 路径上的方法。**

## 没做到的

vtable 起点的**自动定位失败**：用「函数内 adrp+add 到 `__DATA_CONST` + 附近有类名 cstring」
筛出 91 个候选，最近的类名被误配成无关字符串（"Debug Bits Value"）。
**这个启发式不够特化，不能用。** 正确做法应是先枚举全部类构造点（特征：`mov w3,#size` + `bl 0xa3a8414`），
再取每个构造点存的 vtable，才能得到分段正确的 vtable 边界。**没做。**

⇒ **teardown 到底属于哪个类、是哪个虚方法：未定。**

---

# 附录三：类边界枚举 + `x3` 类型 —— 两条结论**互相矛盾**，未定

## 一、类构造点枚举（`tools/vtbound.py`）

特征：`mov w3,#<size>` + `bl <metaclass ctor>`，名字取 x1 的 cstring，vtable 取随后写入 `[x0]` 的 `adrp+add`。
IOSurface kext 内共 85 个构造点，**27 个唯一 vtable**。相关几个：

```
0x83948f0  IOSurface                     size=0x3e0
0x8394b10  IOSurfaceClient               size=0x98
0x8395a28  IOSurfaceRoot                 size=0x4a0   <-- teardown 槽落在这之后
0x8396238  IOSurfaceRootUserClient       size=0x148
```

teardown 槽 `0x8395f08` ∈ [`0x8395a28`, `0x8396238`)，序号 **156**（段长 258 槽）。

## 二、槽本身是虚方法槽（客观）

```
0x8395f08 字0 = 0x8011b085033956c4
  target = bits 0..29 = 0x33956c4  -> VA 0xfffffe000a3996c4   (= teardown)
  高位 0x8011... = isAuth 签名位置位
```

**⇒ 它是一个 PAC 签名的虚方法槽，指向 teardown 本体。这条确定。**

## 三、`x3` 类型（客观，来自 2 个调用点）

`register 0xa3944c0` 的 2 个调用者是**纯尾调用包装**：

```asm
; 0xa397cdc
bti c
ldr  x1, [x2, #0x10]
cbz  x1, ...
mov  x3, x0            ; ★ x3 = 调用者自己的 this
ldr  x2, [x2, #0x30]
ldr  x0, [x0, #0xe8]   ; ★ x0 = *(this + 0xe8)
b    register

; 0xa39bfa8
bti c
mov  x3, x0            ; ★ 同上
ldr  x0, [x0, #0xe8]
b    register
```

**确定事实**：`x3` = 调用者自己的 `this`；该对象的 **`+0xe8` 指向注册表/根对象**。
**`x3` 的对象体积 ≥ 0xf1**（因为 teardown 在它上面写 `strb [x20?+0xf1]`，`x20 = x1 = self`）。

## 四、矛盾

```
路径 A：x3 = 某个 this，其 +0xe8 指向 root
        => node+0x58 = 那个 this（用户侧对象，size ≥ 0xf1）
        => teardown 的 self = 那个 this
        => teardown 应在「那个 this 的类」的 vtable 上

路径 B：teardown 槽在 IOSurfaceRoot 的 vtable 区间内（序号 156/size 0x4a0）

两条不能同时成立。
```

**若 A 成立，则 B 的区间内存在一个我漏掉的类边界**（`0x8395a28` 与 teardown 之间还有 156 槽）。
**若 B 成立，则 `node+0x58` 指向 `IOSurfaceRoot` 对象**，可是 root 的 `+0xe8` 指回 root 自身不合常理。

**我倾向前者：枚举有漏。** 依据：本次枚举用的是「`mov w3,#size` + 任意 `bl` + 邻近 cstring」，
**已见明显误配**（把 log 字符串 "Process caught creating IOFence deadlock" 当成类名）。
`IOSurface` 用的是 ctor `0xa3a8424` 而非 `0xa3a8414`，**说明存在多种元类构造入口，我的过滤条件不完整**。

## 五、未定，以及钉死它需要的那一步

**teardown 到底属于哪个类：未定。**
S2 机制（surface 析构 ∥ sel17 还是 close ∥ sel17）**因此仍未定**。

钉死需要：**枚举全部元类构造入口**（不只是 `0xa3a8414`，还有 `0xa3a8424` 等），
并把每个构造点写入 `[x0]` 的**真实 vptr 值**（含 `+0x10` 偏移）作为边界；
再用「边界之间不允许出现 ZTV 头 `[0]=0,[1]=0`」做一致性校验。
本次扫出 5 个头部样位置（`0x8395a28/0x8395bd8/0x8395c08/0x8395c40/0x8396230`），
**说明这段里确实还有我没归类的边界**。

---

# 附录四：`0x8395ec8` 假设的检验 —— 前提不成立，假设未被支持

## 一、前提有反例：vtable 长度 ≠ 实例大小

父的推算用了 `vtable 终点 = 起点 + sizeof(类)`。**这个关系不成立。** 本 kext 内四个类的实测：

| 类 | sizeof | sizeof/8 | 实测 vtable 区间槽数 |
|---|---|---|---|
| `IOSurface` | 0x3e0 | 124 | **68** |
| `IOSurfaceRoot` | 0x4a0 | 148 | **258** |
| `IOSurfaceRootUserClient` | 0x148 | 41 | **734** |
| `IOSurfaceClient` | 0x98 | 19 | **38** |

**两列毫无关系。** 所以 `0x8395a28 + 0x4a0 = 0x8395ec8` 这个边界是**由假设本身推出来的**，
再用它去证假设 —— 循环论证。

（注：区间槽数取自「下一个已检出边界」，本身受枚举漏检影响，但 `IOSurface` 68 vs 124
和 `IOSurfaceRoot` 258 vs 148 这两个方向相反的偏差已足够说明两者无关。）

## 二、直接检验：没人写 `0x8395ec8`

搜 IOSurface kext 全部函数里 `adrp+add` 指向 `0x8395ec8` 或 `0x8395ed8` 的位置：

```
引用 0x8395ec8/0x8395ed8 的位置: 0
```

**没有任何构造点把它当作 vptr 写进对象。** 假设「`0x8395ec8` 是某个类的 vtable 起点」**未被支持**。

同时确认：`IOSurfaceRootUserClient` 的构造点 `0xa39704c` 写的是 **`0x8396248`**（= 0x8396238 + 0x10），
**这是它唯一的 vptr**。teardown 槽 `0x8395f08` 在其之前 0x330，
**⇒ teardown 也不在 `IOSurfaceRootUserClient` 的 vtable 里。这条对父的「大概率是它」是反证。**

## 三、所以现在的确切状态

```
确定：
  teardown 槽是 PAC 签名的虚方法槽（字 0 高位 0x8011...）
  IOSurfaceRootUserClient 的 vptr = 0x8396248（构造点直接写入）
  teardown(0x8395f08) 在 0x8396248 之前 0x330  => 不在 userClient vtable
  x3 = 调用者自身 this，其 +0xe8 → 注册表，对象 ≥0xf1

未定：
  teardown 属于哪个类
  因此 node+0x58 的类型未定
  因此 V_TEARREG 是否打对对象未定
```

## 四、剩余唯一线索

在 `[0x8395a38, 0x8395f08)` 这个区间里存在**至少一个我还没归类的 vtable 起点**。
ZTV 头样位置扫出过 `0x8395bd8 / 0x8395c08 / 0x8395c40`（`[0]=0,[1]=0`），
但该特征在满是函数指针和零槽的区段里**不够特化**，不能直接采信。

**要钉死必须做完整的 ZTV 枚举**：收集所有「`adrp+add` 得 X → `add X,X,#0x10` → `pacda` → `str X,[x0]`」
的 X（ZTV 基址），再按 `X+0x10` 排序当边界，与 ZTV 头一致性交叉校验。
本附录的 `vtbound.py` 只做了「取到 `__DATA_CONST` 地址就记下」，
**没有统一 `+0x10` 口径，也没覆盖多个元类构造入口** —— 这是 156 那个数字不可信的根因。

---

# 附录五：统一口径后的 ZTV 枚举（本轮收官）

> ## 给后来者的显眼警告
> **vtable 槽数 与 类实例大小 无关。** 本 kext 实测：sizeof/8 = **124 / 148 / 41 / 19**
> vs 实测 vtable 区间槽数 = **68 / 258 / 734 / 38** —— 两列毫无关系，偏差方向还相反。
> **不能用「起点 + sizeof(类)」推 vtable 边界，那是循环论证。**

## 1. 统一口径

`vptr = ZTV基址 + 0x10`（Itanium ABI 两个头部字：offset-to-top、typeinfo）。边界一律用 vptr。
工具 `tools/vtbound2.py`。

## 2. 决定性结构证据：`0x8395c40` 是真 ZTV 基址

| 事实 | 值 |
|---|---|
| 槽 `0x8395c40` / `0x8395c48` | **不是链槽**（头部两个字，符合 ABI） |
| 槽 `0x8395c50` 起 | 全部是链槽，解出代码地址 |
| 写入该 vptr 的构造/析构点 | **5 个**：`0xa3970a0`、`0xa3970f0`、`0xa397140`、`0xa39725c`、`0xa397488` |

这 5 个函数形态完全一致（80 字节）：

```asm
bti c ; pacibsp
bl   #0xa3a8574              ; 先调基类
adrp x16, #0x8395000
add  x16, x16, #0xc40 ; add x16, x16, #0x10
mov  x17, x0 ; movk x17, #0xcda1, lsl #48
pacda x16, x17
str  x16, [x0]               ; 写 vptr = 0x8395c50
str  q0,  [x0, #0x100]       ; 清零 [0x100,0x110)
```

**vptr = `0x8395c50`，虚表条目自该处开始。**

## 3. teardown 的位置（统一口径下）

```
前边界 vptr = 0x8395c50
teardown 槽 = 0x8395f08
序号 = (0x8395f08 - 0x8395c50)/8 = 0x2b8/8 = 0x57 = 87
后边界 vptr = 0x8396248 (IOSurfaceRootUserClient)
段长 191 槽
```

**⇒ teardown 是 vtable `0x8395c40` 所属类的第 87 个虚方法。**

## 4. 类名：未定

这 5 个写入点**都不内嵌类名字符串**（它们调 `0xa3a8574`，不调 `0xa3a8414` 那种带名字的元类构造）。
所以**无法从它们直接读类名**。

有一条值得记下的观察：`0x8395c50`（条目 [0]）解出的目标正是 `0xa39725c` ——
而 `0xa39725c` 本身是那 5 个写入点之一。**虚表第 0 项指向一个会写 vptr 的函数**，
这更像**析构函数**（析构时把 vptr 改回基类）而非普通虚方法。
**⇒ 这 5 个 80 字节函数可能是析构器，`0xa3a8574` 是基类析构器。**
**这条只是形态推断，未验证。**

## 5. 本轮收官状态

```
✅ teardown 的 vtable 基址确定为 0x8395c40（头部非链槽 + 5 个写入点，双证据）
✅ teardown 在该 vtable 的第 87 项
✅ IOSurfaceRootUserClient 的 vptr = 0x8396248，teardown 不在其中（反证保留）
❌ 该 vtable 所属类的名字 —— 未定（写入点不内嵌类名）
❌ 因此 node+0x58 的类型、V_TEARREG 是否打对对象 —— 未定
```

**静态侧到此封口。** 类名要靠「元类构造 `0xa3a8414` 的 x1 cstring 与 vptr 配对」才能解，
而本 kext 里这两者**不在同一个函数里**（写入点调 `0xa3a8574` 而非带名字的元类构造），
所以需要跨函数关联 —— **这轮没做，如实记为未定。**

---

# 附录六：对「第 87 项」的复核 —— 序号**不能**确认为虚方法序号

## 查一：段内没有第二个 ZTV 头

以「非链槽」为判据（链表的 `next` 步长可以跳过非指针字，所以非链槽正好暴露头部两个字）：

```
段 [0x8395c50, 0x8396248)  共 191 槽
非链槽连续段：1 个
  0x8396230..0x8396240 （3 字，在段尾）
```

**⇒ 段内没有任何中间 ZTV 头。** 从 `0x8395c50` 到 `0x8396228` 是**一段连续不断的链式指针区**。

## 结论修正：87 是「位置」不是「序号」

父的怀疑方向对，但结论要换个说法：

```
可证：teardown 位于连续指针区 0x8395c50 起的第 87 个指针
不可证：它就是该类的第 87 个虚方法
```

原因：**ZTV 头只能证明表的起点，不能证明表的终点。**
链式指针区在 `__DATA_CONST` 里是天然连续的一段（附录三已述），
所以「`0x8395c40` 的虚表在哪结束、后面是否紧接着另一张表」**无法用非链槽判据分开**。

**⇒ 「191 个虚方法」这个读法既不成立、也无法排除；「第 87 项」作为事实保留，作为「虚方法序号」不成立。**

## 查二：`0xa3970a0` 完整函数体（80 字节，全貌如下）

```asm
bti c ; pacibsp
stp x29,x30,[sp,#-0x10]! ; mov x29,sp
bl   #0xa3a8574              ; 基类构造（同 kext __TEXT_EXEC）
adrp x16,#0x8395000 ; add x16,#0xc40 ; add x16,#0x10
mov  x17,x0 ; movk x17,#0xcda1,lsl #48
pacda x16,x17 ; str x16,[x0]  ; vptr = 0x8395c50
movi v0.2d,#0
str  q0,[x0,#0x100]           ; 清 [0x100,0x110)
str  wzr,[x0,#0x110]
str  xzr,[x0,#0x118]
str  q0,[x0,#0x130]           ; 清 [0x130,0x140)
str  xzr,[x0,#0x140]
ldp x29,x30,[sp],#0x10 ; retab
```

- **没有任何 cstring 引用**（无 `adrp+add` 到 `__TEXT`）。类名不在这个函数里，80 字节就是全部。
- 清零范围覆盖到 **`+0x148`**（最后一次写到 `+0x140` 的 8 字节）。

**注意**：`IOSurfaceRootUserClient` 的 `sizeof = 0x148`，与本函数清零上界**完全吻合**。
这是**巧合还是同族类的证据，未定** —— 但两个 0x148 值得记一笔。

## 查三：`0xa3a8574` 与 `0xa3a8414` 的关系（只能给到这一层）

```
0xa3a8574  属于 com.apple.iokit.IOSurface  __TEXT_EXEC   <- 被 5 个 vptr 写入点调用
0xa3a8414  属于 com.apple.iokit.IOSurface  __TEXT_EXEC   <- 带类名的元类构造（IOSurfaceRootUserClient 用）
```

两者都在本 kext。**`0xa3a8574` 不在 `LC_FUNCTION_STARTS` 的函数表里**（`v.functions()` 中查不到它），
所以它要么是被 tail-call 的内部入口，要么是函数表中未被登记的片段。
**它是否是「不带类名的基类构造」：未验。** 本轮预算用尽，如实记录。

## 收官状态（静态侧最后一版）

```
✅ vtable 基址 0x8395c40（头部两字非链槽 + 5 个写入点，双证据）
✅ teardown 位于连续指针区第 87 个指针（事实）
❌ 「第 87 个虚方法」不成立（ZTV 头只能定起点，不能定终点）
❌ 所属类名 —— 未定（5 个写入点均无 cstring；0xa3a8574 语义未验）
❌ node+0x58 类型、V_TEARREG 是否打对对象 —— 未定
```

**静态侧封口。**
