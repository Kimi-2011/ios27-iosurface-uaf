# A 类（真插入）全表 —— 46 条逐条摊开

源：`out/PATCH-HUNT.raw.json`（`tools/fdiff.py` 输出），本表由 `tools/a_class_report.py` 生成。
判定「真插入」= 27.2 多出指令、27.0.1 无对应删除（`removed == []`）。

可达性：**L1** = 本身是 census handler；**L2** = 从 handler 向下 ≤2 跳；**L3** = 其余。

**分布：L1 0 / L2 1 / L3 45（合计 46）**

## 1. L1 / L2：详写

### `iokit_IOSurface` `0xfffffe000a3460f0` → `0xfffffe000a3944c0`  [L2 1 跳]

- 判断: 字节门；函数 260 字节，相似度 0.97
- 静态调用者: ['0xfffffe000a3460f0', '0xfffffe000a3498f4', '0xfffffe000a34dbc0']
```diff
+ ldrb w8,[x21, #0xf1]
+ tbz w8,#0,#3
+ add w20,w20,#0x1b
+ b #39
```

## 2. L3：一行一条，不展开

| # | kext | 27.0.1 | 27.2 | 增删 | 新增的是什么 | 我的判断 |
|---|---|---|---|---|---|---|
| 1 | `driver_AppleAVD` | `0xfffffe00086b4a4c` | `0xfffffe000873e778` | +12/−0 | cbz x1,#6<br>adds w8,w2,w3<br>b.hs #4 | 比较 |
| 2 | `iokit_IOMobileGraphicsFamily-DCP` | `0xfffffe000a14f37c` | `0xfffffe000a19e638` | +5/−0 | cmp w2,#0xbc<br>b.ls #4<br>mov w0,#0x2c2 | 错误码/比较 |
| 3 | `AGXG18P` | `0xfffffe00084b1a7c` | `0xfffffe00084e6e7c` | +4/−0 | ldr x8,[x0, #0x558]<br>ldr x8,[x8, #0xcc0]<br>ldr w0,[x8, #0x5e0] | 其它 |
| 4 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904963c` | `0xfffffe00090c32d8` | +4/−0 | movi d0,#<IMM><br>str d0,[x0, #0x40]<br>str wzr,[x0, #0x48] | 其它 |
| 5 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904de98` | `0xfffffe00090c3320` | +4/−0 | movi d0,#<IMM><br>str d0,[x0, #0x40]<br>str wzr,[x0, #0x48] | 其它 |
| 6 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904981c` | `0xfffffe00090c3488` | +4/−0 | movi d0,#<IMM><br>str d0,[x0, #0x40]<br>str wzr,[x0, #0x48] | 其它 |
| 7 | `AGXG18P` | `0xfffffe00084b3324` | `0xfffffe0008525dd8` | +2/−0 | ldr x8,[x0, #0x2a8]<br>ldr x0,[x8, #0x160] | 纯内联 |
| 8 | `AGXG18P` | `0xfffffe00084b595c` | `0xfffffe0008531198` | +2/−0 | ldr x8,[x0, #0xcc0]<br>str w1,[x8, #0x6c8] | 纯内联 |
| 9 | `AGXG18P` | `0xfffffe00084b4d68` | `0xfffffe0008538d7c` | +2/−0 | ldr x8,[x0, #0xcc0]<br>ldr x0,[x8, #0x5d0] | 纯内联 |
| 10 | `driver_AppleAVE2` | `0xfffffe00088ecad0` | `0xfffffe0008926f88` | +2/−0 | udf #0<br>udf #0 | 其它 |
| 11 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904ded0` | `0xfffffe0009114d58` | +2/−0 | stp xzr,xzr,[x0, #0xa0]<br>str xzr,[x0, #0xb0] | 纯内联 |
| 12 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904f0c4` | `0xfffffe0009114d98` | +2/−0 | stp xzr,xzr,[x0, #0xa0]<br>str xzr,[x0, #0xb0] | 纯内联 |
| 13 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904e054` | `0xfffffe0009114ef8` | +2/−0 | stp xzr,xzr,[x0, #0xa0]<br>str xzr,[x0, #0xb0] | 纯内联 |
| 14 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009200fe0` | `0xfffffe00092627cc` | +2/−0 | ldr q0,[x1]<br>str q0,[x0, #0x6590] | 纯内联 |
| 15 | `iokit_IOSurface` | `0xfffffe000a346364` | `0xfffffe000a394744` | +2/−0 | mov w8,#1<br>strb w8,[x20, #0xf1] | 其它 |
| 16 | `AGXG18P` | `0xfffffe00084b3ad8` | `0xfffffe00084d8a18` | +1/−0 | ldr x0,[x0, #0x208] | 纯内联 |
| 17 | `AGXG18P` | `0xfffffe00084b1a74` | `0xfffffe00084e62d8` | +1/−0 | ldr x0,[x0, #0x558] | 纯内联 |
| 18 | `AGXG18P` | `0xfffffe00084b5138` | `0xfffffe0008539484` | +1/−0 | strb w1,[x0, #0x2ba] | 其它 |
| 19 | `AGXG18P` | `0xfffffe00084b5cc8` | `0xfffffe0008542d24` | +1/−0 | ldr w0,[x0, #0x1d5c] | 纯内联 |
| 20 | `AGXG18P` | `0xfffffe00084b5cd0` | `0xfffffe000854f2f8` | +1/−0 | ldr x0,[x0, #0x208] | 纯内联 |
| 21 | `AGXG18P` | `0xfffffe00084b5e38` | `0xfffffe0008555a7c` | +1/−0 | ldr x0,[x0, #0x208] | 纯内联 |
| 22 | `AGXG18P` | `0xfffffe00084b69d0` | `0xfffffe000855be98` | +1/−0 | ldr x0,[x0, #0x208] | 纯内联 |
| 23 | `AGXG18P` | `0xfffffe0008504c58` | `0xfffffe000858be8c` | +1/−0 | mov w2,#0x1ca8 | 纯内联 |
| 24 | `AGXG18P` | `0xfffffe00084b6bd0` | `0xfffffe0008595b44` | +1/−0 | add x0,x0,#0x344 | 纯内联 |
| 25 | `AGXG18P` | `0xfffffe00084b6bd8` | `0xfffffe0008595b50` | +1/−0 | add x0,x0,#0x33c | 纯内联 |
| 26 | `AGXG18P` | `0xfffffe00084b7200` | `0xfffffe0008595d58` | +1/−0 | ldr w0,[x0, #0x338] | 纯内联 |
| 27 | `AGXG18P` | `0xfffffe0008506280` | `0xfffffe0008596550` | +1/−0 | mov w2,#0x400 | 纯内联 |
| 28 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090490a8` | `0xfffffe00090955ac` | +1/−0 | str wzr,[x0, #0xa0] | 纯内联 |
| 29 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe0009049604` | `0xfffffe00090955e8` | +1/−0 | str wzr,[x0, #0xa0] | 纯内联 |
| 30 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000905d2c4` | `0xfffffe00090956f0` | +1/−0 | str wzr,[x0, #0xa0] | 纯内联 |
| 31 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe0009049288` | `0xfffffe0009095774` | +1/−0 | str wzr,[x0, #0xa0] | 纯内联 |
| 32 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090497c0` | `0xfffffe00090957d4` | +1/−0 | str wzr,[x0, #0xa0] | 纯内联 |
| 33 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090496e4` | `0xfffffe00090a4564` | +1/−0 | mov w1,#0x48be | 纯内联 |
| 34 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090490e0` | `0xfffffe00090c53bc` | +1/−0 | ldr x0,[x0, #0x78] | 纯内联 |
| 35 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090a3a34` | `0xfffffe00090e1040` | +1/−0 | mov w2,#0x180 | 纯内联 |
| 36 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904df78` | `0xfffffe00090f121c` | +1/−0 | mov w1,#0x4594 | 纯内联 |
| 37 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090e515c` | `0xfffffe00090f18cc` | +1/−0 | mov w2,#0x470 | 纯内联 |
| 38 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904e544` | `0xfffffe0009115018` | +1/−0 | mov w1,#0x4594 | 纯内联 |
| 39 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090e55c0` | `0xfffffe000917164c` | +1/−0 | mov w2,#0x470 | 纯内联 |
| 40 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904f1a4` | `0xfffffe0009173a48` | +1/−0 | mov w1,#0x48be | 纯内联 |
| 41 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe0009184cb4` | `0xfffffe00091b4024` | +1/−0 | mov w8,#0x2e4 | 纯内联 |
| 42 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe00091fff64` | `0xfffffe0009249184` | +1/−0 | mov w0,#0x3e8 | 纯内联 |
| 43 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009200fd8` | `0xfffffe0009252988` | +1/−0 | mov w0,#0x3e8 | 纯内联 |
| 44 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009201000` | `0xfffffe000926ae8c` | +1/−0 | mov w0,#0x3e8 | 纯内联 |
| 45 | `iokit_IOHIDFamily` | `0xfffffe000a0e4310` | `0xfffffe000a1333ec` | +1/−0 | ldr x23,[x8] | 纯内联 |

## 3. 为什么 45/46 是 L3 —— 这是本轮的方法论结论

把 46 条按形态归类：

- **纯内联**：36 条
- **其它**：7 条
- **比较**：2 条
- **字节门**：1 条
- **错误码**：1 条

**不限跳数**（不是 2 跳）从 census handler 出发统计 46 条：

| 距离 | 条数 |
|---|---|
| 1 跳 | 1 |
| 2–6 跳 | 0 |
| 完全不可达 | **45** |

这不是筛选失误。同一套 BFS 在 IOSurface 上：61 个 handler 落点、不限跳数可达 **356 / 1330** 个函数；
而 `+0xf1` 读门恰好在 **1 跳**，`+0xf1` 写标记却**完全不可达** —— 后者我们**动态打穿过**。

⇒ 两条硬结论：

1. **census 体系能覆盖的函数上限只有约 27%**（IOSurface 356/1330；M2Scaler 4/10262 ≈ 0.04%）。
   原因是 IOKit external method 走 `IOCommandGate::runAction(gate, actionFn, ...)` 和虚派发，
   action 函数地址既不是 `bl` 立即数、也没有 `adrp+add` 取地址 —— 静态调用图必然断掉。
2. **「有没有 selector」这个判据几乎无法用于排序**。它筛出的 L1/L2 是空集或单元素，
   而真正已知可用的那条（`+0xf1` 写标记）恰好被判成不可达。

⇒ 要让这一列有意义，必须先解 `IOCommandGate` 的 action 表。在那之前，可达性只能靠动态证据
（`out/fuzz2.raw.ndjson` 里我们实际打穿过的 selector），不能靠 census。

---

## 4. 按判据分类：46 条里真正值得记的只有 2 条

判据照 `+0xf1` 那次：

| 判据 | 命中 |
|---|---|
| 新增「读字段 + 比较 + 条件跳错误返回」 | 2 条（见下） |
| 新增 lock/unlock 配对 | **0 条** |
| 新增 refcount CAS / `ldaxr`-`stlxr` | **0 条** |
| 纯内联 / 纯搬运 / 纯寄存器分配 | 其余 44 条 |

### 4.1 `driver_AppleAVD` `0xfffffe00086b4a4c` → `0xfffffe000873e778`（+12/−0）

唯一一条完整的「溢出 + 越界」双重检查：

```asm
cbz   x1, skip            ; 空指针
adds  w8, w2, w3          ; ★ 无符号加法，进位标志 = 溢出
b.hs  out                 ; ★ 溢出则直接退出
ldr   w9, [x1, #0x2c]     ; ★ 对象里的长度上限
cmp   w8, w9
b.ls  ok                  ; ★ 不超上限才继续
ret                       ; 否则返回（w0 已是错误码）
ok:  ldr x8, [x1, #8]
```

即 `if (w2 + w3 溢出 || w2 + w3 > obj->limit_0x2c) return 错误;`
**这是本轮 46 条里唯一一条教科书式的整数溢出修复。** 27.0.1 侧没有这三条检查。

- 可达性：L3（不限跳数也不可达）
- 但要记：AVD 在 census 里有 **9 个 handler**（不算多；对照：`AppleH16CameraInterface` 120、`AppleSEPManager` 83、`IOMobileGraphicsFamily` 79）。它是本表里**唯一**带溢出检查的类
- **判断：值得留着。若哪天能解 action 表，这条第一个回来看。**

### 4.2 `driver_AppleAVE2` `0xfffffe00088ecad0` → `0xfffffe0008926f88`（+2/−0）

```asm
udf #0
udf #0
```

新增两条 `udf`（`__builtin_unreachable()` / BUG 断言）。说明 27.2 在这里**把某个状态判定为不可能**。
统计上无害，但如果能找到让 27.0.1 走进来的输入，它对应的就是「27.2 会断言、27.0.1 会继续执行」的分界。

- 可达性：L3
- **判断：低优先，但形态独特，记一笔。**

### 4.3 其余 44 条

- 9 条是 `ldr x0,[x0,#0xN]` 式访问器被内联（AGX / M2Scaler）
- 若干是 `stp xzr,xzr,[x0,#0xa0]` 式清零
- 若干是 `mov wN,#imm` 常量变化（`#0x2e4` `#0x3e8` `#0x4594` `#0x48be` 等，多为内联常量）
→ 全部不符合上面任何一条判据，不展开。

---

## 5. 更正记录（父两次指出的错误，落盘留痕）

### 5.1 P1 `IOMobileGraphicsFamily-DCP 0xa14f37c` → 降级

我原先读成「增了 188 这个数组上限」。父反汇编后指出：**该函数是薄转发桩**：

```asm
ldr  x16, [x0]                       ; vtable
movk x17, #0xcda1, lsl #48
autda x16, x17
mov  x17, #0xa10
add  x16, x16, #0xa10                ; 槽位 0xa10
ldr  x8, [x16]
braa x16, x17                        ; 尾调用虚方法
```

**⇒ `cmp w2, #0xbc` 是加在桩的入口，约束的是所有调用者，不是函数体内的数组边界。**
`bl` 调用者 = 0、不在任何派发表里 ⇒ **L3，用户态短期到不了**。
`188` 这个上限本身保留记录：**它是一旦找到调用路径就立刻可用的入口**，但当前不可用。

### 5.2 `0xbc` 的二义性 —— 必须永远区分

父同时指出：`driver_AppleAVD 0xfffffe0008710cd4` 里的 `0xbc` **不是 188，是结构体偏移**：

```asm
add  x8, x1, #0xbc            ; ★ x8 = x1 + 0xbc —— 偏移
mov  w10, #9                  ; 循环 9 次
ldr  w11, [x8, x9, lsl #2]    ; *(u32*)(x1 + 0xbc + x9*4)
cmp  w11, w2
b.eq found                    ; 在 9 个 u32 里找匹配
```

**⇒ 同一个字面量 `0xbc` 在两个 kext 里分别是「数量 188」和「偏移 0xbc」。
我上一轮在 §5.1 里把两者混着说，是错的。** 本表 4.1 里 `[x1, #0x2c]` 才是长度字段，`add x8,x1,#0xbc` 是另一处。

**教训固化**：反汇编里看到 `#imm` 必须分清它出现在 `cmp/b.ls`（数量阈值）还是
`add xN, xM, #imm` / `[xN, #imm]`（结构体偏移）里。前者是补丁，后者是布局。

---

## 6. 桩陷阱：`bti c ; b <body>` 会让归因挂错对象（父指出，已确认，比预想更严重）

### 6.1 46 条里有 5 条入口是跳转桩

| kext | 桩 | 实体（27.0.1） |
|---|---|---|
| `AGXG18P` | `0x84b1a74` | `0x8587ffc` |
| `AGXG18P` | `0x84b1a7c` | `0x8587ffc` ← **同一个** |
| `AGXG18P` | `0x84b3324` | `0x8587ffc` ← **同一个** |
| `driver_AppleAVD` | `0x86b4a4c` | `0x86b49d0` |
| `driver_AppleM2ScalerCSCDriver` | `0x90490e0` → `0x914c870` → `0x9186458` | 两层桩链 |

**三个不同的 AGX 桩指向同一个实体** ⇒ 我的表把同一处改动计成了三条独立条目。

### 6.2 AVD 那条「整数溢出修复」是**假阳性**，比父说的更彻底

父指出 `0x86b4a4c` 是 `bti c ; b <body>`。实测更糟：

| | 27.0.1 | 27.2 |
|---|---|---|
| 地址 | `0x86b4a4c` | `0x873e778` |
| 字节数 | **8 B**（`bti c; b 0x86b49d0`） | **56 B** |
| 相似度 | \multicolumn — fdiff 报的 `sim = 0.25` | |

fdiff 把一个 **8 字节的桩**和 **56 字节的实体**配成了一对，`+12/−0` 是这个错配的产物。

**而且 27.0.1 本来就有同样的检查**，在另一个函数里：

```
27.0.1  0xfffffe0008708130:
  adds w9, w1, w2
  b.hs  ...
  ldr  w10, [x8, #0x2c]
  cmp  w9, w10
  b.ls  ...
```

27.2 有 2 处（`0x873e2e0`、`0x873e778`），27.0.1 有 1 处 —— 这是**同一检查的不同内联版本**，不是新增补丁。

⇒ **§4.1 撤稿。** 「唯一一条教科书式整数溢出修复」不成立。

### 6.3 46 条表的实际含金量

按 27.0.1 侧函数体积分布：

| 体积 | 条数 |
|---|---|
| ≤16 B（几乎全是桩或两指令访问器） | **25** |
| 17–32 B | 1 |
| 33–64 B | 8 |
| >64 B | 12 |

再把 >64 B 的 12 条逐条看形态，**全部是单指令内联或 `mov wN,#imm` 常量变化**，唯一有实质内容的是：

- `iokit_IOSurface 0xa3460f0`（`+0xf1` 读门，`+4/−0`）
- `iokit_IOSurface 0xa346364`（`+0xf1` 写标记，`+2/−0`）

**⇒ A 类 46 条的净内容是 2 条，且都是已知的。** 剩下 44 条是桩↔实体错配、内联差异和常量漂移。

### 6.4 工具教训（已固化）

`tools/fdiff.py` 的配对环节需要加两条拒绝规则：

1. **体积悬殊**：`max(s1,s2) / min(s1,s2) > 3` 时拒绝配对（AVD 是 56/8 = 7）
2. **任一侧 ≤16 B**：当作桩处理，先跟随 `bti c ; b <x>` 到实体，再用实体做 diff；
   跟不到实体就不进 A 类

不修这两条，任何「真插入」统计都会被小函数污染 —— 本次污染率 **25/46 ≈ 54%**。
