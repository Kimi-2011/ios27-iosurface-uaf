# CENSUS-GAP — 派发表普查的覆盖缺口（AGX / IOGPU）

1. **目的**：不是再找一条洞，是确认**普查分母可不可信**。`census.json` 的 244 张表 / 2266 个 selector 是用「`cmp w1,#N` + 数据段指针连续」两条判据找出来的。
2. **触发点**：§8.2 已证「AGX 按 `cmp w1,#N` 找 externalMethod 不成立」；§8.1 又证明 vtable 真实存在（AGX `__DATA_CONST.__const` 里 3463 个 auth-signed 代码指针）。两者叠加 ⇒ 普查必然漏。
3. **方法**：从 vtable 反查。`va = 0xfffffe0007004000 + (q & 0xFFFFFFFF)`，**不判 bit63**（高 32 位是 key/addrDiv/diversity）。先用 IOGPU 已知的 `externalMethod` 锚定槽位，再看 AGX 同形槽位。
4. **结论**：**8 个 vtable 引用的 selector 派发器，1 个被普查覆盖（且编号错误），7 个完全不在普查里**。2266 这个分母对这两块 kext **不成立**。
5. **AGX 缺口原因（结构性）**：AGX 的 selector 派发用 `__TEXT` 里的 PC 相对跳转表（`ldrsw`+`adr`+`br`），**不是数据段指针数组**，所以「数据段指针连续」这条判据**按构造看不见**。共 5 张跳表、167 个 switch 项。
6. **IOGPU 缺口原因（合并缺陷）**：普查把相邻两张 56 条表 **A(0x82f69f0) + B(0x82f64b0) 合并成一条**，报成 `table=0x82f64b0, selector 0..111`。内容对得上，但 **selector 56–111 是幽灵行**（真实上界 `0x37`=55）。
7. **另一个普查有、我没有的发现**：IOGPU 还有第三张表 `0xfffffe00082fba68`（3 个 selector，handler `0xa0591d8/0xa059314/0xa059390`），管理函数 `0xa059178`（`cmp w1,#0x2; b.ls`）。这一张本轮之前没解出来。
8. **纪律**：自动结果一律标「未手读」。本文所有 VA 为 27.0.1 静态镜像地址；未调用真机。
9. **未证明**：AGX 那 6 个派发器**是不是** `externalMethod` 仍未定（§8.2：全部不读 `IOExternalMethodArguments` 特征偏移）。称它们「externalMethod 候选」而不是「externalMethod」。
10. **直答见文末**：7。

---

## 一、vtable 是真的（前置事实）

| kext | `__DATA_CONST.__const` 里的代码指针 | 分布 |
|---|---|---|
| AGX | **3463** | mod_init 119 / mod_term 93 / `__DATA.__data` 1 / `__const` 3463 |
| IOGPU | 见下（本次只解 `__const`） | — |

解码式（两条判据都试过，只有这条自洽）：

```
target = 0xfffffe0007004000 + (q & 0xFFFFFFFF)
```

抽样 `q = 0x8011c597014f4bb4 → 0xfffffe00084f8bb4`。高 32 位 `0x8011c597` 是 key/addrDiv/diversity，**不是目标**。用 `v >> 63` 过滤会把整片 vtable 抹掉 —— 这是本项目前几轮「无 vtable」错误的唯一原因。

## 二、锚定：IOGPU 的 `externalMethod` 在 vtable 里的位置

已知实现（§6.7.1）：`0xa024d94`（user client #1，`cmp w1,#0x37`）、`0xa024e4c`（user client #2，`cmp w2,#0xd`）。

| 目标 | vtable 槽 | 槽后一项 | 槽前一项 |
|---|---|---|---|
| `0xa024d94` | `0xfffffe00082f6378` | `0xa024f44` | `0xb321c7c`（跨 kext 继承槽） |
| `0xa024e4c` | `0xfffffe00082f6400` | `0xa024970` | `0xb3743a8`（跨 kext 继承槽） |

两个槽相距 `0x88` = 17 项，说明是**两个相邻子类的 vtable**，各有一个 `externalMethod` 覆写。这正是普查的盲区形态：**方法本体不认识 `cmp w1`，靠 vtable 才连得上**。

## 三、缺口表（核心交付）

「是否在 census.json 里」的判据：看该派发器**实际使用的 selector 集合**是否出现在 `census.json` 的 `(kext, table, selector)` 行里。

| # | kext | vtable 槽 | 派发器 VA | bound | 在 census 里？ | selector 怎么派发 |
|---|---|---|---|---|---|---|
| 1 | IOGPU | `0x82f6378` | `0xa024d94` | `0x37`(56) | **部分**：`table=0x82f64b0` 的 112 行里前 56 行是它，但表被与 A 合并，**selector 56–111 是幽灵行** | 2×56 条 24B `IOExternalMethodDispatch`，`csel` 于 `[this+0x103]&1` |
| 2 | IOGPU | `0x82f6400` | `0xa024e4c` | `0x0d`(14) | **否**（表 `0x82f7088` / `0x82f6f38` 均不在 census） | 2×14 条 24B 记录，同一 `csel` |
| 3 | AGX | `0x7f22f08` | `0x850f170` | `0x10`(17) | **否** | `__TEXT` 跳表（`cmp w1,#0x10; b.hi; ldrsw; adr; br`） |
| 4 | AGX | `0x7f22300` | `0x851070c` | `0x0f`(16) | **否** | `__TEXT` 跳表 |
| 5 | AGX | `0x7f22e08` | `0x8514ae0` | `0x64`(101) | **否** | `__TEXT` 跳表 |
| 6 | AGX | `0x7f228c8` | `0x851cfd0` | `0x11`(18) | **否** | `__TEXT` 跳表，18 项，12 个 live（§6.3 已解全表） |
| 7 | AGX | `0x7f26e08` | `0x85335f4` | `0x32`(51) | **否** | `__TEXT` 跳表，51 项 |
| 8 | AGX | `0x7f25e18` / `0x7f26dc0` / `0x7f27ce0` / `0x7f294e8`（**4 个 vtable 共用**） | `0x84b81c0` | `0x41`(66) | **否** | `__TEXT` 跳表，66 项（基类方法被 4 个子类继承） |
| — | IOGPU | 未定 | `0xa059178` | `0x02`(3) | **是**：`table=0x82fba68`，3 行，handler `0xa0591d8/0xa059314/0xa059390` | 普查独有，本轮之前未解出 |

## 四、缺口是怎么造成的（两条，都可修）

### 4.1 AGX：跳表在代码段，判据看不到

```asm
cmp  w1, #BOUND
b.hi default
mov  w16, w1
csneg x16, x16, xzr, ls
adrp x17, TABLE_PAGE
add  x17, x17, #TABLE_OFF
ldrsw x16, [x17, x16, lsl #2]   ; 32 位相对偏移，不是指针
adr  x17, .+8
add  x16, x17, x16
br   x16
```

表项是 **PC 相对偏移**，落在 `__TEXT_EXEC` 内，**不是数据段里的指针数组**。普查按「数据段指针连续」找表，**按构造看不见这类派发**。AGX 侧共 5 张：66 / 15 / 18 / 51 / 17 项，合计 **167 个 switch 项**。

### 4.2 IOGPU：相邻表被合并，selector 编号虚增

- 表 B `0x82f64b0`（56 条，上界 `0x37`）之后紧接表 A `0x82f69f0`（56 条），间距正好 `0x540` = 56×24。
- 普查没有按 bound 截断，一路走到 **112 行**，报成 `table=0x82f64b0, selector 0..111`。
- 核验：`sel 0 → 0xa021ee8`，`sel 55 → 0xa0240cc`，**`sel 56 → 0xa021ee8`（= B[0] 的 handler 又出现一次）**，`sel 111 → 0xa0240cc`。⇒ 56–111 是 A 的行，被改号了。
- **危害**：任何人「查 IOGPU selector 100」都会拿到一行假数据；反过来，「IOGPU 上界只有 55」这个正确结论也会被 112 行掩盖。

## 五、直答

> **AGX 与 IOGPU 的 user-client 类里，有 7 个的 selector 派发不在现有普查中。**

数字与清单：

- **AGX：6 个** —— `0x84b81c0`（bound 0x41，被 4 个 vtable 共用）、`0x850f170`(0x10)、`0x851070c`(0x0f)、`0x8514ae0`(0x64)、`0x851cfd0`(0x11)、`0x85335f4`(0x32)。全部经 `__TEXT` 跳表派发，普查按构造看不见。
- **IOGPU：1 个** —— `0xa024e4c`（bound 0x0d），其两张 14 条表 `0x82f7088` / `0x82f6f38` 不在 census；这 28 个 selector 全部缺失。
- **IOGPU 的 `0xa024d94` 算「部分覆盖」**：内容在（112 行 = 56 + 56），但表被合并、selector 56–111 是幽灵行，**上界信息丢失**。

**所以 2266 这个分母对 AGX / IOGPU 不成立**：AGX 侧普查只有 4 行（2 表 × 2 selector），而实际至少有 167 个 switch 项 + 6 个派发器；IOGPU 侧至少缺 28 个 selector，另有 56 个被错编号。

**未证明的**：AGX 那 6 个派发器是不是 `externalMethod` —— 全部不读 `IOExternalMethodArguments` 特征偏移（`+0x20/+0x28/+0x30/+0x38/+0x40/+0x48/+0x50/+0x58/+0x60`），所以只能叫「vtable 引用的 selector 派发器」。**没证据就是没证据，不往上加一级。**

---

## §4 AGX 派发器性质判定

**问题**：那 6 个 `cmp w1,#N` 派发器（`0x84b81c0` / `0x850f170` / `0x851070c` / `0x8514ae0` / `0x851cfd0` / `0x85335f4`）是不是 `IOUserClient::externalMethod`？

**答案：否。6 个都不是。**

### 4.1 先立 ABI（用已确证的实例做基准）

IOGPU 的 `0xfffffe000a024d94` 是确证的 `externalMethod`（§6.7.1），它给出该 override 的寄存器约定：

```asm
0xa024da8  cmp  w1, #0x37            ; x1 = selector
0xa024db0  ldr  x9, [x2, #0x10]      ; x2 = IOExternalMethodArguments*（+0x10 = asyncReference）
0xa024e00  csel x3, x11, x12, ne     ; x3 = dispatch
0xa024e14  mov  x4, x0               ; x4 = target
0xa024e20  braa x16, x17             ; super::externalMethod(sel, args, dispatch, target, ref)
```

即 **x1 = selector、x2 = `IOExternalMethodArguments*`**。据此，任何真正的 override 都**不可能一次都不碰 `[x2, …]`** —— 至少要把 args 原样转交给父类，或读 `args->structureInput`(0x30) / `scalarInput`(0x20)。

### 4.2 逐个核对

| 派发器 | 长度 | 是否解引用 `x2` | 结论 |
|---|---|---|---|
| `0x84b81c0` | 3 条 | **否**（尾跳 thunk） | 否 |
| `0x850f170` | 37 条 | **否** | 否 |
| `0x851070c` | 10 条 | **否** | 否 |
| `0x8514ae0` | 20 条 | **否** | 否 |
| `0x85335f4` | 2 条 | **否**（尾跳 thunk） | 否 |
| `0x851cfd4` | 2309 条 | **否**（§6.6.1 逐条手读：`x2` 只出现 4 次——`mov x20,x2`、`stp x20,[sp,#0x70]`、`str w20,[sp,#4]`、两处 `ldr w,[sp,#4]` 后喂 `umull`，**无一处解引用**） | 否 |

**标注**：上表 5 个「否」是自动扫描结果，**未手读**；`0x851cfd4` 是手读确证。自动扫描对 `0x851cfd4` 曾报 24 处「x2 解引用」，逐个看全是 `[x28,…]` / `[x0,…]`，**是我别名追踪器的假阳性**（假阳性史继续：2/2 → 现在 3/4）。

### 4.3 方法 3（vtable 槽号）为什么执行不了

你要的「拿 `0x82f6378` 的槽位号去 AGX vtable 里取」，卡在**槽位号算不出来**：

- `0x82f6378 - IOGPU__const基址(0x82f50c0) = 0x12b8`，但那不是槽号，因为**数组起点未知**。
- 实测该区域是一段**连续 ≥48 个非空 auth 指针**（`0x82f61c0`–`0x82f6418` 无一个为 0），**没有终止符**；`0x82f6420`–`0x82f6430` 的 4 个 0 之后又有代码指针。
- 没有符号表（`nsyms=0`）就无法定位「vtable 从哪一项开始」，槽号随之无法计算。

**断链点就在这里**：不是方法错，是这个镜像里**缺少建立数组边界的信息**。除非拿到带符号的 kext、或用 `OSMetaClass` 的运行时对象反推（需真机），否则第 3 条走不通。

### 4.4 反证：真正的 externalMethod 也**不在这 6 个**里

AGX 里唯一读 `[x2,#0x30]` 的函数是 `0xfffffe0008558c18`（`ldr x21,[x2,#0x30]`），读出来当**用户缓冲区**逐字节解析：

```asm
0x8558c0c  ldrb w19, [x2, #0x2]      ; 计数（u8）—— args 的 +0x2 不是计数字段
0x8558c18  ldr  x21, [x2, #0x30]     ; 缓冲区
0x8558c1c  ldb  w22, [x21, x20]
0x8558c20  lsl  x16, x22, #6
0x8558c24  sub  x16, x16, x22, lsl #3 ; ×0x38 = 56 字节记录
0x8558c34  b.ls …                     ; 有上界比较
```

`+0x2` 当计数字段与 `IOExternalMethodArguments`（`+0x00 version`、`+0x04 selector`）不符 ⇒ **这是子类自己的精简参数结构**，不是 args。也就是说 AGX 的 user-client 方法把参数**再包了一层**。

### 4.5 直答

> **不是。AGX 那 6 个 `cmp w1,#N` 派发器都不是 `IOUserClient::externalMethod`。**

判定依据：确证 ABI 下 `x2 = IOExternalMethodArguments*`，而 6 个函数**全部不解引用 `x2`**（1 个手读、5 个自动扫描未手读）。

**连带的结论**：`0x84b81c0` 那 167 个 switch 项**不因此变成用户可达**，也不能就此排除 —— **AGX 真正的 `externalMethod` 仍未找到**。搜索签名应当同时满足「`cmp w1,#N`」+「读 `[x2,#0x10]`」+「读 `[x2,#0x30]` 或 `[x2,#0x20]`」，三者同在的函数在 AGX 里**一个都没有**（`[x2,#0x30]` 全 kext 仅 1 处、`[x2,#0x38]` 0 处）。这说明 AGX 的 user-client 层不在本 kext 的 `__TEXT_EXEC` 里直连 args —— 要么参数被上一层拆好，要么入口在别处。

**没证据就留白**：这一条到此为止，不再往上加级。
