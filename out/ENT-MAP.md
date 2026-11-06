# ENT-MAP — 哪个 entitlement 卡住哪个 selector

范围：`IOMobileGraphicsFamily`(MFB) / `IOMobileGraphicsFamily-DCP`(mfbd) / `IOSurface` / `IOGPUFamily` / `AGXG18P`，
镜像 `out/kernelcache.27.0.1`（设备版本，主），`out/kernelcache.27.2.ga` 仅做交叉核对。

标签定义：**读到** = 指令/数据结构直接可见；**推断** = 由多条独立证据收敛但缺一条直连指令；**未证** = 只到候选，不排除其它可能。

---

## 0. 结论表（TL;DR）

| 服务 | type | sel | handler VA | 卡住的 entitlement | 标签 | 检查实际发生的位置 |
|---|---|---|---|---|---|---|
| IOMobileFramebuffer / AppleCLCD2 | 0 | 23 | `0xfffffe000a17ed98` | `com.apple.private.iomfb.set-block` | 推断 | 派发表 entry+0x20 字段；不在 handler 内 |
| 同上 | 0 | 78 | `0xfffffe000a17e264` | `com.apple.private.iomfb.set-block` | **读到** | handler 调 `0xa17bf1c`（`bl` @`0xa17e2bc`）→ `IOTaskHasEntitlement` |
| 同上 | 0 | 83 | `0xfffffe000a17dcec` | `com.apple.private.allow-explicit-graphics-priority` | 推断 | 派发表 entry+0x20 字段；备选 `mfbd 0xa153e80` |
| 同上 | 0 | 86 | `0xfffffe000a17e684` | `com.apple.private.gain-map-access` | 推断 | 派发表 entry+0x20 字段；不在 handler 内 |
| 同上 | 0 | 100 | `0xfffffe000a17e714` | `com.apple.private.gain-map-access` | 推断 | 派发表 entry+0x20 字段；不在 handler 内 |
| IOSurfaceRoot | 0 | 30 | `0xfffffe000a349f14` | `com.apple.private.iosurfaceinfo` | **读到** | user client 初始化置位 `[self+0x122]`，handler 只读该位 |
| AGXAcceleratorG18P | 33 | 0 | 未证（见 §5） | 候选 `com.apple.internal.display-params-access-privileged` | 未证 | kext 内唯一 C1 产生者 `0x84f0948` |
| AGXAcceleratorG18P | 33 | 2 | 未证（见 §5） | 同上 | 未证 | 同上 |

**最值结论（任务要求的特别标注）**：**没有任何一个 NotPrivileged selector 能只靠一个 `com.apple.developer.*` 解锁。**

- 全图形栈里出现的 `developer.*` 只有两个：`com.apple.developer.gpu-restricted`（iosf/iogpu）、`com.apple.developer.metal.performance-state-assertion`（agx）。
- `com.apple.developer.gpu-restricted` 落点是 IOSurface user client 的 **`[client+0x127]`**，而 sel 30 卡的位是 **`[client+0x122]`**（只由 `com.apple.private.iosurfaceinfo` 置位）——**两者不是同一个位**，故 sel 30 不会被 developer 变体解锁（读到：两条 `strb` 目标偏移不同）。
- `com.apple.developer.metal.performance-state-assertion` 的检查在 agx `0x84f0b54`，是性能状态断言路径，与 t33 sel 0/2 无可证连线（未证）。
- 因此：`out/ents-gpu-dev.plist` 存在的意义是把「developer 能拿到的部分」全部拉满以排除"其实只缺 developer"的可能，而不是预期它能解锁 C1。

---

## 1. 方法：怎么把「校验藏在 callee 里」这类假阳性压下去

本项目历史上的假阳性全部来自「handler 里没看到检查 → 误判为不需要 entitlement，其实校验在 callee / 在更上层」。本轮把结论建立在四条互相独立的证据链上，任何一条单独都不下结论：

### 1.1 证据链 A：派发表里逐 selector 的 entitlement 字段（数据级）

`IOMobileGraphicsFamily` 的 `IOExternalMethodDispatch` 条目实测步长 **40 字节**（不是 XNU 的 24），布局取自 `0xfffffe000832fd70`：

```
+0x00 const void *action            (arm64e chained fixup → BASE+(raw&0xFFFFFFFF))
+0x08 uint32_t scalarInputCount
+0x0c uint32_t structInputSize
+0x10 uint32_t scalarOutputCount
+0x14 uint32_t structOutputSize
+0x18 uint32_t flags               (全表恒为 1)
+0x1c uint32_t pad
+0x20 const char *entitlement      ← 通常是 0；非 0 处即该 selector 声明的必需 entitlement
```

全表 101 项（sel 0–100，穴 59–65、70–71；sel 100 是最后一项，表尾 `0xfffffe0008330d38`），`__DATA_CONST`，起于 `0xfffffe000832fd70`。
`+0x20` 非 0 的 **只有 4 项**，且全部落在实测返回 C1 的集合里：

| sel | +0x20 指向的字符串 |
|---|---|
| 23 | `com.apple.private.iomfb.set-block` (`0xfffffe00079c6206`) |
| 83 | `com.apple.private.allow-explicit-graphics-priority` (`0xfffffe00079c6756`) |
| 86 | `com.apple.private.gain-map-access` (`0xfffffe00079c64b4`) |
| 100 | `com.apple.private.gain-map-access`（同址） |

4/4 命中、0 反例。但**这不是"读到校验指令"**，所以只标推断——见 1.4 的解释。

### 1.2 证据链 B：C1 常量产生者的穷举枚举（这是本项目唯一可靠的"排除法"）

单纯 grep `#0x2c1` 会漏掉编译器把返回值折进别的常量的写法。本轮枚举了四种产生 `0xE00002C1` 的方式，并用 numpy 掩码扫描整个 `__TEXT_EXEC`：

1. `movz wN,#0x2c1` + `movk wN,#0xe000,lsl#16`（掩码 `w&0xFFFFFFE0==0x52805820` / `0x72BC0000`，同一 N 且相邻）；
2. **C2−1**：先 `movz #0x2c2`+`movk #0xe000`，之后对同一寄存器 `sub wN,wN,#1`；
3. **C2+4**：`movz #0x2bd`（`kIOReturnNotPermitted`）+`movk #0xe000`，之后 `add wN,wN,#4`；
4. `__TEXT_EXEC` 里 4 字节字面池直接出现 `0xE00002C1`（5 个 kext 全部为 0 处）。

结果（每个 kext 的 C1 产生者清单）：

| kext | C1 产生点 | 说明 |
|---|---|---|
| IOMobileGraphicsFamily | `0xa17de40`(func `0xa17ddd0` = sel 5 handler)、`0xa17e850`(func `0xa17e804` = sel 68 handler) | 只有 2 处，且都在**别的** selector 的 handler 里 |
| IOMobileGraphicsFamily-DCP | `0xa153f00`(func `0xa153e80`) | gated action 包装器，检查 `allow-explicit-graphics-priority` |
| IOSurface | `0xa349fa8`(func `0xa349f14` = **sel 30 handler**)，经 C2+4 折叠到 `0xA349F14` 的 `add w19,w19,#4` | 唯一产生者，且就是目标 handler 内 |
| IOGPUFamily | `0xa042fa4`,`0xa059334`,`0xa0593a8`,`0xa059420` | 各自是某个 user client 方法的默认返回 |
| AGXG18P | `0x84f0974/0x84f09c0/0x84f0a2c`(func `0x84f0948`) | **整只 kext 只有这一个函数能返回 C1** |

这条清单是"某个 handler 不产生 C1"的**有限性证明**：不是"没看到"，而是"该 kext 里能产生 C1 的指令位置已枚举完"。

### 1.3 证据链 C：callee 边界（BFS + 间接调用不可解）

- 直接 `bl` 调用图用 `entana.walker` 做 BFS（`bl` + 最近前置 `adrp/ldr` 解析出的 `braa/blraa`），深度上限见脚本参数；`braa` 的目标来自对象 vtable 槽，**静态无法绑定 class**，因此凡是"handler 以 `braa` 收尾"的地方都算**未闭合**。
- 未闭合就用 1.2 反证：如果检查在某个 vtable callee 里，那么该 callee 必然在某处 materialize `0xE00002C1`。
  - 若 callee 在同一 kext → 与 1.2 的清单矛盾（清单只有那几处）→ 排除；
  - 若 callee 在别的 kext → 只有 5 个图形 kext 在范围内，逐个用 1.2 的清单核对，唯一相关的是 mfbd `0xa153e80`，已逐指令读完（见 §2.3），它 gate 的条件是 `[self+0x160]!=0` 且 (`allow-explicit-graphics-priority` 或 `[self+0x4d0f]&1`)。
- 结论：MFB sel 23/86/100 的 C1 **不可能**由 handler 或其同 kext callee 产生，只剩"上一层"——即把 entry 交给 `IOUserClient::externalMethod` 的那一层。

### 1.4 证据链 D：C1 与 C2 的区分（排除"参数校验"假阳性）

`kIOReturnBadArgument`(C2/`0xE00002C2`) 与 `kIOReturnNotPrivileged`(C1/`0xE00002C1`) 只差 1，很多"看起来是权限"的失败其实是参数形状不对。判定规则：

- IOKit 对 dispatch 契约的检查是 `scalarInputCount != 声明值 → C2`，而 `scalarOutputCount >= 声明值` 即可。所以"同一 selector 只要给足输出容量就从 C2 变 C1"说明 C1 发生在**契约校验之后**，是真权限位（AGX t33 sel 0/2 即此形态：`soc=0 → C2`，`soc=1 → C1`）。
- 反之"给足输出容量仍是 C2"说明连契约都没过，此时谈 entitlement 没有意义。

### 1.5 关于"上一层"为何仍标推断

我在 `com.apple.kernel` 里行为性定位到了 entitlement API：

- `0xfffffe000b3b1fd4` = `IOTaskHasEntitlement(task, const char *)`：`task==NULL → current_task()`、`ent==NULL → false`、`task==kernel_task(0x7ef5c58) → false`、否则取 `[0x7ef2898]+0x1c8` 的 vtable 方法比较字符串（读到）。
- `0xfffffe000b379b54` = 取 OSObject 形态的 getter（`+0x1e8` 槽、带出参，读到）。
- 图形 kext 全部通过 `__TEXT_EXEC` 尾部的 `adrp/ldr/braa` 跳板（PLT 形态，槽在 `__DATA_CONST`）调用它们；MFB 的跳板目标解出即 `0xb3b1fd4`。

但：**我没有在 kernel 里定位到"读 dispatch entry +0x20 并据此返回 C1"的那条指令**（kernel 里 29 处 C1 产生点已枚举，没有一处与 `IOTaskHasEntitlement` 调用同函数）。因此 1.1 的字段只标**推断**。若要闭环，下一步是在 kernel 里找 `IOUserClient::externalMethod` 的契约检查块（读 entry+0x8/+0xc/+0x10/+0x14 的那段），确认它是否顺带读 +0x20。

---

## 2. 逐 selector 证据

### 2.1 MFB sel 23 — `com.apple.private.iomfb.set-block`（推断）

handler `0xa17ed98`（0x44 字节，纯 thunk）：

```
0xa17ed98  bti c
0xa17ed9c  ldr x8,[x2,#0x20]        ; args->structureInput
0xa17eda0  ldr w1,[x8]              ; 第 1 个 u32
0xa17eda4  ldr w2,[x8,#8]           ; 第 2 个 u32
0xa17eda8  ldr x0,[x0,#0xd8]        ; 目标对象
0xa17edac..0xa17edd8  取 vtable、autda、add #0x5d8、braa   ; 尾调用，无 bl
```

- 全函数**没有任何 `bl`，没有 C1 常量**；返回码来自尾调用的 vtable 方法。
- 派发表 entry 23 的 `+0x20` = `com.apple.private.iomfb.set-block`。
- 同名字符串在 kext 内的两处代码引用（`0xa17b734` → `set-block-client-profile`，`0xa17bfec` → `set-block`）分别属于 init 路径和 sel 78 的 gate，与 sel 23 无 `bl` 连线。

### 2.2 MFB sel 78 — `com.apple.private.iomfb.set-block`（读到）

```
0xa17e280  mov w23,#0x2c2 ; movk w23,#0xe000,lsl#16   ; 默认返回值 = C2
0xa17e28c  ldr x19,[x2,#0x30]  ; structureInput
0xa17e2bc  bl  0xa17bf1c                              ; ← 权限判定
0xa17e2c0  cbz w0, 0xa17e340
...
0xa17e340  sub w23,w23,#1                             ; C2-1 = 0xE00002C1
0xa17e344  mov x0,w23
```

被调方 `0xa17bf1c`（= "这个 set-block 请求是否被允许"）：

```
0xa17bf34  ldrb w8,[0xb998ee8]  ; 全局提前返回位
0xa17bf48  cmp w2,#2 ; b.eq 0xa17bfe4                  ; mode==2 → 走权限检查
0xa17bf50  cmp w2,#1 ; b.ne 0xa17bfb4                  ; mode==1 → 查表命中后也走权限检查
0xa17bfb4..0xa17bfd8  查另一全局位，未命中 → 只记日志、return 0
0xa17bfe4  adrp/add x1, "com.apple.private.iomfb.set-block"  (0x79c6206)
0xa17bfec  bl 0xa1976f0    ; 跳板 → kernel 0xfffffe000b3b1fd4 = IOTaskHasEntitlement
0xa17bff0  cmp w0,#0 ; cset w0,ne                       ; 返回 bool
```

- `com.apple.private` 且**不在**我们的 44 项里 → 这就是 sel 78 的硬门槛。
- 选 `&&`/`||` 说明：`mode==2` 与"查表命中"是**并列的 OR 触发**（两者都会走向同一个 entitlement 检查），而 entitlement 本身是**必要条件**（单条 `&&`）。
- 结构旁证：sel 78 的派发表契约是四个 `0xFFFFFFFF`（`kIOExternalMethodArgumentsAreChecked`，即 **IOKit 层完全不校验参数**），所以"参数形状 → C2"不会抢先，handler 自己的 `[x2+0x30]`（structureInput 非空）、`[x2+0x28] >= 2` 检查就是第一道闸。这也解释了为什么它是唯一一个在零参/任意形状下都能把 C1 暴露出来的 MFB selector。

### 2.3 MFB sel 83 — `allow-explicit-graphics-priority`（推断，有备选路径）

handler `0xa17dcec` 同样是 thunk（取 `[x2+0x28]` 计数、`[x2+0x20]` 指针，尾调用 vtable `+0x800`），无 `bl`、无 C1 常量，也无 entitlement 字符串。

两条可能的实际检查点：

1. 派发表 entry 83 的 `+0x20` = `com.apple.private.allow-explicit-graphics-priority`（推断，机制同 §1.5）；
2. mfbd `0xa153e80`：

```
0xa153e98  ldr x8,[x0,#0x160] ; cbz → return C1
0xa153eac..0xa153eb8  bl <stub> → kernel 0xfffffe000b3b1fd4  ("com.apple.private.allow-explicit-graphics-priority")
0xa153ec4  or  [self+0x4d0f]&1  → 任一成立才往下走 gated action，否则 C1
```

即 mfbd 侧是 `entitlement || 位 0x4d0f` 的 **OR**。sel 83 是否落到这里未证（间接 `braa` 未闭合）。

### 2.4 MFB sel 86 / 100 — `gain-map-access`（推断）

两个 handler（`0xa17e684`、`0xa17e714`）都是 thunk（尾调用 vtable `+0x760`/`+0x768`），无 C1 常量。

字符串 `com.apple.private.gain-map-access` 在 kext 内的两处**代码**引用都在别的 selector 上：`0xa17de0c`（func `0xa17ddd0` = sel 5 handler，site 之后 `add w19,w19,#4` 之外的路径 → 返回 C1）与 `0xa17e848`（func `0xa17e804` = sel 68 handler）。这两个 handler 的契约（sel 5 要 1760 字节 structIn）在零参/常规阶梯里先被 C2 挡住，所以探测面上看不到它们的 C1。

⇒ 86/100 的 C1 来自派发表 `+0x20`（与 23/83 同一机制），而不是来自它们自己的 handler。

### 2.5 IOSurfaceRoot sel 30 — `com.apple.private.iosurfaceinfo`（读到）

handler `0xa349f14`：

```
0xa349f2c  mov w19,#0x2bd ; movk w19,#0xe000,lsl#16     ; 默认 C2-1 基址
0xa349f34  ldrb w8,[x0,#0x122]
0xa349f38  tbz  w8,#0,0xa349fa4
0xa349fa4  add  w19,w19,#4                              ; = 0xE00002C1  ← sel 30 的 C1
0xa349f40  ldr  x8,[x2,#0x78] ; cbz → add w19,w19,#5     ; = 0xE00002C2（结构输出指针缺失）
```

`[client+0x122]` 的唯一写入点：`0xa34ab5c`（IOSurface user client 初始化）：

```
0xa34abc8  adrp/add x2, "com.apple.private.iosurfaceinfo" (0x7a1b59e)
0xa34abd4  bl 0xa34ae94                     ; entitlement 查询包装（OSObject 形态）
0xa34abd8  strb w0,[x19,#0x122]             ; ← sel 30 的唯一开关
0xa34abdc  adrp/add x2, "com.apple.private.gpu-restricted" (0x7a1b5be)
0xa34abe8  bl 0xa34ae94 ; tbz → 再查 "com.apple.developer.gpu-restricted" (0x7a1b5df)
0xa34ac08  strb w0,[x19,#0x127]             ; ← 落到**另一个**位，sel 30 不用它
0xa34ac0c..0xa34ac18  bl 0xa34ae94 ("com.apple.private.IOSurface.protected-access" 0x7a1b602)
0xa34ac20  ldrb w8,[x19,#0x122] ; orr w8,w8,w0 ; and #1
0xa34ac2c  strb w8,[x19,#0x126]             ; ← iosurfaceinfo || protected-access
```

- `+0x122` 只被 `iosurfaceinfo` 置位（全镜像仅 1 处 `strb`，读到）→ sel 30 只能由 `com.apple.private.iosurfaceinfo` 解锁。
- `+0x126` 是 `iosurfaceinfo || IOSurface.protected-access`（OR）；`+0x127` 是 `private.gpu-restricted || developer.gpu-restricted`（OR）。**不要把 `developer.gpu-restricted` 误当成 sel 30 的钥匙**。

### 2.6 AGXAcceleratorG18P type 33 sel 0 / 2 — 未证

已确证的事实：

- 探测面上：`soc=0 → C2`，`soc=1 → C1`，`soc≥2 → C2` ⇒ 声明契约是 `scalarOutputCount=1, structOutputSize=0`，且 C1 发生在契约校验之后（真权限位）。
- 在 `AGXG18P` 的整只 `__TEXT_EXEC`（`0x84b1960–0x85896fc`）里，能产生 C1 的**只有一个函数** `0x84f0948`：

```
0x84f0974  mov w0,#0x2c1 ; movk w0,#0xe000,lsl#16        ; 默认 C1
0x84f097c  ldrb w8,[x21,#0x130] ; tbnz w8,#0, → 直接走 gated call   ; 缓存位
0x84f0984  ldr x0,[x21,#0x120]
0x84f0988  adrp/add x1, "com.apple.internal.display-params-access-privileged"
0x84f0990  bl <stub>                                       ; 权限查询
0x84f0994  tbz w0,#0, → return C1                          ; 不满足 → C1
0x84f09bc  strb w24,[x21,#0x130]                           ; 缓存结果
0x84f09c0  mov w0,#0x2c1 ; movk w0,#0xe000,lsl#16        ; 第 2 个 C1 出口（权限查询失败且要写回缓存位）
0x84f0a28  strb wzr,[x21,#0x130] ; mov w0,#0x2c1 ; ...     ; 第 3 个 C1 出口（查询返回 0 的分支）
0x84f0a38  add  w0,w0,#8                                   ; 相邻分支：C1+8（另一类 IOReturn），不是 C1
```

- AGX 内**不存在** stride 24/40 的派发表能对上观察到契约（对全 kext 做了 8 字节对齐穷举，`sOut=1,stOut=0` 的条目 0 个）；t33 的 selector→handler 绑定因此**未闭合**。
- 也**没有**任何 `bl` 到 `0x84f0948`：它的地址只作为 auth-rebase 指针出现在 `__DATA_CONST 0xfffffe0007f20850`（vtable/函数指针槽），只能经 `braa` 进入 —— 这正是本项目"检查在 callee 里看不见"的典型形态。
- 因此：AGX t33 sel 0/2 的 C1 **要么**由 `0x84f0948`（`com.apple.internal.display-params-access-privileged`）经未绑定的 vtable 路径产生，**要么**由 kext 之上的一层产生。两者都未证，故标未证。
- 旁证（有利于前者，推断级）：IOGPU 派发表第 0/2 项（`0xa021ee8`/`0xa022030`，`stOut=64`/`536`）就是把设备侧 `[dev+0xf8]` 的 `0x1e8/0x1f0/0x200/0x224/0x22c/0x140` 等字段抄进 structureOut —— 形态与"取 display/device params"一致；而 `0x84f0948` gate 之后调用的 action（`0x84cc968`）也是填充结构体的形态。两者功能同型，但没有一条指令把 sel 0/2 与它连起来。

---

## 3. 三个 plist

均以 `out/ents.plist`（44 项，未改动，md5 `991b3fdeefb2069cda5f6e6c3bd24c6b`）为底，只做并集，`plutil -lint` 全部 OK：

| 文件 | 条目 | 增量 |
|---|---|---|
| `out/ents-gpu-dev.plist` | 46 | `com.apple.developer.gpu-restricted`、`com.apple.developer.metal.performance-state-assertion` |
| `out/ents-gpu-mix.plist` | 57 | 上述 2 个 developer + 11 个 private/internal：`private.iomfb.set-block`、`private.iomfb.set-block-client-profile`、`private.allow-explicit-graphics-priority`、`private.gain-map-access`、`private.iosurfaceinfo`、`private.gpu-restricted`、`private.IOSurface.protected-access`、`private.agx.performance-spi`、`private.agx.rt-priority-spi`、`private.ioaccelmemoryinfo`、`internal.display-params-access-privileged` |
| `out/ents-gpu-all.plist` | 66 | 上述 13 + `private.ggdsw.GPUProcessProtectedContent`、`private.graphics-restart-no-kill`、`private.iogpu.disable_wired_collector`、`agx.{rt-priority-spi,performance-spi}` 以外的 `agx.ctxswitchlatency`/`agx.gpurole`/`agx.restartreport`/`agx.thmcounters`、`driver.iomfb.nested_rpc_telemetry`、`iomfb.dcp_reset_req` |

枚举来源 `out/_entwork/gpu-ents-found.json`（5 个 kext 的字符串全集，26 条；已剔除 `com.apple.iokit.*` 三个类名，它们不是 entitlement）。

用途：dev/mix/all 是**三档对照**，不是"能装"的承诺——见 §5。

---

## 4. Harness

`harness/entprobe/main.m` → `harness/entprobe/out.bin`（arm64 Mach-O，编译干净无警告）：

```
xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc main.m -o out.bin \
  -framework Foundation -framework UIKit -framework IOKit -framework CoreFoundation
```

设计要点：

- 每个 (svc,type,sel) **只调一次** `IOConnectCallMethod`，**不带任何输入**（`scalarInputCount=0`、`structureInput=NULL`），输出容量拉满（16×u64 / 4096B）——这样 IOKit 的 `scalarOutputCount >= 声明值` 不会误判成 C2，调用能落到 handler 自己对权限位的判断上（§1.4）。
- 只记返回码，输出 JSON 行（与 `svcreenum` 的 schema 同族）：
  `{"k":"@e","svc":"IOMobileFramebuffer","type":0,"sel":23,"kr":-536870207,"krh":"0xE00002C1"}`
- 首行 `@meta` 带 build 戳（`__DATE__ __TIME__`）、`operatingSystemVersionString`、输出容量与 `inputpolicy`。
- 覆盖 `IOMobileFramebuffer`(t0)、`AppleCLCD2`(t0) 各自 sel 23/78/83/86/100，`AGXAcceleratorG18P`(t33) sel 0/2，`IOSurfaceRoot`(t0) sel 30；`@open` 行单独报 `IOServiceOpen` 结果，方便区分"open 失败"和"sel 被拒"。

**macOS 自检**（只验 schema 与调用路径，不作为 iOS 证据）：同一份 `main.m` 用 `-sdk macosx` 编出来跑，输出
`harness/entprobe/selftest-macos.txt`：`IOMobileFramebuffer`/`IOSurfaceRoot` 均能 open（`kr=0`），sel 23/78/83/86/30 返回 `0xE00002C2`、sel 100 返回 `0xE0000001`，`AppleCLCD2`/`AGXAcceleratorG18P` 无服务（`0xFFFFFFFF`）。
说明：JSON 行可解析、`@meta`/`@open`/`@e` 三类齐全、且不同平台的返回码确实不同 —— 探针不是恒返回某个固定值的空转。

判读规则（换 plist 重跑时）：**`kr` 从 `-536870207` 变成 `0` 或别的值 = 该变体补上了钥匙**；仍是 `-536870207` = 该变体没覆盖到；变成 `-536870206`(C2) = 参数形状不对，与 entitlement 无关。

---

## 5. `com.apple.private.*` 在分发证书下的签名可行性

### 5.1 机制（来源：Apple 签名/描述文件校验模型 + 本地实测）

- `codesign` **不校验** entitlement 键是否合法、是否被描述文件授予：它把 plist 原样编进签名（并在 `--generate-entitlement-der` 时同时写 DER 形态）。**本轮本地实测**：`codesign --sign - --entitlements out/ents-gpu-mix.plist` 后 `codesign -d --entitlements :-` 读回 57/57 项，11 个 `private.*`/`internal.*` **一个没丢**（读到）。
- 真正的闸门在**安装/首次启动**：`installd`/`amfid` 要求「签名里的 entitlement ⊆ 描述文件 `Entitlements` 字典」，越界即拒（典型 `0xe8008016` / "application-verification failed"）。所以"**sign 接受但 install 拒**"是默认形态，"**sign 静默丢弃**"在 `codesign` 路径上不成立（至少对 ad-hoc 与 `--entitlements` 显式指定而言）。
- 带证书签名本轮**未能实测**：`codesign --sign 15E16F67…(iPhone Distribution: <DEVELOPER> DFH8ZCU6D4)` 返回 `errSecInternalComponent`（私钥 ACL 需要交互授权，本会话审批被禁用）。这属于环境限制，不是签名结论。

### 5.2 结论（分级）

| entitlement | 能否进签名 | 能否生效 | 标签 |
|---|---|---|---|
| `com.apple.developer.*`（含 `gpu-restricted`、`metal.performance-state-assertion`） | 能（实测，ad-hoc 读回一致） | 仅当描述文件授予；`developer.gpu-restricted` 是否在开发者可申请能力清单内 —— **未证**（需查 Apple 能力目录/`embedded.mobileprovision`） | 未证 |
| `com.apple.private.*`、`com.apple.internal.*` | 能（实测读回不丢） | 分发证书的描述文件不可能包含 → **install 会拒**。除非设备侧签名校验被绕过（越狱/`amfid` patch），否则拿不到 | 推断（install 侧未实测，本轮不碰设备） |

### 5.3 怎么区分"sign 接受但 install 拒" vs "sign 静默丢弃"（推荐流程）

1. **读回比对**（必做）：`codesign -d --entitlements :- Out.app > got.plist`，与输入 plist 做键集合 + 值 diff；再 `codesign -d --entitlements - --xml` 与 DER 形态交叉核对。
2. **描述文件预测**（install 之前就能判）：`security cms -D -i Out.app/embedded.mobileprovision > prof.plist`，取 `Entitlements` 做子集测试；同时看 `ProvisionsAllDevices`/`ExpirationDate`/`application-identifier` 是否匹配 `DFH8ZCU6D4.com.example.ios27poc`。
3. **install 侧**：用 `devicectl`/`ideviceinstaller` 装并抓 `installd`/`amfid` 日志；`sign 丢` 与 `install 拒` 的区别是——前者在步骤 1 就发现键消失，后者在步骤 1 一致但 install 报 entitlement 越界。

> 本轮不执行步骤 3（任务要求不碰设备）。

---

## 6. 未证清单 / 下一步（按性价比排序）

1. **kernel 侧 dispatch-entry entitlement 检查点**：定位 `IOUserClient::externalMethod` 的契约校验块，确认是否读 entry `+0x20` 并返回 C1。闭环后 §2.1/2.3/2.4 可从推断升到读到。
2. **AGX t33 sel 0/2 的 selector→handler 绑定**：解 `AGXDeviceUserClient` 的 vtable（`__DATA_CONST` auth-rebase 槽 `0x7f20850` 所在表），把 sel 0/2 与 `0x84f0948` 连上或否证。
3. **MFB 间接 callee 的 class 绑定**：handler 23/83/86/100 的 `braa` 目标槽（`+0x5d8`/`+0x760`/`+0x768`/`+0x800`）归属类，验证 §2.3 的 mfbd 备选路径。
4. `developer.gpu-restricted` / `metal.performance-state-assertion` 是否在开发者可授予清单（查 Apple 能力目录 + 手头描述文件）。
5. 幂等性：本轮 harness 只跑一次、只记返回码，若要在同一进程内比较多个 plist 变体，需重签重装（每变体一次），别在同一进程里 cache 权限位（IOSurface 的 `+0x122`/AGX 的 `+0x130` 都是 per-user-client 缓存，重开 client 才会重算）。

---

## 附：本轮使用的脚本（`out/_entwork/`，均为新增，不改既有产物）

| 文件 | 作用 |
|---|---|
| `entana.py` | arm64e chained-fixup 解码、`adrp/add/mov` 地址解析、函数边界、capstone 反汇编（已开 `skipdata`，否则会在字面池处截断——mfb 会少解 2.3 万条指令） |
| `kscan.py` | 整只 kernelcache 的 kext/segment 索引，`va(fo)` 反查与 `adrp` 页扫描 |
| `walker.py` | 调用图 BFS（`bl` + 间接 `braa` 解析） |
| `callsites.py` | 跳板(`adrp/ldr/braa`)→kernel 目标解析，并扫描"寄存器里持有 cstring 的 `bl` 调用点"，用于把 entitlement 字符串绑到函数上 |
| `gpu-ents-found.json` | 5 个 kext 的 entitlement 字符串全集（26 条）+ 来源 kext |

注意 `callsites.py` 的已知噪声：字符串也会作为参数流向日志/`OSString` 类函数，因此"目标出现次数最多者"才是 entitlement API（`0xfffffe000b3b1fd4`），单条命中不能直接当结论。
