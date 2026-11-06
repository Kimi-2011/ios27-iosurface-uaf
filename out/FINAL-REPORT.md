# 最终报告：iOS 27.0.1 / iPhone 17 Pro Max 内核 r/w → 越狱

> **⚠ 本报告 §2 的「唯一存活线索」判定已被推翻。**
> 真机上另有 4/4 复现的 **IOSurface 内核 UAF**（`0xa34ff88`），
> 其源码曾被覆盖丢失、已完成恢复。
> **请以 `out/RESEARCH-IOSURFACE-UAF.md` 为准。**
> 下方 §2 保留原文，作为过程记录。

> 目标：挖出内核读/写漏洞，最终实现全链越狱
> **结论：未达成。** 找到并定位了一处真实的内核越界写修补，但其可控性未能验证。
> 截止：2026-11-06　设备：DEVICE-UDID（iPhone18,2 / 27.0.1 / 24A446）

---

## 1. 一句话结论

**iOS 27.0.1 上，app 沙箱可达的内核攻击面已被系统性地加固到找不到可用的内存破坏原语。**
17 轮里逐条关闭了 IOKit、图形栈、网络栈、文件系统解析器、内核自身五条线。
唯一存活的一条（Mach IPC 端口容器的越界写）已定位到指令级，但**可控性未验证**，
实验因 harness bug + 设备掉线未能跑通。

---

## 2. 唯一存活的技术线索

### 2.1 位置

| 项 | 值 |
|---|---|
| 漏洞函数（27.0.1） | `0xfffffe000ab6b660`（208 B） |
| 修补后（27.2） | `0xfffffe000abbb654`（232 B） |
| 唯一调用点 | `0xab72ac8`（函数 `0xab721b8`） |
| 对应 CVE（推测） | **CVE-2026-112507** |

### 2.2 修补形态（已确证）

```asm
; 27.0.1
ldr  w8,  [x9, #8]          ; 容器元素计数
lsl  x11, x8, #4            ; 元素 16 字节
add  x12, x11, #0x10        ; 再放一个所需空间
cmp  x11, w11, sxtw         ; 只检查是否超 31 位（溢出），不是上界
add  x13, x9, w11, sxtw     ; x13 = 基址 + 计数*16  = slot[计数]
cmp  x12, x10               ; x10 = 容量
csel x10, xzr, x13, hi      ; 空间不足 -> x10 = 0
str  w1,  [x10, #8]         ; 写地址 0x8（必然 panic）
str  x9,  [x13]             ; ★ 越界写 slot[计数]，不受上面约束，16 字节

; 27.2
cmp  x12, x10
b.hi out                    ; ★ 空间不足直接跳出
cbz  x10, out               ; ★ 二次检查
str  x9,  [x10]             ; ★ 改用受检地址
```

**这是全项目唯一一处「形态明确、Apple 承认、写入侧无上界约束」的修补。**

### 2.3 子系统（已定位，置信度高）

调用者索引一张 **50 项、步长 40** 的表（基址 `0xfffffe0007de5658`）。
表项 = `{u32 标志; u32 字符串偏移}`，用 `KB + 偏移` 解码，**链式自洽**（`"port set"` 长 9 字节，下一项偏移正好 +9）：

```
[0] port set            [7]  notification port
[1] port                [8]  exception port
[2] service port        [9]  timer port
[3] bootstrap port      [10] reply port
[4] weak service port   [11] special reply port
[5] connection port     [12] weak reply port
[6] conn port with ool port array
```

**⇒ 这是 Mach IPC 的端口类型表。越界写作用在 `port + 0x68` 的容器上。**

### 2.4 为什么这条值得单独留下

| 候选 | app 能否直接触达 | 前置条件 |
|---|---|---|
| 网络栈 `nat464_translate_64/46`（旧归属） | **否** | 需构造 NAT64/CLAT 报文、网络位置 |
| **Mach 端口容器** | **是** | 无，`mach_port_*` 不需要任何 entitlement |

**Mach 端口是任意 app 都能创建的最基础内核对象。** 这是 17 轮里唯一
「Apple 承认 app 可达 + 定位到具体指令 + 入口无需任何特权」三者同时成立的组合。

**但归属有冲突**：`out/NAMED-CHANGED.md:81` 曾把 112507 归给网络栈。
静态无法判定哪条才是 112507，详见 `out/KERNEL-OOB-WRITE.md` §15。

---

## 3. 明确关闭的路线（全部有证据，不要重开）

| 面 | 覆盖度 | 关闭依据 |
|---|---|---|
| IOKit 用户客户端 | 8 个服务全覆盖 | 见下 |
| AGXAcceleratorG18P | 56 个 selector（0–55） | `SVC-REENUM.md` |
| IOMobileFramebuffer / AppleCLCD2 | 47 个 selector 契约全解 | `MFB-CONTRACT.md`：25 个 `kr==0`、22 个已知错误，structOut 通道空，无内核 VA |
| AppleM2ScalerCSCDriver | 12 个 selector | 曾有「只有 1 个」的错误结论，已推翻；实为 12 个 |
| IOSurfaceRoot | 7 个 selector（19,30,32,36,37,38,45） | `SEL32-PAGE.md`：sel 32 的 16 KiB 页 1382 次全页比对、2683 次内核调用，**恒为零** |
| AppleJPEGDriver | 5 个 | sel 8 是假信号 |
| AppleSEPKeyStore | 170 个 selector | 全负 |
| AppleAVD | 全部 NotPrivileged | 参数是硬件寄存器索引/长度，非用户数据 |
| AVE / AVE2 | — | `AVE-DOS-FINAL.md`：只能自伤 DoS，读取点全是日志形态 |
| AppleH16NeuralANE | — | CoreML 阻断 IO 路径 |
| IOSkywalkFamily | 108 个改动函数 | 全部 `+1 指令`（清 object+8 的 bit 8，非原子 RMW），dChk 全 0 |
| FontParser / CoreText / Model I/O | — | 已审 |
| 内核网络栈 | 159 候选 | `KERNEL-137-TRIAGE.md`：仅 2 处真实补丁，**均非内存破坏** |
| 内核 27 个强信号 | 已分类 | 只有 2 个真新增原子指令、1 个越界写（即 §2） |

### 3.1 entitlement 门：已静态证伪

`out/ENT-MAP.md`：**没有任何一个 `NotPrivileged` selector 只靠一个 `com.apple.developer.*` 就能解锁。**

- `developer.gpu-restricted` 落在 IOSurface client `[+0x127]`，而 `sel 30` 卡的位是 `[+0x122]` —— **不是同一个位**
- `codesign` 实测**不丢弃也不校验**未知 entitlement（57/57 读回），**闸门在 install 的「⊆ 描述符」**
- ⇒ `com.apple.private.*` 进不了分发描述文件，install 必拒

### 3.2 若干曾被当成结论、后来被推翻的东西

见 `out/RECORD-CORRECTIONS.md`（6 条）与 `out/TOOLING-PITFALLS.md`（5 个工具坑）。其中最重要的两个：

1. **`IOConnectCallMethod` 的输出参数是 in/out**，`scalarOutputCount`/`structOutputSize` 是**精确匹配**的派发键 —— 太大 `C2`、太小 `C7`。这一条曾导致「大量 selector 不存在」的系统性假阴性。
2. **`kdiff` 类检测器只数对保留/释放辅助函数的 `bl`**，**内联 `casa`/`casl` 完全不可见** —— `KERNEL-UAF-SIG.md` 的「新增 retain/release 函数 0 个」是检测器盲区，不是事实。§2 的那个越界写正是靠形态检测才被看见。

---

## 4. 最后实验：为什么没跑通（诚实交代）

三次上机尝试，**全部失败在我们自己的 harness bug 上**，不是假设被否证。

| 次数 | 结果 | 根因 |
|---|---|---|
| 1 | A 阶段全失败、C2 崩 | `0x1000000A` = **`MACH_SEND_INVALID_RIGHT`**（脚本把它错标成 `MACH_MSG_OVERDUE`，导致方向判断偏移）；C2 `EXC_GUARD/ILLEGAL_MOVE` 是对同一 port name 二次 `MOVE_SEND_ONCE` |
| 2 | 同一处崩 | 首次调用就 trap（EXC_GUARD 是信号不是错误码，`break` 拦不住） |
| 3 | 设备掉线，无数据 | CoreDevice 连接失效，设备 `unavailable` |

**已修但未经真机验证**：
1. `m.d.disposition = MACH_MSG_TYPE_COPY_SEND`（SDK 的 LP64 结构里该字段位于 `address` 之后的位域组中，一直被忽略；默认 0 = `MOVE_SEND`，第一次发送即消费掉权限）
2. `N > gPoolN` 时跳过并记录（端口池可能建不满，NULL name 触发 `INVALID_RIGHT`）
3. 失败立即 break

**唯一有效的阴性数据**：阶段 B（同一接收端口累积 K=8/64/512/4096 条不接收）`qkr=0`，**未触发**。

**panic 计数全程 5 → 5，从未出现过内核 panic。**

---

## 5. 距离目标还有多远（直答）

```
S1 用户态代码执行   ✅ 已有（dev 签名直接给）
S2 内核内存破坏     ❌ 唯一候选见 §2，可控性三条全未证
S3 内核地址泄漏     ❌ 17 轮从未拿到过任何内核 VA
S4 沙箱逃逸         ⬜ 未开始
S5 代码签名绕过     ⬜ 未开始（TXM）
S6 持久化           ⬜ 未开始
```

**§2 这条线索要变成可用的原语，还差三步，每一步都可能失败：**

1. **容器容量能否被用户输入顶满** —— 容量编码在 `port+0x68` 的 PAC 指针位域里，来源未定
2. **越界目标是否可控** —— 越界量固定 +16 字节（恰好一格），落在容器之后
3. **写入内容 `x3|x2` 的可控度** —— `x3` 是常量 3，`x2` 是端口指针 ⇒ 写的是「端口指针|tag」

**注意**：容器满时 `str w1,[x10,#8]` 会写地址 `0x8`，**必然 panic**。
所以这条路的第一个现象是内核崩溃而不是静默破坏 —— 既是坏消息（容易被发现），
也是好消息（**panic 本身就是「到达容量上限」的精确探针**）。

---

## 6. 若要继续，从这里接

1. 恢复设备连接，跑 `harness/oolprobe/run.sh`（三处 bug 已修），观察 A 阶段 `send` 是否变 0
2. 若 A 通了且无 panic → 用 panic 作探针，逐步二分容器容量
3. 若 A 仍报新错误码 → 需要重写 OOL 消息构造（对照 SDK 的 LP64 位域布局逐字段核对）
4. 若要验证网络栈那条归属，查 `nat464_translate_64` 的 `b.hs`/`b.lo` 之后是否有 `str`

---

## 7. 文件索引

| 文件 | 内容 |
|---|---|
| `out/KERNEL-OOB-WRITE.md` | §2 这条线的全部细节、反汇编、CVE 归属冲突（§15） |
| `out/ENT-MAP.md` | entitlement 门静态证伪 |
| `out/MFB-CONTRACT.md` | 47 个 MFB selector 契约 |
| `out/SVC-REENUM.md` | 8 个服务的真实 selector 数 |
| `out/RECORD-CORRECTIONS.md` | 6 条被推翻的旧结论 |
| `out/TOOLING-PITFALLS.md` | 5 个会制造假阴性的工具坑 |
| `out/KERNEL-STRONG27.md` | 27 个强信号的分类与假信号案例 |
| `harness/oolprobe/` | 最后实验的完整代码（已修，未验证） |
