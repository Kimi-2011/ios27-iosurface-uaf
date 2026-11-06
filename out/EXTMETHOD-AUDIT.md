# 外方法面审计（iOS 27.0.1）

## ⚠ 撤回声明（2026-11-01 第 6 轮，本次修订）

**本文档第 2.1 节的「越界写命中 0」结论已撤回。**

撤回理由：该数字来自一个**从未通过校准**的检测器。

```
校准方法  取 stOut != 0 的 1346 个条目（handler 必然使用 structureOutput）
          要求检测器在其中命中的比例显著大于 0
实测      0 / 1346  = 0.0%
结论      检测器零灵敏度，其「stOut==0 组命中 0」不含任何信息
```

两次修正尝试均失败：
1. 单步 `mov` 跟踪 —— `mov x19,x2` 后失联
2. 指针污点（`ldr Rd,[args,#0x58]` → 追踪写） —— 仍未命中
   真实原因是 handler 常把输出指针交给 `memcpy` 一类的被调函数，本检测器不跟 `bl`

**因此：本文档只能确认「表结构已枚举完」，不能确认「越界写不存在」。**

---

# 以下为原始记录（结论部分已作废，数据保留）

## 0. 原文的一句话（作废）

**1965 个外方法入口中，`structOut==0` 却写 `structureOutput` 的有 0 个。** ← 作废，见上


## 1. 方法

1. 全 `__DATA_CONST` 扫 stride-40 条目：字段 0 是指向 `__TEXT_EXEC` 的 chained 指针，
   字段 1 的两个 32 位半字都 ≤ 0x10000。连续 ≥4 条即判为一张派发表。
2. 自检：已知表 `0x137bcb8`（含 `wrapA`）必须被检出，实测通过。
3. 逐条解码 `(scalarIn, structIn, scalarOut, structOut)`。
4. 对条目 handler 跟随 `b` 尾调用（深度 ≤4），判断是否访问
   `args->structureInput` / `args->structureOutput`。

## 2. 结果

```
派发表        242 张
入口总数      1965 个
structIn==0     1843 (93.8%)   <- 多数方法本就不用结构输入
structOut==0    1838 (93.5%)
```

### 2.1 越界写类别：`structOut==0` 且写 `structureOutput`

```
命中 0
```

**含义**：没有哪一个 handler 在「长度未校验」的情况下向 `structureOutput` 写入。
`structureOutput` 是内核按调用方声明的 `structureOutputSize` 分配的缓冲，
若 handler 固定写入超过该长度的数据即为内核堆溢出 —— **这一类在 27.0.1 不存在。**

### 2.2 越界读类别：`structIn==0` 且读 `structureInput`

```
命中 3
  com.apple.driver.AppleMSG                0x91c3f0c  (表 0x811b1e0 条目 15, 17)
  com.apple.iokit.IOMobileGraphicsFamily   0xa17e0f8  (表 0x832fd70 条目 53)
```

**可达性**：AppleMSG 为内核内部消息通道、IOMobileGraphicsFamily 为显示驱动，
**两者均不是沙箱 app 可直接打开的用户客户端**。IOSurface（app 可达）命中 0。

## 3. `IOExternalMethodArguments` 字段偏移（**从代码反推，非猜测**）

取自 IOSurface handler `0xa3492f4`（该条目声明 stIn=12 / stOut=3176）：

```
args+0x20  scalarInput          ldr x8,[x2,#0x20]; ldr w1,[x8]
args+0x30  structureInput       ldr x1,[x2,#0x30]
args+0x38  structureInputSize   ldr w3,[x2,#0x38]   (32 位)
args+0x58  structureOutput      ldr x8,[x2,#0x58]
args+0x60  scalarOutput         add x4,x2,#0x60
```

## 4. 工具坑

- **表条目 stride 是 40 字节，不是 `IOExternalMethodDispatch` 的 24**。
  按 24 检测会得到 0 张表（本项目实际发生过）。
- 判据必须是「字段 0 为 chained 指针 + 字段 1 两半都是小整数」。
  只要求「连续 8 字节都是指针」会把表判成 0 张。
- 过滤条件与结论标签要分开写。本项目一度只过滤 `structIn==0`，
  却把结果标成 `stOut=0`，产出了 16 个假候选。


## 6. 重做后的审计（第 7 轮，**检测器已校准**）

### 6.1 检测器

对 handler 跟踪「args 基址寄存器 + 偏移」的映射（`mov` 传播、`add Rd,Rs,#imm` 偏移、`b` 尾调用继承），
判定其是否访问 `args+0x58`（structureOutput）与 `args+0x60`（structureOutputSize）。

**校准（必须先过）**：
```
0xa3492f4  ->  {0x58, 0x60}   ✓ 与手工反汇编一致
```
前两次实现均校准失败（0/1346、0/1346），原因是：
1. 只跟踪单步 `mov`
2. 按逗号切分操作数，`[x2, #0x58]` 被切成 `['x8','[x2','#0x58]']`，方括号丢失

### 6.2 结果

```
全体 1965 条入口
  使用 structureOutput          94
  读取 structureOutputSize      60

stOut==0 的 619 条
  使用 structureOutput          21
  自校验 structureOutputSize    26
  用而不校验                    12   <- 目标集合
```

### 6.3 那 12 条

| kext | 条数 |
|---|---|
| `com.apple.iokit.IOMobileGraphicsFamily` | 7 |
| `com.apple.driver.AppleAVE2` | 5 |

### 6.4 可达性：**全部不可达**

实测本 app 的 44 项 entitlement 中，与 `ave / video / gpu / graphic / surface / hid / usb / ane / jpeg /
iokit / driverkit` 相关的**为 0 项**。

```
IOMobileGraphicsFamily   显示驱动，非公开用户客户端      不可达
AppleAVE2                硬件编解码，需私有 entitlement   不可达
IOSurface                公开服务，实测可开（sel17/sel18） 可达
  -> 但 IOSurface 落在「自校验」那一组（26 条里），不在 12 条里
```

> **结论：能达的那个 kext 没有这类问题；有这类问题的 kext 都到不了。**
> 这是可达性上的结构错位，不是遗漏。

### 6.5 那 5 条 AppleAVE2 的性质（若能达）

handler 形如：
```
mov x21, x2        ; args
mov w25, #8
mov w0, #0x51
mov w1, #8
bl  0x88485dc
```
派发表声明 `stIn=0 stOut=0`，handler 却使用 `args+0x58` 且不校验 `args+0x60`。

若调用方传入 `structureOutputSize=8` 以外的值，写固定长度即可越界。
**但 `structureOutputSize=0` 时 `structureOutput` 为 NULL（崩溃而非可控越界），
可控窗口只有 1..7 字节级，属极窄堆溢出。**

## 5. 上一轮新增的实证（有效部分）

反汇编 IOSurface handler `0xa3492f4` 及其尾调用目标 `0xa34bc34`，得到**未加猜测的字段语义**：

```
handler 0xa3492f4:
  ldr x1, [x2, #0x30]     ; x1 = structureInput 指针
  ldr x8, [x2, #0x58]     ; x8 = structureOutput 指针
  ldr w3, [x2, #0x38]     ; w3 = structureInputSize
  add x4, x2, #0x60       ; x4 = &structureOutputSize
  mov x2, x8
  b   0xa34bc34

callee 0xa34bc34:
  cbz x2, ret             ; 输出指针非空
  cbz x1, ret             ; 输入指针非空
  cmp w3, #0xc            ; structureInputSize 必须 == 12
  b.ne ret
  ldr w8, [x4]            ; w8 = structureOutputSize
  cmp w8, #0xc68          ; 必须 == 3176
```

**⇒ 两个结论：**

1. **`args+0x30` = structureInput, `+0x38` = structureInputSize,
   `+0x58` = structureOutput, `+0x60` = structureOutputSize**（由代码定，非猜测）
2. **handler 自己在入口处重新校验了两个长度**
   （`cmp w3,#0xc` 与 `cmp w8,#0xc68`），不依赖派发表。

**第 2 条意味着：即使派发表声明 `structOut==0`，handler 也可能自带长度校验。
所以「`stOut==0` ⇒ 危险」这个前提本身就不成立，本审计的整个判据需要重做。**

## 7. 覆盖范围限制（第 8 轮，必须先说清）

本审计**只覆盖用 `IOExternalMethodDispatch` 表的 user client**（242 表 / 1965 入口）。
有些 kext **一张表都没有**，它们用**手写 selector switch**（IOSurface 的 sel17/sel18 就是这种，
已实测「数据槽 0」）。这些**完全在本审计之外**。

按候选服务的静态统计：

| kext | 表 | 入口 | 输入不校验 | 输出不校验 |
|---|---:|---:|---:|---:|
| IOMobileGraphicsFamily | 4 | 82 | 3 | 7 |
| IOSurface | 10 | 86 | 0 | 0 |
| AppleAVE2 | 3 | 48 | 5 | 5 |
| AppleSPU | 8 | 60 | 0 | 0 |
| AppleH16ANEInterface | 7 | 58 | 0 | 0 |
| IOHIDFamily | 2 | 14 | 0 | 0 |
| AppleJPEGDriver | 1 | 10 | 0 | 0 |
| AppleM2ScalerCSCDriver | 2 | 8 | 0 | 0 |
| **IOGPUFamily** | **0** | **0** | — | — |
| **IOSurfaceAccelerator** | **0** | **0** | — | — |
| **IOUSBHostFamily / IOBiometricFamily / AppleH13CamIn / AppleCLCD** | **0** | **0** | — | — |

**⇒ 零表的 kext 说明它们不走派发表，本审计对它们没有任何结论。**
**而 `IOGPUFamily` 恰恰是通过 Metal 可达的那一个。**

**下一阶段的正确目标是「手写 switch 的 user client」，不是继续在 1965 条里翻。**
