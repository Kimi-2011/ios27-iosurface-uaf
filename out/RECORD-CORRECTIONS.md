# 项目记录更正（2026-11-01，本会话）

> **必读**。以下六条旧结论已被真机实验推翻，根因绝大多数是同一个工具误用。
> 后续任何一轮开工前先看这份，避免在错的基线上继续推。

## 根本原因：`IOConnectCallMethod` 的输出参数是 in/out

```c
// 错误（前两轮全部这么写的）
IOConnectCallMethod(c, sel, NULL,0, NULL,0, NULL, NULL, NULL, NULL);

// 正确
uint64_t so[16]; size_t soc = 16;      // 预填容量
uint8_t  st[4096]; size_t sst = 4096;  // 预填容量
IOConnectCallMethod(c, sel, NULL,0, NULL,0, so, &soc, st, &sst);
```

**后果不是「输出为空」，而是：**

```
(0,0)  ->  该 selector 从派发键里被直接抹掉  ->  返回 0xE00002C7 Unsupported
       ->  看起来「这个 selector 不存在」
```

**派发键包含输出维度。** 传 0 等于告诉内核「我不要输出」，于是派发器认为该 selector 不存在。

## 被推翻的六条

| # | 旧结论 | 出处 | 实测 | 根因 |
|---|---|---|---|---|
| 1 | AGX 14 个 SUCCESS selector **零字节回吐** | `GPU-PROBE.md` / `GPU-DUMP.md` | `sel 1 @ (0,64)` 回吐 ASCII **"AGXG18P"**；`sel 16` → `0x2739e190` | (0,0) |
| 2 | AGX `sel 55` **handler 永不返回（挂死）** | `GPU-PROBE.md` | 只有 `(0,0)` 挂 3 s；给标量输出容量后立刻返回 | (0,0) |
| 3 | `AppleM2ScalerCSCDriver` **只有 1 个 selector** | `M2SEL11-OPCODE.md` | **12 个（0–11）** | (0,0) |
| 4 | M2Scaler `sel 11` 是**空 external method** | `M2SEL11-OPCODE.md` | 有界 copyout，`sc=664` 字节，内核真的写 | 输出容量外形判断错 |
| 5 | `IOMobileFramebuffer` / `AppleCLCD2` 各 **10 个** selector | `SVC2-PROBE.md` | **各 47 个**（且逐条一致） | (0,0) |
| 6 | `SVC2-PROBE.md` 的「27 SUCCESS / 23 distinct、零 hexdump」 | 同文件 | 同一类假阴性；该文件已加作废声明 | (0,0) |

## 第二个易犯的坑：C7 判据不是万能的

```
表驱动（缺失行返回 0xE00002C7）   -> C7 判据有效
   AppleM2ScalerCSCDriver（表 0–11）
   AGXAcceleratorG18P type 1（表 0–55）

手写 switch（未知 selector 返回 0xE00002C2 BadArgument） -> C7 判据退化
   IOSurfaceRoot / AGX type 33 / IOHIDEventService
   AppleJPEGDriver / IOMobileFramebuffer / AppleCLCD2
```

在手写 switch 服务上，「0..N 每个 selector 每组容量都返回 C2」
会被误读成「256 个 selector 全部存在」——**零信息量**。

**正确判据**：返回码**离开 C2** 才算 handler 真的跑了。

## 第三个坑：连接前置状态

`AGX sel 19 / sel 42` 在全新连接的第一发返回 `BadArgument`，
按 A 表顺序预热（`0,1,2,3,4,5,16,17,…`）后才 `SUCCESS`。
**不预热会低估可用 selector 数。**

## 第四个坑：`devicectl copy from` 会取回陈旧文件

隧道抖动（`Device disconnected during socket operation (10002)`）时，
`copy from` 可能成功返回**上一次**的 ndjson。
**必须在输出里写 `@meta`（含本次请求的 svc/type），取回后校验，不匹配就丢。**

## 当前真实 selector 面（替代所有旧数字）

| 服务 | type | selector 数 | 列表 |
|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 0 | **12** | 0–11 |
| `AGXAcceleratorG18P` | 1 | **56** | 0–55（56–255 全 C7） |
| `AGXAcceleratorG18P` | 33 | **2** | 0, 2（均 NotPrivileged） |
| `IOSurfaceRoot` | 0 | **7** | 19, 30, 32, 36, 37, 38, 45 |
| `IOHIDEventService` | 2 | **3** | 0, 1, 2 |
| `AppleJPEGDriver` | 0 | **5** | 0, 2, 4, 5, 9 |
| `IOMobileFramebuffer` | 0 | **47** | 与 CLCD2 逐条一致 |
| `AppleCLCD2` | 0 | **47** | 同上 |

**来源**：`out/SVC-REENUM.md`（726 行，8 个服务全覆盖，panic 5→5）。

## 未触发停机条件

全库 dump **0 个 8 字节对齐的 `0xfffffe...`**，0 个 PAC 形态。

三个「像地址」的标量输出待定性（已派 MFB-CONTRACT 任务）：
```
IOSurfaceRoot sel 32       -> 0x0000000102c48000
IOMobileFramebuffer sel 77 -> 0x00000030aec27220
AppleCLCD2 sel 77          -> 0x00000030b8f8b1a8
```

---

## 第五个坑：`soc` 是精确匹配的派发键，**给少了给多了都失败**

同一个坑的两面：

```
给少（(0,0)）     -> selector 从派发键里被抹掉 -> 0xE00002C7 Unsupported  （看起来"不存在"）
给多（表里写 0，你给 1） -> 精确匹配失败       -> 0xE00002C2 BadArgument  （看起来"调不动"）
```

实测（`out/SEL32-PAGE.md` §5）：MFB/CLCD2 的 12 个纯动作型 selector
（12/13/19/22/26/31/33/51/53/56/81/88，派发表里 `oc=0`）如果传 `soc=1`，
**全部 `BadArgument`**，看起来像"这些 selector 调不动"；改成 `soc=0` 后 **25/25 全绿**。

**规则**：`scalarOut` / `structOut` 的容量**必须严格等于派发表声明的值**，
不是"至少"，也不是"预填够大就行"。

## 因此：MFB 47 个 selector 的完整正确姿势

```
纯动作型（派发表 oc=0，sc=0）        -> (soc=0, sst=0)
返回 1 个标量（oc=1）                -> (soc=1, sst=0)
sel 56（stIn=156）                   -> (soc=0, sst=0, sti=156)
```

**`sst` 在 MFB 上全部为 0**——25 个成功 selector 里没有一个需要 structOut。

## 新增的两条契约（此前只知道"存在"）

| selector | 契约 | 返回 |
|---|---|---|
| `IOSurfaceRoot 19` | `(sin=0, sti=64, soc=0, sst=0)` | `kr==0` |
| `IOSurfaceRoot 36` | `(sin=1, sti=0, soc=2, sst=0)` | `kr==0`，写回 2 个标量 |

`sel 36` 的 v0 四次为 `0x4cc3 / 0xa433 / 0x8423 / 0x7a1b`：**<0x10000、非单调、非时钟、未定性**。
`sel 37/38/45` 在 300 组网格里 **0 次 `kr==0`**。

## SEL32-PAGE 的结论（已收敛）

`IOSurfaceRoot sel 32` 返回的 16 KiB 只读页 **永不填充**：

```
6 个独立进程、1382 次整页比对（全走 vm_read_overwrite）、2683 发内核调用
nz>0 = 0 次   changed>0 = 0 次   first 恒 -1
1388 页落盘字节 sha256 全等于 16384 个 0x00 的 sha256 (4fe7b59a…)
```

覆盖：12 组 `IOSurfaceCreate` + 锁定 + 全局往返（`kIOSurfaceIsGlobal` + `Lookup`）、
`sel 19/36/37/38/45` 各 60 组 300 发、MFB/CLCD2 25×2 全绿、8 个 user client。

**每进程一页、进程内所有连接共享同一 VA**（8/8 同 VA）；跨进程 VA 各不相同（9 个不同值无重复）。

⇒ **固定占位 mapping，不构成 kernel→user 通道。本线关闭。**
