# IOMobileGraphicsFamily 派发表地图

> ⚠ **第 6 条已作废**：真机实测 MFB/CLCD2 调 `0x83308b0` 的第 6/7 条全是 `BadArgument`，
> 而在用表是 `0x832fd70`（同 s=6 返回 `kIOReturnNoPower`，说明 handler 真的跑了）。
> 所以「wildcard ⇒ 不校验 ⇒ 可达」这一步不成立，wildcard 行得另找可达服务。
> 保留本文件是因为 92 条表结构本身仍有参考价值，但**不要把 wildcard 那节当作可达面**。

> 来源：`out/kc.27.0.1.full` 双 stride + 同 kext + `__TEXT_EXEC` 严格判据扫描
> 可达性：`IOMobileFramebuffer` type 0 **真机实测可开**；`AppleCLCD2` type 0 **真机实测可开**
> 状态：静态完成，**等真机 selector 探测结果对照**

## 0. 一句话

92 条派发条目里，**7 条 wildcard（其中 2 条四个字段全 wildcard = IOKit 完全不校验）**，
另有 **3 条输入结构 ≥1.7 KB（最大 32776 字节）**。这是一个可达、未校验、大输入的面。

## 1. 三张表

```
0xfffffe000832fd70   59 条   [__DATA_CONST]
0xfffffe00083308b0   29 条   [__DATA_CONST]
0xfffffe00083307c0    4 条   [__DATA_CONST]
合计                 92 条
```

## 2. wildcard 条目（IOKit 层不做尺寸校验）

| 表内序号 | handler | sIn | stIn | sOut | stOut | wildcard 字段 |
|---|---:|---:|---:|---:|---|---|
| 6 | `0xa17e264` | W | W | W | W | **全部四个** |
| 7 | `0xa17e35c` | W | W | W | W | **全部四个** |
| 13 | `0xa17e438` | W | W | 0 | 0 | sIn + stIn |
| 14 | `0xa17e684` | 0 | W | 1 | 0 | stIn |
| 27 | `0xa17e774` | 0 | W | 1 | 0 | stIn |
| 28 | `0xa17e714` | 0 | W | 0 | 0 | stIn |
| 2 | `0xa17e804` | 1 | W | 0 | 0 | stIn |

`W = 0xFFFFFFFF`

**`[6]`/`[7]` 四个字段全 W**：IOKit 的 `IOExternalMethodDispatch` 校验对这两条**完全跳过**，
尺寸完全由 handler 自己决定怎么用。

## 3. 大输入结构条目

| 表内序号 | handler | stIn | 说明 |
|---|---|---:|---|
| 3 | `0xa17f6d4` | **32776** | 32 KB + 8 |
| 17 | `0xa17eb38` | **3084** | ~3 KB |
| 5 | `0xa17ddd0` | **1760** | 1.7 KB |
| 56 | `0xa17e13c` | 156 | |
| 3 | `0xa17f66c` | 136 | 同序号不同表 |
| 55 | `0xa17ef24` | 72 | |
| 21/23 | `0xa17e4b8`/`0xa17e57c` | 20 | |
| 44 | `0xa17f44c` | 16 | |
| 43/12 | `0xa17f3f8`/`0xa17ef68` | 4 | |

**全部 `stOut = 0`** ⇒ 纯输入型 handler，只读不写。

## 4. 为什么它曾经看起来值得打（已被真机否定，见文件头）

1. ~~真机可达~~ → **已否**：类能开，但那 7 条 wildcard 不在在用表上
2. **IOKit 层不校验**：7 条 wildcard，其中 2 条四字段全 wildcard
3. **输入巨大**：32 KB 结构交给 handler 解析，内部偏移/长度字段一旦被当下标用就是 OOB
4. **未审计**：`out/S2-NOW.md` 记分板里这一行的原语栏是「未证」，且没有任何 handler 级审计产物
5. **安全相关**：framebuffer / 显示管线在沙箱外，是提权链的合理目标

## 5. 下一步（等设备空闲）

真机逐个调用这 7 条 wildcard + 3 条大输入结构的 selector，记录 `kr`：

- 返回 `0xE00002C7 Unsupported` ⇒ 该序号不在这个 client 的面上
- 返回 `0xE00002C2 BadArgument` ⇒ 进了校验层，需要调参数
- 返回别的码 ⇒ **真的进了 handler**，有戏

然后对「真的进了 handler」的那几个做内容 fuzzing（`harness/kfuzz/main.m` 已就绪，
只需把这批目标加进表里）。
