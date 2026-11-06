# AVE 属性校验缺失 —— 当前最强线索的结算

> 前置：`out/AVE-REACH.md`（真机实验）、`out/AVE2-PATCH-LOCATED.md`（27.2 检查函数定位）
> 本文件只做结算：**什么已证、什么未证、下一步唯一值得做的实验**

## 1. 已经证明的四件事

### 1.1 AVE 对普通 app 真实可达（内核日志实证）

```
app  ->  videocodecd (ave.videoencoder 插件)  ->  kernel{AppleAVE2}
```

证据：抓 `syslog live` 同时跑属性扫描，`videocodecd{ave.videoencoder}[457]` 打出了
`AVE_Prop_HEVC_SetNumberOfTemporalLayers:6111`。**调用链完整，不是推断。**

这与「`AppleAVE2Driver` 的 user client type 0..255 穷举打不开」不矛盾——
打不开的是**直接 IOKit 通道**，而属性是走媒体栈转发进内核的。

### 1.2 `NumberOfTemporalLayers` 在 27.0.1 上无上界

真机扫描（带真实编码）：

```
=0     -> -12900（用户态拒）
=1     -> 0  编码成功
=255   -> 0  编码成功
=1024  -> 0  编码成功
=65535 -> 0  编码成功    ← 内核照单全收
=-1    -> -12900
```

内核日志里只有 **2 条**错误（对应 `0` 和 `-1`），**`65535` 一条都没有**。

### 1.3 27.0.1 只检查下界，27.2 才加上界

用户态插件里的断言是 `iNumberOfTemporalLayers >= 1`——**只有下界**。

27.2 新增字符串：
```
number of temporal layers (prop) is out of range %d %d %d
```
**`(prop)` 明确指属性** ⇒ 这条就是给 `NumberOfTemporalLayers` 补的上界。

### 1.4 这一批 27.2 新增的 AVE 越界检查共 20 条

```
HEVC VPS vps_max_layers_minus1 / layer_id_in_nuh / num_add_layer_sets
          layer-set total / highest_layer_idx_plus1 sum / extension layer-OLS counts
HEVC PPS / SPS / RPS count
HEVC log2_max_pic_order_cnt_lsb_minus4 (max %d)
MCTF strength count / iRefNum / temporal layers (prop)
AVC log2_max / AVC PPS count
```

27.0.1 原有 34 条同类，**这 20 条是新增的**。

## 2. 已证伪 / 卡住的

- ❌ **app 不能直接注入原始 VPS/SPS/PPS 字节**：19 个候选属性键全部 `-12900`。
  只有 `UserParameterSetsIds`（ID 列表）和 `NumberOfTemporalLayers` 两个未公开属性可用。
  ⇒ 那批 `HEVC VPS ... out of range` 的输入源**不是** app 提供的码流。
- ❌ **字符串无法映射到函数**：27.2 新串 `0xfffffe0007304fda` 在 kernelcache 里
  **绝对地址 0 命中、chained 指针 0 命中**。AVE 的日志是运行时按 ID 建表，
  静态无法从串反查代码。
- ❌ **属性派发表不是扁平指针数组**：在 `com.apple.driver.AppleAVE2` 全数据段扫
  「连续 ≥0x110 个指向 text 的指针」，**0 张**。

## 3. 未证的关键一环

**`65535` 进入内核后没有被立即使用。** 设置极端值后编码正常、无 panic。

可能的三种解释（未区分）：
1. 值被存起来但只在特定分支才用（需要 temporal scalability 开关）
2. 需要配合每帧 `temporalLayerId` attachment 才会索引该数组
3. 真正危险的是**分配**而非索引，`65535 * sizeof(x)` 只是分配失败

## 4. 下一步唯一值得做的实验

**让 `65535` 真正被使用**，而不是只被存起来：

1. 设 `NumberOfTemporalLayers = 65535`
2. 打开 temporal scalability（`kVTCompressionPropertyKey_...` 相关开关）
3. **对每一帧用 `kVTEncodeFrameOptionKey_...` 指定 `temporalLayerId`**，
   逼编码器按该维度分配/索引
4. 同时试「小 NumberOfTemporalLayers + 大 temporalLayerId」这个反向组合
   ——**后者更容易命中「按 idx 索引固定大小数组」**
5. 全程抓 `syslog live` 里的 `kernel{AppleAVE2}` 日志（这是免 KDK 的符号预言机）

**判据**：出现新 panic / 新 AVERR 行 / 编码器 hang，任一即是进展。

## 5. 为什么这条比前 14 轮所有线索都强

| 维度 | 前 14 轮的靶子 | AVE 这条 |
|---|---|---|
| 可达性 | 能开但不一定进 handler | **内核日志证明进了内核函数** |
| 靶子来源 | 我自己猜哪里可能有 bug | **Apple 自己的补丁指出来缺检查** |
| 用户可控性 | 参数常常被校验 | **65535 实测无阻进入内核** |
| 是否有已知缺失 | 无 | **27.2 明确补了这条上界** |

**这是唯一一个「已知缺检查 + 已证可达 + 已证用户可控」三者同时成立的组合。**

---

## 6. 差分已全部过完，AVE2 是唯一剩下的（本会话结算）

按用户提醒「很多差分都已经做了一遍了」，改为**只读既有结论、不重做差分**。汇总：

| 组件 | 改动函数 | 强信号 | 有无新增边界检查 | 可达性 | 结论 |
|---|---:|---:|---|---|---|
| `com.apple.kernel` | 449 | 8 个候选 | 1 个 CAS 所有权协议（竞态/UAF） | 部分 | 已三角筛选，候选 `0x40969fc` |
| **`AppleAVE2`** | **31** | **有** | **✅ 20 条新增越界检查** | **✅ 内核日志实证** | **主攻** |
| `IOSkywalkFamily` | 108 | **0** | **❌ 无** | 未实证 | 本会话关闭，见 §7 |
| `AppleAVD` | 6 | — | ❌ 修在用户态 | — | 关闭 |
| `IOStorageFamily` | 21 | — | ❌ 内联访问器 | — | 关闭 |
| `IOAudioCodecs` | 9 | — | ❌ 用户态为主 | — | 关闭 |
| `IOHIDFamily` | 45 | — | 需外接 HID | — | 关闭 |
| `IOUSBHostFamily` | 61 | 有候选 | 需恶意 USB 设备 | — | 关闭 |

**⇒ AVE2 是「有新增边界检查 + 可达性已实证 + 用户可控已实证」三者唯一的交集。**

## 7. IOSkywalkFamily 关闭理由（本会话实测）

用现成 `tools/kdiff_all.py` 跑：

```
函数 2166 -> 2166，代码 +276 字节
配对改动 108；强信号 0、位置迁移 6、弱信号 102
布局平移 delta: -1008
```

**108 个函数形态完全一致**：`168→172 (+15/−14)` 或 `308→312 (+16/−15)`，净 +1 条指令。

手工读了 `0xfffffe000a2ea4ec → 0xfffffe000a338794` 的实际差异：

```asm
- ldr x10,[x9]            + ldp x12,x19,[x9]
- ldr w10,[x10,#0x20]     + ldp w11,w10,[x9,#0x10]
- cmp w10,#1              + ldr x9,[x9,#0x18]
- b.ne ...                + ldr x13,[x9,#8]
- ldr x10,[x9,#0x18]      + and x13,x13,#0xfffffffffffffeff   <<< 清 bit 8
- ldr x11,[x10,#0x10]     + str x13,[x9,#8]                   <<< 写回
- cmp x11,#1              + ...
```

**判读**：真实逻辑改动 = **清对象 `+8` 处的 bit 8（in-flight/busy 标志）**，
批量套用到 108 个函数。这是「统一在错误路径清标志」类重构，**不是新增边界检查**。

附带观察：`ldr / and / str` 是**非原子读-改-写**，同一字段若有并发访问，这个"修复"本身留了竞态窗口。

**可达性**：`IOSkywalkFamily` 属 Skywalk 包处理栈，走 `utun` / NECP / 无线驱动。
「app 联网即触达」这个说法**未实证**——普通 app 建 socket 走的是 BSD socket 层，
不等于进了 Skywalk。**不满足「可达性已证」门槛，不投入。**
