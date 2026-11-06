# 更高效的差分方法（已落地）

## 问题
逐个函数反编译对照太慢：2273 个改动函数，人工读一天也看不完，且多数是功能变更。

## 方法阶梯（从便宜到贵）

| # | 方法 | 成本 | 产出 |
|---|---|---|---|
| 1 | **字符串集合差分** | 10 秒 | 直接指出被打补丁的子系统 |
| 2 | 新增串按 kext 聚类 | +5 秒 | 排优先级 |
| 3 | 热点 kext 的"形状全新函数" | 10 秒 | 定位重写过的解析器 |
| 4 | 只反编译 3–5 个大改函数 | 5 分钟 | 看到具体校验 |
| 5 | 真机 selector 扫描 | 2 分钟 | 判断可达性 |
| 6 | 等 Apple 安全说明 | 零成本（等外部） | CVE→组件的权威映射 |

## 已跑出的结果（1–3 步）

27.0.1 → 27.2：**新增字符串 3457 条，其中 215 条是诊断类**。

按 kext 聚类（新增串数）：
```
1623  com.apple.filesystems.tmpfs
 243  com.apple.kernel
 202  com.apple.driver.AppleH16ANEInterface
 141  com.apple.security.sandbox
  62  com.apple.driver.AppleAVE2        ← 视频编解码
  45  com.apple.driver.AppleMobileDispH18P-DCP
```

### AppleAVE2（最有价值的新线索）
新增诊断串全是**码流解析的越界校验**：
```
HEVC VPS num_add_layer_sets is out of range
HEVC SPS count is out of range
HEVC RPS count is out of range
AVC PPS count is out of range
AVC log2_max is out of range
AV1 MCTF strength count out of range
... （共 62 条）
```

意义：**AVE 是 app 可达的**——任何 app 都能通过 VideoToolbox 解码 attacker 提供的 HEVC/AVC 码流。这比 ANE（要授权）、KeyStore（功能变更）有价值得多。

形状分析：AVE2 里 **34 个函数的指令形状在 27.2 完全变化**（新写或大改），最大 12305 条指令。

## 结论
之前"逐函数挖"的路子效率极低。字符串差分一步就把方向从"猜"变成"看"。
下一步只需反编译 3–5 个最大的形状变化函数，就能看到新增校验的具体位置。
