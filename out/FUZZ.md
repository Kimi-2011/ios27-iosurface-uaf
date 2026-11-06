# 真机视频解码 Fuzzer（AppleAVE2 / AppleAVD）

## 状态：基础设施可用，未发现崩溃

## 一、架构
```
种子生成（AVAssetWriter 现场编码 H.264）
   ↓ AVAssetReader 取出压缩样本（AVCC 长度前缀 + NAL）
   ↓ 结构化变异（解析 NAL 边界，只改载荷，保留长度前缀）
   ↓ 8 线程并行，每线程独立 VTDecompressionSession
   ↓ VTDecompressionSessionDecodeFrameWithOutputHandler
   ↓ 回调统计 decoded / frameerr，每秒落盘进度
   ↓ pymobiledevice3 apps pull 拉回 + 检查崩溃日志
```

## 二、关键工程结论（踩坑记录）
| 问题 | 原因 | 解决 |
|---|---|---|
| app 20 秒被杀 | `0x8BADF00D` **启动看门狗**（未调 UIApplicationMain） | 改成正规 UIKit app，可长期前台运行 |
| 400/400 帧错误 | 10 帧拼接当一帧送 | 逐帧送 |
| 循环 0 次 | `CMBlockBufferCreateWithMemoryBlock(NULL)` 失败 | 用 `kCFAllocatorNull` 直接引用缓冲区 |
| `CFRetain` 崩溃 | 格式描述为 NULL 未判空 | 判空 |
| 只统计入队成功 = 空转 | 缺解码回调 | 加 `VTDecompressionSessionDecodeFrameWithOutputHandler` |
| 通过率 0.36% | 随机翻转打到 NAL 长度前缀 | 解析 AVCC 边界，只改载荷 → **0.76%** |

## 三、吞吐实测
```
8 线程：约 24,000 次/秒（约 8600 万次/小时）
600 秒跑完：12,524,968 次迭代
```
最新一轮（结构化变异）：359 秒 / 7,193,720 次 / decoded=1322

## 四、瓶颈与未解决的问题
`decoded` 在启动后几秒内就停止增长（1322 后不再增加），说明：
- **10 个种子帧过于同质**（同一段视频连续帧）
- 变异后基本都落在"必然非法"区域
- 无覆盖率反馈

## 五、代码
`harness/vfuzz/main.m`（单文件，含种子生成、变异器、多线程执行、进度落盘）

## 六、若要继续
1. 多种子池（不同分辨率/QP/运动/slice 类型/多帧 GOP）+ 成功样本回灌
2. SPS/PPS 定向变异（需重建 format description）
3. H.264 / HEVC / AV1 多编码器覆盖
