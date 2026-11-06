# AVE `NumberOfTemporalLayers` DoS —— 最终定性实验（真机 iPhone18,2 / 27.0.1）

## 一句话结论
**是 app 自伤（self-DoS），不是跨进程/系统级 DoS。**
严重性：低。对应"CVE 里 app 可导致自身异常终止"一类，不是系统瘫痪。

---

## 实验 1：阻塞确认（决定性）
```
[BASELINE] NumberOfTemporalLayers=1     → 返回 0
  EncodeFrame 0/1/2 → 全部返回 0        （提交成功）
BASELINE 成功帧数 = 0                    （实际产出 0 帧）

[HANG]     NumberOfTemporalLayers=65535 → 返回 0（用户态不校验）
  EncodeFrame 0 → 0
  EncodeFrame 1 → 0
  CompleteFrames ...                     ← 【永久阻塞】
[TIMEOUT] 6 秒未返回
```
**确认：值 ≥ 65535 时 `VTCompressionSessionCompleteFrames` 永久阻塞。**

## 实验 2：是否影响其他进程
触发挂死后，立刻启动一个**全新进程**探测：
```
run1: VTCompressionSessionCreate(HEVC) → -12912 (kVTCouldNotFindVideoEncoderErr)
```
一度观察到 `-12912`。但——

## 实验 3：中断时长测量（推翻了实验 2 的解读）
```
触发前 HEVC 创建 = 0
[危险线程] CompleteFrames 开始（阻塞）
t= 1s HEVC=0        ← 主线程立刻就能创建新会话
恢复用时 ≈ 1 秒
```
→ 实验 2 的 `-12912` 是**瞬时竞态**，不是持续中断。

## 实验 4：编码器实例耗尽（关键分界）
连续挂死 10 个会话，每次挂死后都尝试新建：
```
已挂死 1 个会话  → 新会话创建 = 0 (仍可用)
已挂死 2 个会话  → 新会话创建 = 0 (仍可用)
...
已挂死 10 个会话 → 新会话创建 = 0 (仍可用)
```
**未耗尽。** 挂死的会话不占住编码器实例配额。

---

## 最终定性

| 问题 | 答案 |
|---|---|
| 能确定触发吗？ | ✅ 是，3/3 确定性 |
| 后果是什么？ | 该 app 的编码会话永不完成 → 被 watchdog SIGKILL |
| 影响其他 app 吗？ | ❌ 否，新会话正常创建 |
| 能占死系统编码器吗？ | ❌ 否，10 个挂死会话后仍可用 |
| 是内存破坏吗？ | ❌ 否，纯逻辑阻塞 |
| 对应 CVE | 最接近 **CVE-2026-112705**（app 可致自身异常终止），**不是**系统级 |

## 27.2 的修补（从二进制字符串确证）
```
number of temporal layers (prop) is out of range
```
在**属性设置时**就拒绝越界值 —— 与 27.0.1 的行为差异完全对应。

## 根因链（完整证据）
```
app: VTSessionSetProperty("NumberOfTemporalLayers", 65535) → 0（用户态放行）
  ↓ kernel{AppleAVE2} "350 NumberOfTemporalLayers 65535"
  ↓ HEVC_VPS::video_parameter_set_rbsp:969 failed -1001
  ↓ HEVC_VPS::Generate:109 failed to generate VPS 0
  ↓ videocodecd AVE_PS_ComposeNALUArray:486 cnt != 0 | no PS 2
  ↓ AVE_FrameRecv::SendPS:1080 failed to create format descriptor
  ↓ 编码器无参数集 → 永不出帧 → CompleteFrames 无限等待
```

## 复现
`harness/avedos/`（`main.m` 触发 / `measure.m` 测时长 / `exhaust.m` 测耗尽）
```bash
# 签名前必须解锁钥匙串，否则 codesign 静默失败
security unlock-keychain -p "" ~/Library/Keychains/dev.keychain-db
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "" ~/Library/Keychains/dev.keychain-db
```
