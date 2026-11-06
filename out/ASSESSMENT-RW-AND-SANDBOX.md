# 能否从当前进度走到任意读写 / 沙箱逃逸？—— 直接结论

**日期**：2026-10-31 22:30
**结论**：**走不到。** 不是"再挖挖就行"，是这条路线有三个结构性障碍。

---

## 一、已跑完的全量扫描结果

对 27.2 安全公告中 32 个 WebKit/WebRTC bug，逐个定位修复提交与回归测试：

| 状态 | 数量 | 说明 |
|---|---|---|
| 有提交 + 纯 JS 可跑 + **真机崩溃** | **2** | 321669（确定性 UAF）、322743（竞态） |
| 有提交 + 纯 JS 可跑 + 无崩溃 | 4 | 323130、323148（WebGPU）、322033（JSC）、323079（AV1，见下） |
| 有提交但需 `testRunner`/`$vm`/`Internals` | 3 | 322120、318331、323079(部分) |
| 有提交但无测试 | 2 | 322916、323173 |
| **窗口内找不到任何提交** | **21** | 含 328129（沙箱逃逸）、328141（JS Bindings）等最新一批 |

## 二、三个结构性障碍

### 障碍 1：已确认的 UAF 形状不适合利用

```
m_builder.destroy(*existingPseudoElement);      // 释放匿名块 wrapper
// ← 中间无 JS 执行点
m_builder.attach(renderer, move(pseudoElement), beforeChild);   // 使用已释放指针
```

free 与 use 在**同一个 C++ 调用链内同步完成**。竞态那个（322743）虽有跨线程窗口，
但如果预期的 `WebCodecsEncodedVideoChunkStorage` 槽被重新占用，也只是让编码器
**读**到受控数据（潜在信息泄露），不是写。要变成任意写入需要额外的工程。

### 障碍 2：形状对的 bug 全部被环境门槛挡住

| 候选 | 形状 | 实际门槛 | 结论 |
|---|---|---|---|
| 321608 陈旧 IC watchpoint | 🔥 悬垂 `JSObject*` → 类型混淆 | 需 `$vm.gc()` + `--forceEagerCompilation` | ❌ 无 `jsc` shell |
| 319303 陈旧 IC 访问器 | 🔥 陈旧 getter | 需 `$vm.toCacheableDictionary()` | ❌ 同上 |
| 323079 AV1 堆越界读 | 🔥 信息泄露 | 需 ~2GB OBU（整数溢出条件 `obu.size > INT_MAX - max_payload_len`） | ❌ iPhone 分配不出 |
| 321872 Worker 启动 UAF | 🔥 跨线程窗口 | 2000 个 SharedWorker 未命中；且不在 27.2 列表（27.0.1 已修） | ❌ |

真机诊断证据：
```
RTP 能力: video/AV1 ✅   RTCRtpScriptTransform ✅   AV1 编码器 ✅
MediaStreamTrackProcessor = undefined
```
能力都在，但 AV1 测试走不通是因为整数溢出条件要求 2GB 分配——补丁自己也写明
「only enable the test for sar3 as it may crash otherwise」（仅在 Mac 上启用）。

### 障碍 3：最有价值的那批 bug 没有公开修复提交

27.2 的 32 个 bug 里 **21 个**在 5000 次提交窗口内找不到修复提交，包括：

- **328129** —— "break out of Web Content sandbox"（沙箱逃逸）
- **328141** —— JS Bindings
- **328131 / 328132 / 328114** —— WebKit 内存安全

原因：Apple 的安全修复常先落私有分支，公开发布滞后数周。
**没有补丁 = 没有回归测试 = 没有现成 PoC**，这套"从公开修复提交反推 PoC"的方法
对这批 bug 完全失效。

## 三、要到任意读写，实际需要什么

真机上要打通，缺的不是"再找几个 UAF"，而是：

1. **一个不需 `$vm`/`testRunner` 的 JSC 类型混淆**
   —— 这是 WebContent R/W 唯一现实的出口。必须在纯 JS 下可控触发。
2. **或一个 free/use 跨任务边界的 WebCore UAF**
   —— 中间要有完整 JS 执行窗口才能堆喷。
3. **或越狱** —— 拿到 `jsc` shell 后 321608/319303 这类 stale IC 立刻可测。

沙箱逃逸（328129 类）**必须在 1 或 2 成功之后**才谈得上，且它本身还需要一个
独立的 IPC/Process Model 漏洞。

## 四、诚实的进度定性

| 已达成 | 未达成 |
|---|---|
| ✅ 2 个真机确认的 WebContent 内存破坏 bug | ❌ 任意读写原语 |
| ✅ 其中一个 19/19 确定性复现 | ❌ 信息泄露原语 |
| ✅ 根因与官方补丁逐帧对应 | ❌ 沙箱逃逸 |
| ✅ 完整的方法论与工具链（批量扫描器） | ❌ 代码执行 |

**当前成果的性质**：一套经过验证的"WebKit 安全修复 → 真机 PoC"流水线，
产出 2 个确认漏洞，其中 1 个确定性。这是扎实的漏洞研究产出，
但距离利用链还差一个**可用原语**，而那个原语目前被环境门槛挡着。
