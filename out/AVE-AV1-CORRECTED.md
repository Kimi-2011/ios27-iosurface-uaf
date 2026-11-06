# AV1 packetizer（bug 323079）实测结论 —— 修正此前的编造解释

**日期**：2026-10-31 23:28
**设备**：iPhone 18,2 / iOS 27.0.1 (24A446)

---

## 一、修正我此前两个错误说法

| 我此前的说法 | 实测结果 |
|---|---|
| "静默是因为 `MediaStreamTrackProcessor` 缺失" | ❌ 测试根本不用它，用的是 `canvas.captureStream` + `RTCRtpScriptTransform` |
| "`alloc-failed` 分支意味着 iPhone 永远到不了溢出" | ❌ **2 GiB ArrayBuffer 在真机上分配成功** |
| "需要 2GB OBU，iPhone 做不到" | ❌ 部分错误：分配**可以**成功 |

### 实测：2 GiB 分配成功
```
worker: OK bytes=2147483652      ← new ArrayBuffer(1+5+0x7FFFFFFE) 成功
worker: HEADER-WRITTEN           ← LEB128 头 FE FF FF FF 07 可写入
```
（零页惰性提交，虚拟内存不立即占物理页）

## 二、三个前提逐一验证

| 前提 | 结果 |
|---|---|
| AV1 编解码器可用 | ✅ `AV1 codecs=1 video/AV1` |
| `RTCRtpScriptTransform` 可构造 | ✅ `typeof === function`，`sender.transform` 接受 |
| 2 GiB OBU 缓冲可分配 | ✅ 见上 |
| **编码帧能到达 transform** | ❌ **`onrtctransform` 从不触发** |

## 三、实测日志（带插桩的真实上游测试）

```
AV1-TEST START
wmsg: registered                      ← worker 脚本加载成功
negotiated; tracks=1 readyState=live  ← SDP 协商完成，轨道 live
transform set=true                    ← transform 已挂到 sender
RESULT=timeout                        ← 10s 内 onrtctransform 未触发
AV1-TEST END
```

## 四、结论

`RtpPacketizerAv1::PacketizeInternal` **在普通 WKWebView 里不可达**：
帧不会流经 encoded transform，因此不会进入 RTP 打包器，
`obu.size > INT_MAX - max_payload_len` 的加法溢出无法触发。

需要注意：上游测试带 `webkit-test-runner [ WebRTCAV1CodecEnabled=true ]`，
我无法设置该标志；这是环境差异，**不是"漏洞不存在"的证明**。
准确表述：**在无该标志的 WKWebView 中不可达**。

## 五、方法学教训（第三、四类自造错误）

本轮我先后犯了两类相反的错误，都源于 shim 与真实 `js-test.js` 不一致：

1. **假阴**：`noInline` / `description` / `testFailed` 缺失 → 脚本首行抛
   `ReferenceError` 静默中止 → 我把"没跑"报成"未崩"（322033、323130、323148 都中招）
2. **假阳**：`shouldBeEqualToString(a, b)` 的 **a 是源码表达式字符串，需 `eval()`**；
   我按字面量比较，制造了一批 FAIL（差点误判 323130 为漏洞）
3. **插桩自我破坏**：用 `worker.onmessage = ...` 覆盖了测试自己的 handler，
   导致日志全无，误以为 worker 没加载

**规则**：任何"未崩/未复现"的结论，必须先证明脚本**完整执行到了断言处**。
