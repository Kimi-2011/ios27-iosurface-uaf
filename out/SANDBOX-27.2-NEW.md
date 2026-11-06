# sandbox kext 那 11.9KB 到底是什么（已查清）

## 提问
27.2 的 `com.apple.security.sandbox` 比 27.0.1 大了 **+11,904 字节**，这 11.9KB 是什么？

## 定位：全在 __TEXT（策略数据），不是代码
| 段 | 27.0.1 | 27.2 | 差 |
|---|---|---|---|
| __TEXT | 2,064,258 | 2,076,170 | **+11,912** |
| __TEXT_EXEC | 239,908 | 240,428 | +520 |
| __LINKEDIT | 471,081 | 471,697 | +616 |

函数数量几乎不变（**659 → 658**），所以增长不是新代码，而是
**__TEXT 里的沙箱策略/服务名数据**。

## 内容：标识符级差分（3897 → 3922，新增 43 / 消失 18）

### 真正新增（非改名）
```
com.apple.imageio.atx  /  com.apple.imageio.png   ← ImageIO 按格式区分的沙箱操作名
kTCCServiceMotionSensors                           ← 新 TCC 隐私服务（运动传感器）
com.apple.developer.home
com.apple.developer.upi-device-validation          ← 新 entitlement
com.apple.matter.framework.xpc / com.apple.matter.native.xpc
com.apple.appledepthd
com.apple.iond.output
com.apple.settingsagent
com.apple.trustdFileHelper
com.apple.generativesearch.server.salientpostings
com.apple.corepersonalization.server.graphEmbedding
com.apple.corespeech.corespeechd.endpointer.service
com.apple.Carousel.CSLSDetentService / .alertSuppression
com.apple.HomePodDisplayService.xpc
com.apple.ScreenTimeSettingsAgent.public
com.apple.ValidUpdater
com.apple.appmanagedfeatures.configuration
com.apple.deviceconfigurationd.consumer
com.apple.diagnosticextensionsd.session-debug
com.apple.linkd.application-service
com.apple.manageddeviced.managed-apps
com.apple.siriactionsd.xpc
com.apple.siri.embeddedspeech.speechmaintenanced
com.apple.uikit.viewservice.com.apple.QuickboardViewService
com.apple.EligibilityQuorum.com.apple.AudioIntelligence
```

### 消失
```
com.apple.hid.PencilHaptics                 ← HID 服务从策略里移除
com.apple.STExtractionService.privileged
com.apple.healthcontentd
com.apple.diskimagesiod.
com.apple.AudioIntelligence                 → 并入 EligibilityQuorum.*
com.apple.QuickboardViewService             → 并入 uikit.viewservice.*
com.apple.tailspin.{augmentationserver,symbolicationserver} → 合并为 com.apple.tailspin.
com.apple.cloudkit.audience-provider.com.apple.family → 改为 ...com.apple.
com.apple.private.GenerativeAgentsTransport.runtime.
```

## ⚠️ 更正我之前的一个误报
先前我列出的「新增」
`/System/Library/Frameworks/SystemConfiguration.framework/deprecated-get-network-info`
**在 27.0.1 里就已存在**（实测两版都有）。

误报原因：我的标识符正则要求首字符为字母，带前导 `/` 的路径串被漏匹配，
于是 27.2 侧匹配到、27.0.1 侧没匹配到，造成"新增"假象。
**教训：字符串差分必须对两版使用同一套提取规则并交叉验证。**

## 结论
这 11.9KB **不是漏洞修复**，是沙箱策略的服务名/entitlement 调整：
- 大量是**改名**（Quickboard、AudioIntelligence、tailspin、cloudkit audience）
- 真正新增的是：**matter 框架服务、ImageIO 按格式操作名、appledepthd、新 TCC（MotionSensors）、两个新 entitlement**
- 移除的是：**PencilHaptics HID 服务、STExtractionService.privileged**

安全含义：**隐私/权限面收紧**（运动传感器需授权、HID 服务被移除），
不是内存破坏类修复，无法转成 PoC。
