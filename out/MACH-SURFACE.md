# 真机 Mach 服务攻击面（iOS 27.0.1 / uid=501 沙箱 app）

## 方法
自签 app（无私有授权）调用 `bootstrap_look_up`，遍历 4805 个 `com.apple.*` 候选名
（来源：kernelcache 字符串 + AppCryptex plist）。得到发送权即视为可达。

## 结果
**295 个服务可达**（占候选的 6.1%）。

对比之前的 IOKit 面：327 个类里只有 **5** 个能 `IOServiceOpen`。
**Mach 服务才是真正的主攻击面。**

## 高价值目标（按"处理不可信输入"筛选）

| 服务 | 为什么值得看 |
|---|---|
| `com.apple.TextInput` 系列（6 个） | 键盘/输入法，解析输入法与文本数据 |
| `com.apple.ABDatabaseDoctor` | 通讯录数据库，解析外部数据库文件 |
| `com.apple.GameController.gamecontrollerd` | HID 输入解析 |
| `com.apple.Safari.SafeBrowsing.Service` | 处理网络返回数据 |
| `com.apple.MobileFileIntegrity` | 文件完整性校验，解析签名数据 |
| `com.apple.FSEvents` | 文件系统事件 |
| `com.apple.PowerManagement.control` | 电源管理，IOKit 相关 |
| `com.apple.DeviceAccess.xpc` | 设备访问 |
| `com.apple.MobileAccessoryUpdater` | 配件固件更新，历史高危 |
| `com.apple.CoreAuthentication.daemon` | 认证 |

完整列表：`out/device/mach-services.txt`（295 行）

## 为什么这一步有价值
1. 越狱链的第一跳绝大多数落在 Mach 服务上，而不是 IOKit user client
2. 这些服务的实现体在加密系统卷里，**无法做静态差分**——只能靠真机动态测试
3. 我们已经有可复用的真机循环（改码→签名→装→跑→拉结果，2–3 分钟/轮）

## 下一步（按顺序）
1. **消息级探测**：对 295 个服务逐个 `xpc_connection_create` + 发送最小合法消息，
   记录"拒绝/接受/崩溃"——筛出真正处理消息的子集
2. 对筛出的子集做结构变异 fuzz（XPC 字典键值、长度、嵌套深度）
3. 崩溃样本 → 归因到服务 → 判断是否有安全边界意义

## 校准：entitlement 对可达集的影响（实测）

同一二进制、两种签名配置：

| 配置 | 可达数 |
|---|---|
| 完整 distribution profile（HealthKit/VPN/NFC/Siri/system-extension） | 295 |
| 最小集（application-identifier + team-id + keychain-access-groups） | **290** |

差集（5 个），每项对应一个 entitlement：
| 服务 | entitlement |
|---|---|
| `com.apple.nfcd.service.corenfc` | `com.apple.developer.nfc.readersession.formats` |
| `com.apple.callkit.networkextension.voip` | `com.apple.developer.networking.networkextension` |
| `com.apple.siri.vocabularyupdates` | `com.apple.developer.siri` |
| `com.apple.group-activities.conversationmanagerhost` | Group Activities |
| `com.apple.DriverKitAppServer` | `com.apple.developer.system-extension.install` |

**结论**：证书类型（distribution vs development）本身不影响；起作用的是 profile 的 entitlement 集合。
`get-task-allow` 只影响调试。免费个人证书的 entitlement 更窄 → 大概率是 290 或更少。
**290 是普通第三方 app 的基线。**

## 消息级探测结果（空字典探测，2.0 秒完成 290 个）

| 结果 | 数量 | 含义 |
|---|---|---|
| REPLY | **59** | 建连、收消息、返回字典 —— 真正可交互 |
| CONN-INTERRUPTED | 197 | bootstrap 可见但连接被服务侧拒绝（entitlement 门控） |
| TIMEOUT | 34 | 建连成功但 40ms 内无响应 |

### 59 个可交互服务

```
com.apple.DeviceAccess.xpc
com.apple.airplay.endpoint.xpc
com.apple.analyticsd
com.apple.cfprefsd.daemon
com.apple.cfprefsd.daemon.system
com.apple.containermanagerd
com.apple.containermanagerd.system
com.apple.coremedia.capturesession
com.apple.coremedia.capturesource
com.apple.coremedia.endpointremotecontrolsession.xpc
com.apple.coremedia.figvirtualcapturecard.xpc
com.apple.coremedia.mediaparserd.formatreader.xpc
com.apple.coremedia.mediaparserd.mutablemovie.xpc
com.apple.coremedia.mediaplaybackd.asset.xpc
com.apple.coremedia.mediaplaybackd.assetcacheinspector.xpc
com.apple.coremedia.mediaplaybackd.assetimagegenerator.xpc
com.apple.coremedia.mediaplaybackd.audioprocessingtap.xpc
com.apple.coremedia.mediaplaybackd.bytestream.xpc
com.apple.coremedia.mediaplaybackd.cpe.xpc
com.apple.coremedia.mediaplaybackd.customurlloader.xpc
com.apple.coremedia.mediaplaybackd.figcpecryptor.xpc
com.apple.coremedia.mediaplaybackd.figmetriceventtimeline.xpc
com.apple.coremedia.mediaplaybackd.formatreader.xpc
com.apple.coremedia.mediaplaybackd.mutablecomposition.xpc
com.apple.coremedia.mediaplaybackd.player.xpc
com.apple.coremedia.mediaplaybackd.remaker.xpc
com.apple.coremedia.mediaplaybackd.samplegenerator.xpc
com.apple.coremedia.mediaplaybackd.sandboxserver.xpc
com.apple.coremedia.mediaplaybackd.videocompositor.xpc
com.apple.coremedia.mediaplaybackd.videoqueue
com.apple.coremedia.mediaplaybackd.videotarget.xpc
com.apple.coremedia.mediaplaybackd.visualcontext.xpc
com.apple.coremedia.routediscoverer.xpc
com.apple.coremedia.routingcontext.xpc
com.apple.coremedia.routingsessionmanager.xpc
com.apple.coremedia.sandboxserver.xpc
com.apple.coremedia.sts
com.apple.coremedia.systemcontroller.xpc
com.apple.coremedia.videocodecd.decompressionsession.xpc
com.apple.coremedia.volumecontroller.xpc
com.apple.coresymbolicationd
com.apple.cvhwa.xpc
com.apple.dasd.end-prewarm
com.apple.dnssd.service
com.apple.itunesstored.xpc
com.apple.mediaexperience.endpoint.xpc
com.apple.mediaexperience.systemmediacastingcontroller.xpc
com.apple.mobileassetd.v2
com.apple.mobilemail.services.xpc
com.apple.modelmanager
com.apple.nehelper
com.apple.pluginkit.pkd
com.apple.securityd
com.apple.seserviced.passkit-extensions
com.apple.spotlight.IndexAgent
com.apple.spotlight.SearchAgent
com.apple.symptoms.symptomsd.managed_events
com.apple.tccd
com.apple.trustd
```

### 34 个超时（可能只是慢）

```
com.apple.ABDatabaseDoctor
com.apple.Music.MPMusicPlayerControllerInternal
com.apple.UIKit.statusbarserver
com.apple.VoiceOverTouch
com.apple.VoiceOverTouch.xpc
com.apple.accessibility.gax.backboard
com.apple.asktod
com.apple.backgroundassets.user
com.apple.commcenter.mobile-helper
com.apple.devicemanagementclient.managedappsd
com.apple.dockaccessoryd
com.apple.dt.testmanagerd.uiprocess
com.apple.fairplayd
com.apple.fairplayd.versioned
com.apple.hangtracerd
com.apple.hid.PencilHaptics
com.apple.iap2d.xpc
com.apple.iapd
com.apple.iphone.axserver-systemwide
com.apple.locationd.spi
...
```

### 高价值目标

- `com.apple.coremedia.mediaparserd.formatreader.xpc` —— **媒体格式解析**，直接吃攻击者数据
- `com.apple.coremedia.videocodecd.decompressionsession.xpc` —— 视频解码会话
- `com.apple.coremedia.mediaplaybackd.*`（十余个）—— 播放管线各环节
- `com.apple.containermanagerd` / `securityd` / `tccd` / `trustd` —— 安全关键
- `com.apple.mobileassetd.v2` —— 资源下载解析

**35/59 属于媒体/编解码** —— 与之前发现的 AVE2 改动方向一致，但这里是用户态服务，攻击面更大。
