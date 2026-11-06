# 用户态二进制获取方案调研（iOS 27.0.1 → 27.2 补丁差分）

> ## ⭐ 结论已变（2026-10-31 12:00 更新）
> **AEA 加密被离线解开。A / B / C 三条线全部不再是必要条件。**
> 直接从 iOS IPSW 里取 `Cryptex1,SystemOS` / `OS` 的 `.dmg.aea`，
> 用 Apple 自带的 `/usr/bin/aea` + 一个公开 CDN 上的私钥，**十几秒解出 APFS 明文**，
> 得到真机 arm64e 原版二进制。详见 **§D1b**，新增工具 `tools/aea_unlock.py`。
>
> 已实测拿到密钥（都验证过 `base64url(sha256(pubkey)) == URL id`）：
> - iOS **27.0.1 (24A446)** `Ap,ExclaveOS` → 完整解密 + 挂载成功
> - iOS **27.2 (24B119)** `OS`（9.26 GB）→ 密钥 `97d90647cf3777a75e7977df2fce83ea8ff31e1258049fe09027780400fd1ab0`
> - iOS **27.2 (24B119)** `Cryptex1,SystemOS`（2.25 GB）→ 密钥 `6c856166116bc7010f1d24f2b9cc2c5ff77c6959ee300ba7f3b550bcd2adbc99`

- 日期：2026-10-31
- 目标：拿到 **iOS 27.2 (24B119)** 与 **iOS 27.0.1 (24A446)** 的用户态框架
  （ImageIO / WebKit / CoreText+FontParser / ModelIO / CoreMedia / CoreGraphics）
  的可读、可符号化二进制，用于函数级差分
- 本文所有"证据"都是本机实测输出，非引用

---

## 0. 结论速览

> **最重要的一条：AEA 已破解（离线）。** 见 §D1b。
> 直接从 iOS IPSW 取 `.dmg.aea`，用 `/usr/bin/aea` + 公开 CDN 上的私钥 + HPKE 解封，
> 0.24 秒拿到 APFS 明文。**这是当前最优路线，其余全部降级为备选/交叉验证。**

| 路线 | 可行性 | 能拿到什么 | 状态 |
|---|---|---|---|
| **D1b. iOS IPSW → `aea decrypt`** | **高（已实测）** | **真机 arm64e 原版**框架，明文 APFS | ✅ 已验证解密+挂载 |
| A. macOS 27.2 InstallAssistant | 中（冗余） | 桌面版框架 | 直链已解析，**不再需要** |
| B. iOS 模拟器运行时 | 中高（冗余） | arm64 / IOSSIMULATOR，符号完整 | 存在但被 Xcode 27 卡住，**不再需要** |
| C. 真机运行时转储 | 高（已验证） | `__TEXT`+函数边界+导出符号；**本地符号被 redact** | 已跑通，可作交叉验证 |

**当前唯一瓶颈是下载量，不是技术：**
6 个目标里 5 个（ImageIO / CoreText / CoreGraphics / ModelIO / CoreMedia / libFontParser）
在 **基卷 `OS`（9.26 GB）**，WebKit / JavaScriptCore 在 **`Cryptex1,SystemOS`（2.25 GB）**。
→ 建议直接下完整 IPSW（13.15 GB/版本），两版本 ~25 GB，约 40 分钟。

# A. macOS 27.2 二进制的其他/更快途径

## A0. 先纠正一个前提：慢不是 Apple 限速，也不是代理

**结论：** `softwareupdate --fetch-full-installer` 慢的真因是 **`swcdn.apple.com` 的落点差 + 单连接被限速**。
本机确实跑着 Clash Verge（mihomo TUN），但 **Apple 流量走的是 DIRECT，没有过机场**。

**证据：**

```
$ ifconfig utun0 ; netstat -rn -f inet | head
utun1024: ... inet4-address 198.18.0.1/30        # fake-ip TUN
2/7  198.18.0.1  UGSc  utun1024
4/6  198.18.0.1  UGSc  utun1024      ...          # 全 IPv4 都灌进 TUN
$ ps aux | grep mihomo
root  682  ... /Library/Application Support/clash-verge-service/cores/verge-mihomo ...
$ dig +short swcdn.apple.com
198.18.0.126                                      # fake-ip，说明 DNS 被劫持进 TUN
```
关键在规则表（`curl --unix-socket /var/run/clash-verge-service/users/501/verge-mihomo.sock http://localhost/rules`，共 67 条）：

```
 29 Domain       developer.apple.com          -> 慈善机场
 41 DomainSuffix blobstore.apple.com           -> 慈善机场
 50 DomainSuffix cdn-apple.com                -> DIRECT
 56 DomainSuffix apple.com                    -> DIRECT     <-- swcdn / swscan / updates.cdn-apple 命中这条
 66 Match                                     -> 慈善机场
```
`swcdn.apple.com`、`updates.cdn-apple.com` 都命中第 56 条 → **DIRECT**。

真正的瓶颈，同一时段对照测量：

| 端点 | 并发 | 实测 |
|---|---|---|
| `swcdn.apple.com` | 1 流 | **1.00 MB/s** |
| `swcdn.apple.com` | 8 流 range | 4.6 MB/s |
| `swcdn.apple.com` | 32 流 range | **14.2 MB/s** |
| `swcdn.apple.com` | 48 流 range | 6～10 MB/s（抖动） |
| `updates.cdn-apple.com` | 1 流 | **10.5 MB/s** |

`swcdn` 的响应头暴露了落点：`X-Responding-Server: protocol_d200:...:mcnode0343.usprz22.pie.apple.com`
（`usprz` = 美国节点）。所以：**是 `swcdn` 选了远节点且按连接限速**，`updates.cdn-apple.com` 好得多。

**可执行步骤（提速）**
1. 能走 `updates.cdn-apple.com` 的（IPSW）就走它，单流就够快。
2. 只有 `swcdn` 有的（InstallAssistant.pkg），用**多连接分段**下载 —— 见 A2 的 `pget.py`。
3. 不要试图"关掉代理提速"：Apple 本来就没走代理。真要动，应该在 mihomo 里给
   `apple.com` 系列加**指定落地节点的策略组**，但实测把 32 路并发打开就够用了，改配置收益小、风险大（会影响整机网络）。

---

## A1. `softwareupdate --fetch-full-installer` 的替代

**结论：** 放弃它，直接用 sucatalog 解析出的 CDN 直链 + 多连接下载。**快 10～15 倍**。

`softwareupdate` 的实测速率约 4 MB/分钟 ≈ 68 KB/s（用户侧观测）。同一条链路用 curl 单流就有 1 MB/s，32 路并发 14 MB/s。

---

## A2. 从 sucatalog 取 InstallAssistant.pkg 直链（已验证）

**结论：** 已完整打通，并**顺带拿到 macOS 27.0.1 的直链**，可以做版本严格对齐的差分。

### 步骤 1：catalog 地址（唯一可用的一条）

```bash
curl -sO 'https://swscan.apple.com/content/catalogs/others/index-27-26-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog'
# 7,056,575 bytes，IndexDate 2026-10-30T23:46:31Z
```
> 注意：`index-27.sucatalog`、`index-26.sucatalog`、`index-15.sucatalog`、`index-1.sucatalog` **全部 404**。
> 只有上面这条长名字的 merged catalog 是活的。gibMacOS 用的就是这一条。

### 步骤 2：从 `Packages[].Size` 反查 product id

`softwareupdate --list-full-installers` 报 macOS 27.2 是 `17389792 KiB` = **17,807,147,008 B**，
和 catalog 里 `142-50055` 的 `InstallAssistant.pkg` 的 `Size` 字段 **17,807,147,403 B** 对得上
（差值来自 KiB 取整）—— 这就是把 `--list-full-installers` 的行和 product id 对上的可靠方法。
catalog 里没有 `Build` 字段，`ExtendedMetaInfo` 只有 `InstallAssistantPackageIdentifiers`，
真正的人类可读版本号在 `Distributions.English` 指向的 `.dist` XML 里（`versStr="27.2"`）。

### 步骤 3：解析结果（2026-10-26 发布的三个 macOS 全量包）

| product id | 产品 | 版本 | InstallAssistant.pkg |
|---|---|---|---|
| `142-50013` | macOS Sequoia | 15.8.2 | — |
| **`142-50055`** | **macOS 27 Golden Gate** | **27.2 (26B123)** | **17,807,147,403 B** |
| `142-50020` | macOS Tahoe | 26.7.2 | — |
| **`142-27367`** | **macOS 27 Golden Gate** | **27.0.1 (26A434)** | ← 同一 catalog，做基线用这个 |

parse 脚本要点（可直接复用）：

```python
import plistlib, json, urllib.request, re
d = plistlib.load(open('cat.sucatalog','rb'))
for pid, p in d['Products'].items():
    if 'InstallAssistant.pkg' not in json.dumps(p, default=str): continue
    dist = (p.get('Distributions') or {}).get('English')
    vers = re.search(r'versStr="([^"]+)"', urllib.request.urlopen(dist).read().decode()).group(1)
    print(pid, vers, p['ExtendedMetaInfo']['InstallAssistantPackageIdentifiers']['SharedSupport'])
```

### 步骤 4：直链（已验证 HTTP 200 + Content-Length 正确）

```
https://swcdn.apple.com/content/downloads/52/46/142-50055-A_O5SYDX5BLY/c72meffi1hj2eaf9fgtakkgwds73ujrr5u/InstallAssistant.pkg
Content-Length: 17807147403        Server: nginx   Accept-Ranges: bytes
```
> **不需要 Apple ID、不需要 session、不需要 notarization 头。** 这条 URL 直接 `curl` 就能下。

### 步骤 5：多连接下载器 `tools/pget.py`（本次新增）

```bash
# 断点续传，幂等，可反复执行
python3 tasks/ios27-chain-poc/tools/pget.py URL OUT --threads 48 --chunk-mb 64
# 用之前必须先验证（重要，见下面的事故记录）
python3 tasks/ios27-chain-poc/tools/pget.py URL OUT --verify-samples 12    # rc=0 才可用
```
产物：`OUT`、`OUT.state`（已完成 chunk idx）、`OUT.coverage`（人可读的字节区间清单）。

自测（已验证）：
```
5,011,550 B 文件，8 线程  →  与 curl 全量下载 cmp 逐字节相同
--verify-samples 6        →  6/6 windows match
```

### 步骤 6：从 pkg 里只取 `SharedSupport.dmg`

`InstallAssistant.pkg` 是 xar。TOC 在文件头，**不需要下完就能读**：

```bash
# xar header: 'xar!' + ... toc_length_compressed @ offset 8 (big endian)
# TOC 是 zlib 压缩的 XML，里面直接写着每个成员的 offset/length
```
实测 TOC（从只下到 40% 的文件里读出来的，说明包结构完好）：
```
SharedSupport.dmg   offset=14,737,926  length=17,792,404,141
PackageInfo         offset=14,737,441  length=453
Scripts             offset=14,736,796  length=645
Payload             offset=90,532      length=14,646,264
Bom                 offset=276         length=90,256
```
**含义：`SharedSupport.dmg` 就是整个包除去头部 14.7 MB。所以"只取 dmg"省不了空间，
但省掉了 xar/安装器解析：`dd if=pkg of=SharedSupport.dmg bs=1 skip=14737926` 即可。**

挂载后是一条普通明文 APFS 卷，`/System/Library/Frameworks/` 下就是全部目标框架。

---

## A3. 有没有更小的增量包？

**结论：没有可用的。** 公开 catalog 里 macOS 27.2 只有全量包。

实测：把 merged sucatalog 里 2026-10-26 之后发布、总大小 < 8 GB 的 product 全列出来，只有 4 个：

```
142-16627  0.24GB   Safari27.2SequoiaAuto.pkg
142-16640  0.26GB   Safari27.2TahoeAuto.pkg
142-50017  0.57GB   BridgeOSBrain.pkg + BridgeOSUpdateCustomer.pkg
142-50405  0.53GB   CLTools_*                     （Command Line Tools）
```
- macOS 的 **delta / combo update 不走 sucatalog**，走 Pallas（`POST https://gdmf.apple.com/v2/assets`，
  `AssetType=com.apple.MobileAsset.SoftwareUpdate`）。抓下来的 catalog 有 2532 条 asset，
  **筛 `Build ∈ {26B123, 26A434, 25G332}` 命中 0 条** —— 该 catalog 不覆盖 macOS 大版本。
- 即便拿到 macOS 的 delta（通常 3～6 GB），**它也不含我们需要的框架明文**：
  delta 里的 payload 是 `bsdiff`/`xar` 补丁流，需要目标版本的原始文件才能还原，
  而原始文件正是我们缺的东西。**所以增量包对这个问题没有帮助，不是"更小的路"。**

**可行性评级：不可行（作为独立路线）。**

---

## A4. 事故记录：`InstallAssistant.pkg` 被判为"损坏"其实是我的工具缺陷

写进踩坑记录，因为它是本次唯一一次真实的方法论错误。

- 现象：下游校验在 11 个采样点里报 7 个 MISMATCH，`xar -xf` 解出的
  `SharedSupport.dmg` 开头是 EFI FAT32 扇区。
- 真因：`pget.py` v1 一启动就 `truncate(total)` 把文件撑到**全长**（17.8 GB），
  所以 **文件大小完全不能当完成信号**。校验时下载只到 40%（8.96 GB / 17.8 GB），
  下载前沿以上的区域读到的全是 0。
- 证据：
```
du -sh *.part                          -> 8.4G     （逻辑 17.8 GB，实际只落盘 8.4 GB）
ls -ls *.part   allocated=17557504     logical=17807147403
逐 4KB 采样非零字节数：
  offset            0 -> 4061     offset  1,000,000,000 -> 4075   （已下载）
  offset  7,000,000,000 -> 4061   offset 10,500,000,000 ->    0   （未下载，全零）
  offset 16,000,000,000 ->    0   offset 17,800,000,000 ->    0
```
  对上下游报的采样点：0 / 1.09 / 3.28 / 7.68 GB 全 OK（前沿以下），
  10.5 / 13.3 / 14.8 / 15.7 / 16.5 / 17.76 GB 全 MISMATCH（前沿以上），**分界线就是下载前沿，无一例外**。
  另外 xar 头部 magic `xar!` 与 TOC 都能正常解出，说明码流本身没问题。
- 修复（已落地）：新增 `OUTPATH.coverage`、`--verify-samples N`（随机窗口回源逐字节比对）、
  改名 `.part`→成品前强制 `os.fsync`、`chunks_done != total` 时绝不改名。
- **规则：`--verify-samples` 返回 rc≠0 之前，任何 `.part` 都不许喂给 `xar` / `hdiutil` / `dsc_extractor`。**

---

# B. iOS 模拟器运行时（重点怀疑项）

## B1. 本机 Xcode 与能装的运行时

```
$ xcodebuild -version
Xcode 26.6   Build 17F113
$ sw_vers
ProductVersion: 26.5.2   BuildVersion: 25F84
$ xcrun simctl runtime list
iOS 26.5 (23F77)      - AF256A90-... (Ready)
watchOS 26.5 (23T570) - EC965EDD-...
```

## B2. 是否存在 iOS 27.2 的模拟器运行时？

**结论：存在。** 从 Apple 官方 downloadable index 查实（这是 `xcodebuild` 自己用的那份 catalog）：

```
$ curl -sO https://devimages-cdn.apple.com/downloads/xcode/simulators/index2.dvtdownloadableindex
# 586,447 bytes, XML plist, 439 条 downloadables
```
> 这个 URL 是从 `~/Library/Caches/com.apple.dt.Xcode/Cache.db` 的 `cfurl_cache_response`
> 表里挖出来的（Xcode 自己请求过它），比自己猜路径可靠。

iOS 27.x 全部条目（节选）：

| simulatorVersion | build | 名称 | 大小 |
|---|---|---|---|
| 27.0 | `24A434` | iOS 27.0 Simulator Runtime | 8.05 GB |
| 27.1 | `24A94425` | iOS 27.1 Simulator Runtime | 7.85 GB |
| 27.2 | `24B114` | **iOS 27.2 Release Candidate** Simulator Runtime | 8.32 GB |
| 27.2 | `24B91016s` | iOS 27.2 Simulator Runtime | 8.32 GB |
| 27.2 | **`24B8117`** | **iOS 27.2 Simulator Runtime（正式）** | 8.32 GB |

条目字段（27.2 正式版那条）：
```json
{ "contentType": "cryptexDiskImage", "downloadMethod": "mobileAsset",
  "authentication": "none", "fileSize": 8321588736, "platform": "com.apple.platform.iphoneos",
  "simulatorVersion": {"buildUpdate": "24B8117", "version": "27.2"},
  "name": "iOS 27.2 Simulator Runtime", "architectures": ["arm64"] }
```

**注意版本对齐**：模拟器侧**没有 27.0.1**（真机是 `24A446`，模拟器只有 27.0 = `24A434`）。
所以 sim 侧基线只能是 27.0；`27.0 → 27.2` 的差分是 `27.0.1 → 27.2` 的**超集**。

## B3. 为什么 `xcodebuild -downloadPlatform` 下不了

**结论：Xcode 26.6 的 SDK 版本选不中这些条目。**

```
$ xcodebuild -downloadPlatform iOS -buildVersion 27.2 -exportPath /tmp/simrt
Finding content...
iOS 27.2 is not available for download.
```
对 `27.0 / 27.1 / 26.6 / 26.5` 逐一试，全部同一句（26.5 已安装所以也报"不可下载"，说明这句不代表"不存在")。

catalog 的 `sdkToSimulatorMappings` 说明了原因 —— 它按 **SDK build** 选 runtime：
```json
{"groupTag":"iphoneos-simgroup-sdk-24B8118","sdkBuildUpdate":"24B8118",
 "sdkIdentifier":"iphoneos27.2","simulatorBuildUpdate":"24B8117"}
```
需要 `iphoneos27.2` SDK（build `24B8118/24B113`）。本机是 `iPhoneOS26.5.sdk`。
**→ 路径 = 装 Xcode 27（或至少 iOS 27.2 SDK）后再 `xcodebuild -downloadPlatform iOS -buildVersion 27.2`。**

另一条路（未打通）：mobileAsset / Pallas 直取。已定位到 asset type，
但公开端点要么 403，要么需要 Apple 侧签名流程：

```
# 从 Xcode 里挖出来的 asset type（DVTFoundation 的 platformIdentifierToMobileAssetType 表）
com.apple.MobileAsset.iOSSimulatorRuntime

$ curl -s -o /dev/null -w '%{http_code}\n' \
  https://mesu.apple.com/assets/com_apple_MobileAsset_iOSSimulatorRuntime/com_apple_MobileAsset_iOSSimulatorRuntime.xml
403
$ curl -s https://gdmf.apple.com/v2/assets
{"Status":"400 Bad Request","Message":"GET request not allowed: /v2/assets","PallasNonce":"..."}
# POST 各种 body 组合都只拿到 400 + ES256 签名的错误体，没有 asset 列表
```
（`mesu.apple.com` 本身可达：`.../com_apple_MobileAsset_SoftwareUpdate/...xml` 返回 200 / 6.7 MB。）

**评级：中。** 卡点是"要 Xcode 27"，而 Xcode 27 需要 App Store / 开发者账号 ——
本机 `MobileMeAccounts` 里有已登录的 Apple ID（`761954797@qq.com`），但**没有存密码**，
无法无人值守安装。这一步需要人工在 App Store 里点一下。

## B4. 下载后的内容是否可读（用本机已有的 iOS 26.5 运行时实测）

运行时挂在 `/Library/Developer/CoreSimulator/Volumes/iOS_23F77/.../RuntimeRoot`，
目录结构与真机**完全一致**，连 `/System/Cryptexes/OS` 的 symlink 都在：

```
$ ls -ld .../RuntimeRoot/System/Library/Frameworks/WebKit.framework
lrwxr-xr-x  WebKit.framework -> ../../../System/Cryptexes/OS/System/Library/Frameworks/WebKit.framework
```

| 框架 | arch | platform | 大小 | **符号数** | cryptid |
|---|---|---|---|---|---|
| ImageIO | arm64 | IOSSIMULATOR | 8,723,680 | 29,868 | 0 |
| CoreText | arm64 | IOSSIMULATOR | 3,338,784 | 8,347 | 0 |
| CoreGraphics | arm64 | IOSSIMULATOR | 9,801,376 | 23,061 | 0 |
| ModelIO | arm64 | IOSSIMULATOR | 1,895,376 | 1,035 | 0 |
| CoreMedia | arm64 | IOSSIMULATOR | 2,536,640 | 12,769 | 0 |
| WebKit | arm64 | IOSSIMULATOR | 43,101,440 | 131,413 | 0 |
| JavaScriptCore | arm64 | IOSSIMULATOR | 35,680,112 | 46,459 | 0 |
| libFontParser（私有） | arm64 | IOSSIMULATOR | 4,117,344 | 13,175 | 0 |

- **`cryptid = 0`** → 明文，直接可读
- **符号表完整**（真机侧被 redact，见 §C3 —— 这是模拟器路线最大的优势）
- `codesign -dvvv` 显示 Apple 原签名完好（`Identifier=com.apple.WebKit`、`CDHash` 可校验）
- FontParser 的正确路径是 `/System/Library/PrivateFrameworks/FontServices.framework/libFontParser.dylib`

## B5. 与真机的差异有多大？

**结论：这个问题的答案取决于你怎么用，分三种情况：**

**(1) 不要做"模拟器 vs 真机"的差分 —— 那是错的。**
- 模拟器：`LC_BUILD_VERSION platform = IOSSIMULATOR`、**arm64**、无 PAC
- 真机：`platform = IOS`、**arm64e**、全指令流带 pointer authentication

两种 ISA 混着比，指令级差异会被 PAC 指令淹没，没有意义。

**(2) 但"模拟器 27.0 vs 模拟器 27.2"的差分是干净的。**
两边同为 arm64/IOSSIMULATOR/同一 SDK 家族，**arm64e 的问题根本不进入差分**。
这是 B 线真正的价值：它不是"近似真机"，它是**一个自洽的差分对象**。

**(3) 有一个必须避开的坑：模拟器的 dyld 共享缓存是"本机现建"的。**
```
$ ls /Library/Developer/CoreSimulator/Caches/dyld/
25F84/                                                    <- 用宿主 macOS build 号做 key
$ ls .../25F84/com.apple.CoreSimulator.SimRuntime.iOS-26-5.23F77/
2,815,426,560  dyld_sim_shared_cache_arm64
  442,613,760  dyld_sim_shared_cache_arm64.01
```
→ 缓存**按宿主 macOS 版本号分目录**。如果你在 macOS 26.5.2 上建 27.0 的缓存、
之后升级到 macOS 27.2 再建 27.2 的缓存，两次缓存的代码布局会因为宿主 dyld 不同而漂移，
**差分会被污染**。
→ **正确做法：只比较运行时里的散装 Mach-O（`RuntimeRoot/.../Frameworks/X.framework/X`），
那是 Apple 原样产物，与宿主无关。**

## B6. B 线可执行步骤（结论）

```bash
# 前提：存在一个带 iOS 27.2 SDK 的 Xcode（需要人工在 App Store 装 Xcode 27）
xcodebuild -downloadPlatform iOS -buildVersion 27.0 -exportPath ~/rt27.0
xcodebuild -downloadPlatform iOS -buildVersion 27.2 -exportPath ~/rt27.2

# 挂载后直接取散装明文 Mach-O（不要碰 smruntime 里的任何缓存）
RR=~/rt27.2/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS\ 27.2.simruntime/Contents/Resources/RuntimeRoot
cp -a "$RR/System/Library/Frameworks/ImageIO.framework/ImageIO" dest/27.2/
cp -a "$RR/System/Library/Frameworks/WebKit.framework/WebKit"   dest/27.2/
cp -a "$RR/System/Library/PrivateFrameworks/FontServices.framework/libFontParser.dylib" dest/27.2/
# … 27.0 同理，然后 fwdiff / symdiff
```
**评级：中高。** 唯一阻塞是"拿到 Xcode 27"，且这一步不能自动化。

---

# C. iOS 设备侧的运行时转储

## C1. 实测：普通开发签名 app 能读自己的 `__TEXT`（已验证）

**环境**：iPhone 17 Pro Max / iPhone18,2 / iOS 27.0.1 (24A446) / A19 Pro
**签名**：`iPhone Distribution: <DEVELOPER> (<TEAMID>)`，`get-task-allow = false`（不是调试签名！）
**无越狱、无 entitlement、无调试器**。

代码：`probe/dscdump/main.m`（≈380 行，纯 Foundation + mach API）

**真机输出（原样）：**
```
=== dscdump start ===
mode   = iOS-device-v2
TMPDIR = /private/var/mobile/Containers/Data/Application/506A0B81-.../tmp/
pid    = 2472
[NEGCTL] 0x1000: vm_read=0 kr=1 prot=0x5            <- 负向对照：未映射地址确实被拒
[dlopen] /System/Library/Frameworks/ImageIO.framework/ImageIO                        -> OK
[dlopen] /System/Library/Frameworks/CoreText.framework/CoreText                      -> OK
[dlopen] /System/Library/Frameworks/CoreMedia.framework/CoreMedia                    -> OK
[dlopen] /System/Library/Frameworks/CoreGraphics.framework/CoreGraphics              -> OK
[dlopen] /System/Library/Frameworks/ModelIO.framework/ModelIO                        -> OK
[dlopen] /System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore          -> OK
[dlopen] /System/Library/Frameworks/WebKit.framework/WebKit                          -> OK
[dlopen] /System/Library/PrivateFrameworks/FontServices.framework/libFontParser.dylib -> OK
[objc] WKWebView class = WKWebView
[dyld] image_count = 922
  ImageIO __TEXT vmsize=6605668 prot=0x1 sha256=84bebe812b54bd7f...
  WebKit  __TEXT vmsize=25384788
  JavaScriptCore __TEXT vmsize=40016496
  libFontParser.dylib __TEXT vmsize=2687392
[result] dumped 13 images
```
`systemName: Version 27.0.1 (Build 24A446)`（从 `NSProcessInfo` 读到，确认机型固件）

**产物**（已拉回 Mac）：`probe/dscdump/build/dev-ondev-v2/`，共 202 MB / 46 个文件

| 镜像 | `__TEXT` | FUNCSTARTS 函数数 | 符号表条目 | 其中未 redact |
|---|---|---|---|---|
| ImageIO | 6,605,668 | 23,179 | 22,345 | 7,913 |
| WebKit | 25,384,788 | 76,792 | 90,263 | 10,542 |
| JavaScriptCore | 40,016,496 | 39,720 | 35,660 | 6,706 |
| CoreGraphics | 8,099,192 | 14,379 | 13,427 | 4,253 |
| CoreText | 2,128,032 | 5,462 | 6,730 | 1,753 |
| CoreMedia | 2,443,216 | 14,971 | 15,365 | 6,905 |
| ModelIO | 1,517,328 | 4,987 | 1,048 | 1,048 |
| libFontParser | 2,687,392 | 8,397 | 4,134 | 794 |

## C2. iOS 27 有没有额外硬化？

**结论：没有。** 逐项排除：

| 硬化项 | 实测结果 |
|---|---|
| `__TEXT` 不可读 | ❌ 不存在。`vm_region` 报 `prot=0x1`（`VM_PROT_READ`），`vm_read_overwrite` 直接 `KERN_SUCCESS` |
| 需要特殊 entitlement | ❌ 不存在。`get-task-allow=false` 的普通发布签名就能读 |
| 沙箱限制读 | ❌ 不存在。沙箱只限制**写**路径（必须用 `getenv("TMPDIR")`），不限制读自己映射的代码页 |
| 私有框架拿不到 | ❌ 不存在。`libFontParser.dylib` `dlopen` 成功 |
| 代码页加密（cryptid） | ❌ 不存在。cache 映射的 `__TEXT` 是明文，与磁盘上的 dsc 一致（见 C5 逐字节验证） |

## C3. ⚠ 重大负面发现：真机的本地符号名被 redact

**结论：真机 dyld 共享缓存的符号表里，非导出符号的名字被替换成字面量 `<redacted>`。**

```
$ grep -c '<redacted>' ImageIO.179.symbols.txt ; wc -l < ImageIO.179.symbols.txt
14432
22345
$ head -3 ImageIO.179.symbols.txt
00000001878b52e0 1e   1 <redacted>
00000001878b52e4 1e   1 <redacted>
00000001878b53b0 1e   1 <redacted>
$ grep -v '<redacted>' ImageIO.179.symbols.txt | head -2
0000000187b5c4f4 0f   1 _CGAnimateImageAtURLWithBlock
0000000187b5c728 0f   1 _CGAnimateImageDataWithBlock
```

| 镜像 | 总符号 | `<redacted>` | 占比 |
|---|---|---|---|
| ImageIO | 22,345 | 14,432 | 65% |
| CoreText | 6,730 | 4,977 | 74% |
| CoreGraphics | 13,427 | 9,174 | 68% |
| WebKit | 90,263 | 79,721 | **88%** |
| JavaScriptCore | 35,660 | 28,954 | **81%** |
| libFontParser | 4,134 | 3,340 | 81% |
| ModelIO | 1,048 | 0 | 0% |

对照组（同一份代码，macOS / 模拟器）：**redacted = 0**，全名保留。

**后果（必须写进方法论）：**
- 真机路线能拿到：**全部代码字节 + 全部函数边界（FUNCSTARTS）+ 导出符号名**
- 真机路线拿不到：**本地函数名** → 无法按函数名做差分，只能按函数**序号 + 大小序列**对齐
- 因此：**要"补丁函数叫什么名字"，走模拟器/macOS 路线；要"这段代码在真机上到底是什么字节"，走真机路线。两条路互补，不能互相替代。**

## C4. 如何把 dump 重组成可用于差分的 Mach-O

**不需要**拼一个完整 Mach-O。差分只需要三样东西，而这三样都已经拿到：

| 需要的东西 | 在 dump 里的位置 | 状态 |
|---|---|---|
| 机器码 | `<img>.<idx>.TEXT.bin`（整个 `__TEXT`，含 `__text`/`__const`/`__cstring`/`__unwind_info`） | ✅ |
| 函数边界 | `<img>.<idx>.FUNCSTARTS.bin`（原始 ULEB128，`Σ` 后即函数地址） | ✅ 不需要符号名 |
| 符号名 | `<img>.<idx>.symbols.txt`（`n_value n_type n_sect name`，地址是 **unslid**） | ⚠ 本地名被 redact |
| 导出名（备用） | `<img>.<idx>.EXPORTS.bin`（`LC_DYLD_EXPORTS_TRIE`） | ✅ |

重组要点：
1. `__TEXT.bin` 的头部就是完整的 mach header + load commands，**直接 `mmap` 就能当 Mach-O 解析**，
   只是 `fileoff`/`section.offset` 是 **cache 相对**的（数值很大，见 C5 的对比）。
2. `__LINKEDIT` **不要 dump**：共享缓存里每个 image 的 `__LINKEDIT` 都指向同一块
   600～740 MB 的区域，按 image 存一次就是几十 GB 的浪费。正确做法是像 `main.m` 里
   `addrForFileOffset()` 那样，**用 `LC_SYMTAB.symoff/stroff` 算出地址，只读需要的字节**。
3. 字符串表也是全镜像共享的（本机实测 `strsize = 407,273,877`，19 个 image 共用）。
   逐镜像保存会炸盘（实测 7.4 GB → 修正后 205 MB）。**在设备上就地解析名字、输出符号索引**。

## C5. 验证链：证明 dump 是真的，不是"拼出来像"

**(a) `__TEXT` 逐字节对 ground truth（macOS 26.5.2，有 dsc_extractor 可对照）**

`tools/verify_textdump.py` 比较"活进程里 dump 的 `__TEXT`"与"`dsc_extractor` 从**同一个缓存**解出来的 Mach-O"：

| 框架 | segment/section 元数据 | load command 之后的全部字节 | 唯一 header 差异 |
|---|---|---|---|
| ImageIO | 相同 | 3,400,528 B **逐字节相同** | `flags` 差 `0x80000000` |
| CoreText | 相同 | 2,256,760 B **逐字节相同** | 同上 |
| CoreGraphics | 相同 | 7,680,672 B **逐字节相同** | 同上 |
| ModelIO | 相同 | 1,472,888 B **逐字节相同** | 同上 |
| CoreMedia | 相同 | 1,702,768 B **逐字节相同** | 同上 |
| WebKit | 相同 | 22,962,080 B **逐字节相同** | 同上 |
| JavaScriptCore | 相同 | 28,267,080 B **逐字节相同** | 同上 |
| libFontParser | 相同 | 2,939,048 B **逐字节相同** | 同上 |

`0x80000000` = **`MH_DYLIB_IN_CACHE`** —— 正是 dyld 在运行时才加的那一位。
这一位差异本身就是证据：说明字节确实来自活缓存，而不是我手工拼的。
（`sect.reloff` 全部不同且数值巨大，是 cache 相对 vs 文件相对的差异，符合预期。）

结果是 **8/8 VERIFIED**。

**(b) 符号表交叉校验**

```
$ python3 tools/verify_symbols.py <ref-macho> <dump.symbols.txt>
ImageIO          ref=21745 dump=21745 common=21745 addr_mismatch=0 -> VERIFIED
ModelIO          ref=1011  dump=1011  common=1011  addr_mismatch=0 -> VERIFIED
CoreMedia        ref=12818 dump=12818 common=12818 addr_mismatch=0 -> VERIFIED
WebKit           ref=113878 dump=113878 common=113878 addr_mismatch=0 -> VERIFIED
JavaScriptCore   ref=49514 dump=49514 common=49514 addr_mismatch=0 -> VERIFIED
FontParser       ref=7111  dump=7111  common=7111  addr_mismatch=0 -> VERIFIED
CoreText         ref=8456  dump=8455  common=8455  addr_mismatch=0 only_ref=1
CoreGraphics     ref=22966 dump=21722 common=21722 addr_mismatch=0 only_ref=1244
```
**所有共有符号地址 0 错配**。两个"不全"的是因为 `dsc_extractor` 会把共享缓存的
**local-symbols 副文件**（`dyld_shared_cache_arm64.01`）合并进去，运行时的 `LC_SYMTAB`
里没有那部分 —— 属于已知且可解释的差异，不影响差分（两边同样缺，差分时抵消）。

**(c) 差分工具链自检（`tools/symdiff.py`，本次新增）**

```
$ python3 tools/symdiff.py <dump> <同一份 dump> --ordinal
ImageIO              A=23178 B=23178 aligned=23178 inserted=0 deleted=0 replaced=0 (0.0%)
WebKit               A=76791 B=76791 aligned=76791 inserted=0 deleted=0 replaced=0 (0.0%)
libFontParser.dylib  A= 8396 B= 8396 aligned= 8396 inserted=0 deleted=0 replaced=0 (0.0%)
TOTAL common=200179 added=0 removed=0 size-changed=0
```
**恒等自比对 200,179 个函数、0 差异** —— 工具是确定的，不是随机噪声。

`--ordinal` 模式用 `difflib.SequenceMatcher` 对齐两条**函数大小序列**，
天然处理插入/删除造成的整体位移，正好适配"名字被 redact"的真机路线。

## C6. 可执行步骤（真机）

```bash
cd tasks/ios27-chain-poc/probe/dscdump
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
xcrun -sdk iphoneos clang -fobjc-arc -O2 -arch arm64 -miphoneos-version-min=16.0 -isysroot "$SDK" \
  -DDSCDUMP_TAG='"iOS-device-v2"' -framework Foundation -o build/dev/Payload/dscdump.app/dscdump main.m

# bundle id 必须等于 profile 里 application-identifier 的后缀（显式 App ID，换不了）
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier com.example.ios27poc" build/dev/Payload/dscdump.app/Info.plist
cp ~/Downloads/profile.mobileprovision build/dev/Payload/dscdump.app/embedded.mobileprovision

security unlock-keychain -p "" ~/Library/Keychains/dev.keychain-db
codesign -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)" --keychain ~/Library/Keychains/dev.keychain-db \
  --entitlements /tmp/ents.plist --generate-entitlement-der -f build/dev/Payload/dscdump.app

xcrun devicectl device install app  --device DEVICE-UDID build/dev/Payload/dscdump.app
xcrun devicectl device process launch --device DEVICE-UDID --terminate-existing com.example.ios27poc
sleep 60
xcrun devicectl device copy from --device DEVICE-UDID \
  --domain-type appDataContainer --domain-identifier com.example.ios27poc \
  --source tmp/dscdump --destination ./dev-ondev-v2/
```
**注意：设备必须处于解锁状态**，否则 `devicectl` 会被 `SBMainWorkspace` 以
`Locked / FBSOpenApplicationErrorDomain error 7` 拒绝，且这个错误无法远程绕过。

**评级：高。** 已完全跑通，唯一约束是"设备解锁"和"bundle id 只能复用同一个"。

---

# D. 其他途径

## D1. ⚠ 修正背景里的一个前提：IPSW 系统卷的 AEA 密文**不是每台设备唯一**

**结论：`OS.dmg.aea` 和 `Cryptex1,SystemOS.dmg.aea` 的 `Personalize = False`，
意味着**同一机型所有设备拿到的密文是同一份字节**。密钥仍要设备侧解封，但"每台设备唯一"这句是错的。

**证据（27.0.1 IPSW 的 BuildManifest）：**
```python
OS              -> Path: 043-69487-662.dmg.aea   Personalize: False  Trusted: True
Cryptex1,SystemOS -> Path: 043-70037-715.dmg.aea Personalize: False
Cryptex1,AppOS  -> Path: 043-69297-793.dmg       Personalize: False   # 明文，可直接挂
```
AEA 头部结构（`fw/x2701/043-68570-757.dmg.aea`，前 96 字节）：
```
00000000: 4145 4131 0100 0000 6808 0000 3000 0000  AEA1...........
00000010: 636f 6d2e 6170 706c 652e 776b 6d73 2e75  com.apple.wkms.u
00000020: 726c 0068 7474 7073 3a2f2f 776b 6d73       rl.https://wkms
00000030: 2e73 642e 6170 706c 652e 636f 6d55 03..   .sd.apple.comU.
...
com.apple.wkms.auth-data
com.apple.wkms.fcs-response
{"enc-request": "BCV5Zmz3...", "wrapped-key": "4nLIICi1IPeUf..."}
saksKey
```
- `com.apple.wkms.*` = Apple 的 Web Key Management Service
- `fcs-response` 里同时带 `enc-request` 和 **`wrapped-key`** —— **解封材料是随镜像一起下发的**
- `hdiutil attach` 直接报"无法识别映像"（预期）

**战略含义（重要）：**
- 你**不需要**每台设备各做一遍。只要有任何一台能跑解封路径的设备
  （被利用的设备 / 有 class key 的调试环境 / Apple 内部构建），解出来的就是**所有人的明文**。
- 这把"每设备唯一 → 必须攻破我这台"降级成"攻破任意一台"。
- 但**这不改变短期可行性**：仍然需要一个能执行 AEA 解封的上下文，本机没有。

## D1b. ⭐⭐ 已打通：AEA 可以完全离线解密（不需要设备 / 越狱 / macOS 安装包）

这一节是本次调研的最终结论，也是整条链最关键的一步。**已实测解密并挂载成功。**

### (1) 本机就有 Apple 自己的 AEA 工具

```
$ which aea
/usr/bin/aea
$ aea            # 关键子命令
  decrypt   Decrypt the contents of encrypted archive `input_file` to `output_file`
  -key key_file | -key-value key | -keychain
  -range-offset / -range-size
```
**不需要第三方工具、不需要 keybag 文件、不需要设备。**

### (2) 每个 `.dmg.aea` 的 prologue 自带密钥溯源材料

```
$ aea id -i OS.27.2.dmg.aea -v
  profile: hkdf_sha256_aesctr_hmac__symmetric__none     <- 对称，一把 32 字节密钥
  archive identifier: 4d1a0c8783cf67a7ae3c0866c696ebfe5ddc1b469e48f19b0d996397a28ab84d
  auth data: 2136 B
  - com.apple.wkms.url          : 25 B   https://wkms.sd.apple.com
  - com.apple.wkms.auth-data    : 816 B
  - saksKey                     : 895 B
  - com.apple.wkms.fcs-response : 190 B  {"enc-request": <65B P-256 点>, "wrapped-key": <48B>}
  - com.apple.wkms.fcs-key-url  : 83 B   https://wkms-public.apple.com/fcs-keys/<id>
```

### (3) `fcs-key-url` 是一个**未鉴权**的公钥→私钥换取端点

```bash
$ curl -sIL 'https://wkms-public.apple.com/fcs-keys/ZW7OeAWRSMQd8VUKuhTq8hm2geKyeJkP-79qIeqXrAo='
HTTP/2 301  location: https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/ZW7O...rAo=
HTTP/2 200  content-type: application/x-pem-file
$ curl -sL 'https://wkms-public.apple.com/fcs-keys/ZW7OeAWRSMQd8VUKuhTq8hm2geKyeJkP-79qIeqXrAo='
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRpJqfl2IVKWw2ZKr
SPnH2cEyOdkdRn+tus7nMBfqGt6hRANCAATGP5msvrT8qFLrD7WGLxXr65NUHVzn
BKhaoaHchCG8GPzO628uzkQvGIovVk9qYa+XxZGfxfgloR9eIz6NOQ/n
-----END PRIVATE KEY-----
```
- 无 Cookie / token / Apple ID / device identity；两次抓取字节相同；错误 id → **403**
- 寻址规则已证实：**`<id> == base64url(sha256(未压缩 P-256 公钥))`**（精确匹配）

### (4) 封装算法 = HPKE (RFC 9180) —— 从系统二进制里读出来的，不是猜的

```
$ nm diskimagescontroller.xpc | swift demangle | grep -i unwrap
+[FetchRestoreKeys.CryptoKitWrapper unwrapEncryptionKeyWithWrappedKey:encapsulatedKey:privateKey:error:]
```
三个参数名 `wrappedKey / encapsulatedKey / privateKey` 就是 HPKE 的 `ct / enc / skR`。
用 **CryptoKit 本尊** 解（`tools/aea/hpke_open.swift`）：

```swift
var r = try HPKE.Recipient(privateKey: sk,                   // fcs-key-url 拿到的私钥
                          ciphersuite: .P256_SHA256_AES_GCM_256,
                          info: Data(),
                          encapsulatedKey: enc)             // fcs-response.enc-request
let aeaKey = try r.open(wrapped)                            // fcs-response.wrapped-key -> 32 B
```

### (5) 端到端实测结果

```
$ python3 tools/aea_unlock.py fw/x2701/043-68570-757.dmg.aea -o /tmp/full.dmg
profile      : hkdf_sha256_aesctr_hmac__symmetric__none
fcs-key-url  : https://wkms-public.apple.com/fcs-keys/QCqzQwl_I7Qqryu1rCa3pUU9B0bB8stoEultRXeT16I=
key id check : OK
symmetric key: 56eb7804df395bdf0a56f8a9cff6a2119e8f2657a7c649314a35c9dbc8a6fd5e
decrypting -> /tmp/full.dmg
/tmp/full.dmg: Apple File System (APFS), blocksize 4096        # 503,316,480 B

$ hdiutil attach -nobrowse -readonly /tmp/full.dmg
/dev/disk9s1  41504653-0000-11AA-AA11-0030654  /Volumes/Rave24A446.V54ExclaveOS
```
`real 0m0.243s`，1719 个文件全部可读（含 `dyld_shared_cache_arm64e` + `.symbols`）。

### (6) 只花 ~400 KB 流量就能拿到一把密钥（不用下整个 IPSW）

IPSW 是 ZIP，中央目录在文件尾部，成员是 `method=0` 存储 —— 所以可以纯 Range 取：

```bash
# 1) 取最后 1 MB，解析 ZIP64 EOCD + 中央目录，拿到 165 个成员的 offset/size
curl -r $((SIZE-1048576))-$((SIZE-1)) -o tail.bin "$IPSW"
# 2) 取该成员前 256 B，读 local file header，算出真实数据偏移
curl -r $OFF-$((OFF+255)) -o lfh.bin "$IPSW"
# 3) 取成员前 256 KB，就是 AEA prologue
curl -r $DATAOFF-$((DATAOFF+262143)) -o head.aea "$IPSW"
aea id -i head.aea -v          # 对截断文件也工作
python3 tools/aea_unlock.py head.aea --key-only
```

### (7) iOS 27.2 (24B119) 已解析出的成员表

| 组件 | IPSW 成员 | IPSW 内数据偏移 | 大小 | 解密后挂载点 |
|---|---|---|---|---|
| `OS` | `141-10103-215.dmg.aea` | 198,733,876 | 9,261,023,232 | `/` 基卷 |
| **`Cryptex1,SystemOS`** | `141-10617-227.dmg.aea` | **10,184,346,542** | **2,415,919,104** | **`/System/Cryptexes/OS`** |
| `Ap,ExclaveOS` | `141-10120-237.dmg.aea` | 9,459,757,138 | 536,870,912 | ExclaveKit |
| （AppCryptex） | `141-10697-238.dmg.aea` | 12,600,265,646+71 | 243,269,632 | `/System/Cryptexes/App` |

### (8) ⚠ 目标框架分散在**两个**卷里（这条会决定下载量）

用本机 iOS 26.5 运行时验证（布局与真机一致）：

| 框架 | 所在卷 |
|---|---|
| ImageIO / CoreText / CoreGraphics / ModelIO / CoreMedia / FontServices/libFontParser | **基卷 `OS`（9.26 GB）** |
| WebKit / JavaScriptCore | **`Cryptex1,SystemOS`（2.25 GB，`/System/Cryptexes/OS` 覆盖层）** |

→ 6 个目标里 5 个在 9.26 GB 的基卷里，**大包躲不掉**。
→ **结论：直接下完整 IPSW（13.15 GB/版本）比分别取成员更省事**，且顺带拿到 AppCryptex。
→ 两版本合计 ~25 GB；`updates.cdn-apple.com` 单流 10.5 MB/s ≈ 40 分钟。

### (9) 已知边界（诚实记录）
- AEA 是**压缩 + 加密**（ExclaveOS 实测 416 MB 密文 → 480 MB 明文），所以
  `-range-offset/-range-size` 的随机访问不能用"稀疏文件只填头部"的方式骗过去
  （实测：填正确长度 + 前 256 KB → `decrypting cluster header / HMAC` 失败；
  对照组用**已知正确的完整文件**做同样实验也失败 → 说明是稀疏文件不合法，不是密钥错）。
  **要按需取文件必须先把 AEA 的 cluster 索引逆出来**，本次未做。
- `aea decrypt` 必须拿到完整成员数据。

### (10) 战略含义
- 任务背景里"AEA 密钥封装给 Secure Enclave、每台设备唯一"的假设**不成立**：
  `Personalize = False`（见 §D1），且密钥材料就在镜像的 prologue 里、对端私钥在公开 CDN 上。
- 这条路拿到的是**真机 arm64e 原版二进制**，比 macOS 路线（26B123 桌面版）和模拟器路线
  （arm64 / IOSSIMULATOR）都更贴目标，可以直接喂 `fwdiff.py` 做 27.0.1 vs 27.2 差分。

证据包：`out/aea-wkms/`（README.txt + 返回的私钥 PEM）。

---

## D2. `ipsw` 工具能对 AEA 做什么

本机**未安装** `ipsw`（`which ipsw` 空，无 homebrew）。无法实测其 AEA 子命令。
已知能力边界（供参考，未验证）：`ipsw` 能解 IM4P/LZFSE（我们已用自研 `harness/lzfse.swift` 覆盖）、
能解析 BuildManifest、能打各类 Mach-O 补丁；**AEA 解密需要外部 keybag**，`ipsw` 不提供密钥。
苹果的 AEA 实现是 `libAppleArchive`，容器里的 `wrapped-key` 需要 WKMS 侧解封。

## D3. 可行性评级表

| 途径 | 评级 | 依据 |
|---|---|---|
| **macOS 27.2 InstallAssistant → SharedSupport.dmg** | **高** | 直链已验证；17.8 GB；挂载即明文全框架 |
| **iOS 27.x 模拟器运行时（散装 Mach-O）** | **中高** | 存在已验证；被 Xcode 27 SDK 卡住；**符号完整**是最大优势 |
| **真机 `__TEXT` + FUNCSTARTS 转储** | **高** | 已完整跑通；但本地符号名被 redact |
| 真机 + 27.2 固件（换一台 27.2 设备） | 中 | 只要有一台 iOS 27.2 设备，同款 app 直接 dump → 真机 vs 真机、同 ISA 的完美差分 |
| macOS 27.0.1 (`142-27367`) 作对齐基线 | 高 | 同 catalog，版本严格对齐，patch delta 就是 iOS 27.0.1→27.2 那批 |
| **WKMS `fcs-key-url` 私钥托管端点** | **中（唯一可能一击解决的线索）** | 端点未鉴权、私钥已拿到、对称 profile、`aea` 工具本机自带；**只差封装公式**，见 §D1b |
| `ipsw`/其他工具破 AEA | 低 | 本机未装；且 AEA 不需要它 —— `/usr/bin/aea` 就是 Apple 官方解密器 |
| 第三方 dyld cache 镜像仓库 | 低-中 | 存在（各类"iOS 固件转储"镜像），但 27.x 太新、来源不可验证、法律风险高 |
| Apple Developer Disk Image / Symbols 包 | 低 | DDI 只含调试桩；`dSYM`/符号包只给已发布系统的符号，且需要开发者账号 |
| Cryptex 处理（`Cryptex1,AppOS`） | **已可用** | 27.0.1 的 AppOS **本来就明文**，`hdiutil` 可挂 → Safari/WebKit 系已能 diff，不需要新方案 |
| 企业/教育渠道镜像 | 低 | AppleSeed/Enterprise 仍走同一套 AEA，不改变加密 |
| 旧设备跑同一大版本 | 低 | 要用在 **27.2** 上；任何能跑 27.2 的机型都同样受 AEA + 无 bootrom 漏洞约束，不因为机型旧而变简单 |
| `OSXCollector` 类工具 | 不适用 | 那是 macOS 取证工具，与 iOS 固件解密无关 |

---

# E. 建议的下一步（具体动作）

**并行两条，互不阻塞：**

1. **[今天]** A 线收尾：用 `pget.py --threads 48` 续传 `InstallAssistant-27.2-26B123.pkg`
   （已落盘 8.4 GB，state 完整，剩 ~7 分钟），
   `dd if=... of=SharedSupport.dmg bs=1m skip=14` → `hdiutil attach` →
   直接和本机 26.5.2 的 `/System/Library/Frameworks` 跑通 `fwdiff.py` 全流程，
   验证"差分工具链 + 真实 macOS 二进制度"这条腿。
2. **[今天]** 真机侧补最后一刀：把 `probe/dscdump` 的 v2 产物接进 `symdiff.py --ordinal`，
   确认"真机 27.0.1 侧"的基线可用（这条腿已经有 202 MB 真实数据）。

**然后二选一（取决于能不能装 Xcode 27）：**

- **能装 Xcode 27** → 走 B 线。`xcodebuild -downloadPlatform iOS -buildVersion 27.0 / 27.2`，
  取散装 Mach-O，做 **sim 27.0 vs sim 27.2** 的符号级差分。这是**信息量最大**的一步：
  能给出"哪个框架的哪个函数被改了"的带名字清单。
- **不能装** → 退到 **"换一台 iOS 27.2 真机"**：用同一套 `dscdump` 在 27.2 设备上跑一遍，
  得到 **真机 27.0.1 vs 真机 27.2** 的同 ISA 差分（arm64e vs arm64e，最干净）。
  这一步只需要第二台设备，不需要任何额外软件。

---

## 附：本次新增/修改的文件

| 文件 | 作用 |
|---|---|
| `probe/dscdump/main.m` | 真机/模拟器/macOS 通用的 `__TEXT`+符号表+函数边界转储器 |
| `tools/pget.py` | 多连接分段下载器（含 `--verify-samples` 与 `.coverage`） |
| `tools/verify_textdump.py` | dump 的 `__TEXT` vs `dsc_extractor` 逐字节验证 |
| `tools/verify_symbols.py` | dump 的符号表 vs `LC_SYMTAB` 双向验证 |
| `tools/verify_dump_sections.py` | 缓存态 vs 散装文件的 section 级比对（用于说明 branch-island 差异） |
| `tools/symdiff.py` | 函数级差分（`--ordinal` 支持 redact 符号） |

---

# F. 已经产出的真实差分（27.0.1 vs 27.2，真机 arm64e）

> 这一节不是方案，是**跑出来的结果**。用 §D1b 的方法解出 `Cryptex1,AppOS`
> （两版本各只有 ~9 MB、且本来就是明文 dmg），挂载后直接对真机二进制做差分。

## F1. 拿到的方式（20 MB 流量，两分钟）

```bash
python3 tools/ipsw_aea.py extract <27.2  IPSW> "Cryptex1,AppOS" -o AppOS.27.2.dmg.zip
python3 tools/ipsw_aea.py extract <27.0.1 IPSW> "Cryptex1,AppOS" -o AppOS.27.0.1.dmg.zip
python3 -c "import zlib,sys;open('a.dmg','wb').write(zlib.decompress(open('AppOS.27.2.dmg.zip','rb').read(),-15))"
hdiutil attach -nobrowse -readonly a.dmg          # -> /Volumes/AppCryptex
```
成员在 IPSW 里是 `method=8`（deflate），`data_off` 分别是 47 和 625,391,700。

## F2. 文件级结果

| | |
|---|---|
| 两版文件数 | 各 **1155**，新增 0 / 删除 0 |
| 内容不同 | **159** 个（其中 142 个是 `Info.plist` / `version.plist` / `locversion.plist` / `.strings` 等构建产物） |
| **Mach-O 二进制不同** | **17** 个 |

## F3. 17 个变化二进制，逐个函数级定性

| 二进制 | Δsize | 函数数 27.0.1 → 27.2 | 判定 |
|---|---|---|---|
`MobileSafariSettings` | **+19,648** | 1,958 → **1,990** | **+32 个函数**，真实功能变更 |
`SafariBookmarksSyncAgent` | +256 | 4,420 → 4,421 | **+1 函数** |
`webbookmarksd` | +528 | 501 → **503** | **+2 函数** |
`safarifetcherd` | +368 | 265 → **266** | **+1 函数**（新增 shape 1 个，A 侧无删除 → 纯新增） |
`MobileSafari.migrator/MobileSafari` | +192 | 113 → 113 | 等函数数、有代码变动 |
`com.apple.Safari.History` | +0 | 1 | 代码**逐字节相同**，仅构建元数据 |
`guidedbrowsingd` | +0 | 31 | 代码**逐字节相同** |
`browserkitd` | +0 | 305 | 代码**逐字节相同** |
`webpushd` | +0 | 1 | 代码**逐字节相同** |
`AuthenticationServicesAgent` | +0 | 544 | 代码**逐字节相同** |
`webinspectord` | +0 | 20 | 代码**逐字节相同** |
`passwordbreachd` | +0 | 1 | 代码**逐字节相同** |
`SafariUsageBundle` | +0 | 61 | 代码**逐字节相同** |
`CloudTabsMigrator` | +0 | 2 | 代码**逐字节相同** |
`CloudBookmarksAccountsNotifier` | +0 | 6 | 代码**逐字节相同** |
`WebSearch` | +0 | 3 | 代码**逐字节相同** |
`Safari`（assistant plugin） | +0 | 3 | 代码**逐字节相同** |

**读法：12 个 "改了但代码没变" 的，说明它们的差异 100% 来自 LC_UUID / 版本号 / 链接时戳
—— 这是很容易被误当成"被打补丁"的假阳性，必须靠函数级比对排除。**

## F4. `browserkitd` 的逐字节归因（示例，说明工具能定位到字节）

```
runs: 总差异段 399，占文件 2.0%
  落在 header/load commands (0..0x19f8) : 26 段
  落在某个函数体内部                    : 0 段
  其它（__stubs / __const / __cstring） : 373 段
→ 305 个函数全部逐字节相同 ⇒ 这个二进制在 27.2 没有被改代码
```

## F5. 工具
- `tools/funchdiff.py` —— **精确**函数级差分：`LC_FUNCTION_STARTS` 定边界、`LC_SYMTAB` 定名字、
  逐函数 sha256 比对；检测到符号被 strip 时自动退化为**序号配对**并显式告警。
  比 mnemonics-"形状"比对强的地方：能抓到**操作数级**改动（常量、跳转目标、新增的检查）。
- `tools/fwdiff.py`（既有）—— 形状比对，适合函数**数量变化**时看新增/删除。

## F6. 边界（必须说清楚）
1. AppCryptex 里**没有 WebKit.framework 本体**（它在 `Cryptex1,SystemOS`），
   所以这一节的结论只覆盖 Safari 的外围 daemon / 设置面板，不覆盖 WebKit 引擎。
2. `__TEXT` 之外的段（`__DATA_CONST` 里的 chained-fixup、`__cstring`）本次只定位未逐条归因。
3. 函数序号配对仅在两版函数数相同或差异很小、且编译器未重排时才可靠；
   `MobileSafariSettings` 差 32 个函数，需要先做对齐再逐函数定性（下一步）。

---

# G. 交接状态与续跑指令（截至 2026-10-31 13:10）

## G1. 已完成并验证
| 事项 | 状态 |
|---|---|
| AEA 离线解密链路 | ✅ 端到端跑通，`Ap,ExclaveOS`(27.0.1) 解密+挂载成功 |
| 27.2 `OS` 密钥 | ✅ `97d90647cf3777a75e7977df2fce83ea8ff31e1258049fe09027780400fd1ab0` |
| 27.2 `Cryptex1,SystemOS` 密钥 | ✅ `6c856166116bc7010f1d24f2b9cc2c5ff77c6959ee300ba7f3b550bcd2adbc99` |
| 两版 `Cryptex1,AppOS` | ✅ 已下载+解压+挂载（`fw/cryptex/`） |
| **27.0.1 vs 27.2 真实差分** | ✅ §F，17 个二进制、逐函数定性 |
| 工具链 | ✅ `aea_unlock.py` / `ipsw_aea.py` / `funchdiff.py` / `pget.py` / `verify_*` |

## G2. 未完成（纯带宽问题，非技术阻塞）
`fw/ios272/CryptexSystemOS.27.2.dmg.aea.part` —— **2269 MB / 2304 MB**，
只差 **3 个 32 MB 分块（62 / 63 / 71）**。CDN 当时被并发下载压到 ~500 KB/s。

**续跑（幂等，直接重跑即可）：**
```bash
cd tasks/ios27-chain-poc/fw/ios272
python3 ../../tools/pget.py \
  "https://updates.cdn-apple.com/2026FallFCS/82995481-b196-4d33-bd11-97788acc1d53/iPhone18,2_27.2_24B119_Restore.ipsw" \
  CryptexSystemOS.27.2.dmg.aea --offset 10184346542 --length 2415919104 \
  --threads 20 --chunk-mb 32
# 完成后：
python3 ../../tools/aea_unlock.py CryptexSystemOS.27.2.dmg.aea \
  -o CryptexSystemOS.27.2.dmg          # 会用 prologue 里的 fcs-key-url 自动解封
hdiutil attach -nobrowse -readonly CryptexSystemOS.27.2.dmg
# → /Volumes/.../System/Library/Frameworks/WebKit.framework/WebKit  (+ JavaScriptCore)
```

## G3. 还需要的两块（决定谁能拿到全部 6 个目标）
| 需要的卷 | 27.0.1 | 27.2 | 含哪些目标 |
|---|---|---|---|
| `OS`（基卷） | 8,992,587,776 | 9,261,023,232 | ImageIO / CoreText / CoreGraphics / ModelIO / CoreMedia / libFontParser |
| `Cryptex1,SystemOS` | 2,348,810,240 | 2,415,919,104 | WebKit / JavaScriptCore |

27.2 的 Cryptex 已 98% 落盘（见 G2）；其余三个卷待下。
密钥用 `python3 tools/ipsw_aea.py key <ipsw|url> "<组件名>"` 现取即可（~400 KB 流量）。

## G4. 教训（写进流程）
1. **后台下载必须用 harness 的 background job**；`nohup ... &` / `setsid` 在 macOS 上会随
   bash 调用结束被 SIGTERM（本次踩了两次，第一次卡在 26%）。
2. 多连接下载在**同一出口 IP 上会互相抢**：本次三条线并发时单线只有 0.5–3 MB/s，
   单线独占时 `updates.cdn-apple.com` 能到 10.5 MB/s。**并行前先协调。**
3. 稀疏 `.part` 文件的**大小不是完成信号**，必须看 `.state` / `.coverage`。
