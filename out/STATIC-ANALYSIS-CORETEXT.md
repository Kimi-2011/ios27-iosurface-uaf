# CoreText 光学尺寸可达性验证（阶段性）

> ⚠️ **本文档已被 `out/STATIC-ANALYSIS-CORETEXT-FINAL.md` 取代。以下三处判断是错的，已由后续工作推翻：**
>
> 1. ❌ **"OS/2 v5 光学尺寸字段在偏移 92/94"** —— 错。实测反汇编：
>    `0x19a2ae2f8: ldrh w9,[x8,#0x60]` / `0x19a2ae2fc: ldrh w8,[x8,#0x62]` → **偏移是 96/98**（v5 表长 100 字节）。
>    92/94 是 `usBreakChar`/`usMaxContext`。
>    因此本文档里"截断到 78/84/90 字节"的测试**根本没碰到光学尺寸字段**——那一轮全绿是无效实验。
>
> 2. ❌ **"27.2 新增 71 处边界检查"** —— 误判。27.2 指令膨胀主要是加了一层全局 unordered_map 缓存。
>    真正读 OS/2 的 `TBaseFont::CopyOpticalPointSizes` 两版**逐条相同**（92 条，归一化相似度 1.0000，
>    已独立验证）；`GetOpticalPointSizes` 反而从 54 条缩短到 32 条（抽出辅助函数）。
>    **没有任何一处是加校验。**
>
> 3. ❌ **"TFont::SetOpticalSize 只在系统字体匹配时调用"** —— 错。xref 显示它有 6 个直接调用者，
>    全是 TFont 构造函数（含 `TFont::TFont(CGFont*,...)`，`0x19a29f128` 是无条件 `bl`）。
>    `CTFontCreateWithGraphicsFont` **一定进得去**，前一轮全绿是"进去了但被内部守卫挡掉"。
>
> 4. ❌ **"被设备锁屏阻塞"** —— 误判。真因是 harness bug：iOS 27 的
>    `contentsOfDirectoryAtPath:` 返回 Swift 字符串，`sortedArrayUsingSelector:@selector(compare)`
>    抛 `-[Swift.__StringStorage compare]: unrecognized selector`，程序写几行就死。
>
> **结论：本线索应从"最高质量线索"降级——它不是 CVE-2026-112656 的修补点。**


## 一、子代理已完成的部分（有实测证据）

### 环境确认
```
osversion: Version 27.0.1 (Build 24A446)
TMPDIR=/private/var/mobile/Containers/Data/Application/.../tmp/
```

### 关键结果 1：字体注册**成功**
```
CTFontManagerRegisterFontsForURL(..., kCTFontManagerScopeProcess, &err)
  → register(Process) = 1        ← 成功
  → err = (none)
```
**结论：app 可以把任意字体的注册进进程字体域，这条路没有被封。**

### 关键结果 2：按名解析**成功**
```
CGFont 从数据创建成功
ps = EvilOS2Pocok_v5_100
full = EvilOS2Pocok_v5_100 Regular
CTFontCreateWithName(ps, 20, NULL) → 成功，能取到 asc/desc/cap/rect
```

### 关键结果 3：5 条创建路径 × 18 个字体 × 多字号，**全部无崩溃**
```
[A] CTFontCreateWithName(psName, size)
[B] 描述符 + kCTFontOpticalSizeAttribute
[C] 描述符 + kCTFontOpticalSizeAttribute + kCTFontVariationAttribute
[D] CGFont + 光学尺寸描述符
[E] CTFontCreateCopyWithAttributes
共 1914 行日志，结论「全部完成，未崩溃」
```

### 附带发现
```
CTFontManagerRegisterGraphicsFont → 返回 0，错误 305
  ("Could not register the CGFont ...")
```
即 CGFont 方式注册被拒（305），但 **URL 方式注册可成功**——两者不同。

---

## 二、尚未完成：路线 B（系统字体名冒充）

从 SFNS.ttf 的 name 表读到真实族名：
```
nameID 1 (Family) = ".SF NS"
nameID 4 (Full)   = "System Font"
```

据此构造了 15 个冒充系统字体名的字体（`harness/fontpoc/sysname/`）：
| 族名 | 变体 |
|---|---|
| `.SF NS` | V5full / V5trunc78 / V5max |
| `.AppleSystemUIFont` | 同上 |
| `SF Pro` | 同上 |
| `SF Pro Text` | 同上 |
| `.SFUI-Regular` | 同上 |

**思路**：注册后按 `.SF NS` 解析，CoreText 会走**系统字体匹配**（而非普通族名查找），
这条路径才会调用 `TFont::SetOpticalSize` → `SelectOpticalStyleFromOS2`。

**测试代码已写好**（`harness/fontpoc/main.m`），验证：
- `CTFontManagerRegisterFontsForURL`
- `CTFontCreateWithName(psName/fullName, size)`
- `CTFontCreateUIFontForLanguage(kCTFontUIFontSystem / kCTFontUIFontUser, size, NULL)`
（最后这条强制走系统 UI 字体路径）

**状态：被设备锁屏阻塞**（`BSErrorCodeDescription = Locked`），安装被拒。

解锁后一条命令即可出结果：
```bash
DEV=DEVICE-UDID
P=<PROJECT>
xcrun devicectl device install app --device $DEV "$P/harness/fontpoc/Payload/FP.app"
xcrun devicectl device process launch --device $DEV com.example.ios27poc
sleep 35
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer \
  --domain-identifier com.example.ios27poc --source tmp/fontpoc.log --destination /tmp/imp.log
```

## 三、判读标准
| 观察 | 含义 |
|---|---|
| 崩溃 / SIGKILL | **PoC 成功** |
| 全部正常 + 字体名被系统接受（asc/cap 与系统字体一致）| 走进了系统匹配但仍安全 → 大概率不可达 |
| 字体被拒绝注册 | 冒充被识别，转其他族名 |
