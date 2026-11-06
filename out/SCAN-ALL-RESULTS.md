# 全量用户态差分扫描（4,689 个 dylib）——完整候选清单

## 方法
```
4689 个 27.0.1 dylib × 对应 27.2 版本
  → 按【符号名】精确 join（用户态有完整符号，无配对歧义）
  → 每个函数算：指令数 + 比较/条件跳转数
  → 筛出「Δ比较 > 0 且函数变长」= 新增了检查
```
耗时 20.7 分钟（8 进程），产出 `out/scan_all.jsonl`。

## 总量
| 项 | 值 |
|---|---|
| 扫描 dylib | 4,689 |
| 候选函数 | **15,278** |
| Δ检查 ≥ 3 且函数名含安全关键词 | 894 |
| 剔除高噪声 dylib 后 | 5,397 |

## 候选最集中的 dylib
```
1340  WebCore            815  JavaScriptCore     612  SwiftUICore
 411  WebKit             379  HomeKitDaemon      262  AppleDepth
 261  ConversationKit    230  libwebrtc          216  PommesRankingCore
 213  HealthDaemon       203  TokenGenerationCore 198  ANECompiler
```
⚠️ WebCore/JSC/WebKit/SwiftUI 每版都大幅重构，**噪声极大**，需单独排除。

## 剔除噪声后的高分候选（节选）
| Δ检查 | Δ指令 | dylib | 函数 |
|---|---|---|---|
| 84 | 439 | MetalPerformanceShadersGraph | `mlir_ods_local_type_constraint_MPSSP...` |
| 67 | 593 | SpotlightIndex | `preIterateQueryForIndex_block_invoke.52` |
| **71** | **337** | **CoreText** | **`TFont::SelectOpticalStyleFromOS2`** ★ |
| 71 | 332 | WebGPU | `WebGPU::Texture::setPreviouslyCleared` |
| 64 | 306 | WebGPU | `wgpuQueueWriteBuffer` |
| **59** | **201** | **WebCore** | **`dav1d_parse_sequence_header`** ★ |
| 32 | 539 | AudioToolbox | `SpatializationManager::GetPreferences` |
| **56** | **272** | **QuartzCore** | **`CA::FB::DecoderImpl::add_asset_to_context`** ★ |
| 45 | 214 | WebCore | `dav1d_decode_frame_exit` ★ |
| 27 | 335 | CoreSpeechFoundation | `+[CSFModelConfigDecoder decodeJsonFromFile:]` |

★ = 解析不可信数据的组件

## 当前主攻：CoreText `TFont::SelectOpticalStyleFromOS2`

**差分**：27.0.1 `299 条` → 27.2 `886 条`（**3 倍增长**，+71 处新比较）
**地址**：27.0.1 `0x19a30b73c` / 27.2 `0x19a4ac9d0`
**对应 CVE**：CVE-2026-112656（CoreText，越界读 → 泄漏进程内存）

**27.0.1 的逻辑**（反汇编节选）：
```asm
bl <取表>                       ; 取 OS/2 表
adrp x1, #...; add x1, x1, #0xff8   ; tag
mov w2, #4
bl <GetTable(tag,4)>
cbz x1, ...                     ; 表不存在则退出
add x2, x0, x1                  ; table_end = base + len
...
fcmp d1, d0 ; b.hi / b.mi / b.eq ; 比较两个光学尺寸
```
→ 对应 OS/2 **version 5** 的 `usLowerOpticalPointSize` / `usUpperOpticalPointSize`（偏移 92/94）。

**假设**：声明 version=5 但表实际长度不足 96 字节 → 读到表尾之外。
（27.2 把整个解析重写成 886 条，加了大量长度/区间校验。）

## 实测结果：未触发
构造 15 个字体（`harness/fontpoc/os2/`）：
```
version=5 + 长度 8/16/32/68/76/78/80/84/90/96
version=5 + lower/upper = 0xFFFF,0 / 0,0 / 0xFFFF,0xFFFF
version=6 / version=65535
```
每字体 × 10 个字号（1,7,8,9,64,95,96,143,144,145）× 4 个 CoreText API：
**全部正常，无崩溃。**

**判读**：`SelectOpticalStyleFromOS2` **大概率未被触达**——
Apple Symbols 没有光学尺寸数据，`CTFontCreateWithGraphicsFont` 不走该路径。
要触发需要「真正带 opsz 光学尺寸的字体」（如 SF Pro 系），
或该函数在别的入口（字体注册/系统字体匹配）被调用。

## 下一步
1. 找到 `SelectOpticalStyleFromOS2` 的**调用者**（逆向交叉引用），确定真实触发条件
2. 若需要 opsz 字体：可从 macOS 系统取 SF Pro 变体字体做基底改写 OS/2
3. 或转向 `dav1d_parse_sequence_header`（AV1 解析，媒体入口，同样不可信输入）

---

## CoreText 线索的进一步追踪（结论：仍未打通）

### 1. 调用者已逆出
```
[直接调用] 2 处，都来自：
   TFont::SetOpticalSize(__CTFontDescriptor const*)
     0x19a2574e4  bl
     0x19a2577cc  bl
[数据段指针] 1 处（可能是 vtable/函数指针表项）
```
→ 唯一入口是 `TFont::SetOpticalSize`，不是 `CTFontCreateWithGraphicsFont` 直接路径。

### 2. 用真 opsz 可变字体复测（SFNS.ttf，opsz 轴 17–96）
构造 9 个变体（`harness/fontpoc/os2b/`）：
```
OS/2 v5 完整 96 字节          （对照）
OS/2 v5 但截断到 78/84/90/32 字节   （越界读假设）
OS/2 v5 opsz=[0xFFFF,0xFFFF] / [0xFFFF,0] / [0,0]
OS/2 v4 + opsz 字段
```
真机测 5 个字体 × 9 字号（1,8,16,17,20,28,64,96,200）× **3 条创建路径**：
```
① CTFontCreateWithGraphicsFont(cg, size, NULL, NULL)
② + 描述符带 kCTFontOpticalSizeAttribute
③ + 描述符带 kCTFontVariationAttribute{opsz: size}
→ 142 行日志，全部 OK，无崩溃
```

### 3. 判读
`TFont::SetOpticalSize` 在以下情形才被调用：
- **系统字体匹配**（`CTFontCreateWithName` / `CTFontCreateForString`）选出光学样式时
- 字体经 `CTFontManagerRegisterFontsForURL` **注册进系统**后再按名解析

而「从 data provider 直接造 CGFont」这条路**不经过字体匹配**，所以到不了。

### 4. 若要继续，正确的触发方式
1. 用 `CTFontManagerRegisterFontsForURL` 把恶意字体注册进 app 沙盒的字体域
2. 再用 `CTFontCreateWithName` 按字体族名解析（触发匹配 → SetOpticalSize）
3. 或伪造一个「系统字体替换」（`.SFNS-*` 之类的私有族名）诱导匹配路径

### 5. 诚实结论
已确认：**有实质代码改动（299→886 条，+71 检查）、有对应 CVE（112656）、有唯一入口**。
未确认：**能否从 app 沙盒内真正走到该入口**。
下一步需要验证「字体注册 + 按名解析」这条路——这是可达性的最后一道门。
