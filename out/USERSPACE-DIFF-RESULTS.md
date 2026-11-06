# 用户态补丁点差分 — 首批结果（iOS 27.0.1 ↔ 27.2）

## 怎么拿到的（全离线，无设备、无越狱）
1. `.dmg.aea` 的 AEA 头自带 `fcs-key-url` → 苹果公开 CDN 无鉴权返回 P-256 私钥
2. HPKE 解封出 32 字节对称密钥 → `/usr/bin/aea decrypt`
3. 挂载明文 APFS → 取 `Cryptex` 卷里的 `dyld_shared_cache_arm64e`（5.4GB 分片）
4. `dsc_extractor` 提取出 4696 / 4770 个独立 dylib
5. 按**函数名**对齐比对（同名但指令形状不同 = 被修改）

## 各组件改动统计

| 组件 | 27.0.1 函数 | 27.2 函数 | **同名异形（真改动）** | 仅旧版 | 仅新版 |
|---|---|---|---|---|---|
| **ImageIO** | 11329 | 11374 | **197** | 6 | 51 |
| **libFontParser** | 2555 | 2560 | **68** | 16 | 21 |
| **CoreText** | 4173 | 4177 | **47** | 12 | 16 |
| **CoreGraphics** | 9373 | 9400 | 276 | 262 | 289 |
| **CoreMedia** | 8264 | 8273 | **84** | 20 | 29 |
| JavaScriptCore | 34033 | 34314 | 5274* | 2962 | 3243 |
| WebKit | 61608 | 61769 | 2129* | 1212 | 1373 |

\* WebKit/JSC 的数字含大量假阳性（600 条指令上限截断导致），需提高上限后重算。

## ImageIO 改动最大的函数（197 个中的前列）
```
GPSCopy::processData                          247→470
KTX2ReadPlugin::decodeImageImp                446→601   ← KTX2 纹理解码
KTXReadPlugin::decodeImageImp                 468→601   ← KTX 纹理解码
PSDReadPlugin::mergeLayers                    153→275   ← PSD 图层合并
KTXReadPlugin::initialize                     383→481
_cg_JP2CompressorSetup                        144→239
JP2ReadPlugin::loadDataFromXPCObject           68→127
BCReadPlugin::decode8888toRGBX                118→168
IIO_Reader_BC::testHeader                     267→315   ← Block Compression
IIO_Reader_ASTC::testHeader                   253→300   ← ASTC 纹理
IIOReadPlugin::prepareGeometry                470→511
HEIFWritePlugin::createISO5_MasteringDisplay  110→153
```

## libFontParser 改动最大的函数（68 个中的前列）
```
sc_FindExtrema                                352→235
TFont::CreateFontEntitiesForFile              264→335
TFragmentCache::FindValue                      80→109
TFileDataReference::Map                       123→98
TSFNTOpenTypeCFF2Font::MakeHandler            218→240   ← CFF2 解析
TFlexConversion::AddValue                      86→106
ComputeDestBitmap                             126→107
TType1ToType2CharStringConversionContext::StoreCount 247→231  ← Type1→Type2 转换
RenderBitmap                                  476→489
sbit_GetBitMapInfo                            138→151   ← 嵌入位图（越界写高发区）
```

## 对照 27.2 的 CVE
| 组件 | CVE | 类型 |
|---|---|---|
| **FontParser** | CVE-2026-112683 | **越界写** |
| FontParser | CVE-2026-112642 | 越界读 |
| **Model I/O** | CVE-2026-112486 | **越界写** |
| Model I/O | CVE-2026-112413 | 越界读 |
| Model I/O | CVE-2026-112485 | 内存破坏 |
| ImageIO | CVE-2026-112561 | 越界读（泄漏内存） |
| ImageIO | CVE-2026-112634 | 越界读 |
| CoreText | CVE-2026-112656 | 越界读（泄漏） |
| CoreMedia | CVE-2026-86992 | 内存处理 |

**下一步**：对 `sbit_GetBitMapInfo`、`TSFNTOpenTypeCFF2Font::MakeHandler`、
`KTX2ReadPlugin::decodeImageImp` 等做双版本反编译，确认新增的是边界检查还是重构。

## 产物
- 提取的 dylib：`/tmp/dsc/ios2701/`（4696 个）、`/tmp/dsc/ios272/`（4770 个）
- 解密卷：`fw/ios2701/OS.27.0.1.dmg`、`fw/ios2701/Cryptex.27.0.1.dmg`、
  `fw/ios272/OS.27.2.dmg`、`fw/ios272/Cryptex.27.2.dmg`
- 工具：`tools/aea_unlock.py`、`tools/fwdiff.py`、`tools/namediff.py`、`tools/grab.py`

---

## ✅ 第 1 个确认的修补点：`sbit_GetBitMapInfo`（libFontParser）

### 反编译对比
```c
// 27.0.1（有缺陷）
ComputeDestBitmap(uVar12, &local_80, param_4);          // 返回值直接丢弃

// 27.2（已修）
uVar5 = ComputeDestBitmap(uVar12, &local_80, param_4);
if ((uVar5 & 1) == 0) {                                  // ← 新增返回值检查
    throw(...)                                            // C++ 异常
    return;
}
```

**缺陷**：`ComputeDestBitmap`（位图目标计算）失败时返回值被忽略，
函数继续用未正确初始化的目标位图执行后续写入 → **越界写**。

**修补**：检查返回值 bit0，失败即抛异常返回。

### 对应 CVE
**CVE-2026-112683**（FontParser，越界写）
> "Processing a maliciously crafted font may lead to unexpected app termination or corrupt memory"
> "An out-of-bounds write issue was addressed with improved bounds checking."

### 可达性
字体解析在 WebKit、CoreText、任意用 `CTFontCreateWithData` 的进程内都会触发，
**纯数据驱动，无需任何权限**。

---

## 方法学（可复用于任何 iOS 版本）
```
IPSW → 只取 OS/Cryptex 成员的 .dmg.aea
     → aea_unlock.py（读 fcs-key-url → HPKE 解封 → aea decrypt）
     → hdiutil attach
     → dsc_extractor 提取 Cryptex 里的 dyld_shared_cache
     → namediff.py 按函数名对齐比对（同名异形 = 改动）
     → Ghidra 双版本反编译确认新增判断
```
全程离线，不需要设备、不需要越狱、不需要跑起来。

---

## ✅ 第 2 个确认点：`PSDReadPlugin::mergeLayers`（ImageIO）

**C 代码 116 → 218 行**，新增检查（节选）：
```c
if (0x7f < uVar4)                          // 上界检查
if ((uVar2 & 7) != 0)                      // 对齐检查
if ((ulong)(*(double *)(param_2+0x18) << 2) <= *(ulong *)(param_2+0x30))  // 缓冲区尺寸比较
if ((uVar4 < 0xfd82) && (local_250 == 4))  // 尺寸/类型门槛
```
对应 ImageIO 越界读 CVE（112561 / 112634），入口是 PSD 图层数据解析。

## ✅ 第 3 个确认点：`IIO_Reader_BC::testHeader`（ImageIO）

**163 → 190 行**，新增：
```c
if ((8 < uVar2 - 0x17) || ((0x10dU >> (uVar2 - 0x17 & 0x1f) & 1) == 0))  // 范围+合法集校验
if ((int)uVar2 < 0x42433555) ...                                          // 魔数 'BC4S'/'BC5U'
if (*(int *)(param_2 + 0x58) != 8) return 0;                              // 块大小必须为 8
```
Block Compression 纹理头解析，原本缺魔数/块尺寸校验。

---

## ImageIO 改动排行（按新增检查数）
| Δ检查 | Δ指令 | 函数 |
|---|---|---|
| +29 | +122 | `PSDReadPlugin::mergeLayers` ✅已确认 |
| +21 | +48 | `IIO_Reader_BC::testHeader` ✅已确认 |
| +16 | +98 | `KTXReadPlugin::initialize` |
| +13 | +49 | `BCReadPlugin::decodeImageImp` |
| +12 | +50 | `BCReadPlugin::decode8888toRGBX` |
| +10 | +95 | `_cg_JP2CompressorSetup` |
| +10 | +47 | `IIO_Reader_ASTC::testHeader` |
| +9 | +223 | `GPSCopy::processData` |

---

## ✅ 批量确认：ImageIO 另外 6 个函数

| 函数 | 新增判断 | 关键新增内容 |
|---|---|---|
| `KTXReadPlugin::initialize` | 41 | `((uint)uVar8 & 0xffff) < (uint)local_68` 等尺寸比较 |
| `GPSCopy::processData` | 39 | JPEG 段解析：`if (uVar4 == 0xffd8)` / `0xffe1`，+223 条指令 |
| `IIO_Reader_ASTC::testHeader` | 25 | 新增 DDS 容器识别：`0x93 < len && *p == 'DDS ' && p[0x15] == 'DX10'` |
| `BCReadPlugin::decodeImageImp` | 16 | `if (iVar6 < 0xb444)` / `if (iVar6 != 0x8888)` 格式分派 |
| `BCReadPlugin::decode8888toRGBX` | 15 | `if (lVar4 != lVar10)` / `lVar3 == param_3[3]` 缓冲区尺寸比较 |
| `_cg_JP2CompressorSetup` | 4 | 空指针检查 |

## 累计确认的修补点：**9 个**
libFontParser 1（越界写）、ImageIO 8（越界读为主）。

## PoC 思路（基于差分定向，而非盲 fuzz）
1. 差分告诉我们 27.2 在校验哪些字段：
   - BC：块尺寸必须 == 8、魔数必须在合法集合
   - KTX：宽高 / `& 0xffff` 与声明值关系
   - ASTC/DDS：总长必须 > 0x93 且魔数 'DDS '/'DX10'
   - PSD：图层数据尺寸 `(x<<2) <= y`
2. 针对 27.0.1 **缺失**的这些校验构造文件，把对应字段设成越界值
3. 在真机 app 里用 `CGImageSourceCreateWithData` 解码，观察崩溃 / ASAN 类行为
4. 优先级：ASTC/DDS（校验最简单、字段最明确）> BC > KTX > PSD

---

## PoC 实测结果（真机 iPhone18,2 / iOS 27.0.1）

工具链：`harness/imgpoc/`（`gen.py` 生成畸形文件 + `gen2.py` 定向变体 + `main.m` 用 ImageIO 解码并记录）

### 第一批（14 个：巨大维度 / 异常 mipmap / faces / array）
```
ktx_layers_bad.ktx  →  source OK, count = 2147483647   ← 接受 21 亿张！
dds_arr_max.dds     →  source OK, type=com.microsoft.dds
全部 decode 返回 NULL，未崩溃
```
**有价值的观察**：注入 `numberOfArrayElements = 0x7fffffff` 后，
`CGImageSourceGetCount()` 直接返回 2147483647 —— **27.0.1 完全不做范围校验**，
正是 27.2 新增校验要挡的。但解码器提前返回，未触发内存破坏。

### 第二批（12 个：合法 4x4 / imageSize 巨大但数据短 / 块数据截断）
```
dds_bc1_4x4_ok.dds  →  image 4x4 bpp=32   （唯一成功解码）
其余全部 NULL，未崩溃
```

### 结论
- PoC 基础设施可用，能在真机跑通并观测行为
- **KTX/DDS 解析器对粗暴畸形输入都安全退出**（校验前就 return NULL）
- 要真正触发越界，需要**结构合法但字段内部矛盾**的输入
  （例如 PSD 的图层数据尺寸与实际数据不符、KTX 的 mipmap 层级数据长度不符）
- 确认的 9 个修补点给出了精确的字段位置，下一轮应按 PSD 优先

## 今日总成果
| 项 | 状态 |
|---|---|
| AEA 离线解密（无需设备/越狱） | ✅ 端到端验证（416MB → 480MB APFS，2.4 秒） |
| 从 IPSW 提取系统卷 | ✅ 27.0.1（9.6GB）+ 27.2（9.9GB）+ 两个 Cryptex |
| dyld 缓存提取 | ✅ 4696 / 4770 个带完整符号的 dylib |
| 按名对齐差分工具 | ✅ `tools/namediff.py` |
| **已确认修补点** | **9 个**（libFontParser 1 越界写 + ImageIO 8） |
| PoC 框架 | ✅ 真机可跑，已观测到元数据校验缺失 |
| 内存破坏 PoC | ❌ 未达成（需更精细的构造） |

---

## ⚠️ 重要修正：部分"修补点"其实是功能新增

### 观察
- `IIO_Reader_ASTC::testHeader` 新增 `*param_2 == 'DDS ' && param_2[0x15] == 'DX10'` → 这是**新增 DDS 容器识别**
- `IIO_Reader_BC::testHeader` 新增 'BC4S'/'BC5U' 魔数比较 → 同样是**格式识别扩展**
- `KTXReadPlugin::initialize` 41 处新增判断 → 版本/格式兼容扩展

**即：ASTC / BC / KTX 那批大改动，很可能是 iOS 27.2 新增纹理格式支持，
不是安全修补。** 我把"改动大"当成了"修补重"，这是判断失误。

### 仍然站得住的
| 函数 | 为什么仍认为是修补 |
|---|---|
| `libFontParser sbit_GetBitMapInfo` | 27.0.1 **丢弃** `ComputeDestBitmap` 返回值；27.2 检查失败即抛异常。纯鲁棒性修复，无功能动机 |
| `PSDReadPlugin::mergeLayers` | 新增 `(width<<2) <= buffer_size` 缓冲尺寸比较，属防护性检查 |
| `GPSCopy::processData` | JPEG 段解析新增边界判断 |

其余（ASTC/BC/KTX/JP2）**需要重新判定**，倾向功能新增。

### PSD PoC 实测（真机）
```
psd_canvas4_layer1024.psd   → image 4x4 bpp=32   正常解码
psd_canvas8_layer512.psd    → image 8x8 bpp=32   正常解码
psd_canvas16_layer4096x64   → image 16x16 bpp=32 正常解码
psd_canvas4_layer8192x8     → image 4x4 bpp=32   正常解码
均未崩溃
```
**结论**：图层矩形超出画布时，ImageIO 会安全裁剪，不触发越界写。
27.2 新增的缓冲尺寸检查属于纵深防御，对应漏洞需要更特殊的构造。

### 诚实的方法论教训（第四次同类错误）
前三次是工具层面的假阳性（内联重构 / 地址重定位 / 分支重排），
这次是**语义层面的误判**：把"改动大"等同于"修补重"。
⚠️ **补丁差分只能告诉你"哪里变了"，不能告诉你"为什么变"。
必须结合"是否有功能动机"来判断，否则会把新功能当成安全修复。**

---

## 字体 PoC 实测（真机，全部未崩溃）

测试框架：`harness/fontpoc/`（`makefonts.py` 用 fontTools 造畸形 sbix 字体 + `main.m` 用 CoreText 渲染）

| 测试 | 输入 | 结果 |
|---|---|---|
| 极端字号 | AppleColorEmoji / Helvetica / PingFang，size 12 → 1e9 | 全部正常 |
| 极端变换 | scale 1e6 / 1e-6 / 1e9 | 全部正常（被钳制）|
| 畸形 sbix | ppem=65535 / ppem=1 / origin=±32767 / 空数据 / 垃圾数据 | 全部正常 |
| 渲染路径 | `CGContextShowGlyphsAtPositions` → `CTFontDrawGlyphs` | 两条路径都正常 |

**结论**：CoreText 对字号、变换、sbix 元数据都做了安全钳制，
未能在 27.0.1 上触发 `ComputeDestBitmap` 失败路径。

### 若要继续这条线
需要精确逆出 `ComputeDestBitmap` 的失败条件（它返回 bit0=0 的判据），
再用能命中该判据的字体/变换组合。这是纯静态工作，不靠试错。

### 踩过的坑（供后续参考）
1. 字体路径在 iOS 27 变了（`/System/Library/Fonts/Core/` 下 75 项），要用 `CTFontCreateWithName`
2. `CGContextShowGlyphsAtPositions` **不查 sbix**，必须用 `CTFontDrawGlyphs`
3. sbix 数据要挂在字形名上，绘制必须用 cmap 解析出的真实 glyph id（'A' → 2063）

---

## PoC 全量试错记录（4 类攻击面，约 70 个输入，全部未崩溃）

| 攻击面 | 输入数 | 手法 | 结果 |
|---|---|---|---|
| KTX / DDS 纹理 | 26 | 巨大维度、异常 mipmap/faces/array、截断块数据 | 全部安全返回 NULL |
| PSD 图层 | 4 | 画布 4×4 但图层矩形 1024×1024 / 8192×8 | 全部正常解码（安全裁剪）|
| sbix 嵌入位图字体 | 6 字体 × 4 字号 × 2 渲染路径 | ppem=65535/1、origin=±32767、空/垃圾数据 | 全部正常渲染 |
| JPEG EXIF / TIFF / PNG / PDF Type1 | 25 | IFD 计数 0/0xFFFF、EXIF 偏移 0x7FFFFFFF、PNG 维度 0x7FFFFFFF、PDF Type1 Subset 0/0xFFFF | 全部安全拒绝或正常渲染 |

### 观察到的有价值行为
1. **KTX `numberOfArrayElements=0x7FFFFFFF` → `CGImageSourceGetCount()` 返回 2147483647**
   —— 27.0.1 不做范围校验（27.2 新增校验要挡的），但解码器提前返回，不触发越界
2. 所有解析器对"粗暴畸形"（极端字段值）都有安全退出，不会走到越界
3. PDF Type1 Subset 各变体都能正常渲染

### 结论
**朴素畸形输入打不动这些解析器。** 要触发真实的越界，
必须精确命中"结构合法但内部字段矛盾"的状态——需要先静态逆出具体的失败判据，
再反推输入构造。这是纯静态工作，不是试错能解决的。

### 今天的 PoC 结论
- ✅ PoC 基础设施完整可用（生成器 + 真机解码 + 日志回传，全部跑通）
- ✅ 观测到元数据校验缺失（KTX count=0x7FFFFFFF）
- ❌ 未能在 27.0.1 上触发任何内存破坏

---

## 静态深挖结果：`sbit_GetBitMapInfo` / `ComputeDestBitmap` 完整逆向

### 27.2 的两处修补（都已确认）

**修补 1：`ComputeDestBitmap` 改为返回状态，每次 M3x3Mul 后检查**
```c
// 27.0.1（void，返回值全丢）
M3x3Mul(m, flags, &p0, 1); M3x3Mul(m, flags, &p1, 1);
M3x3Mul(m, flags, &p2, 1); M3x3Mul(m, flags, &p3, 1);
// 27.2（逐级检查，任一失败即返回）
iVar3 = M3x3Mul(...); if (iVar3 == 0) { ... }
```

**修补 2：`rowBytes * height` 的 32 位乘法回绕**
```c
// 27.0.1
iVar3 = *(int*)(param_4+4) * (uVar7 & 0xffff);   // 32 位，可回绕
*piVar9 = iVar3;                                  // 用作位图块分配大小
// 27.2
uVar5 = (ulong)rowBytes * (ulong)(uVar7 & 0xffff);
if ((uVar5 & 0xffffffff00000000) != 0) throw;     // 溢出即拒绝
```

### `M3x3Mul` 失败判据（逆出）
- `flags == 7`（w=0 透视退化）→ 返回 1。**但 CGAffineTransform 恒有 w=1，此路不可达**
- `flags ∈ 0..5`：16.16 定点乘法结果超出 int32 → 返回 1
- `flags == 6`：齐次分母 < 1 → 返回 1

### 理论触发条件（修补 2）
`rowBytes × height > 4294967295`，其中 `rowBytes ≈ 宽度/8`、`height ≤ 65535`
→ 需要 **dest 宽度 > 524288 设备像素**

### 实测：不可达（真机验证）
```
合法 PNG 的 sbix 字体（ppem 64/256/1024/4096），
请求字号 262144 / 524288 / 1048576 / 4194304 / 16777216
CTM 放大 16384 / 65536 / 262144
→ CTFontGetSize 如实返回（未钳制），但绘制全部成功，无崩溃
```

**根因分析**：CoreText 只在**请求字号 ≈ strike ppem** 时启用嵌入位图路径；
字号远离 ppem 时回退轮廓渲染。而 ppem 上限 65535，
此时 `rowBytes × height ≤ 8192 × 65535 ≈ 5.3e8`，**够不到 4.29e9 的溢出门槛**。

→ **两条约束互相掐死：要位图路径就得字号≈ppem（dest 不够大），
  要 dest 够大就得字号≫ppem（不走位图路径）。**

### 结论
`sbit_GetBitMapInfo` 的两处修补属于**纵深防御（hardening）**，
在 CoreText 现有的渲染路径约束下**不可达**。
这与"ASTC/BC/KTX 是功能新增"一起，说明 27.2 的很多改动是加固而非对应可达漏洞。

### 今日 PoC 最终结论
| 攻击面 | 结果 |
|---|---|
| KTX/DDS/PSD/JPEG/TIFF/PNG 畸形（约 70 个输入） | 全部安全 |
| sbix 畸形 + 极端字号 + 极端 CTM | 全部安全 |
| 退化变换矩阵 | 静态证明不可达 |
| `rowBytes×height` 溢出 | 静态+实测证明不可达 |

**未能在 iOS 27.0.1 上触发任何内存破坏。**

---

# 静态逆向最终结论（子代理，见 out/STATIC-ANALYSIS.md 427 行）

## ⚠️ 决定性判定：`sbit_GetBitMapInfo` 攻击面选错了

七个结构常数逐一对上 **EBLC/CBLC + EBDT/CBDT + EBSC**（老式嵌入位图表），**不是 sbix**：

| 反编译 | OpenType 结构 |
|---|---|
| `*local_68 == 0x200` | **EBSC** version `0x00020000` |
| 步进 `0x1c`，`ppemX@0x18 / ppemY@0x19` | **EBSC `bitmapScaleTable`**（28 字节）|
| 步进 `0x30` | **EBLC `bitmapSizeTable`**（48 字节）|
| `lVar18 + 5` | **`SmallGlyphMetrics`**（5 字节）|
| `*(byte*)(lVar25+0x5e)` 分派 1/2/4 | **EBDT `imageFormat`** |
| 表 tag `0x45425343` | **`EBSC`** |

→ **sbix 的 PNG 由 CoreText 侧当图片缩放，根本不经过 `sbit_*`。**
之前 6 个 sbix 字体 × 4 字号 × 2 路径全部无效，**不是参数不对，是表选错了**。

## `M3x3Mul` / `ComputeDestBitmap` 判据（已完全逆清）
- `M3x3Flags()==7` ⇔ `m[8] < 1`（w<1）→ 但 `CGAffineTransform` 恒有 `m[8]=0x40000000`，**永不可达**
- flags∈0..5：定点溢出（`(x*m+0x8000)>>16` 放不进 int32）
- flags==6：透视分母 < 1

## 实测
- 真机 **624 次绘制**（6 个合法 PNG sbix 字体 × 26 字号 64→262144 × 4 绘制模式）：**无崩溃**
- `CTFontGetSize()` 与请求值完全一致（没有被钳制，此前判断不准）
- 墨迹严格 = `(字号×CTM)²`，跨 32768/65536 阈值**无任何突变** → 失败路径从未触发

## 补充推导
失败后角点必然落在以 2³² 为模的 65536 px 窗口内 → 包络 ≤ 65536 px
→ `rowBytes ≤ 8192` → `rowBytes*height ≤ 5.4e8 < 2³¹` **不会回绕**。
即 M3x3Mul 失败只造成**位图塌缩（视觉异常）**，不足以构成越界写。
真正的 OOB 更可能在 `RenderBitmap` 的 1bpp→4bit 展开分支（32 位乘可回绕）。

## 🆕 附带发现：真实 DoS
**`CTFontGetBoundingRectsForGlyphs` 对 sbix 字形必挂死**（2/2 可复现，60 秒无进展；
去掉该调用后同一 app 跑完 878 行）。
任何做字形测量/排版计算的进程（WebKit、任意 app）都会被卡死。
怀疑在 `sbit_CalculateTransformSpaceNeeded` 找最大子表的循环。

---

# 转向 Model I/O（参考 CVE 表）

## 定位
`ModelIO.framework` 两个版本**完全一致**（4987 函数、形状零差异）→ CVE 不在这里。
真实 3D 解析在 **`/usr/lib/usd/libusd_ms.dylib`（OpenUSD，63MB，30203 函数）**。

## 差分结果：34 处改动，集中在文本/纹理/图像解析
```
SdfZipFile::Iterator::operator++        +62    ← USDZ(ZIP) 条目迭代
SdfZipFile::Iterator::Iterator(_Impl*)  +73
SdfZipFile::DumpContents                +38
SdfZipFile::Open                        -10
ArMemoryResolver::_Resolve              +36
ArMemoryResolver::_OpenAsset            +26
adobe::usd::Image::allocate            +106    ← USD 内嵌图片
adobe::usd::Image::read                +100
processAnisotropyPixelsFromRoughness    +92
HdStPtexMipmapTextureLoader::Block::Generate +170 (Ptex 纹理)
```

**USDZ 就是 ZIP 包**，`SdfZipFile::Iterator` 大改 = ZIP 解析越界防护的典型形态，
对应 **Model I/O CVE-2026-112486（越界写）/ 112413（越界读）**。

## USDZ PoC 就绪（等设备解锁）

已构造 14 个畸形 USDZ（`harness/usdpoc/usdz/`），全部通过 ZIP 结构自检：
```
usdz_ok.usdz                  正常版（自检通过，59 字节 usda）
usdz_cdoff_{4,10000000,7fffffff,ffffffff}.usdz   中央目录偏移越界
usdz_cdcount_{1000,32767,65535}.usdz             条目数异常
usdz_lhoff_{7fffff00,7fffffff,ffffffff}.usdz     本地头偏移越界
usdz_namelen_ffff / extra_ffff / compsize_huge    长度字段异常
```
测试 app：`harness/usdpoc/`（`MDLAsset initWithURL:`，14 个文件全跑，逐项记录 count / 异常）

**阻塞**：设备锁屏，`install`/`launch` 全部被拒（`BSErrorCodeDescription = Locked`）。
解锁后一条命令即可取结果。

## 27.0.1 `SdfZipFile::Iterator::operator++` 反汇编（关键）
```asm
ldr x8, [x0]              ; _Impl*
ldr x9, [x8]
ldp x10, x9, [x9,#0xf8]   ; base 指针
ldr x8, [x8, #0x48]       ; offset（来自 ZIP 中央目录）
add x11, x10, x8          ; ← base + offset，【无任何边界检查】
bl  ...                   ; 直接解引用读取
cmp w8, #0x04034b50       ; 读到之后才校验 "PK\3\4" 签名
```
**先读后校验、offset 不受限** → 典型的越界读形态。

27.2 的对应函数（107 条 vs 45 条）改动是**新增第二条代码路径 + shared_ptr 引用计数**
（结构体偏移 0xf8→0x178、0x48→0x50），`base+offset` 处**仍未加边界检查**。
→ 修复点可能在别处（`SdfZipFile::Open` -10 / `DumpContents` +38 / `ArMemoryResolver` +36/+26），
   或该函数本身并非漏洞所在。

---

# 新发现：`sbit_CalculateTransformSpaceNeeded` 的数组边界不一致（两个版本都未修）

## 反汇编（libFontParser，27.0.1 `0x1b7ab83d0`，27.2 同函数指令数 66→66，**完全相同**）
```asm
ldr  w8,  [x1]              ; EBSC version，要求 == 0x200
ldr  w9,  [x1, #4]          ; numSizes（攻击者可控）
sub  x10, x8, #8
umulh/lsr x10,...           ; x10 = (len - 8) / 28      ← 容量按 28 字节/条算
cmp  w9, w10
csel w9, w9, w10, lo        ; w9 = min(numSizes, (len-8)/28)
loop:
  ldr  w12, [x11]           ; 读条目
  cmp  w12, w8
  b.hs throw                ; 值 >= len 即抛
  ...
  add  x11, x11, #0x30      ; ← 步进 48 字节（不是 28！）
  sub  w9, w9, #1
  cbnz w9, loop
```

**缺陷**：容量按 **28 字节/条** 计算，实际步进 **48 字节/条**。
条目数 >1 时，第 k 次读取位于 `8 + 48k`，可远超表尾 → **越界读**。
且 `numSizes` 与表长都来自字体，若表长被放大，`capacity` 可达上亿 →
**循环巨久 + 大量越界读 = 挂死**。

## 与子代理实测的对应
子代理观测到 `CTFontGetBoundingRectsForGlyphs` 对嵌入位图字体**必挂死**（2/2，60 秒无进展）。
本函数正是字形测量路径上读 EBSC 的地方，**行为吻合**。

## 关键点：这是未修补的活漏洞
| 版本 | 函数指令数 | 是否相同 |
|---|---|---|
| 27.0.1 | 66 | — |
| 27.2 | 66 | **完全相同** |
`FPFontGetBoundingBox`、`sbit_FontMatch`、`sbit_IsThereAGlyphImage` 也全部相同。
→ **不是 27.2 修的补丁，而是两版都存在的缺陷**，属于可报的 DoS/OOB read。

## 已就绪的 PoC 产物（等设备解锁）
`harness/fontpoc/ebsc/`（3 个）：
```
ebsc_numsizes_max_len4x.ttf    EBSC 实际 64B → 目录声明 256B      numSizes=0xFFFFFFFF
ebsc_numsizes_max_len1k.ttf    EBSC 实际 64B → 目录声明 65536B
ebsc_numsizes_max_len64k.ttf   EBSC 实际 64B → 目录声明 4MB
```
（用 EBLC/EBDT 表进入 `sbit_*` 路径；生成器 `makeebsc.py`，用 `DefaultTable` 绕过 fontTools 的 EBDT 解析器）

测试 app `harness/fontpoc/`（已签名有效）依次调用：
`CTFontGetBoundingRectsForGlyphs` → `CTFontGetAdvancesForGlyphs` → `CTFontDrawGlyphs`
每步前后都写日志，**挂死时可从日志定位到具体哪一步**。

解锁后执行：
```
DEV=DEVICE-UDID
xcrun devicectl device install app --device $DEV harness/fontpoc/Payload/FP.app
xcrun devicectl device process launch --device $DEV com.example.ios27poc
sleep 30
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer \
  --domain-identifier com.example.ios27poc --source tmp/fontpoc.log --destination /tmp/fontpoc.log
```
判读：日志停在 `[1] ... 开始` 无「完成」⇒ **DoS 复现成功**。

---

# 🔬 真机实测收尾（设备已解锁）

## 实测 1：EBSC 长度放大的字体 —— 未挂死，且 EBDT 被忽略
5 个字体 × 3 个 API = 15 次调用，**全部完成**，无挂死、无崩溃。

关键判读（决定性）：
| 字体 | CTFontGetBoundingRectsForGlyphs 返回 |
|---|---|
| `eb_nooutline.ttf`（只有 EBDT 位图，无轮廓） | **rect=(0.0, 0.0, 0.0, 0.0)** ← 什么都没画 |
| `eb_64x64_ppem12.ttf`（EBDT + 轮廓） | rect=(0.7, 0.0, 31.7, 34.4) ← **与普通轮廓字体完全相同** |
| `ebsc_numsizes_max_len*`（EBSC 长度放大） | 同上，无差异 |

→ **iOS 27 的 CoreText 完全忽略 EBDT/EBLC**，`sbit_*` 标量位图路径是**死代码**。

## 实测 2：sbix 字体 —— 同样被忽略，且**未挂死**
3 个 sbix 字体（ppem 64/512/4096）× 3 个 API，全部正常完成：
```
sbix_png4096_ppem4096.ttf → rect=(0.7,0.0,31.7,34.4)   ← 与轮廓字体相同
sbix_png4096_ppem512.ttf  → rect=(0.7,0.0,31.7,34.4)
sbix_png64_ppem64.ttf     → rect=(0.7,0.0,31.7,34.4)
=== done 未挂死 ===
```

### ⚠️ 更正子代理的 DoS 结论
子代理报告「`CTFontGetBoundingRectsForGlyphs` 对 sbix 字形必挂死（2/2）」。
**我用 3 个不同的合法 sbix 字体、3 个 API 重复测试，均无法复现挂死。**
该结论**不予采信**，已从结论中剔除（可能是它自己的测试代码问题或特定字体组合所致）。

## 🎯 FontParser 这条线正式关闭

| 攻击面 | 结论 | 证据 |
|---|---|---|
| sbix（PNG 位图） | 不进入 `sbit_*` | 7 个结构常数不符 + 实测 rect 与轮廓一致 |
| EBDT/EBLC/EBSC | **iOS 27 已忽略** | `eb_nooutline.ttf` 渲染出 0 墨迹 |
| 退化变换矩阵 | 不可达 | `CGAffineTransform` 恒 w=1 |
| `rowBytes*height` 溢出 | 不可达 | 需 dest 宽 >524288，与位图路径互斥 |

**CVE-2026-112683（FontParser 越界写）在 iOS 27 上无法作为 app 攻击面触达。**
27.2 的两处修补（`ComputeDestBitmap` 返回值检查、64 位乘法）属于**纵深防御**，
可能服务于其他平台/历史路径。

## 今日最终交付
- AEA 离线解密链（端到端验证）
- 用户态差分流水线（`aea_unlock.py` / `grab.py` / `fwdiff.py` / `namediff.py`）
- 9 个差分候选 + FontParser 全部逆向到判据级
- USD/ModelIO 新攻击面定位（34 处改动，`SdfZipFile` 等）
- 2 次子代理误判的纠正（sbix≠EBDT；DoS 不可复现）

---

# USDZ / Model I/O 实测：14 个畸形文件全部无崩溃

```
canImport usdz=1
usdz_ok.usdz                → asset OK count=1  [0] MDLObject
usdz_cdoff_ffffffff.usdz    → asset OK count=1  [0] MDLObject   ← 中央目录全废也能读
usdz_cdoff_7fffffff.usdz    → asset OK count=1
usdz_lhoff_ffffffff.usdz    → asset OK count=1
usdz_cdcount_65535.usdz     → asset OK count=1
usdz_namelen_ffff.usdz      → asset OK count=0  (正确拒绝)
usdz_compsize_huge.usdz     → asset OK count=0  (正确拒绝)
=== done 未崩溃 ===
```

**关键观察**：即使中央目录偏移被改成 `0xFFFFFFFF`，仍返回 `count=1`。
说明 USD **在中央目录损坏时会退化为顺序扫描本地文件头**，
根本走不到 `SdfZipFile::Iterator` 那条依赖中央目录偏移的路径。
→ 朴素 ZIP 字段畸形无法命中。

---

# �� 系统性结论：差分引导的朴素畸形法已穷尽

## 五个攻击面，全部失败
| # | 攻击面 | 输入量 | 失败原因 |
|---|---|---|---|
| 1 | KTX/DDS 纹理 | 26 | 解析器提前 return NULL |
| 2 | PSD 图层 | 4 | 上层安全裁剪 |
| 3 | sbix 字体 | 6 字体 × 多参数 | **走不到 sbit_\*（表选错）** |
| 4 | JPEG/TIFF/PNG/PDF | 25 | 安全拒绝 |
| 5 | USDZ/ModelIO | 14 | 退化为顺序扫描，绕开目标路径 |

## 为什么这条路系统性失效
1. **差分只告诉你"哪里变了"，不告诉你"为什么变"**
   （ASTC/BC/KTX 大改动 = 新增 DDS 支持，不是安全修复）
2. **未修复的漏洞在差分里不可见**
   （`sbit_CalculateTransformSpaceNeeded` 两版完全相同，差分找不到）
3. **"漏掉校验" ≠ "可达漏洞"**
   PSD 的校验在更上层；FontParser 的代码是死的；USDZ 有降级路径
4. **现代解析器对"字段取极值"普遍有安全退出**
   要触发必须构造"结构合法但内部自相矛盾"的状态，需要精确的格式语义知识

## 可行的下一步（按性价比）
| 方案 | 成本 | 预期 |
|---|---|---|
| **覆盖率引导 fuzz**（在真机上跑，libFuzzer/AFL + harness） | 高（需建 harness + 长时间跑） | **最高**，能自动找到"结构矛盾"输入 |
| 深挖单个格式语义（如 USD usda 文本解析器） | 中高 | 中 |
| 转向内核/网络面（13 个网络可达 CVE） | 中 | 已知有真 DoS（AVE 已复现 3/3） |
| 接受 27.0.1 用户态已充分加固 | — | 诚实结论 |
