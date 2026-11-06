# CoreText 光學尺寸解析（CVE-2026-112656）— 可達性驗證與 PoC 嘗試【終版】

> 承接 `out/HANDOFF-CORETEXT.md`。本文只做一件事：驗證
> `TFont::SetOpticalSize` → `TFont::SelectOpticalStyleFromOS2` 這條路徑在
> iOS 27.0.1（24A446）的 app 沙盒內是否可達，並嘗試做出 PoC。
>
> 實測環境：iPhone 18,2 / iOS 27.0.1 (24A446) / bundle `com.example.ios27poc`
>
> **與 `out/STATIC-ANALYSIS-CORETEXT.md` 的關係**：那份是階段性記錄（含路線 B
> 的進行中狀態）。本文是同一個入口的**完整終版**，補上了 §3.4 的決定性探針、
> §2.3/§2.4 的反匯編定性、以及 §1 的三處更正。建議以本文為準。

---

## 0. 結論摘要

| 問題 | 結論 | 依據 |
|---|---|---|
| `TFont::SetOpticalSize` 會被 app 觸發嗎？ | **會，且是無條件呼叫** | 6 個呼叫者全是 `TFont` 建構式；`CTFontCreateWithGraphicsFont` 那條在 `0x19a29f128` 是無條件 `bl` |
| CoreText 會讀沙盒內註冊字體的 OS/2 v5 光學尺寸欄位嗎？ | **會，且讀到的就是我偽造的位元組** | `CTFontCopyAttribute(...,"CTFontOpticalPointSizesAttribute")` 回傳 `(upper<<16)|lower`，18/18 字體逐一對上 |
| 「宣告 v5 但表不足 100 字節 → 越界讀」成立嗎？ | **不成立。27.0.1 已有長度校驗** | `0x19a2ae2d8: cmp x8, #0x64` / `0x19a2ae2f0: cmp w9, #5`，在讀 `+0x60/+0x62` 之前 |
| 27.2 的 `299 → 886` 是「新增 71 處邊界檢查」嗎？ | **不是，主要是加了一層全域哈希快取** | 新增指令中 129 條（含 45 條比較）純屬哈希表查找；`CopyOpticalPointSizes` 兩版指令序列一致 |
| PoC 成功了嗎？ | **沒有。540 次字體建立 + 18 次註冊，零崩潰** | `harness/ctreach/logs/run-full-18fonts.log` |

**一句話**：這條路徑的**入口可達**（比前文判斷的更可達），但 **CVE 假設的觸發方式
（截斷 OS/2 表）在 27.0.1 已經被堵住**，越界讀在讀取點之前就被長度校驗攔下。
交付結論：**「入口可達、越界不可達」**，與 FontParser 那條的處理方式一致。

---

## 1. 對前文的更正（重要，請一併更新認識）

### 更正 1：`SetOpticalSize` 不是「只在系統字體匹配時」被呼叫

`HANDOFF-CORETEXT.md` §二 的根因判斷是：

> 「`TFont::SetOpticalSize` 只在**系統字體匹配**時調用；從 data provider 直接造
> `CGFont` 不經過匹配，所以到不了目標函數。」

**這是錯的。** `tools/xref.py` 對 `TFont::SetOpticalSize`（`0x19a2570a4`）的直接呼叫者是
6 個建構式，全部無條件呼叫：

```
[直接调用] 6 处
   0x19a25637c bl  ← TFont::TFont(__CTFontDescriptor const*, double, CGAffineTransform const*, __CTFontDescriptor const*)
   0x19a27cc90 bl  ← TFont::TFont(__CFString const*, double, CGAffineTransform const*, char const*, unsigned long)
   0x19a29f128 bl  ← TFont::TFont(CGFont*, double, CGAffineTransform const*, __CTFontDescriptor const*)   ★ CTFontCreateWithGraphicsFont
   0x19a2a2750 bl  ← TFont::TFont(__CTFontDescriptor const*, double, CGAffineTransform const*, unsigned, __CTFontDescriptor const*)
   0x19a2ca240 bl  ← TFont::TFont(TFont const&, char16_t const*, unsigned long, __CFString const*, unsigned long, CTFontFallbackMode, long&)
   0x19a309b20 bl  ← TFont::TFont(TFont const&, char16_t const*, unsigned long, CFRange&)
```

CGFont 建構式裡的呼叫上下文（`0x19a29f100`–`0x19a29f128`）沒有任何條件分支：

```asm
0x19a29f100  mov  x0, x19            ; this
0x19a29f104  mov  x1, x20            ; 傳進來的 descriptor
0x19a29f108  mov  x2, #0
0x19a29f10c  bl   #0x19a2563a0
0x19a29f110  mov  x0, x19
0x19a29f114  mov  w1, #0
0x19a29f118  mov  x2, x20
0x19a29f11c  bl   #0x19a2568f8
0x19a29f120  mov  x0, x19
0x19a29f124  mov  x1, x20
0x19a29f128  bl   #0x19a2570a4      ; ← TFont::SetOpticalSize，無條件
```

→ 上一輪 142 次「全綠」的真正原因**不是進不去**，而是進去了卻在 `SetOpticalSize`
內部的守衛上退出。守衛見 §2.2。

### 更正 2：OS/2 v5 光學尺寸欄位在偏移 **96 / 98**，不是 92 / 94

前文與 `makeos2.py` / `makeos2b.py` 都按「偏移 92 / 94」構造，這是錯的。實際佈局：

| OS/2 版本 | 表長度 | 說明 |
|---|---|---|
| v0 | 78 | |
| v1 | 86 | |
| v2–v4 | 96 | |
| **v5** | **100** | `+96 usLowerOpticalPointSize`、`+98 usUpperOpticalPointSize` |
| | | 偏移 92/94 是 `usBreakChar` / `usMaxContext`（v2 起就有，不是光學尺寸）|

反匯編直接印證（`0x19a2ae2f8` / `0x19a2ae2fc`：`ldrh w9,[x8,#0x60]`、
`ldrh w8,[x8,#0x62]` → 96 / 98）。

**後果**：舊腳本截斷到 78/84/90 字節的那些字體，**根本還沒走到光學尺寸欄位**
（甚至沒到 v2+ 的 96 字節邊界），自然不可能觸發任何與光學尺寸相關的讀取。
這一條足以解釋上一輪 142 次為何全無反應。

本輪已改用 `makeos2c.py`，偏移、長度、以及「目錄長度謊報」都按正確規格構造。

### 更正 3：「+71 處新增邊界檢查」很可能是誤判

`out/SCAN-ALL-RESULTS.md` 把 `cmp/條件跳轉` 增量當成「新增校驗」。實測統計
（本輪用 capstone 直接數）：

| | 27.0.1 | 27.2 |
|---|---|---|
| `SelectOpticalStyleFromOS2` 指令數 | 301 | 885 |
| 比較／條件跳轉 | 45 | **172**（Δ=127，非 71；量測口徑不同） |
| 其中「純哈希表查找」區塊（`0x19a4acb58–0x19a4acc58`、`0x19a4acdd0–0x19a4acec8`） | — | 129 條指令、**45 條比較** |

也就是說 Δ 比較裡 **35%（45/127）純粹來自 `unordered_map` 查找**
（`udiv` / `msub` / `tst` / `cmp` 這類哈希取模與 bucket 比對），與邊界檢查無關。
27.2 相對 27.0.1 的主要語意變化是加了一層全域快取：

```asm
; 27.2 新增：全域快取（27.0.1 這裡只有約 10 條指令）
0x19a4acb58  adrp x8, #0x1edfa1000
0x19a4acb5c  add  x8, x8, #0xb78
0x19a4acb60  ldaprb w8, [x8]          ; 全域 "已有快取" 旗標
0x19a4acb64  tbz  w8, #0, #0x19a4ad770
0x19a4acb78  mov  x0, x22
0x19a4acb7c  mov  w1, #0x50000
0x19a4acb80  bl   #0x1a0103c80        ; 取鎖
0x19a4acba8  bl   #0x1a00fe080        ; 算 key 的哈希
0x19a4acbc8  udiv x8, x24, x19
0x19a4acbcc  msub x26, x8, x19, x24   ; key % bucket_count
0x19a4acbdc  ldr  x8, [x8, x26, lsl #3]
```

**更關鍵的反證**：真正讀 OS/2 光學尺寸的 `TBaseFont::CopyOpticalPointSizes`
兩版指令序列**逐條相同**（連 `cmp x8,#0x64` 的位置都一致）：

| | 27.0.1 | 27.2 |
|---|---|---|
| `TBaseFont::CopyOpticalPointSizes` | `0x19a2ae228`，含 `cmp x8,#0x64` / `cmp w9,#5` | `0x19a44f32c`，同樣的 `cmp x8,#0x64` / `cmp w9,#5` |

`TBaseFont::GetOpticalPointSizes` 則是 54 → 32 條（**變短**，因為把解包邏輯
抽成新的 `TBaseFont::UnpackOpticalPointSizesAttribute`，語意不變）。**沒有任何一處
是「加校驗」**。

→ **判斷**：`CVE-2026-112656` 若要對應到 CoreText 的哪個修補，**不會是這條 OS/2
光學尺寸路徑**；`SelectOpticalStyleFromOS2` 的膨脹形態是「加快取」的效能重構，
不是安全強化。建議把這條從「最高質量線索」降級。

---

## 2. 反匯編事實（附片段）

### 2.1 目標函數與呼叫者

```
__ZN5TFont25SelectOpticalStyleFromOS2EPK9TBaseFontb
  = TFont::SelectOpticalStyleFromOS2(TBaseFont const*, bool)
  27.0.1  0x19a30b73c  301 條
  27.2    0x19a4ac9d0  885 條
唯一呼叫者 = TFont::SetOpticalSize(__CTFontDescriptor const*) 0x19a2570a4
  0x19a2574e4  bl   （呼叫點 1）
  0x19a2577cc  bl   （呼叫點 2）
```

### 2.2 `SetOpticalSize` 的守衛鏈（為何 142 次會全綠）

```asm
; ---- 入口 ----
0x19a2570cc  ldr  x21, [x0, #0x198]   ; x21 = TBaseFont*
0x19a2570d0  cbz  x21, ...            ; 沒有 TBaseFont → 直接返回
; ---- 取描述符上的 kCTFontOpticalSizeAttribute ----
0x19a2570e0  add  x8, x0, #0xa8       ; TFont+0xa8 = descriptor
0x19a2570e4  ldapr x0, [x8]
0x19a2570ec  adrp x8, #0x1e0ce9000
0x19a2570f0  add  x8, x8, #0xef0      ; ← _kCTFontOpticalSizeAttribute
0x19a2570f4  ldr  x1, [x8]
0x19a2570f8  bl   #0x1a00f9760        ; CFDictionaryGetValue(desc, key)
...
; ---- ★ 光學尺寸 == 0 → 立刻返回（沒有這個屬性就一定到不了）----
0x19a257314  ldr  d0, [sp, #0x30]
0x19a257318  str  d0, [x19, #0x20]    ; TFont+0x20 = 當前光學尺寸
0x19a2573b4  fcmp d0, #0.0
0x19a2573b8  cset w8, eq
0x19a2573bc  bic  w8, w8, w23
0x19a2573c0  tbnz w8, #0, #0x19a257948   ; 光學尺寸為 0 → 返回
; ---- 表存在性檢查 ----
0x19a257130  mov  w1, #0x4154
0x19a257134  movk w1, #0x5354, lsl #16   ; 0x53544154 = "STAT"
0x19a25713c  blraa x8, x16               ; HasTable("STAT")
0x19a257188  mov  w1, #0x616b
0x19a25718c  movk w1, #0x7472, lsl #16   ; 0x7472616b = "trak"
0x19a257194  blraa x8, x16               ; HasTable("trak")
; ---- 兩道偏好設定閘（皆為常數字串）----
0x19a2573c4  adrp x0, #0x19a424000 ; "CoreText"
0x19a2573cc  adrp x1, #0x19a425000 ; "AltThaiUIFont"
0x19a2573d4  bl   #0x1a00f6dd0
0x19a2573d8  cbz  w0, #0x19a25745c
0x19a2573e4  adrp x1, #0x19a425000 ; "AllowMixedThaiFontStyles"
0x19a2573ec  bl   #0x1a00f6dd0
0x19a2573f0  cbz  w0, #0x19a25745c
; ---- ★ 字體資料物件的型別閘 ----
0x19a2573fc  ldr  x8, [x19, #0x198]
0x19a257400  add  x8, x8, #0x60          ; TBaseFont+0x60 = 字體資料物件
0x19a257404  ldapr x0, [x8]
0x19a257424  cmp  x0, #0x1ead5f0d8       ; 型別比對
0x19a257440  bl   #0x1a0101990          ; dynamic_cast
0x19a257454  cbnz w8, #0x19a2574d8      ; 只有轉型成功才走到呼叫點 1
0x19a2574d8  mov  x0, x19
0x19a2574dc  mov  x1, x21
0x19a2574e0  mov  x2, x22
0x19a2574e4  bl   #0x19a30b73c          ; ★ SelectOpticalStyleFromOS2
```

**由此可見**：要在 `SetOpticalSize` 內走到目標函數，至少要同時滿足
①有 `TBaseFont` ②描述符帶 `kCTFontOpticalSizeAttribute` 且值 > 0
③有 `STAT` 或 `trak` 表 ④字體資料物件能通過 `dynamic_cast`。
（本輪字體已滿足 ①②③——見 §3.3 的 `varAxes` / `table STAT|trak` 日誌——
剩下的 ④ 是決定性的，靜態上無法在不跑起來的情況下確認。）

### 2.3 目標函數的真實語意（與前文描述不同）

前文把 `SelectOpticalStyleFromOS2` 描述成「直接比較兩個光學尺寸」。實際讀
27.0.1 的 301 條，它是：

```
1) 0x19a30b7a4  vtable+0x1b0(basefont) → (lower, upper)     ; = TBaseFont::GetOpticalPointSizes
2) 0x19a30b7b0  d0 = TFont+0x20（當前光學尺寸）
   0x19a30b7b4  fcmp d1(lower), d0 ; b.hi → 繼續往下做
   0x19a30b7c0  fcmp d0, d1(upper) ; b.mi → 返回
   0x19a30b7c8  fcmp d1(upper), #0.0 ; b.eq → 返回
   → 即：只有當前字號 **落在字體宣告的光學區間之外** 才繼續
3) 0x19a30b86c  取 "OS/2" 表（tag 0x4f53/0x2f32 @0x1ead5eff8）
   0x19a30b884  add x2, x0, x1        ; table_end
   0x19a30b894  sub x3, x22, x2       ; 剩餘長度 = dataLen - tableEnd
4) 0x19a30b8f4  取 named instances 清單
5) 0x19a30b954  逐個實例：比對 traits（1 個 flags + 3 個 double，
                 由 TBaseFont::CreateTraitsValuesFromTraitsDictionary 產生），
                 再比對該實例的 (lower, upper) 是否覆蓋當前字號
6) 0x19a30bb98  命中則把 TFont+0x198 換成該實例的字體
```

**意思是**：這是一個「當前字號落在字體宣告光學區間之外時，挑一個更合適的
具名實例」的選擇器。它**不負責讀 OS/2 的光學尺寸欄位**——那只發生在
`TBaseFont::CopyOpticalPointSizes` 裡（§2.4）。所以「截斷 OS/2 表 → 在
`SelectOpticalStyleFromOS2` 內越界讀」這個因果鏈，本身就不成立。

### 2.4 真正讀 OS/2 v5 的地方，以及它已有的邊界校驗

`TBaseFont::CopyOpticalPointSizes`（vtable +0x1b8）在 27.0.1 `0x19a2ae228`：

```asm
0x19a2ae2b0  mov  w1, #0x2f32
0x19a2ae2b4  movk w1, #0x4f53, lsl #16   ; tag = 0x4F532F32 = "OS/2"
0x19a2ae2bc  blraa x9, x16                ; GetTable("OS/2")，結果寫到 sp+0x20/0x28
0x19a2ae2c8  bl   #0x19a2b9cac
0x19a2ae2d4  ldr  x8, [sp, #0x28]         ; x8 = 表長度
0x19a2ae2d8  cmp  x8, #0x64               ; ★ 長度 >= 100 ?
0x19a2ae2dc  b.lt #0x19a2ae310            ;   否 → 回傳「無」(哨兵 0xFFFF0000)
0x19a2ae2e0  ldr  x8, [sp, #0x20]         ; x8 = 表資料
0x19a2ae2e4  ldrh w9, [x8]
0x19a2ae2e8  rev  w9, w9
0x19a2ae2ec  lsr  w9, w9, #0x10
0x19a2ae2f0  cmp  w9, #5                  ; ★ version >= 5 ?
0x19a2ae2f4  b.lo #0x19a2ae310            ;   否 → 回傳「無」
0x19a2ae2f8  ldrh w9, [x8, #0x60]         ; ★ +96 usLowerOpticalPointSize
0x19a2ae2fc  ldrh w8, [x8, #0x62]         ; ★ +98 usUpperOpticalPointSize
0x19a2ae300  cbnz w9, #0x19a2ae38c
0x19a2ae304  mov  w10, #0xffff
0x19a2ae308  cmp  w8, w10
0x19a2ae30c  b.ne #0x19a2ae38c
0x19a2ae310  mov  w23, #-0x10000          ; ← 哨兵 0xFFFF0000 = 「沒有光學尺寸」
```

27.2 對應的 `0x19a44f32c` **逐條相同**：

```asm
0x19a44f3d8  ldr  x8, [sp, #0x28]
0x19a44f3dc  cmp  x8, #0x64
0x19a44f3e0  b.lt #0x19a44f414
0x19a44f3e4  ldr  x8, [sp, #0x20]
0x19a44f3f0  cmp  w9, #5
0x19a44f3f8  b.lo #0x19a44f414
0x19a44f3fc  ldrh w9, [x8, #0x60]         ; 96
0x19a44f400  ldrh w8, [x8, #0x62]         ; 98
```

→ **27.0.1 已有 `cmp length,#100` + `cmp version,#5` 雙重前置檢查**，
截斷表/版本謊報在讀取點之前就被擋下。這就是本輪所有截斷字體都回傳哨兵的
原因，也是「越界讀」不成立的直接證據。

---

## 3. 真機實測

### 3.1 字體構造（修正版 `makeos2c.py`）

相對舊腳本的三個修正：正確偏移 96/98、v5 表長 100、以及新增「表目錄長度謊報」
（這是唯一能讓 `剩餘長度 = dataLen - tableEnd` 無符號下溢的手法），
並把 OS/2 表**物理放在檔案末尾**，讓越界讀直接越過檔案尾。

基底字體用 `/System/Library/Fonts/SFHebrew.ttf`（63 KB，`wght`+`opsz` 可變、
9 個具名實例、自帶 `STAT`/`trak`/`fvar`/`avar`），改族名後當「第三方字體」註冊。
另用 `/System/Library/Fonts/SFNS.ttf`（7.7 MB，opsz 17–96，369 個實例）做高保真變體。

兩個關鍵實現細節：

```python
struct.pack_into(">H", base, 0,  base_ver)   # version
struct.pack_into(">H", base, 96, lower)      # usLowerOpticalPointSize ← 96，不是 92
struct.pack_into(">H", base, 98, upper)      # usUpperOpticalPointSize ← 98，不是 94
data = bytes(base[:trunc])                   # 截斷到 96/97/98/99/100
...
out = build_sfnt(ver, tabs, os2_last=True, os2_dir_len=dir_len)  # 目錄長度可獨立謊報
```

字體清單（`harness/fontpoc/os2c`）：

| 檔名 | version | 實際 OS/2 長度 | 目錄宣告長度 | opsz |
|---|---|---|---|---|
| `ok_v5_100` | 5 | 100 | 100 | 17 / 96 |
| `v5_trunc96` / `97` / `98` / `99` | 5 | 96…99 | 同實際 | 17 / 96 |
| `v5_trunc92` / `78` / `32` / `8` | 5 | 92…8 | 同實際 | 17 / 96 |
| `v5_dirhuge` | 5 | 96 | 0x7FFFFFFF | 17 / 96 |
| `v5_dirmax` | 5 | 96 | 0xFFFFFFFF | 17 / 96 |
| `v5_inverted` | 5 | 100 | 100 | 0xFFFF / 0 |
| `v5_zerovals` | 5 | 100 | 100 | 0 / 0 |
| `v5_maxvals` | 5 | 100 | 100 | 0xFFFF / 0xFFFF |
| `v5_range1_10` | 5 | 100 | 100 | 1 / 10 |
| `v5_range100_200` | 5 | 100 | 100 | 100 / 200 |
| `v65535_trunc98` / `v6_trunc98` | 0xFFFF / 6 | 98 | 98 | 17 / 96 |

`harness/fontpoc/os2e`（合法 100 字節內容 + 目錄長度謊報，唯一能同時通過
長度校驗又讓 span 長度下溢的組合）：`e_ctl_ok`、`e_dirhuge100`（0x7FFFFFF0）、
`e_dirmax100`（0xFFFFFFFF）、`e_dirbig100`（0x10000）。

`harness/fontpoc/os2d`（SFNS 基底）：`sfns_ok_v5`、`sfns_v5_trunc96`。

### 3.2 測試矩陣（`harness/ctreach/main.m`）

每個字體先 `CTFontManagerRegisterFontsForURL(..., kCTFontManagerScopeProcess)`
註冊，再走 5 條建立路徑 × 6 個字號（1, 8, 17, 20, 96, 200）：

```
[A] CTFontCreateWithName(psName, size, NULL)                      ; 純按名
[B] descriptor{kCTFontNameAttribute, kCTFontOpticalSizeAttribute} ; ★ 帶光學尺寸
[C] descriptor{B} + kCTFontVariationAttribute{opsz}               ; +可變軸
[D] CTFontCreateWithGraphicsFont(cg, size, NULL, desc{optSize})   ; 上一輪的做法
[E] CTFontCreateCopyWithAttributes(base, size, NULL, desc{optSize})
```
每條路徑都立刻做 `CTFontGetAscent/Descent/CapHeight/Leading/XHeight/BoundingBox`、
`CTFontGetBoundingRectsForGlyphs`、`CTFontGetAdvancesForGlyphs`、`CTFontDrawGlyphs`。

### 3.3 結果：零崩潰

```
字体数=18   register(Process)=1  ×18（全部成功）
[A]=108  [B]=108  [C]=108  [D]=108  [E]=108      → 共 540 次字體建立
grep -c '=== CTREACH 全部完成，未崩溃 ==='  → 1
```

自檢日誌（證明字體在 CoreText 眼裡確實是「帶 opsz 軸的可變字體 + STAT + trak」）：

```
==== 03_ok_v5_100.ttf (64664 B) ====
  register(Process)=1 err=(none)
  CGFont=ok ps=EvilOS2Pocok_v5_100
  基线 ps=EvilOS2Pocok_v5_100
    varAxes=(
        { NSCTVariationAxisIdentifier = 2003265652; NSCTVariationAxisMinimumValue = 1;
          NSCTVariationAxisMaximumValue = 1000; NSCTVariationAxisDefaultValue = 400; },
        { NSCTVariationAxisIdentifier = 1869640570;   // 'opsz'
          NSCTVariationAxisMinimumValue = 17; NSCTVariationAxisMaximumValue = 28;
          NSCTVariationAxisDefaultValue = 28; }
    )
    table fvar = present(182 B)
    table STAT = present(234 B)
    table trak = present(256 B)
    table avar = present(44 B)
  --- size=200 ---
    [A name-only     ] ps=EvilOS2Pocok_v5_100 asc=190.43 desc=48.24 cap=140.92 ...
    [B desc+optSize  ] ps=EvilOS2Pocok_v5_100 asc=190.43 desc=48.24 cap=140.92 ...
    [C desc+opt+var  ] ps=EvilOS2Pocok_v5_100 asc=190.43 desc=48.24 cap=140.92 ...
    [D cg+optSize    ] ps=EvilOS2Pocok_v5_100 asc=190.43 desc=48.24 cap=140.92 ...
    [E copyWithAttrs ] ps=EvilOS2Pocok_v5_100 asc=190.43 desc=48.24 cap=140.92 ...
```

`registerGraphicsFont` 對這些字體一律失敗（`CTFontManagerErrorDomain 305`），
不影響字體檔註冊路徑。

**另註**：`[A]`～`[E]` 的 PostScript 名與所有度量在每個字號下**完全相同**，
即「帶 `kCTFontOpticalSizeAttribute` 與否」對結果沒有任何可觀測差異。
這與 §2.3 的判讀一致：對本輪字體，即使 `SelectOpticalStyleFromOS2` 被進入，
也會因為「沒有任何具名實例的區間覆蓋被請求的字號」而選不出東西。

### 3.4 ★ 正面發現：CoreText 真的讀了我偽造的 OS/2 v5 位元組

這是本輪最有價值的實測。用未公開但存在的鍵
`CTFontOpticalPointSizesAttribute`（`_kCTFontOpticalPointSizesAttribute`，字串見
二進位 `0x1fc1cb`）把 `TBaseFont::CopyOpticalPointSizes` 的回傳值直接取出來。
回傳是 `(upper << 16) | lower` 的 CFNumber（單位是 1/20 pt）：

```objc
CFTypeRef ops = CTFontCopyAttribute(base, CFSTR("CTFontOpticalPointSizesAttribute"));
```

| 字體 | 我寫入 (lower,upper) | 回傳 raw | 解出 | 判讀 |
|---|---|---|---|---|
| `03_ok_v5_100` | 17, 96 | 6291473 | **17, 96** | ✅ 逐位元組相符 |
| `01_sfns_ok_v5` | 17, 96 | 6291473 | **17, 96** | ✅ |
| `04_v5_range1_10` | 1, 10 | 655361 | **1, 10** | ✅ |
| `05_v5_range100_200` | 100, 200 | 13107300 | **100, 200** | ✅ |
| `15_v5_inverted` | 0xFFFF, 0 | 65535 | **0xFFFF, 0** | ✅ 反向區間原樣回傳 |
| `14_v5_maxvals` | 0xFFFF, 0xFFFF | 4294967295 | **0xFFFF, 0xFFFF** | ✅ |
| `16_v5_zerovals` | 0, 0 | 0 | **0, 0** | ✅ |
| `06/07/08/09_v5_trunc96/97/98/99` | 17, 96 | 4294901760 | 哨兵 0xFFFF0000 | ⛔ 被長度校驗拒絕 |
| `12_v5_trunc8`, `13_v5_trunc32` | 17, 96 | 4294901760 | 哨兵 | ⛔ |
| `10_v5_dirhuge`, `11_v5_dirmax` | 17, 96 | 4294901760 | 哨兵 | ⛔ 目錄長度謊報也被拒 |
| `17_v65535_trunc98` | 17, 96 | 4294901760 | 哨兵 | ⛔ |
| `02_sfns_v5_dirhuge`, `00_sfns_v5_trunc96` | 17, 96 | 4294901760 | 哨兵 | ⛔ |

第二輪（`logs/run-dirlen-lie.log`，內容為合法 100 字節 v5、只謊報目錄長度）：

```
e_ctl_ok        (dir len = 100)         → 6291473  = lower 17, upper 96   READ OK
e_dirhuge100    (dir len = 0x7FFFFFF0)  → 4294901760  哨兵
e_dirmax100     (dir len = 0xFFFFFFFF)  → 4294901760  哨兵
e_dirbig100     (dir len = 0x10000)     → 4294901760  哨兵
```

**結論（兩層）**：
1. **正面**：CoreText 從 app 沙盒內註冊的字體裡，確實**逐位元組讀出了
   OS/2 v5 的 `usLowerOpticalPointSize` / `usUpperOpticalPointSize`**，
   連 `0xFFFF/0`、`0/0` 這種畸形值都原樣讀出。所以「OS/2 光學尺寸解析」
   這條**資料流在沙盒內是活的**——這比前文的悲觀判斷更可達。
2. **反面**：但**長度/版本校驗在真正讀取之前**（§2.4 的 `cmp #0x64` / `cmp #5`），
   截斷或謊報長度一律回哨兵。越界讀打不通。

### 3.5 過程中遇到並解決的三個坑（誠實記錄）

1. **我自己的 harness bug（浪費了 5 輪）**：`contentsOfDirectoryAtPath:` 在
   iOS 27 回傳的是 Swift 字串，我對它做 `sortedArrayUsingSelector:@selector(compare)`
   直接拋 `-[Swift.__StringStorage compare]: unrecognized selector`，
   未捕獲異常使程序在寫完第 3～7 行日誌後就死。初期我誤判成「設備鎖屏」和
   「並行 session 搶 bundle id」，加了 heartbeat 和 `--console` 才看到真正的異常：

   ```
   P-EXC sort: -[Swift.__StringStorage compare]: unrecognized selector sent to instance 0x156438000
   ```

   修法：包 `@try/@catch` 並改用不排序的原始陣列。
2. **並行 session 搶同一個 bundle id**：`com.example.ios27poc` 同時被另一個
   session 使用（它在做路線 B：偽造 `.AppleSystemUIFont` / `.SF NS` 族名，
   日誌寫 `fontpoc.log`）。它會覆蓋 `harness/fontpoc/` 下的 `main.m`、`Payload/FP.app`
   資源，並把 `Payload` 縮成只剩 5 個字體。我最後把工作區隔離到
   `harness/ctreach/`，並把日誌改名為 `ctreach.log` 才穩定。
   **注意：`harness/fontpoc/main.m` 現在不是本文的版本**（本文的版本在
   `harness/ctreach/main.m` 與 `harness/fontpoc/ctreach-main.m`）。
3. **設備會自動鎖屏**：鎖屏時 `install/launch` 回
   `BSErrorCodeDescription = Locked`。

> 順帶：路線 B（偽造系統私有族名 `.AppleSystemUIFont` / `.SF NS`）已被那個並行
> session 測過，日誌 `fontpoc.log` 顯示 `CTFontCreateUIFontForLanguage` 拿到的仍是
> **真正的系統字體**（`[UISystem]` / `[UIUser]` 行的度量與偽造字體不同），
> 偽造族名沒有騙過匹配，同樣零崩潰。

---

## 4. 可重現步驟

```bash
P=~/Documents/deepseek-harness/default-workspace/tasks/ios27-chain-poc
cd $P/harness/fontpoc

# 1) 生成字體（修正版：偏移 96/98、v5=100 字節、可謊報目錄長度、OS/2 置於檔尾）
python3 makeos2c.py /System/Library/Fonts/SFHebrew.ttf     # → os2c/  18 個
python3 makeos2c.py /System/Library/Fonts/SFNS.ttf         # → 見 os2d/（SFNS 基底）

# 2) 編譯 + 簽名（工作區建議用隔離目錄，見 §3.5）
cd $P/harness/ctreach
cp os2c/*.ttf os2d/sfns_ok_v5.ttf os2d/sfns_v5_trunc96.ttf os2e/*.ttf Payload/FP.app/
security unlock-keychain -p "" ~/Library/Keychains/dev.keychain-db
xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc main.m \
  -o Payload/FP.app/FP -framework Foundation -framework CoreText -framework CoreGraphics
codesign -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)" \
  --keychain ~/Library/Keychains/dev.keychain-db \
  --entitlements /tmp/ents.plist --generate-entitlement-der -f Payload/FP.app
codesign -dvvv Payload/FP.app | grep Identifier      # 必須印出 Identifier

# 3) 安裝 / 執行 / 取日誌（install 必須用絕對路徑）
DEV=DEVICE-UDID
xcrun devicectl device install app --device $DEV "$P/harness/ctreach/Payload/FP.app"
xcrun devicectl device process launch --terminate-existing --device $DEV com.example.ios27poc
sleep 55
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer \
  --domain-identifier com.example.ios27poc \
  --source tmp/ctreach.log --destination /tmp/ctreach.log
grep OpticalPointSizes /tmp/ctreach.log     # ← 關鍵探針
```

排錯提示：想看真實死因（而非猜「設備鎖屏」）請加 `--console`：
`xcrun devicectl device process launch --console --terminate-existing --device $DEV com.example.ios27poc`

---

## 5. 判讀與建議

### 對 CVE-2026-112656 的判斷

| 假設 | 實測／反匯編結論 |
|---|---|
| 宣告 v5 + 表截斷 → 在 `SelectOpticalStyleFromOS2` 越界讀 | ❌ `SelectOpticalStyleFromOS2` 根本不讀 OS/2 光學欄位 |
| 宣告 v5 + 表截斷 → 在 `CopyOpticalPointSizes` 越界讀 | ❌ 27.0.1 已有 `cmp len,#100` + `cmp ver,#5` |
| 目錄長度謊報 → 剩餘長度下溢 | ❌ 被同一道長度校驗（對著實際可讀長度）拒掉 |
| 27.2 的 3 倍膨脹 = 71 處新增邊界檢查 | ❌ 主要是全域哈希快取；`CopyOpticalPointSizes` 兩版逐條相同 |

→ **這條線索不應該是 CVE-2026-112656 的修補點**。建議：
1. 把 `SelectOpticalStyleFromOS2` 的 27.2 變更重新定性為**效能重構**，
   從「最高質量線索」降級；
2. 若要繼續在 CoreText 找 27.0.1→27.2 的真實安全修補，應改用
   「27.2 新增了什麼前置檢查（`cmp` 緊鄰 `ldrh`/`ldr`）」
   而不是「cmp 數量增量」來篩選——本輪已證明後者會被哈希表查找污染（35%）；
3. 真正有價值的新事實是 §3.4：**沙盒內註冊的字體，其 OS/2 v5 光學欄位
   會被 CoreText 全程讀出且原樣回傳**。若後續要打這條資料流，
   攻擊面應該在**消費這些值的上層邏輯**（例如實例選擇、區間比較、
   `DerivedOpticalFontDescriptor`），而不是在讀取點本身。

### 保留的可疑點（供後人接手）

- `SetOpticalSize` 內那個 `dynamic_cast` 目標型別 `0x1ead5f0d8`（以及
  `0x19a25723c` 比對的 `0x1ead5f098`、`0x19a257260` 的 `0x1ead5f0b8`）我沒能
  解出類名（共享快取裡的 chained fixup 未還原）。若能解出，就能判斷
  「註冊字體」與「系統 spliced 字體」在這道閘上的差別，也就能確定
  `SelectOpticalStyleFromOS2` 到底有沒有被進入。
- `SetOpticalSize` 在 `0x19a2573c4` / `0x19a2573dc` 的兩道 `"CoreText"` /
  `"AltThaiUIFont"` / `"AllowMixedThaiFontStyles"` 閘門性質未定
  （CFPreferences？編譯期特性開關？），實機上觀察到的是「不影響結果」。
- 我沒能證明 `SelectOpticalStyleFromOS2` **一定**被進入。理由是：即使進入了，
  對本輪的字體也不會有可觀測副作用——該函數只在「當前字號落在字體宣告區間
  **之外**」時才選實例，而此時所有具名實例的區間也同樣不覆蓋該字號，
  選擇結果為空。要做出可觀測差異，需要一個**每個具名實例各帶獨立 OS/2
  光學區間**的字體，那是 Apple spliced font 的私有格式，第三方無法構造。

---

## 附錄：本輪產物

| 路徑 | 內容 |
|---|---|
| `harness/ctreach/main.m` | 測試 harness（註冊 + 5 路徑 × 6 字號 + 光學尺寸探針）|
| `harness/ctreach/Payload/FP.app` | 現成簽名好的測試 app |
| `harness/ctreach/logs/run-full-18fonts.log` | 主實驗日誌（1808 行，540 次建立，零崩潰）|
| `harness/ctreach/logs/run-dirlen-lie.log` | 目錄長度謊報實驗日誌 |
| `harness/ctreach/logs/run-3fonts-console.log` | `--console` 抓到的 Swift 字串異常（排錯記錄）|
| `harness/fontpoc/makeos2c.py` | 修正版字體生成器（偏移 96/98、可謊報目錄長度）|
| `harness/fontpoc/ctreach-main.m` | 同 `harness/ctreach/main.m` 的副本（放在 fontpoc 下方便取用）|
| `harness/fontpoc/os2c/` | 18 個 OS/2 v5 變體（SFHebrew 基底）|
| `harness/fontpoc/os2d/` | 2 個 SFNS 基底變體 |
| `harness/fontpoc/os2e/` | 4 個「合法內容 + 目錄長度謊報」變體 |
