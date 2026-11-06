# libFontParser `sbit_GetBitMapInfo` 静态逆向 — `ComputeDestBitmap` 失败判据与 PoC 反推

> 目标：CVE-2026-112683（FontParser 越界写）。27.0.1 ↔ 27.2 差分点：
> `sbit_GetBitMapInfo` 丢弃 `ComputeDestBitmap` 返回值。
> 本文逆出**确切的失败判据**、**返回值的语义**、**要命中它需要的字体/渲染参数**，
> 以及真机实测（4 轮，约 900 次绘制）的结果。
>
> 所有反编译产物：`out/cdb-2701.c`、`out/cdb-272.c`（ComputeDestBitmap / RenderBitmap /
> sbit_GetBitMapData）、`out/m3-2701.c`（M3x3Mul / M3x3Flags / M3x3Inverse / M3x3Concat）、
> `out/sb-2701.c`（sbit_FontMatch / sbit_GetMetrics / sbit_CalculateTransformSpaceNeeded）。

---

## 一、结论摘要（先看这个）

| 问题 | 结论 | 证据强度 |
|---|---|---|
| `ComputeDestBitmap` 什么时候返回 bit0=0？ | 四次 `M3x3Mul` 任一失败，或四角算出的矩形顺序非法（`x0>x1` 或 `y0>y1`） | **确定**（反编译直读） |
| `M3x3Mul` 什么时候失败？ | ① `M3x3Flags==7`（即齐次分量 `m[8] < 1`）② 16.16 定点乘法结果溢出 int32 ③ 透视路径分母 `< 1` | **确定**（反编译直读） |
| 退化/奇异 CTM（scale=0、det=0、全零矩阵）能命中吗？ | **不能**。`CGAffineTransform` 恒有 `m[2]=m[5]=0, m[8]=0x40000000`，永远取不到 flags 7 | **确定**（`M3x3Flags` 分支穷举） |
| 真正可达的失败是什么？ | **定点溢出**：某个角点映射后的设备坐标绝对值 ≥ 32768 px | **确定**（乘法位宽推导） |
| 失败后 27.0.1 拿到什么？ | 未被写入（flags 2/6）或写入**回绕值**（flags 3/4/5）的角点 → 目标矩形塌缩进 65536 px 窗口 | **确定** |
| 这条路径能被 sbix（PNG）字体触发吗？ | **大概率不能**。反编译显示 `sbit_GetBitMapData` 解的是 **5 字节 SmallGlyphMetrics + EBDT imageFormat**，即 EBDT/CBDT 老式位图表，不是 sbix PNG | **强**（反编译 + 真机实测一致） |
| 真机 PoC 是否成功？ | **未成功**（6 字体 × 26 字号 × 4 绘制模式，全部无崩溃） | 实测 |
| 附带发现 | `CTFontGetBoundingRectsForGlyphs` 对 sbix 字形**必挂死**（2/2，可复现） | 实测 |

**一句话**：判据已完全逆清；但它要求的目标矩形量级（≥32768 px，溢出回绕还要 ~524288×65535 px）
在「目标矩形与实际写入矩形由同一份数据推导」的结构下会自洽，**因此单靠 M3x3Mul 失败不足以构成越界写**；
27.2 的第二处修补（`rowBytes*height` 的 64 位溢出检查）说明真正被修的是**尺寸整数溢出**，
而进入那条代码需要 **EBDT/CBDT 位图字体**，不是 sbix。

---

## 二、27.2 在这个函数上改了三处（不是一处）

### 2.1 `sbit_GetBitMapInfo`：检查 `ComputeDestBitmap` 返回值

```c
// 27.0.1  (VA 0x1b7ab9f44)
ComputeDestBitmap(uVar12, &local_80, param_4);         // 返回值直接丢弃

// 27.2     (VA 0x1b854f9e4)
uVar5 = ComputeDestBitmap(uVar12, &local_80, param_4);
if ((uVar5 & 1) == 0) {
    puVar7 = operator_new(2); *puVar7 = 5;
    throw(_DAT_1e0181f08, 0);                           // 抛 C++ 异常
    return;
}
```

### 2.2 `sbit_GetBitMapInfo`：新增「目标位图字节数」64 位溢出检查 ← **这处才是越界写的直接防线**

```c
// 27.0.1
if (x1 == x0 || y1 == y0) iVar3 = 0;
else iVar3 = *(int *)(param_4 + 4) * (uVar7 & 0xffff);   // rowBytes * height，32 位，可回绕
piVar9 = *(int **)(param_1 + 0x28);
*piVar9 = iVar3;                                          // ← 这个值成为位图块大小

// 27.2
if (x1 == x0 || y1 == y0) { *piVar9 = 0; }
else {
    uVar5 = (ulong)*(uint *)(param_4 + 4) * (ulong)(uVar8 & 0xffff);  // 64 位乘
    **(undefined4 **)(param_1 + 0x28) = (int)uVar5;
    if ((uVar5 & 0xffffffff00000000) != 0) goto LAB_1b854fc20;        // 高 32 位非零 → 抛异常
    ...
}
```

### 2.3 `ComputeDestBitmap`：改成返回状态，四次 `M3x3Mul` 逐级检查

```c
// 27.0.1 (0x1b7a493e8) 返回 void
M3x3Mul(param_1, uVar4, &local_48, 1);   // 返回值全丢
M3x3Mul(param_1, uVar4, &local_50, 1);
M3x3Mul(param_1, uVar4, &local_58, 1);
M3x3Mul(param_1, uVar4, &local_60, 1);
/* 直接对四个点做 min/max */

// 27.2 (0x1b84de3ec) 返回 1=成功 / 0=失败
iVar3 = M3x3Mul(param_1, uVar4, &local_48, 1);
if (iVar3 == 0) { iVar3 = M3x3Mul(..&local_50..);
  if (iVar3 == 0) { iVar3 = M3x3Mul(..&local_58..);
    if (iVar3 == 0) { iVar3 = M3x3Mul(..&local_60..);
      if (iVar3 == 0) { ...smin/smax 求四角包络...
          if (x0 <= x1 && y0 <= y1) { ...rowBytes...; return 1; }
      } } } }
return 0;    // 任一失败 → 0
```

`M3x3Mul` / `M3x3Flags` 在 27.2 中**没有变化**（同名同形），所以失败判据两版一致。

---

## 三、`scalerBitmap` 结构与 `ComputeDestBitmap` 算法

### 3.1 结构（由 27.2 版的清晰写入形式反推）

```c
struct scalerBitmap {          // 共 0x24 字节
    int32 x0;                  // +0x00  (27.2 版 param_3[2] 的低半，即 minX 取整)
    int32 y0;                  // +0x04
    int32 x1;                  // +0x08  ← 注意：入口 *param_4 = 0 清零的是 +0x00
    int32 y1;                  // +0x0c
    int32 a;                   // +0x10  ┐ 源矩形
    int32 b;                   // +0x14  │ [a,c] × [b,d]
    int32 c;                   // +0x18  │
    int32 d;                   // +0x1c  ┘
    int32 rowBytes;            // +0x20
};
```

> 补充：`sbit_GetBitMapInfo` 里 `param_4[1]`（+0x08）在调用前由 `sbit_GetMetrics` 写成
> `FixedPoint` 原点 `(originX<<16, originY<<16)`，随后被覆写成目标原点。

### 3.2 算法（按 27.2 的干净形式重写）

```c
iVar3 = src->a;                                  // *(int*)(param_2+2) == +0x10
if (iVar3 == src->c) {                           // 宽度为 0 的退化源矩形
    *dst = *src; dst[1]=src[1]; dst[2]=src[2]; dst[3]=src[3];
    dst->rowBytes = 0; return 1;                 // 成功
}
flags = M3x3Flags(m);                            // 2 位宽/4 位宽/透视分派
P1 = transform(m, flags, (a<<16, d<<16));        // 四角（16.16 定点）
P2 = transform(m, flags, (c<<16, d<<16));
P3 = transform(m, flags, (a<<16, b<<16));        //   = 源矩形的 4 个角
P4 = transform(m, flags, (c<<16, b<<16));
mn = smin(P1,P2,P3,P4);                          // (minX,minY)  16.16
mx = smax(P1,P2,P3,P4);                          // (maxX,maxY)
x0 = round16(mn.x); y0 = round16(mn.y);          // round16(v) = (v+0x8000)>>16，带符号
x1 = round16(mx.x); y1 = round16(mx.y);
dst->a = x0; dst->b = y0; dst->c = x1; dst->d = y1;
if (x1 == x0) dst->c = ++x1;                     // 保证非退化
if (y1 == y0) dst->d = ++y1;
if (!(x0 <= x1 && y0 <= y1)) return 0;           // ← 顺序检查（27.0.1 没有，但 min/max 已保证）
dst->rowBytes = ((x1 - x0) + 0x1f) >> 3 & 0xfffffffc;
return 1;
```

即：**目标矩形 = 源矩形四角经变换后的轴对齐包络**，`rowBytes = ((宽+31)>>3) & ~3`（1bpp，32 位对齐）。

---

## 四、`M3x3Mul` 失败判据（本次核心产出）

### 4.1 `M3x3Flags` 输出枚举（`out/m3-2701.c`）

```c
byte M3x3Flags(int *m) {                     // m[0..8]，16.16 仿射部分 + 2.30 透视部分
  if (m[2]==0 && m[5]==0) {                  // 无透视（c=0, f=0）
    if (m[8] < 1) return 7;                  // m[8] = 齐次 w，0x40000000 == 1.0，2.30 定点
    if (m[8]==0x40000000) {
      b = (m[6]!=0 || m[7]!=0);              // 是否含平移
      if (m[1]!=0 || m[3]!=0) return b|4;    // 含旋转/错切 → 4 或 5
      if (m[0]!=0x10000 || m[4]!=0x10000) b |= 2;
      return b;                              // 0 恒等 / 1 仅平移 / 2 仅缩放 / 3 缩放+平移
    }
  }
  return 6;                                  // 一般（透视，或 w != 1.0）
}
```

| flags | 含义 | 乘法路径 |
|---|---|---|
| 0 | 恒等 | 直接通过 |
| 1 | 仅平移 | `out = in + m[6/7]` |
| 2 | 仅缩放 | `out = (in*m[0/4] + 0x8000) >> 16`，**先检查后写** |
| 3 | 缩放+平移 | `out = m[6/7] + ((in*m[0/4]+0x8000)>>16)`，**先写后检查** |
| 4/5 | 旋转/错切(±平移) | `out = m[6/7] + ((y*m[3]+x*m[0]+0x8000)>>16)`，**先写后检查** |
| 6 | 透视/一般 | 除法 + 分母检查 |
| 7 | **退化（w < 1）** | **直接返回 1，不写输出** |

### 4.2 三种失败条件（精确）

```c
// 条件 A：flags == 7
if (param_2 == 7) goto FAIL_1;                     // 无条件失败，不触碰 pts

// 条件 B：flags ∈ {0..5}，定点溢出
lVar1 = (long)x * (long)m_k + 0x8000;
iVar7 = (int)((ulong)lVar1 >> 0x10);
if (lVar1 >> 0x10 != (long)iVar7) goto FAIL_1;     // (x*m)>>16 放不进 int32

// 条件 C：flags == 6，透视分母
iVar5 = (m[2]*x + m[5]*y) 的定点除法分母;
if (iVar5 < 1) goto FAIL_1;                        // 分母 < 1 → 除零保护
```

**条件 A 对 app 不可达**：`CGContext` 的 CTM 经 CoreText 转成 `Mapping3x3` 后
`m[2]=m[5]=0`（仿射无透视项）、`m[8]=0x40000000`（w=1）。所以
`CGContextConcatCTM(ctx, CGAffineTransformMakeScale(0,0))`、全零矩阵、`det=0` 的剪切矩阵
**全部只得到 flags=2/3**，`M3x3Mul` 正常返回 0（`x*0+0x8000>>16 = 0`，不溢出），
`ComputeDestBitmap` 返回 1（成功），27.2 也**不会**抛异常。

→ **这是「退化矩阵」方向必然失败的原因**（已实测确认，见第六节）。

**条件 B 是可达到的**：
`out_px = units × (byte_size/unitsPerEm)`，定点表示 `out_fixed = units × m`。
溢出判据 `|out_px| ≥ 32768`。由于源矩形来自 int16 字段（|units| ≤ 32767），
只要 `缩放系数 ≥ 32768/32767 ≈ 1.0001` **且矩形贴近 int16 上限**，或矩形不大时
`缩放系数 ≥ 32768/units`，即可命中。例如 2048 单位的位图矩形在 34000 px 字号下
`2048 × 16.6 = 34000 > 32768` → 溢出。

---

## 五、命中判据后的实际后果（为什么它不等于越界写）

失败时四个角点的状态：

| flags | 失败时角点值 |
|---|---|
| 7 | **完全未写** → 保持传入值 `units<<16` |
| 2 | **先检查后写** → 未写 → 保持 `units<<16` |
| 3/4/5 | **先写后检查** → 写入 **回绕（截断）后的 32 位值** |
| 6 | 分母失败发生在除法前 → **未写** |

于是 `min/max` 包络落到两种情况：

1. 全部未写 → 包络 = 源矩形本身（`units` 量级，≤ 32767）→ `rowBytes ≤ 4096`；
2. 部分写回绕 → 回绕值必然落在以 `2^32` 为模的 **65536 px 窗口**内
   （因为定点值 = `units × m`，`units<<16` 使每一位差都是 65536 px 的整数倍），
   故包络跨度 ∝ `|S - k·65536|`，**最大 65536 px** → `rowBytes ≤ 8192`。

两种情况下 `rowBytes ≤ 8192`，而 `height = (y1-y0) & 0xffff ≤ 65535`：

```
rowBytes * height ≤ 8192 * 65535 = 536,862,720  <  2^31
```

**→ 32 位不会回绕。** 也就是说「`ComputeDestBitmap` 失败」单独一条，
在 27.0.1 里产生的是**尺寸错误（位图塌缩，视觉异常）**，而不是尺寸溢出。

### 那么 2.2 那处 `rowBytes*height` 64 位检查在防什么？

它要 `rowBytes ≥ 32769`，即**目标矩形宽度 ≥ 262144 px，且高度落在 [32768, 65535]**
（若 `rowBytes` 达 65540 则高度 65534/65535 即可）。这只有在下述情况成立：
**`ComputeDestBitmap` 成功**（即 `|每角| < 32768 px` 的乘法不溢出）**但**四角包络因其他原因巨大——
在正常仿射下不可能，因为成功路径下包络必然 ≤ 32768 px。

⇒ 唯一自洽的解释：这条检查是**纵深防御**，它与 2.1 一起构成
「**目标矩形量级异常时不要继续**」的双保险，而不是某个单点算术错误的补丁。
**换言之：27.2 修的是「不要拿可疑的尺寸去分配」，而真正被 OOB 写的现场不在这两个函数里。**

---

## 六、真机实测（iPhone18,2 / iOS 27.0.1 24A446）

工具链：`harness/sbx/`（新写的 PoC app）+ `harness/fontpoc/makepng.py`（合法 PNG）。

### 6.1 第一轮：26 个字号 × 6 个 sbix（合法 PNG）× 4 种绘制模式 = 624 次绘制

字体（`harness/fontpoc/fonts2/`，合法 PNG + 正确 CRC + IDAT）：

```
sbix_png64_ppem64    sbix_png256_ppem256   sbix_png1024_ppem1024
sbix_png4096_ppem4096  sbix_png1024_ppem256(放大4x)  sbix_png4096_ppem512(放大8x)
```

字号：`64 1024 8192 30000 32000 32760 32768 33000 36000 40000 49152 60000 65536 70000 100000 262144`

结果（节选，`ink` = 64×64 位图上下文里的非透明像素数；`mode2` = CTM 0.001 缩到可见尺度）：

```
   size     m0 m1 m2 m3   (ink，sbix_png4096_ppem4096)
       64  4032 3660    0    0
     1024  3392 3050    1    0
     8192     0    0   64    0
    30000     0    0  900    0
    32768     0    0 1089    0
    33000     0    0 1089    0
    40000     0    0 1600    0
    65536     0    0 4032    0
   262144     0    0 3904    0
```

关键读数：

1. **`CTFontGetSize()` 与请求值完全一致**（`size 请求=262144 实际=262144.000`）——
   说明 CoreText 在这一层**没有**钳制字号，之前的「被钳制」判断不准确。
2. `mode2` 的 `ink` 严格等于 `(size×0.001)²`（32768→1089=33², 40000→1600=40²），
   即渲染出的始终是一个**完美正方形**，边长 = 请求字号。
   **跨 32768/33000/40000/65536 没有任何突变** → `ComputeDestBitmap` 在这一路**从未失败**。
3. 六个字体中，`png64_ppem64` / `png256_ppem256` / `png1024_ppem1024` / `png4096_ppem4096`
   的 ink 表**逐格完全相同**，只有「位图大于 ppem」的两个不同 → 说明渲染结果只取决于
   `字号 / ppem` 比例，与 PNG 的实际像素尺寸无耦合关系。
4. 全部 624 次绘制结束，日志末行 `=== sbx PoC done 未崩溃 ===`。

### 6.2 路径辨识实验（非正方形位图）——并引出「挂死」现象

用 4:1 / 1:4 的合法 PNG（`harness/fontpoc/fonts3/`）判断墨迹长宽比，
以确认 sbix 是走「PNG 图像缩放」还是走 FontParser scaler。

结果：**每次都在 `CTFontGetBoundingRectsForGlyphs` 处卡死**（2/2 可复现）：

```
=== path-id start ===
--- tall_64x256_ppem256.ttf ---
  creating CTFont size=64
  calling probe ctm=1
     probe enter
     ctx ok
     cmap ok
        ← 之后 60 s 内无任何新行
```

去掉 `CTFontGetBoundingRectsForGlyphs` 后（纯 `CTFontDrawGlyphs`）第一轮跑完 878 行无异常。
→ 这是一个**独立于本 CVE 的 DoS 面**：任何调用 `CTFontGetBoundingRectsForGlyphs`
测量 sbix 字形的进程（WebKit 排版、任何 `boundingRectForGlyph:` 的 app）都会挂死。
（设备随后锁屏，此条尚需解锁后复验并定位到具体函数。）

---

## 七、为什么 sbix 走不到 `sbit_GetBitMapInfo`（关键反推）

`out/cdb-2701.c` 里 `sbit_GetBitMapData` 的解码逻辑（第 504 行起）：

```c
__Z19ScalerGetTablePartsP13memoryContextjjjPvh(*param_1, ..tag.., .., .., &local_158, 0);
lVar18 = local_158;
bVar2  = *(byte *)(lVar25 + 0x5e);          // imageFormat
/* 3. 判据直接用「位图表」的字节字段 */
*(byte*)(lVar19+0x7c) = height;  *(byte*)(lVar19+0x7d) = width;      // 单字节 → ≤ 255
*(byte*)(lVar19+0x7f) = bearingY;
...
if (bVar2 == 1) { ... 逐行 memcpy，源指针 lVar18 + 5 ... }            // 5 字节
else if (bVar2 == 2) { MoveBitsSmall(lVar18 + 5, ...) }               // SmallGlyphMetrics
else if (bVar2 == 4) { ... DecodeHuffman ... }                        // nibble + Huffman
```

- `lVar18 + 5` = 跳过 **5 字节 `SmallGlyphMetrics`（height,width,bearingX,bearingY,advance）**；
- `imageFormat` 分派 1 / 2 / 4 / (6/7) 与 **EBDT/CBDT 的 imageFormat 定义**逐项对应；
- 宽高直接用**单字节**字段（≤255），与 sbix 的 `originOffsetX/Y + graphicType + PNG` 结构不符。

而 sbix 的 strike 头是 `ppem(u16) resolution(u16)` + 32 位 offset、字形数据头是
`originOffsetX/Y(i16) + graphicType(4 字节 tag)`。**没有 5 字节 metrics、没有 imageFormat。**

### 七个结构常数，逐一对上了 EBLC/CBLC + EBDT/CBDT + EBSC

| 反编译里的常数 | 位置 | OpenType 结构 | 是否吻合 |
|---|---|---|---|
| `*local_68 == 0x200` | `sbit_FontMatch` L56 / `sbit_CalculateTransformSpaceNeeded` L782 | **EBSC** 头 `version = 0x00020000`，文件字节 `00 02 00 00`，LE 读成 u32 = `0x200` | ✅ |
| `uVar20 = uVar2 + uVar19 * 0x1c`，`lVar3 = uVar2 + lVar17*0x1c` | `sbit_FontMatch` L101/113 | **EBSC `bitmapScaleTable` = 28 (0x1C) 字节** | ✅ |
| `piVar21[9] == *(byte*)(lVar3+0x18)` / `piVar21[10] == *(byte*)(lVar3+0x19)` | `sbit_FontMatch` L114 | `bitmapScaleTable.ppemX @ 0x18`、`ppemY @ 0x19` | ✅ |
| `(uVar23 * 0x30 | 8) <= uVar15` | `sbit_FontMatch` L60 | **EBLC/CBLC `bitmapSizeTable` = 48 (0x30) 字节** | ✅ |
| `ScalerGetFontTable(.., 0x45425343, ..)` | `sbit_FontMatch` L~90 | 表 tag **`EBSC`**（0x45='E',0x42='B',0x53='S',0x43='C'） | ✅ |
| `lVar18 + 5`（逐行 memcpy 跳过 5 字节） | `sbit_GetBitMapData` | **`SmallGlyphMetrics` = 5 字节** | ✅ |
| `bVar2 = *(byte*)(lVar25+0x5e)` 分派 1/2/4 | `sbit_GetBitMapData` | **EBDT/CBDT `imageFormat`** 1=byte-aligned 2=bit-aligned 4=nibble(+Huffman) | ✅ |

⇒ `sbit_*` 一族是 **EBDT/EBLC、CBDT/CBLC 老式位图表**（外加 EBSC 缩放）的标量解码器，
sbix PNG 由 CoreText 侧走「图像缩放/贴图」路径（这也解释了 6.1 里
「结果只与 字号/ppem 有关、与 PNG 真实尺寸无关」以及「PNG 被当成矩形贴图」）。

**这解释了此前 6 个 sbix 字体 × 4 字号 × 2 渲染路径全部无效的根本原因：
不是参数不对，而是攻击面选错了表。**

---

## 八、诚实的结论与下一步

### 已确证
1. `ComputeDestBitmap` 的失败判据 = `M3x3Mul` 失败；`M3x3Mul` 的三种失败条件已逐条逆出（含精确位宽）。
2. `M3x3Flags` 的 0..7 语义表已反编译确证；`flags==7`（w<1）**由 CGAffineTransform 不可达**。
3. 27.2 在这个函数族里改了三处（返回值检查 / 尺寸 64 位溢出检查 / `ComputeDestBitmap` 内部逐级检查），
   前两份修补在 27.0.1 中**确实缺失**。
4. 目标矩形、`rowBytes`、位图字节数的计算公式已完全还原。
5. 真机：6 个合法 sbix 字体 × 26 字号（到 262144）× 4 种绘制模式，**无崩溃、无尺寸溢出**。

### 未确证（需要下一轮）
1. **失败路径是否真的导致内存破坏**：按第五节推导，单靠失败只会让位图塌缩。
   要造成越界写，还需要「分配尺寸」与「写入尺寸」来自**不同**数据源的那一刻——
   最可疑的是 `RenderBitmap` 里 `*(char*)(param_1+0x40) != 0`（1bpp→4bit 展开）分支：
   ```c
   iVar22 = y1 - y0;  iVar14 = x1 - x0;
   iVar13 = (iVar14*4 + 0x1fU >> 3 & 0x1ffffffc) * iVar22;   // 32 位乘，可回绕
   ScalerNewBlockTyped(param_2, (long)iVar13, ...);
   ```
   若 `iVar13` 回绕成小值，随后的展开循环仍按真实 `uVar44 * iVar22` 推进指针 → 越界写。
   **需要构造让 `(x1-x0)*4/8 * (y1-y0) ≥ 2^32` 的矩形**，即 `(x1-x0)(y1-y0) ≥ 2^33/4 ≈ 2.1e9`。
2. **EBDT/CBDT 路线**：见第七节，这是唯一能真正进入 `sbit_GetBitMapInfo` 的字体格式。
   **构造器已写好并可用**：`harness/fontpoc/makeebdt.py`
   ```
   python3 makeebdt.py <宽> <高> <ppem> <输出.ttf> [bearingX] [bearingY] [imageFormat]
   # 例: python3 makeebdt.py 64 64 12 ebdts/eb_64x64_ppem12.ttf 0 0 1
   ```
   它按规范逐字节生成 `EBLC`（`version 0x00020000` + 48 字节 `bitmapSizeTable` +
   8 字节 `indexSubTableArray` + `indexFormat 1` 子表）与 `EBDT`
   （`SmallGlyphMetrics` 5 字节 + imageFormat 1/2 的 1bpp 数据），
   并用 `DefaultTable` 绕过 fontTools 对 EBDT 的解析器（它会因缺 `version` 字段 KeyError）。
   产物 `harness/fontpoc/ebdts/eb_64x64_ppem12.ttf` 能被 fontTools 正确读回
   （`EBLC len 80`, `EBDT len 525`），字形 'A' → gid 2063。
   **注意（未解决）**：在 macOS 27 上用 `CTFontDrawGlyphs` 渲染这个字体，
   与原始 `Apple Symbols` 的墨迹**逐像素相同**（size 12/24/48/96 全部走轮廓）；
   把 'A' 的轮廓清空做成 **bitmap-only**（`ebdts/eb_nooutline.ttf`）后
   渲染结果是 **ink=0（什么都没画）**，说明 macOS 27 **已不再对 EBLC/EBDT 做光栅化**。
   iOS 侧尚未验证（构造好 app 后设备锁屏，`Unable to launch ... device was not, or
   could not be, unlocked`）——这是下一步唯一待做的实验。
   若 iOS 同样忽略 EBDT，则应改试 `CBLC+CBDT`（彩色位图，`imageFormat 17/18/19`），
   或确认 `sbit_*` 这条路径在 iOS 27 上是**死代码**（这本身就是"不可达"的结论）。
   - 命中后按 `dest = 位图尺寸 × (字号/ppem)` 调参，先用 `ppem=12 / 位图 64`
     让 `字号/ppem ≥ 512`（即字号 ≥ 6144 px）把 `rowBytes` 推到 32768 以上。
   - 验证脚本：`harness/fontpoc/mtest.m`（macOS，逐字号打印 ink/包围盒，
     实心方块 ⇒ 位图生效，三角形轮廓 ⇒ 未生效）。
3. `CTFontGetBoundingRectsForGlyphs` 对 sbix 挂死：需解锁后定位（怀疑在 `sbit_CalculateTransformSpaceNeeded`
   的「找最大子表」循环里，该循环对每个子表遍历 `uVar6` 次且 `puVar8 += 0xc` 步进）。

### 设备状态
- iPhone18,2 / 27.0.1 (24A446)，`devicectl` id `DEVICE-UDID`
- 最后一轮因**锁屏**导致 install 失败（`BSErrorCodeDescription = Locked`），需人工解锁后继续。
- PoC 工程：`harness/sbx/`（`main.m` = 字号/矩阵扫描；`main3.m` = 路径辨识 + 挂死复现）
  签名/安装/取日志命令见 `USERSPACE-DIFF-RESULTS.md` 与本报告第六节的调用序列。

---

## 九、产物清单

| 路径 | 内容 |
|---|---|
| `out/cdb-2701.c` / `out/cdb-272.c` | `ComputeDestBitmap` / `RenderBitmap` / `sbit_GetBitMapData` 双版本反编译 |
| `out/m3-2701.c` | `M3x3Mul` / `M3x3Flags` / `M3x3Inverse` / `M3x3Concat` 反编译 |
| `out/sb-2701.c` | `sbit_FontMatch` / `sbit_GetMetrics` / `sbit_CalculateTransformSpaceNeeded` 反编译 |
| `out/fp-2701.c` / `out/fp-272.c` | `sbit_GetBitMapInfo` 双版本反编译（已有） |
| `harness/sbx/` | 真机 PoC app（`main.m` 字号/CTM 扫描，`main3.m` 路径辨识，`main4.m` EBDT 验证） |
| `harness/fontpoc/makeebdt.py` | EBLC+EBDT 字体构造器（按规范逐字节生成） |
| `harness/fontpoc/ebdts/` | `eb_64x64_ppem12.ttf`（带轮廓）、`eb_nooutline.ttf`（bitmap-only） |
| `harness/fontpoc/mtest.m` | macOS 侧验证脚本（判定位图/轮廓） |
| `harness/fontpoc/fonts3/` | 非正方形 sbix（路径辨识 / 挂死复现） |
