# PATCH-HUNT：iOS 27.0.1 ↔ 27.2 函数级差分

## 0. 方法与自检

工具 `tools/fdiff.py`（新写）。提取出的 kext **没有符号表**（`nsyms=0`），函数边界只能取 `LC_FUNCTION_STARTS`；VA↔off **只走 segment**（`tools/kext_extract.py` 没重写 `section_64.offset`，按 section 取表会读到垃圾，见 `tools/kseg.py` 头注释）。

归一化：`adrp` 页基址、`adrp` 后续指令的页内偏移、分支/调用绝对目标、`>0xffff` 立即数 → `<X>`/`<PAGEOFF>`/`<IMM>`；**保留 mnemonic、寄存器、小立即数、结构体字段偏移**。
（不加这一层，IOSurface 的 1330 个函数里 708 个会被误判成「改了」，因为函数搬家后 `adrp+add` 的页内偏移全变。）

> **自检标尺**：已知的 IOSurface `+0xf1` 补丁。27.2 的 `0xfffffe000a3944c0` 新增 `ldrb w8,[x21,#0xf1]` + `tbz w8,#0,#3`；`0xfffffe000a394744` 新增 `mov w8,#1` + `strb w8,[x20,#0xf1]`；27.0.1 侧 0 处。**两处都被本工具以「真插入 +4/−0」「+2/−0」命中，diff 干净无噪声** ⇒ 方法有效。

## 0.1 四类判定

| 类 | 含义 | 处理 |
|---|---|---|
| **A 真插入** | 27.2 多出指令、27.0.1 无对应删除 | 直接可读，唯一能当补丁用的 |
| **B 布局位移** | 增删成对、只差 `[reg,#off]`、delta 恒定 | 结构体长胖，delta = 新增块大小（情报） |
| **C 行号漂移** | 只差 `mov wN,#imm` 小立即数 | `__LINE__` / IOLog 断言码，丢弃 |
| **D 混合** | 剩下 | 人工看 |

## 0.2 总量

| kext | 27.0.1 函数 | 27.2 函数 | 归一化后不同 | A 真插入 | B 布局位移 | C 行号 | D 混合 |
|---|---|---|---|---|---|---|---|
| `AGXG18P` | 3421 | 3442 | 1037 | **16** | 295 | 72 | 654 |
| `driver_AppleAVD` | 2328 | 2328 | 27 | **1** | 15 | 6 | 5 |
| `driver_AppleAVE2` | 2995 | 2998 | 415 | **1** | 89 | 155 | 170 |
| `driver_AppleJPEGDriver` | 1807 | 1807 | 1 | **0** | 1 | 0 | 0 |
| `driver_AppleM2ScalerCSCDriver` | 10262 | 10276 | 629 | **20** | 51 | 485 | 73 |
| `driver_AppleMobileDispH18P-DCP` | 1460 | 1484 | 312 | **4** | 99 | 61 | 148 |
| `driver_AppleSPU` | 2330 | 2330 | 8 | **0** | 7 | 0 | 1 |
| `driver_EXDisplayPipeH18P` | 187 | 187 | 2 | **0** | 0 | 2 | 0 |
| `iokit_IOHIDFamily` | 2808 | 2809 | 51 | **1** | 5 | 0 | 45 |
| `iokit_IOMobileGraphicsFamily-DCP` | 800 | 800 | 149 | **1** | 15 | 123 | 10 |
| `iokit_IONVMeFamily` | 3589 | 3556 | 602 | **0** | 2 | 585 | 15 |
| `iokit_IOSurface` | 1330 | 1330 | 20 | **2** | 11 | 6 | 1 |

**合计：A 46 / B 590 / C 1495 / D 1122**

## 1. A 类：真插入（按评分）

| # | kext | 函数 27.0.1 → 27.2 | diff | 新增指令 | 新字段 | 可达性 |
|---|---|---|---|---|---|---|
| 1 | `iokit_IOSurface` | `0xfffffe000a3460f0` → `0xfffffe000a3944c0` | +4/−0 | ldrb w8,[x21, #0xf1]<br>tbz w8,#0,#3<br>add w20,w20,#0x1b<br>b #39 | 0xf1 | — |
| 2 | `AGXG18P` | `0xfffffe00084b5138` → `0xfffffe0008539484` | +1/−0 | strb w1,[x0, #0x2ba] | 0x2ba | — |
| 3 | `iokit_IOSurface` | `0xfffffe000a346364` → `0xfffffe000a394744` | +2/−0 | mov w8,#1<br>strb w8,[x20, #0xf1] | 0xf1 | — |
| 4 | `iokit_IOMobileGraphicsFamily-DCP` | `0xfffffe000a14f37c` → `0xfffffe000a19e638` | +5/−0 | cmp w2,#0xbc<br>b.ls #4<br>mov w0,#0x2c2<br>movk w0,#0xe000,lsl #16<br>ret  | — | — |
| 5 | `driver_AppleAVD` | `0xfffffe00086b4a4c` → `0xfffffe000873e778` | +12/−0 | cbz x1,#6<br>adds w8,w2,w3<br>b.hs #4<br>ldr w9,[x1, #0x2c]<br>cmp w8,w9<br>b.ls #2<br>ret <br>ldr x8,[x1, #8] | 0x8,0x2c | — |
| 6 | `AGXG18P` | `0xfffffe00084b3ad8` → `0xfffffe00084d8a18` | +1/−0 | ldr x0,[x0, #0x208] | 0x208 | — |
| 7 | `AGXG18P` | `0xfffffe00084b1a74` → `0xfffffe00084e62d8` | +1/−0 | ldr x0,[x0, #0x558] | 0x558 | — |
| 8 | `AGXG18P` | `0xfffffe00084b5cc8` → `0xfffffe0008542d24` | +1/−0 | ldr w0,[x0, #0x1d5c] | 0x1d5c | — |
| 9 | `AGXG18P` | `0xfffffe00084b5cd0` → `0xfffffe000854f2f8` | +1/−0 | ldr x0,[x0, #0x208] | 0x208 | — |
| 10 | `AGXG18P` | `0xfffffe00084b5e38` → `0xfffffe0008555a7c` | +1/−0 | ldr x0,[x0, #0x208] | 0x208 | — |
| 11 | `AGXG18P` | `0xfffffe00084b69d0` → `0xfffffe000855be98` | +1/−0 | ldr x0,[x0, #0x208] | 0x208 | — |
| 12 | `AGXG18P` | `0xfffffe0008504c58` → `0xfffffe000858be8c` | +1/−0 | mov w2,#0x1ca8 | — | — |
| 13 | `AGXG18P` | `0xfffffe00084b6bd0` → `0xfffffe0008595b44` | +1/−0 | add x0,x0,#0x344 | — | — |
| 14 | `AGXG18P` | `0xfffffe00084b6bd8` → `0xfffffe0008595b50` | +1/−0 | add x0,x0,#0x33c | — | — |
| 15 | `AGXG18P` | `0xfffffe00084b7200` → `0xfffffe0008595d58` | +1/−0 | ldr w0,[x0, #0x338] | 0x338 | — |
| 16 | `AGXG18P` | `0xfffffe0008506280` → `0xfffffe0008596550` | +1/−0 | mov w2,#0x400 | — | — |
| 17 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090490a8` → `0xfffffe00090955ac` | +1/−0 | str wzr,[x0, #0xa0] | 0xa0 | — |
| 18 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe0009049604` → `0xfffffe00090955e8` | +1/−0 | str wzr,[x0, #0xa0] | 0xa0 | — |
| 19 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000905d2c4` → `0xfffffe00090956f0` | +1/−0 | str wzr,[x0, #0xa0] | 0xa0 | — |
| 20 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe0009049288` → `0xfffffe0009095774` | +1/−0 | str wzr,[x0, #0xa0] | 0xa0 | — |
| 21 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090497c0` → `0xfffffe00090957d4` | +1/−0 | str wzr,[x0, #0xa0] | 0xa0 | — |
| 22 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090496e4` → `0xfffffe00090a4564` | +1/−0 | mov w1,#0x48be | — | — |
| 23 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090490e0` → `0xfffffe00090c53bc` | +1/−0 | ldr x0,[x0, #0x78] | 0x78 | — |
| 24 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090a3a34` → `0xfffffe00090e1040` | +1/−0 | mov w2,#0x180 | — | — |
| 25 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904df78` → `0xfffffe00090f121c` | +1/−0 | mov w1,#0x4594 | — | — |
| 26 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090e515c` → `0xfffffe00090f18cc` | +1/−0 | mov w2,#0x470 | — | — |
| 27 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904e544` → `0xfffffe0009115018` | +1/−0 | mov w1,#0x4594 | — | — |
| 28 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090e55c0` → `0xfffffe000917164c` | +1/−0 | mov w2,#0x470 | — | — |
| 29 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904f1a4` → `0xfffffe0009173a48` | +1/−0 | mov w1,#0x48be | — | — |
| 30 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe0009184cb4` → `0xfffffe00091b4024` | +1/−0 | mov w8,#0x2e4 | — | — |
| 31 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe00091fff64` → `0xfffffe0009249184` | +1/−0 | mov w0,#0x3e8 | — | — |
| 32 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009200fd8` → `0xfffffe0009252988` | +1/−0 | mov w0,#0x3e8 | — | — |
| 33 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009201000` → `0xfffffe000926ae8c` | +1/−0 | mov w0,#0x3e8 | — | — |
| 34 | `iokit_IOHIDFamily` | `0xfffffe000a0e4310` → `0xfffffe000a1333ec` | +1/−0 | ldr x23,[x8] | — | — |
| 35 | `AGXG18P` | `0xfffffe00084b3324` → `0xfffffe0008525dd8` | +2/−0 | ldr x8,[x0, #0x2a8]<br>ldr x0,[x8, #0x160] | 0x160,0x2a8 | — |
| 36 | `AGXG18P` | `0xfffffe00084b595c` → `0xfffffe0008531198` | +2/−0 | ldr x8,[x0, #0xcc0]<br>str w1,[x8, #0x6c8] | 0x6c8,0xcc0 | — |
| 37 | `AGXG18P` | `0xfffffe00084b4d68` → `0xfffffe0008538d7c` | +2/−0 | ldr x8,[x0, #0xcc0]<br>ldr x0,[x8, #0x5d0] | 0x5d0,0xcc0 | — |
| 38 | `driver_AppleAVE2` | `0xfffffe00088ecad0` → `0xfffffe0008926f88` | +2/−0 | udf #0<br>udf #0 | — | — |
| 39 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904ded0` → `0xfffffe0009114d58` | +2/−0 | stp xzr,xzr,[x0, #0xa0]<br>str xzr,[x0, #0xb0] | 0xa0,0xb0 | — |
| 40 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904f0c4` → `0xfffffe0009114d98` | +2/−0 | stp xzr,xzr,[x0, #0xa0]<br>str xzr,[x0, #0xb0] | 0xa0,0xb0 | — |
| 41 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904e054` → `0xfffffe0009114ef8` | +2/−0 | stp xzr,xzr,[x0, #0xa0]<br>str xzr,[x0, #0xb0] | 0xa0,0xb0 | — |
| 42 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009200fe0` → `0xfffffe00092627cc` | +2/−0 | ldr q0,[x1]<br>str q0,[x0, #0x6590] | — | — |
| 43 | `AGXG18P` | `0xfffffe00084b1a7c` → `0xfffffe00084e6e7c` | +4/−0 | ldr x8,[x0, #0x558]<br>ldr x8,[x8, #0xcc0]<br>ldr w0,[x8, #0x5e0]<br>mov w1,#0x20 | 0x558,0x5e0,0xcc0 | — |
| 44 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904963c` → `0xfffffe00090c32d8` | +4/−0 | movi d0,#<IMM><br>str d0,[x0, #0x40]<br>str wzr,[x0, #0x48]<br>strh wzr,[x0, #0x88] | 0x40,0x48,0x88 | — |
| 45 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904de98` → `0xfffffe00090c3320` | +4/−0 | movi d0,#<IMM><br>str d0,[x0, #0x40]<br>str wzr,[x0, #0x48]<br>strh wzr,[x0, #0x88] | 0x40,0x48,0x88 | — |
| 46 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000904981c` → `0xfffffe00090c3488` | +4/−0 | movi d0,#<IMM><br>str d0,[x0, #0x40]<br>str wzr,[x0, #0x48]<br>strh wzr,[x0, #0x88] | 0x40,0x48,0x88 | — |

## 2. B 类：结构体长胖（delta = 新增块大小）

| kext | delta | 命中函数数 | 例子 |
|---|---|---|---|
| `AGXG18P` | +0x8 | 282 | `0xfffffe00084b1a18`: `ldr x0,[x8, #0x140]` → `ldr x0,[x8, #0x148]` |
| `driver_AppleMobileDispH18P-DCP` | +0x8 | 88 | `0xfffffe0009201058`: `ldr x0,[x8, #0x5e28]` → `ldr x0,[x8, #0x5e30]` |
| `driver_AppleAVE2` | +0x8 | 51 | `0xfffffe000872eac4`: `ldr w8,[x0, #0x1b54]` → `ldr w8,[x0, #0x1b5c]` |
| `driver_AppleM2ScalerCSCDriver` | +0x8 | 20 | `0xfffffe000909a248`: `ldr w8,[x0, #0x15c]` → `ldr w8,[x0, #0x164]` |
| `driver_AppleAVE2` | +0x98 | 17 | `0xfffffe000875dfec`: `strb w21,[x20, #0x9c0]` → `strb w21,[x20, #0xa58]` |
| `driver_AppleM2ScalerCSCDriver` | +0x10 | 17 | `0xfffffe000906ac58`: `strb wzr,[x0, #0x78]` → `strb wzr,[x0, #0x88]` |
| `driver_AppleAVE2` | +0x40 | 13 | `0xfffffe00087672f8`: `str wzr,[x19, #0x578]` → `str wzr,[x19, #0x5b8]` |
| `AGXG18P` | +0x48 | 11 | `0xfffffe00085202f0`: `ldr x0,[x0, #0x1840]` → `ldr x0,[x0, #0x1888]` |
| `driver_AppleAVD` | -0x280 | 10 | `0xfffffe00086bb6a8`: `ldr d1,[x13, #0xdc0]` → `ldr d1,[x13, #0xb40]` |
| `iokit_IOSurface` | -0x3f0 | 10 | `0xfffffe000a32a3e0`: `strb w9,[x8, #0x950]` → `strb w9,[x8, #0x560]` |
| `driver_AppleMobileDispH18P-DCP` | +0x140 | 8 | `0xfffffe000920c16c`: `str w9,[x8, #0xce8]` → `str w9,[x8, #0xe28]` |
| `iokit_IOMobileGraphicsFamily-DCP` | -0x3f0 | 8 | `0xfffffe000a15ef64`: `str w10,[x8, #0xdc0]` → `str w10,[x8, #0x9d0]` |
| `driver_AppleM2ScalerCSCDriver` | +0x140 | 7 | `0xfffffe00090afd4c`: `ldr x1,[x24, #0x618]` → `ldr x1,[x24, #0x758]` |
| `iokit_IOMobileGraphicsFamily-DCP` | +0x8 | 6 | `0xfffffe000a14c350`: `ldr x8,[x0, #0x5df8]` → `ldr x8,[x0, #0x5e00]` |
| `driver_AppleAVE2` | -0x2b0 | 4 | `0xfffffe0008861708`: `ldr d0,[x8, #0xef8]` → `ldr d0,[x8, #0xc48]` |
| `driver_AppleM2ScalerCSCDriver` | -0xa0 | 4 | `0xfffffe00090e72c8`: `ldr q3,[x10, #0xd80]` → `ldr q3,[x10, #0xce0]` |
| `driver_AppleSPU` | -0xcd0 | 4 | `0xfffffe00096a4e14`: `ldr x0,[x21, #0xf40]` → `ldr x0,[x21, #0x270]` |
| `iokit_IOHIDFamily` | +0xc10 | 4 | `0xfffffe000a101b54`: `str x9,[x8, #0x380]` → `str x9,[x8, #0xf90]` |
| `driver_AppleAVD` | +0x98 | 3 | `0xfffffe00086ce964`: `ldr w8,[x25, #0x3d0]` → `ldr w8,[x25, #0x468]` |
| `driver_AppleAVE2` | -0x280 | 3 | `0xfffffe0008728fc0`: `ldr d1,[x23, #0xa78]` → `ldr d1,[x23, #0x7f8]` |
| `driver_AppleAVD` | +0xd80 | 2 | `0xfffffe00086d5050`: `ldr d1,[x13, #8]` → `ldr d1,[x13, #0xd88]` |
| `driver_AppleM2ScalerCSCDriver` | -0x110 | 2 | `0xfffffe0009048494`: `ldr q5,[x10, #0x8e0]` → `ldr q5,[x10, #0x7d0]` |
| `driver_AppleSPU` | +0x790 | 2 | `0xfffffe00096d416c`: `ldr d1,[x26, #0x4b8]` → `ldr d1,[x26, #0xc48]` |
| `iokit_IONVMeFamily` | -0x3f0 | 2 | `0xfffffe000a1dbbec`: `str xzr,[x20, #0x8c0]` → `str xzr,[x20, #0x4d0]` |
| `AGXG18P` | +0x4508 | 1 | `0xfffffe000851fb5c`: `ldr x0,[x8, #0x5c8]` → `ldr x0,[x8, #0x4ad0]` |
| `driver_AppleAVE2` | +0xd50 | 1 | `0xfffffe0008759ce0`: `ldr d0,[x16, #0xe0]` → `ldr d0,[x16, #0xe30]` |
| `driver_AppleM2ScalerCSCDriver` | +0x58 | 1 | `0xfffffe000905d448`: `ldrb w8,[x0, #0x30]` → `ldrb w8,[x0, #0x88]` |
| `driver_AppleMobileDispH18P-DCP` | -0x10 | 1 | `0xfffffe000920f88c`: `ldr x0,[x19, #0x5e58]` → `ldr x0,[x19, #0x5e48]` |
| `driver_AppleMobileDispH18P-DCP` | +0x30 | 1 | `0xfffffe000920f8e4`: `ldr x0,[x19, #0x5e40]` → `ldr x0,[x19, #0x5e70]` |
| `driver_AppleMobileDispH18P-DCP` | +0x59f8 | 1 | `0xfffffe000920a6a0`: `ldr x0,[x8, #0x438]` → `ldr x0,[x8, #0x5e30]` |
| `driver_AppleSPU` | +0x330 | 1 | `0xfffffe00096c4074`: `strb w10,[x9, #0x590]` → `strb w10,[x9, #0x8c0]` |
| `iokit_IOMobileGraphicsFamily-DCP` | +0xb | 1 | `0xfffffe000a156ac4`: `ldrb w8,[x22, #0xdf2]` → `ldrb w8,[x22, #0xdfd]` |
| `iokit_IOSurface` | +0x5f0 | 1 | `0xfffffe000a3455ec`: `ldr d0,[x19, #0xa00]` → `ldr d0,[x19, #0xff0]` |
| `driver_AppleJPEGDriver` | +0x140 | 1 | `0xfffffe0009007594`: `strb w9,[x23, #0xbe0]` → `strb w9,[x23, #0xd20]` |
| `iokit_IOHIDFamily` | +0x240 | 1 | `0xfffffe000a115dd0`: `ldr d0,[x24, #0x40]` → `ldr d0,[x24, #0x280]` |
| `AGXG18P` | -0x138 | 1 | `0xfffffe000850bc3c`: `ldr x8,[x0, #0x16d0]` → `ldr x8,[x0, #0x1598]` |

## 3. 有 selector 可达的候选（优先看）

### `driver_AppleAVE2`  `0xfffffe00088d24e4` → `0xfffffe000890c990`  [mixed]

- selector: `com.apple.driver.AppleAVE2` sel 0 (handler `0xfffffe00088d24e4`)
  - `+ cbz w24,#226`
  - `+ b #153`
  - `+ b #96`
  - `+ cbz w20,#55`
  - `+ mov w8,#0xd4`
  - `+ b #58`
  - `+ movk w1,#2,lsl #16`
  - `+ b #-101`
  - `+ mov w8,#0xd4`
  - `+ mov w8,#0xc6`
  - `+ mov w8,#0xc6`
  - `- cbz w24,#225`
  - `- b #152`
  - `- b #95`
  - `- cbz w20,#54`
  - `- mov w8,#0xd8`
  - `- b #57`
  - `- b #-100`
  - `- mov w8,#0xd8`
  - `- mov w8,#0xca`
  - `- mov w8,#0xca`

### `AGXG18P`  `0xfffffe00084f1fe8` → `0xfffffe000850af28`  [mixed]

- selector: `com.apple.AGXG18P` sel 1 (handler `0xfffffe00084f1fe8`)
  - `+ add x8,x8,#0x378`
  - `- add x8,x8,#0x370`


## 4. D 类：混合（需人工看，列前 40）

共 1122 个。前 40：

| # | kext | 函数 | diff | 新增 |
|---|---|---|---|---|
| 1 | `driver_AppleAVE2` | `0xfffffe00088d24e4` | +11/−10 | cbz w24,#226<br>b #153<br>b #96<br>cbz w20,#55 |
| 2 | `AGXG18P` | `0xfffffe00084f1fe8` | +1/−1 | add x8,x8,#0x378 |
| 3 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090fb14c` | +5/−3 | cbz x1,#1693<br>cbz x0,#1688<br>cbz x8,#11<br>ldrb w9,[x8, #0x138] |
| 4 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090b5878` | +7/−1 | ldrb w8,[x21, #0x138]<br>add x9,x21,#0x130<br>adrp x10,#<X><br>ldr x10,[x10, #<PAGEOFF>] |
| 5 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe000920435c` | +7/−7 | cbz x1,#17<br>ldr x0,[x0, #0x5e30]<br>mov w1,#0x3830<br>ldr x0,[x0, #0x5e30] |
| 6 | `AGXG18P` | `0xfffffe00084b37a4` | +10/−5 | ldr x0,[x8, #0x148]<br>ldrb w8,[x20, #0x239]<br>tbnz w8,#0,#12<br>tbnz w8,#0,#13 |
| 7 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090e42a0` | +11/−2 | b.lo #39<br>cbz x8,#35<br>ldrb w9,[x8, #0x138]<br>tbz w9,#0,#8 |
| 8 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090ba5d0` | +12/−6 | b #180<br>b #95<br>b.hs #80<br>cbnz w0,#96 |
| 9 | `iokit_IOMobileGraphicsFamily-DCP` | `0xfffffe000a1657c8` | +13/−10 | b.ne #13<br>tbz w0,#0,#8<br>ldrb w8,[x19, #0x1b1]<br>tbz w8,#0,#4 |
| 10 | `AGXG18P` | `0xfffffe00085531b4` | +14/−15 | cbz x0,#215<br>cbz x0,#195<br>ldrb w8,[x22, #0xd54]<br>ldr x0,[x22, #0xd58] |
| 11 | `AGXG18P` | `0xfffffe0008575a74` | +20/−10 | ldr x0,[x8, #0x148]<br>ldrb w8,[x20, #0x239]<br>tbnz w8,#0,#26<br>tbnz w8,#0,#27 |
| 12 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090b9878` | +22/−10 | cbz x25,#228<br>cbz w0,#201<br>b #198<br>tbz w8,#0,#68 |
| 13 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe0009060888` | +23/−17 | mov x20,x1<br>ldrb w9,[x8, #0x138]<br>add x8,x8,#0x130<br>adrp x10,#<X> |
| 14 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe000921e68c` | +23/−18 | mov x19,x0<br>ldr x8,[x0]<br>cbz x8,#25<br>str xzr,[sp, #0x18] |
| 15 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009222de0` | +25/−30 | cmp w1,#0x10<br>b.hi #24<br>mov x20,x0<br>adrp x21,#<X> |
| 16 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090885f4` | +26/−14 | cbnz w0,#262<br>b #199<br>cbnz w0,#185<br>cbz w0,#108 |
| 17 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe00092165bc` | +26/−11 | ldr x20,[x0, #0x61b8]<br>cbz x20,#50<br>mov x19,x0<br>mov x17,x20 |
| 18 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000905f4ec` | +29/−16 | stp x22,x21,[sp, #-0x30]!<br>stp x20,x19,[sp, #0x10]<br>stp x29,x30,[sp, #0x20]<br>add x29,sp,#0x20 |
| 19 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090ba1b4` | +29/−17 | tbz w8,#0,#87<br>b.hs #200<br>ldrb w9,[x8, #0x138]<br>add x8,x8,#0x130 |
| 20 | `iokit_IOMobileGraphicsFamily-DCP` | `0xfffffe000a167334` | +29/−18 | tbz w8,#0,#41<br>sub sp,sp,#0x40<br>stp x22,x21,[sp, #0x10]<br>stp x20,x19,[sp, #0x20] |
| 21 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe000921b138` | +33/−18 | stp x20,x19,[sp, #0x10]<br>mov w8,#0xaa<br>strb w8,[sp, #0xc]<br>mov w8,#0xaaaa |
| 22 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009201e40` | +36/−14 | stp x22,x21,[sp, #-0x30]!<br>stp x20,x19,[sp, #0x10]<br>stp x29,x30,[sp, #0x20]<br>add x29,sp,#0x20 |
| 23 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090b2378` | +38/−29 | mov w26,#0x8300<br>movk w26,#1,lsl #16<br>ldrb w27,[x8, #0x28d]<br>mov w28,#0x32 |
| 24 | `AGXG18P` | `0xfffffe00084f14d4` | +41/−41 | add x8,x8,#0x460<br>ldr x0,[x8]<br>bl #<X><br>movk x16,#0x65a2,lsl #48 |
| 25 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009203cec` | +42/−56 | mov x19,x6<br>mov x20,x5<br>mov x21,x4<br>mov x22,x3 |
| 26 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009222edc` | +44/−46 | mov x21,x2<br>mov x19,x1<br>mov x20,x0<br>adrp x22,#<X> |
| 27 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009222fc0` | +46/−45 | mov x19,x4<br>mov x20,x3<br>mov x21,x2<br>mov x22,x1 |
| 28 | `AGXG18P` | `0xfffffe00084cee28` | +49/−49 | ldrb w8,[x0, #0x4ba]<br>ldr w8,[x20, #0x450]<br>ldr w8,[x20, #0x454]<br>ldr w0,[x20, #0x49c] |
| 29 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000917a39c` | +50/−30 | mov x3,x30<br>bl #<X><br>mov x30,x3<br>stp x29,x30,[sp, #0x50] |
| 30 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe0009213314` | +50/−28 | mov x20,x2<br>mov w8,#0x5df1<br>add x25,x0,x8<br>ldrb w8,[x25] |
| 31 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe000921e710` | +52/−44 | mov x22,x2<br>mov x23,x1<br>mov x21,x0<br>mov w20,#0x2eb |
| 32 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe000921ea80` | +53/−21 | sub sp,sp,#0x50<br>stp x24,x23,[sp, #0x10]<br>stp x22,x21,[sp, #0x20]<br>stp x20,x19,[sp, #0x30] |
| 33 | `AGXG18P` | `0xfffffe0008529d60` | +55/−15 | ldr x8,[x0, #0x17d8]<br>cbz x8,#63<br>ldr x0,[x0, #0x17f8]<br>bl #<X> |
| 34 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe000921a338` | +57/−15 | mov x20,x1<br>mov x19,x0<br>mov x21,x0<br>ldr x0,[x19, #0x5e90] |
| 35 | `driver_AppleMobileDispH18P-DCP` | `0xfffffe000922097c` | +57/−52 | stp x24,x23,[sp, #0x10]<br>mov x19,x1<br>cmp w1,#0x10<br>b.lo #8 |
| 36 | `AGXG18P` | `0xfffffe000855ec14` | +59/−57 | stp x22,x21,[sp, #-0x30]!<br>stp x20,x19,[sp, #0x10]<br>stp x29,x30,[sp, #0x20]<br>add x29,sp,#0x20 |
| 37 | `driver_AppleM2ScalerCSCDriver` | `0xfffffe000914df0c` | +61/−111 | stp x26,x25,[sp, #0x40]<br>ldr x8,[x0]<br>ldr x8,[x8]<br>ldr x22,[x8, w1, uxtw #3] |
| 38 | `AGXG18P` | `0xfffffe00084daa60` | +62/−56 | b #405<br>add x8,x8,#0x798<br>b.ls #383<br>ldr x0,[x8, #0x148] |
| 39 | `AGXG18P` | `0xfffffe00084e6480` | +65/−60 | add x8,x8,#0x33c<br>tbz w8,#0,#1038<br>add x9,x9,#0xd55<br>ldr x0,[x8, #0x148] |
| 40 | `driver_AppleSPU` | `0xfffffe00096b6f28` | +68/−62 | cbz x0,#1200<br>cbz x0,#1177<br>cbz x0,#1162<br>cbz x0,#1144 |

---

## 5. 新增拒绝路径 / 字节门（详见 `out/PATCH-HUNT-errorpaths.md`）

由 `tools/errorpath_scan.py` 生成。三个指纹 + 两层收紧（必须是**离散插入**：
`新增 ≤ 30 条 / 删除 ≤ 30 条`，且字节门要求的字段偏移在 27.0.1 的同一函数里**一次都没被访问过**）。
不收紧的话会得到 55 个「字节门」，绝大多数只是重排后 `ldrb` 落进了 diff 窗口。

### 5.1 新增 IOReturn 路径（4 处，小 diff，可信）

| kext | 27.0.1 → 27.2 | 新增的错误码 | 27.0.1 原行为 |
|---|---|---|---|
| `driver_AppleAVD` | `0xfffffe0008710cd4` → `0xfffffe00087472c8` | `0xE00002BC` | `mov w19,#0`（**原本返回成功**） |
| `iokit_IOMobileGraphicsFamily-DCP` | `0xfffffe000a14f37c` → `0xfffffe000a19e638` | `0xE00002C2` | 无错误码（+5/−0 纯插入） |
| `iokit_IOMobileGraphicsFamily-DCP` | `0xfffffe000a1512c8` → `0xfffffe000a1a0598` | `0xE00002BC` | 同函数已有该码，但本路径原不返回 |
| `iokit_IOMobileGraphicsFamily-DCP` | `0xfffffe000a1657c8` → `0xfffffe000a1b4aac` | `0xE00002BC` | 同前 |

**最值得看的两条：**

1. `IOMobileGraphicsFamily-DCP 0xa14f37c`：**+5/−0 纯新增**，全文就这五条：

   ```
   cmp  w2, #0xbc          ; 0xbc = 188
   b.ls ok
   mov  w0, #0x2c2
   movk w0, #0xe000, lsl #16   ; = 0xE00002C2 kIOReturnBadArgument
   ret
   ```
   即 **w2（一个 size/count 参数）新增上限 188**。188 这个数字很具体（不是 0xff/0x100），
   说明对应一个真实的数组/表；27.0.1 侧没有这个检查 ⇒ **27.0.1 上 w2 > 188 会走进去**。
   这条是本轮最干净的一个「被修掉的边界」。

2. `driver_AppleAVD 0x8710cd4`：`mov w19,#0` 改成 `mov w19,#0x2bc / movk w19,#0xe000`
   ⇒ **原本返回 0（成功）的路径，27.2 改成返回 `kIOReturnError`**。
   这是「静默成功 → 显式失败」，典型是修掉一个「本该拒绝却放过」的校验。

### 5.2 新增字节门（4 处，与 IOSurface `+0xf1` 同型）

| kext | 函数 27.0.1 → 27.2 | 字段 | 形态 |
|---|---|---|---|
| `iokit_IOSurface` | `0xfffffe000a3460f0` → `0xfffffe000a3944c0` | `+0xf1` | `ldrb` + `tbz #0`（注册路径，命中返回 `0xE00002D8`） |
| `iokit_IOSurface` | `0xfffffe000a346364` → `0xfffffe000a394744` | `+0xf1` | `mov #1` + `strb`（注销路径，打粘滞标记） |
| `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090e42a0` → `0xfffffe000912b940` | `+0x138` | `ldrb` + `tbz #0` |
| `driver_AppleM2ScalerCSCDriver` | `0xfffffe00090fb14c` → `0xfffffe0009142840` | `+0x138` | `ldrb` + `tbnz #0` |

**`M2ScalerCSCDriver` 的 `+0x138` 是一对新发现的门**，和 IOSurface `+0xf1` 完全同型
（一个读检查、一个写标记，同一字段，27.0.1 侧 0 处）。
`M2ScalerCSCDriver` 是我们**有 selector 到达的类**（sel 7 的 `kIOReturnNoMemory` 区间就是它），
所以这条直接对应一个可测目标：27.2 起这两个函数会拒掉某些调用。

### 5.3 数值边界被放宽（不是修 bug，但改变可达面）

`AGXG18P 0xfffffe00084d8a10` → `0xfffffe00084f146c`：

```
- cmp w2, #9        ; 27.0.1 只接受 0..9
+ cmp w2, #0x14     ; 27.2 接受 0..20
- mov w8, #0x28b / lsr w8,w8,w21 / tbz      ; 掩码查表
+ mov w11, #0x28a / movk w11, #0x10, lsl #16 ; = 0x1000028a，33 位掩码
+ tst w10, w11
```

即 AGX 的内部方法表从 10 个扩到 21 个，并改用位掩码判定。
**在 27.0.1 上 w2 = 10..20 是被拒的**，`0x28b` 那个掩码只有 10 位。
这是「新版本开了新入口」的信号：27.2 上能进、27.0.1 上进不去 —— 对我们没用（目标是 27.0.1），
但如果这些新入口对应新加的校验，反过来能提示**27.0.1 上同一批 handler 缺什么检查**。

## 6. `proc_prepareexit_wait` 专项（CVE-2026-112501）

地址：27.0.1 `0xfffffe000b0e5f8c` / 27.2 `0xfffffe000b13b830`（`com.apple.kernel` 内，函数本体 873 条指令）。

**结论：本体没有任何逻辑改动。**

精细归一化（`adrp` 页基址、分支目标、`adrp` 后继的页内偏移全部抹平，**保留 `cmp`/`tst` 的小立即数**）
之后，873 条指令只剩 **14 处差异，全部是结构体字段偏移**：

| 27.0.1 | 27.2 | delta |
|---|---|---|
| `[x8, #0x508]` | `[x8, #0x5e8]` | +0xe0 |
| `[x23, #0xe28]` ×3 | `[x23, #0xf68]` | +0x140 |
| `[x25, #0xeb0]` | `[x25, #0xfa8]` | +0xf8 |
| `[x27, #0xe0]` ×2 | `[x27, #0x220]` | +0x140 |

`struct proc` 变长了（不同字段插入位置不同 ⇒ delta 不同），但**指令序列、比较常量、控制流一模一样**。

所以：如果这条 CVE 确实归到 `proc_prepareexit_wait`，**修复不在这个函数里**。
三种可能，按可能性排：
1. 修复在它的**被调用者**里（它前面就有 `bl` 到 4 个不同函数，我没做法向追踪）；
2. CVE 映射本身要复核（地址来源是哪份 advisory 的哪一节）；
3. 27.2 其实没修这条（只修了别处，函数只是跟着 `struct proc` 布局挪了位置）。

**这是留白，不是结论。** 要判定必须做被调用者追踪，本轮没做。

---

## CVE-2026-112501 复核（外部情报，非静态推断）

**Apple 官方描述**（[OpenCVE](https://app.opencve.io/cve/CVE-2026-112501) / [Tenable](https://www.tenable.com/cve/CVE-2026-112501)）：

> A **race condition** was addressed with **improved state handling**. ... An app may be able to cause **unexpected system termination**.
> Fixed in iOS 26.7.2 / **iOS 27.2** / iPadOS 27.2 / macOS Golden Gate 27.2 / macOS Sequoia 15.8.2 / macOS Tahoe 26.7.2 / tvOS 27.2 / visionOS 27.2 / watchOS 27.2.

[thehackerwire](https://www.thehackerwire.com/vulnerability/CVE-2026-112501/) 标注：**No Public PoC**，危害归类 **Denial of Service (DoS)**。

### 三条推论

1. **此前的 `proc_prepareexit_wait` 归因高度可疑。** 该函数本体 873 条指令、归一化后 0 处逻辑改动（仅 `struct proc` 字段偏移）。与「race condition + improved state handling」的描述也不吻合 —— 那描述指向的是**状态机/生命周期**类修复，不是 exit 路径。
2. **本项目 S2 的 IOSurface 缺陷与该 CVE 描述高度同型**：
   - race condition（register / deregister 与 teardown 并发）
   - improved **state handling**（27.2 新增 `+0xf1` 粘滞状态位）
   - 触发者 = 一个 App
   - 结果 = **unexpected system termination**（正是我们 5 次观测到的 kernel panic）
   - 修复版本 = 27.2
3. **影响等级 = DoS，不是提权。** 若 S2 对应此 CVE，则其评级与我们实测的能力边界一致：**只有崩溃，没有读写原语，没有沙箱逃逸，不构成越狱链的一环。**

### 边界声明

- **组件名未能核实** —— 本次网络受限（`support.apple.com` / `app.opencve.io` / `dev.to` 均无法 fetch，仅能取搜索摘要），未见官方公告明确列出 `IOSurface` 组件。
- 因此「S2 = CVE-2026-112501」是**高度相似的推断**，不是已证实的映射。要坐实需拿到 iOS 27.2 安全公告的组件条目。
