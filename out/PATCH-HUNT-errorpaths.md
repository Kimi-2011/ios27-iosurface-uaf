# 新增拒绝路径 / 字节门（27.2 相对 27.0.1）

由 `tools/errorpath_scan.py` 从 `out/PATCH-HUNT.raw.json` 生成。

## A. 新增了 IOReturn 错误路径（4 处）

### `driver_AppleAVD`  `0xfffffe0008710cd4` → `0xfffffe00087472c8`

- 27.2 新增错误码: `0xE00002BC`
- 27.0.1 同函数里已有的错误码: `0xE00002BC`（本路径原本不返回错误）
```diff
- b.eq #40
- cbz w11,#39
- b #15
- mov w19,#0
+ b.eq #41
+ cbz w11,#40
+ b #16
+ mov w19,#0x2bc
+ movk w19,#0xe000,lsl #16
```

### `iokit_IOMobileGraphicsFamily-DCP`  `0xfffffe000a14f37c` → `0xfffffe000a19e638`

- 27.2 新增错误码: `0xE00002C2`
- 27.0.1 原本: **无错误码**（该路径原本不返回错误）
```diff
+ cmp w2,#0xbc
+ b.ls #4
+ mov w0,#0x2c2
+ movk w0,#0xe000,lsl #16
+ ret 
```

### `iokit_IOMobileGraphicsFamily-DCP`  `0xfffffe000a1512c8` → `0xfffffe000a1a0598`

- 27.2 新增错误码: `0xE00002BC`
- 27.0.1 原本: `0xE00002BC`
```diff
- mov w20,#0x2bc
- movk w20,#0xe000,lsl #16
- b.gt #26
- tbnz w8,#0,#24
+ mov w20,#0x2bc
+ movk w20,#0xe000,lsl #16
+ b.gt #31
+ tbnz w8,#0,#29
+ ldr x0,[x23]
+ bl #<X>
+ tbz w0,#0,#3
+ add w20,w20,#0x1d
+ b #24
```

### `iokit_IOMobileGraphicsFamily-DCP`  `0xfffffe000a1657c8` → `0xfffffe000a1b4aac`

- 27.2 新增错误码: `0xE00002BC`
- 27.0.1 原本: `0xE00002BC`
```diff
- cbz w1,#4
- ldr x0,[x19, #0x160]
- mov x1,#0
- bl #<X>
- b.ne #17
- cmp w0,#0
- mov w8,#0x2bc
- movk w8,#0xe000,lsl #16
- csel w0,wzr,w8,ne
- b #2
+ b.ne #13
+ tbz w0,#0,#8
+ ldrb w8,[x19, #0x1b1]
+ tbz w8,#0,#4
+ ldr x0,[x19, #0x160]
+ mov x1,#0
+ bl #<X>
+ b #6
+ adrp x0,#<X>
+ add x0,x0,#<PAGEOFF>
+ bl #<X>
+ mov w0,#0x2bc
+ movk w0,#0xe000,lsl #16
```

## B. 新增字节门（`ldrb`+`tbz`，与 IOSurface `+0xf1` 同型）（4 处）

- `AGXG18P` `0xfffffe00084b37a4` → `0xfffffe00084cb7a4`  字段 `0x239`  （`ldrb w8,[x20, #0x239]` / `tbnz w8,#0,#12 tbnz w8,#0,#13`）
- `driver_AppleM2ScalerCSCDriver` `0xfffffe00090e42a0` → `0xfffffe000912b940`  字段 `0x138`  （`ldrb w9,[x8, #0x138]` / `tbz w9,#0,#8 adrp x8,#<X>`）
- `driver_AppleM2ScalerCSCDriver` `0xfffffe00090fb14c` → `0xfffffe0009142840`  字段 `0x138`  （`ldrb w9,[x8, #0x138]` / `tbnz w9,#0,#9`）
- `iokit_IOSurface` `0xfffffe000a3460f0` → `0xfffffe000a3944c0`  字段 `0xf1`  （`ldrb w8,[x21, #0xf1]` / `tbz w8,#0,#3 add w20,w20,#0x1b`）

## C. 新增边界比较（小改动，35 处，列前 25）

| kext | 函数 27.0.1 → 27.2 | 新增比较 | diff |
|---|---|---|---|
| `AGXG18P` | `0xfffffe00084b9b38` → `0xfffffe00084d1d80` | cmp x9,#0 | +16/−16 |
| `driver_AppleAVD` | `0xfffffe00086b4a4c` → `0xfffffe000873e778` | cmp w3,#0x40 | +12/−0 |
| `driver_AppleAVE2` | `0xfffffe0008725aec` → `0xfffffe000875c0dc` | cmp w8,#2 | +9/−6 |
| `driver_AppleM2ScalerCSCDriver` | `0xfffffe000909b730` → `0xfffffe00090e2cf0` | cmp x20,#0x299 | +10/−15 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fc660` → `0xfffffe000a14b74c` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x6c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fc744` → `0xfffffe000a14b834` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x74 | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fc82c` → `0xfffffe000a14b920` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x74 | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fc914` → `0xfffffe000a14ba0c` | cmp w12,#1<br>cmp x9,#1<br>cmp w11,#0x54 | +14/−13 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fc9c8` → `0xfffffe000a14bac4` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x6c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fcaac` → `0xfffffe000a14bbac` | cmp w10,#3<br>cmp x10,#3<br>cmp w9,#0x8c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fcbc0` → `0xfffffe000a14bcc4` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x74 | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fcca8` → `0xfffffe000a14bdb0` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x7c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fcd94` → `0xfffffe000a14bea0` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x7c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fd9c8` → `0xfffffe000a14cad8` | cmp w11,#3<br>cmp x11,#3<br>cmp w10,#0x9c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fdcb0` → `0xfffffe000a14cdc4` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x6c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fdd94` → `0xfffffe000a14ceac` | cmp w11,#2<br>cmp x11,#2<br>cmp w10,#0x74 | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fde58` → `0xfffffe000a14cf74` | cmp w11,#3<br>cmp x11,#3<br>cmp w10,#0x94 | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fdf4c` → `0xfffffe000a14d06c` | cmp w10,#2<br>cmp x10,#2<br>cmp w9,#0x84 | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0fe03c` → `0xfffffe000a14d160` | cmp w11,#2<br>cmp x11,#2<br>cmp w10,#0x6c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0ff070` → `0xfffffe000a14e164` | cmp w11,#2<br>cmp x11,#2<br>cmp w10,#0x7c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0ff130` → `0xfffffe000a14e228` | cmp w11,#2<br>cmp x11,#2<br>cmp w10,#0x84 | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0ff200` → `0xfffffe000a14e2fc` | cmp w11,#2<br>cmp x11,#2<br>cmp w10,#0x7c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0ff2c0` → `0xfffffe000a14e3c0` | cmp w11,#3<br>cmp x11,#3<br>cmp w10,#0x8c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0ff3b0` → `0xfffffe000a14e4b4` | cmp w11,#3<br>cmp x11,#3<br>cmp w10,#0x8c | +13/−12 |
| `iokit_IOHIDFamily` | `0xfffffe000a0ff4a0` → `0xfffffe000a14e5a8` | cmp w11,#3<br>cmp x11,#3<br>cmp w10,#0x8c | +13/−12 |
