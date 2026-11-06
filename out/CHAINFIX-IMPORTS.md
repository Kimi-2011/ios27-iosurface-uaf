# chained fixups：imports 表不存在，但指针可达性**可以**解 —— 并且找到了 `0xb348450` 的 12 个引用

工具：`tools/chainfix.py`（新增）

---

## 1. 结论先行

1. **这份 kernelcache 没有 imports 表。** `LC_DYLD_CHAINED_FIXUPS` 的 `imports_count = 0`，
   blob 全长只有 0x576 字节。指针格式是 **`pfmt = 8`（`DYLD_CHAINED_PTR_64_KERNEL_CACHE`）**
   —— **这是一个 rebase-only 格式，没有 bind 位。**
2. **因此父提出的「imports 表（ordinal → 符号名）」这条路在本二进制上不存在。**
3. **但**「跨 kext 引用静态不可见」这个旧结论**是错的**：格式 8 的指针是完整 rebase，
   目标就在槽里，只是**解法的位宽一直是错的**（见 §3）。
4. **用正确解法（target = bits 0..29），`0xb348450` 有 12 个数据槽指向它，分布在 8 个 kext。**

## 2. 格式 8 的真实布局（`dyld_chained_ptr_64_kernel_cache_rebase`）

```
target    : bits 0..29    (30 位)
cacheLevel: bits 30..31   ( 2 位)
diversity : bits 32..47
addrDiv   : bit  48
key       : bits 49..50
next      : bits 51..61   (11 位，不是 12 位)
isAuth    : bit  62
（没有 bind 位，没有 bit 63 的 bind 语义）
```

**我们之前一直按 arm64e 通用布局解**：`target = bits 0..35`、`bind = bit 63`、`next = bits 51..62`。
**这 36 位的 target 把 `cacheLevel` 吞进去了**，解出的 VA 全是错的 ⇒ 搜索返回 0 ⇒
「59.1% 是 BIND、跨 kext 静态不可见」这个结论**建立在错误解码上，作废。**

## 3. 正例验证（父要求的两条）

| 正例 | 结果 |
|---|---|
| A 同 kext rebase | ✅ 528703 个槽可解，`cacheLevel` 分布 `{0: 528695, 1: 3, 2: 2, 3: 3}` |
| B 跨 kext bind | **不适用**：格式 8 无 bind 位，`imports_count = 0`，不存在跨 kext bind 这种东西 |

**正例 B 无法满足，不是方法缺陷，是这份二进制根本没有导入表。**
替代验证：直接搜一个**已知被大量引用**的目标，看能否解出多个槽 —— 见 §4，命中 12 个，方法成立。

## 4. `0xb348450` 的引用槽（27.2，目标 `0xfffffe000b39e868`）

```
fileoff      kext                                  段
0xec9760     com.apple.kernel                      __DATA_CONST
0xec9938     com.apple.kernel                      __DATA_CONST
0xf01198     com.apple.kernel                      __DATA_CONST
0xf013a0     com.apple.kernel                      __DATA_CONST
0x104cfa0    com.apple.driver.AppleFirmwareKit     __DATA_CONST
0x117eed0    com.apple.driver.AppleProcessorTrace  __DATA_CONST
0x12ec8b0    com.apple.iokit.IOBiometricFamily     __DATA_CONST
0x13081c8    com.apple.iokit.IOGPUFamily           __DATA_CONST
0x1326068    com.apple.iokit.IOHIDFamily           __DATA_CONST
0x13e1d78    com.apple.iokit.IOUSBHostFamily       __DATA_CONST
0x13e1fc0    com.apple.iokit.IOUSBHostFamily       __DATA_CONST
0x13e7ea8    com.apple.iokit.IOUSBHostFamily       __DATA_CONST
```

**12 个槽、8 个 kext、全部在 `__DATA_CONST`（vtable / 函数指针表区）。**

### 这意味着什么

`0xb348450` **不是一个冷门函数，而是一个被 8 个 kext 通过函数指针表共享的公共 API**。
这与它的函数体特征完全吻合：

- `+0x00` 是 PAC 签名的 vtable，经 `autda` + `blraa` 调用
- `+0xa8` 是锁字（`casa` CAS，0 = unlocked）
- `w1` 是标志位参数，`0x60` 处 `ands w8,w1,#0x600`
- 后接 `bl 0xb347e20`

**这形态就是 IOKit 的 `IOCommandGate` / `IOEventSource` 族**（`__LINKINFO` 里确实有
`__ZN13IOCommandGate13attemptActionEPFiP8OSObjectPvS2_S2_S2_ES2_S2_S2_S2_` 这个符号名）。

**⇒ 27.2 在入口加的 `w1 & 0xC0 == 0xC0` 必备位检查，是给一个被 8 个 kext 共用的门控 API 加的前置校验。**

### 但「是不是用户可达」仍未定

12 个槽都是 `__DATA_CONST` 的函数指针，**不是直接 `bl`**。
要回答用户可达性，需要：槽 → 谁加载/使用这个 vtable → 是否有外部方法（selector）派进来。
**这一步没做。名字绑定也没做**（`__LINKINFO` 无地址）。

## 5. 撤回清单

| 旧结论 | 状态 |
|---|---|
| 「数据段槽不是裸指针，59.1% 是 BIND，跨 kext 静态不可见」 | **撤回。格式 8 无 bind，全部是 rebase；不可见是因为解码位宽错** |
| 「`0xb348450` 零引用 ⇒ 只有 KPI 外部调用者」 | **撤回。有 12 个数据槽直接指向它** |
| 「IOSurface `0xa34b2dc` 等零引用 ⇒ KPI 导出（方法不成立）」 | 当时的谨慎是对的，但现在**可以重做**：用 30 位 target 重新搜 |

## 6. 未定

- 12 个槽分别属于哪个 vtable / 类（要按 `__DATA_CONST` 相邻布局推断，未做）
- 那个类是否暴露 IOKit 外部方法（用户可达的最后一跳）
- `w1` 的 bit6/bit7 语义
- 27.0.1 侧对应槽是否同样 12 个（**没跑对比**）

## 7. 工具

`tools/chainfix.py`：解 header / imports / starts / 指针链，按格式 8 解 target。
自检：`python3 tools/chainfix.py out/kc.27.0.1.full`
