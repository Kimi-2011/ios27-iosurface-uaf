# `__LINKINFO` 与符号名回收：能不能建立 kext → 导出符号名映射？

**结论：不能。** 但有一个有用的副产品（6168 个 KPI 符号名），以及一条比原计划更划算的替代路线。

数据源：`out/kc.27.0.1.full`（78,135,296 B），全部通过 `tools/kseg.py` 按**段**取数据。

---

## 1. `__LINKINFO` 只有 1 个 kext 有

301 个 fileset entry 里，**只有 `com.apple.kernel`** 带 `__LINKINFO`：

```
com.apple.kernel  vm=0xfffffe000b9c4000  vs=0x49000  fileoff=0x49c0000  fsz=0x48d28
```

其余 300 个 kext 一个都没有。所以「每个 kext 一块 `__LINKINFO`」这个前提不成立。

## 2. 它确实是 plist，但里面没有地址

头部 `bplist00` —— 是 **binary plist**（`plistlib.loads` 直接可读，无需自写解析器）。

结构：

```
WeakRefFallbackSymbol = { SymbolName: "_gOSKextUnresolved" }
SymbolsSets = [ 9 项 ]
    ├ CFBundleIdentifier = com.apple.kpi.bsd          874 个符号
    ├ com.apple.kpi.iokit                            2263
    ├ com.apple.kpi.libkern                           878
    ├ com.apple.kpi.mach                               75
    ├ com.apple.kpi.dsep                               10
    ├ com.apple.kpi.unsupported                       220
    ├ com.apple.kpi.private                          1857
    ├ com.apple.kpi.kasan                               0
    └ com.apple.kpi.kcov                                0
                                       合计 **6168 个符号名**
```

单条符号的**完整结构**：

```python
{'SymbolName': '_IOAlignmentToSize'}      # 就这一个键，没有别的
```

**没有地址、没有偏移、没有大小。**

## 3. 靠「位置推理」也不行 —— 顺序是字母序不是地址序

父的假设是「导出表里的函数通常按地址排序，可以靠位置推理」。实测否证：

| 符号集 | 前三个符号 |
|---|---|
| `kpi.iokit` | `_IOAlignmentToSize`, `_IOBSDNameMatching`, `_IOBSDRegistryEntryForDeviceTree` |
| `kpi.libkern` | `_Assert`, `_MD5Final`, `_MD5Init` |

明显是**字典序**。⇒ 位置 ↔ 地址的推理链断了。

## 4. kext 侧：连导出表都没有

`driver_AppleAVD.macho` 与 `iokit_IOSurface.macho` 的 load commands 全量：

```
LC_SEGMENT_64  ×5
LC_SYMTAB          nsyms=0        ← 符号表被剥掉
LC_DYSYMTAB
LC_UUID(0x1b)
LC_SOURCE_VERSION
LC_FUNCTION_STARTS                ← 只有地址，没有名字
```

**没有** `LC_DYLD_INFO`、**没有** `LC_DYLD_EXPORTS_TRIE`(0x80000033)、**没有** `LC_DYLD_CHAINED_FIXUPS`。

⇒ kext 里任何形式的导出/导入名字都拿不到。所以「AppleAVD 的那个溢出函数是不是 KPI 导出」这个问题，**静态无解**（除非换数据源）。

## 5. `__KLD` / `__KLDDATA` 也不是符号表（这条否掉了一个可能的替代源）

| 段 | 内容 |
|---|---|
| `__KLD` (0x173c B) | **代码**：`bti c` / `adrp` / `stp` 等 arm64 指令，**0 条 ASCII 串** |
| `__KLDDATA` (0x4559 B) | 加载器**日志字符串**：`"Reading startup extensions."` / `"__PRELINK_INFO"` / `"Starting from prelinked kernel."` / `"Error unserializing kext info plist section: %s."` 等 373 条 |

没有 kxld 的 `kxld_sym` 结构表。老式 prelink 内核里的 `__PRELINK_SYMBOL` 表在这份 kc 里不存在。

另外：**301 个 kext 共用同一块 `__LINKEDIT`**（`vm=0xfffffe000ba10000 off=0x4a0c000`），所以也没有 per-kext linkedit 可查。

---

## 6. 副产品：这 6168 个名字仍然很有用

它们给了**内核都导出了什么、签名是什么**。直接命中：

```
__ZN13IOCommandGate13attemptActionEPFiP8OSObjectPvS2_S2_S2_ES2_S2_S2_S2_
__ZN13IOCommandGate14runActionBlockEU13block_pointerFivE
__ZN13IOCommandGate10runCommandEPvS0_S0_S0_
__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_
__ZN13IOCommandGate11commandGateEP8OSObjectPFiS1_PvS2_S2_S2_E
```

⇒ 盲区 A（`IOCommandGate`）的目标函数是**明确已知的**，缺的只是「它在哪」。

## 7. 一条比「签名启发式」更划算的路线

`IOCommandGate` 的类名字符串在 `__TEXT` 的 cstring 池里，已定位：

```
fileoff 0xbf946 -> VA 0xfffffe00070c3946      "IOCommandGate"
fileoff 0xbf95a -> VA 0xfffffe00070c395a      "IOCommandGate"
周边是  site.IOCommandGate / iokit.IOCommandGate /
        IOCommandGate::disable() called when not gated. /
        invalid commandSleep while not holding the gate @%s:%d / IOCommandGate.cpp
```

**OEMetaClass 注册时会把类名传进 `OSMetaClass::OSMetaClass(this, "IOCommandGate", super, size)`**，
那条 `adrp+add` 就是锚点；从元类对象再走到 `__ZTV13IOCommandGate`，vtable 里就能按
「`attemptAction` 是第几槽」取出真实地址。

**我这次没找到 xref，原因是我自己的工具缺陷（如实记）：**
我对整个 `__TEXT_EXEC`（30+ MB）做**线性反汇编**，遇到内嵌数据就会失步，绝大多数真实
`adrp+add` 因此被跳过。正确做法是**按 `LC_FUNCTION_STARTS` 逐个函数反汇编**（`tools/fdiff.py` 里已经是这么做的）。

而 `com.apple.kernel` 我还没抽成 macho slice —— 这是下一步的**第一件事**，很便宜。

## 8. 结论汇总

| 问题 | 答案 |
|---|---|
| 能建立 kext → 导出符号名映射吗 | **不能**。只有 kernel 有 `__LINKINFO`，且只有名字没地址 |
| 靠导出表顺序推地址可行吗 | **不可行**。顺序是字母序 |
| kext 有 export trie / 符号表吗 | **都没有** |
| `__KLD` 是符号表吗 | **不是**，是代码段 |
| 拿到什么有用的 | **6168 个 KPI 符号名**（含 `IOCommandGate::attemptAction` 等完整签名） |
| 下一步最便宜的一步 | 把 `com.apple.kernel` 抽成 macho slice → 按 `LC_FUNCTION_STARTS` 逐函数反汇编 → 找 `"IOCommandGate"` 的 xref → 定位元类与 vtable |
