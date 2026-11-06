# 权威方法：用 `LC_FUNCTION_STARTS` 替代一切启发式边界规则

**日期**：2026-11-01 10:40
**状态**：本文档 **取代** `METHOD-FUNCTION-BOUNDARY.md` 全部内容

---

## README（10 行）

1. `LC_FUNCTION_STARTS` 在这个 kernelcache 的**每一个 kext 里都可用**（此前记录「不可用」是错的）。
2. 解码方式：`ULEB128 增量累加` + 基址 = `__TEXT` 段的 vmaddr。
3. 自证：**首项恰好等于 `__TEXT_EXEC` 的 vmaddr**，六个 kext 全部命中。
4. 本文档之前的全部边界启发式（`BTI c`、`PACIBSP`）**一律作废**。
5. 我修「缺陷三」时引入的错误：规则写成「`BTI c` 且下一条 ≠ `PACIBSP`」，而真实序言恰恰是 `bti c; pacibsp`——**把最常见的情况主动排除了**。
6. 后果：每个函数起点**晚 4 字节**，所有 `bl` 目标不匹配 → 「91% 函数无调用者」等结论全是假象。
7. 指针解码也已解开：`va = 0xfffffe0007004000 + (word & 0xFFFFFFFF)`（auth 条目取低 32 位）。
8. 该解码由**两个独立子代理**各自得出，且经数据扫描与代码 `adrp+add` 双向互证。
9. AVD 的原始数字（`0x8707cf0` / dChk=+5 / 34→39）**是对的**；我后来的「修正」（`0x8707c34` / +3）才是错的。
10. 今后一切 dChk 数值必须标注「基于 LC_FUNCTION_STARTS」。

---

## 一、函数起点表

```python
def function_starts(path):
    d = open(path,'rb').read()
    # 遍历 load commands，取 __TEXT.vmaddr 与 LC_FUNCTION_STARTS(dataoff,datasize)
    ...
    blob = d[dataoff:dataoff+datasize]
    addrs, cur, i = [], 0, 0
    while i < len(blob):
        v = 0; sh = 0
        while True:
            b = blob[i]; i += 1
            v |= (b & 0x7f) << sh; sh += 7
            if not b & 0x80: break
        if v == 0: break          # 终止符
        cur += v
        addrs.append(text_vmaddr + cur)
    return addrs
```

### 自证结果（首项 == `__TEXT_EXEC` vmaddr）

| 文件 | 起点数 | 首项校验 |
|---|---|---|
| `m2s.27.0.1.macho` | 10,262 | ✅ |
| `avd.27.0.1.macho` | 2,328 | ✅ |
| `ane.27.0.1.macho` | 4,959 | ✅ |
| `skywalk.27.0.1.macho` | 2,166 | ✅ |
| `kern.27.0.1.macho` | 21,793 | ✅ |
| `amfi.clean.macho` | 无该 load command | — |

---

## 二、我先前的边界规则错在两个方向

| kext | 真表 | 我的启发式 | 偏差 |
|---|---|---|---|
| m2s | 10,262 | 10,354 | **多 92** |
| avd | **2,328** | 2,092 | **少 236** |
| ane | 4,959 | 4,284 | 少 675 |
| skywalk | 2,166 | 1,909 | 少 257 |
| kern | 21,793 | 23,277 | 多 1,484 |

**双向都错** → 不能用「大致接近」当验收标准，只能用本文档的自证条件。

---

## 三、指针解码（chained fixups）

```python
KB = 0xFFFFFE0007004000
va = KB + (word & 0xFFFFFFFF)          # 普通条目：低 36 位
va = KB + (word & 0xFFFFFFFF)          # auth 条目：取低 32 位
```

### 三路互证
| 证据 | 来源 |
|---|---|
| JPEG `__DATA_CONST` 2635 个非零字里 2365 个（89.8%）落点恰好是 `bti c`/`pacibsp` 序言 | 子代理 1 |
| H16Cam `externalMethod` 里 `adrp+add` 得到的表地址，与纯指针扫描找到的**完全一致** | 子代理 1（代码/数据双向） |
| `kaudit.py` 独立得出同一常量 `KB = 0xFFFFFE0007004000` | 子代理 2 |
| M2Scaler 全 kext 解出 30,884 个指针，5,079 个精确落在函数起点 | 子代理 3 |

**此前「kext `__DATA_CONST` 里没有绝对指针、派发表解不出」的结论作废。**

---

## 四、AVD 数字的更正与再更正

| 版本 | 函数起点 | dChk | 依据 |
|---|---|---|---|
| 原始报告 | `0x8707cf0` | **+5（34→39）** | 启发式 v1 |
| 我的「修正」 | `0x8707c34` | +3 | 启发式 v2（有缺陷） |
| **真表复核** | **`0x8707cf0`** | **+5（34→39）** | **LC_FUNCTION_STARTS** |

真表下 AVD：27.0.1 = 2,328 函数，27.2 = 2,328 函数（**数量一致，无增删**），
6 对 replace，**1 个 dChk>0**，即 `0x8707cf0 → 0x873e2e0`。

**→ AVD 的原始数字正确；我的「修正」是错的；该发现的数值结论不变。**
（该发现的**可利用性**结论仍为「非用户可控」，因为索引来自硬件寄存器——见
`POC-AVD-OOB-WRITE.md` §13。）

---

## 五、新增判据（来自子代理）

### 判据 7：`ubfiz → cmp → csel 毒指针` 是**位移溢出检查**，不是容量检查

```asm
ubfiz x8, x8, #3, #0x20    ; idx << 3
cmp   x8, w8, sxtw         ; 只比较符号扩展一致性
csel  x10, x10, x16, eq    ; 不等则用毒化指针 0x2bad...
```

它检查的是 `idx*8` 有没有越 bit31，**完全不检查 `idx < count`**。
一个 4 元素表配 `idx = 1000` 能完整通过这个「检查」。

与「乘法常数 + 移位异或 + 表容量掩码 = 哈希函数」是同一条纪律的新形态：
**编译器也会让代码「看起来有边界检查」。**

### 判据 8：`IOExternalMethodArguments` 字段偏移（实测）
```
0x10 = asyncWakeTarget
0x18 = scalarInput（打包）
0x20 = scalarInput64 指针
0x30 = structureInput
0x38 = structureInputSize
0x58 = structureOutput
0x68 = structureOutputDescriptor
0x78 = structureVariableOutputData
```

### 判据 9：派发表步长有两种，不能假设 24 字节
| kext | 表地址 | selector 数 | 步长 | 索引方 |
|---|---|---|---|---|
| AppleJPEGDriver | `0x80dd990` | 10 | `0x28` | 内核侧（`IOUserClientDefaultLockingSingleThreadExternalMethod`） |
| AppleProResHW | `0xb905ce0` | 5 | `0x28` | 内核侧 |
| AppleH16CameraInterface | `0x8086ae0` | 117 | `0x18` | kext 自己 `umull` |

---

## 六、教训

这一轮我在同一个问题上错了**三次**：
1. 只用 `BTI c` → 漏掉无 BTI 的函数
2. 加入 `PACIBSP` 但排除了 `bti c; pacibsp` 这种最常见组合 → 全部晚 4 字节
3. 基于错误边界「修正」了一个本来正确的结论（AVD）

**根因**：一直用**启发式**去猜一个**本来就有权威数据源**的东西。
`LC_FUNCTION_STARTS` 从一开始就在文件里，我早期测了一次失败就把它判死了，
之后所有工作都建立在猜测之上。

**纪律**：遇到「解析失败」，要区分「数据不存在」和「我的解析器写错了」。
我把后者当成了前者，代价是整条分析线的数值全部不可用。
