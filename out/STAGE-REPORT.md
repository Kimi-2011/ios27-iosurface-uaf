# 阶段性成果报告（2026-10-23）
> 目标：在 iPhone 17 Pro Max / iOS 27.0.1 (24A446) 上，通过 27.2 RC (24B115) 的补丁差分还原越狱链，评估能否做出 PoC。

## 1. 一句话结论
**拿到了完整的"补丁地图 + 语义化加固点 + 可达性分级"，但没有任何一个候选被证明可触发。** 距离 PoC 还差：入口证明、输入构造、真机验证。

## 2. 数据与工具链（全部自建，15 个工具）
| 环节 | 工具 | 关键结论 |
|---|---|---|
| 定点取件 | `zipfetch.py` | ZIP64 解析，13.16 GB 包中只取 23 MB kernelcache，1.3 秒 |
| 解 IM4P+LZFSE | `lzfse.swift` | 78.5 MB Mach-O fileset，301 kext，**未加密** |
| kext 级差分 | `kdiff.py` | 形状哈希，自比对 0 差异 |
| 函数级排序 | `kfunc.py` + `pairing.py` | 相似度配对，修掉按位置错位 |
| 空指针守卫 | `guardscan.py` | 95 个函数 |
| 边界/位域 | `checkscan.py` | 187 个函数 |
| 混淆指针解码 | `vtable.py` / `dispatch.py` | `0x0010\|fileoff(48)`、`0x8011xx\|fileoff(32)` |
| 调用图 | `callgraph.py` / `upwalk.py` | 27.9 万条分支边，4 秒建图 |
| 反编译 | `kext_extract.py` + Ghidra 12.2 | 自建 macOS arm64 decompiler + BFD stub |

## 3. 补丁地图（27.0.1 → 27.2 RC）
- kext 有改动：**117 / 301**
- 函数变动：**2,273 / 197,356（1.2%）**
- 变化集中：`com.apple.kernel` 449、ANE 229、Camera 225、IOSkywalk 108、FairPlay 65、sandbox 23
- 注意：这是"改动的函数"，**混着功能更新**，不是纯安全修补

## 4. 三条已人工确认的加固点
### 4.1 ANE procedure IO 计数（最完整）
27.0.1：只在索引越界时 `SoftwareBreakpoint(0x800)` panic，无前置校验。
27.2 新增：
```c
if (uVar4 < 0x101) {                        // count 上界
  lVar1 = param_2[10] + idx * 0xb0;
  if ((0xff < *(uint *)(lVar1 + 0x30)) ||   // numInputs
      (0xff < *(uint *)(lVar1 + 0x50))) {   // numOutputs
    log("[ERROR] ... Procedure %u IO counts out of range ...");
    return 0xe00002d1;
```
### 4.2 IOUSBHostFamily 描述符解析
新增 `cbz x2` / `cbz x3` 判空，并用 `ccmp` 补上 11 位长度字段（`& 0x7ff`）的零值检查——原版 `udiv` 除数可为 0。
### 4.3 sandbox 策略判定
新增掩码+状态联合判断，调用导入函数，返回值必须 `== 7` 才放行。

## 5. 可达性三信号（126 候选）
| 信号 | 结果 |
|---|---|
| 落在数据表（放宽解码） | **32** |
| kext 级未见授权串 | **12** |
| 有私有授权门控 | 20 |

已确认语义：ANE 的表是**固件/电源状态机**（`Wire/Unwire/DartMap/PrepareForFirmware/ANE0..3`），构造函数 `FUN_fffffe0008c3c8c0` 分配 0x28d0/0x2748 字节对象并写入 vtable。

## 6. 门控结论
ANE（`com.apple.ane.allow`）、PearlSEP（`com.apple.private.applepearl.allow`）、PPM（`com.apple.private.ppm.*`）、AGX（`com.apple.private.agx.performance`）**都需私有授权**，第三方 app 无法直接触达 → 只能作为第二跳原语。

## 7. 方法学要点（可复用）
1. kernelcache 指针是 `0x0010|offset` / PAC 变体，不按此解码则一切数据引用都搜不到；
2. 全立即数哈希在布局漂移下误报 64%，形状哈希降到 2.1%；
3. 按位置配对会因插入函数整体错位，必须用序列相似度；
4. Ghidra 官方 zip 不含 macOS decompiler，需从源码 `make ghidra_opt` 并自建 BFD stub。

## 8. 未证明事项（必须明确）
- 没有任何候选被证明**可从沙箱内触发**；
- 没有任何崩溃/原语被复现；
- 27.2 的改动里有功能更新，安全修补与功能改动无法仅凭二进制区分（需正式版安全说明对表）；
- 无真机，S5 之后全部无法推进。

## 9. 下一步
1. 12 个未见门控候选逐个反编译表构造函数，产出"类名 + 方法名 + 授权需求"清单；
2. 27.2 正式版发布后与 Apple 安全说明对表，把"改动"收敛成"修补"；
3. 若要继续深入，需要真机（循环依赖）或接受"地图交付"。
