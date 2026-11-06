# 本项目最终状态矩阵（截至 27.0.1 → 27.2 全量差分完成）

## 一、方法论资产（最有价值的部分）

| 能力 | 工具 | 状态 |
|---|---|---|
| AEA 离线解密（无需设备/越狱/SEP） | `tools/aea_unlock.py` | ✅ 端到端验证 |
| 断点续传下载（字节级校验） | `tools/grab.py` | ✅ 48MB/s 实测 |
| dyld 共享缓存提取 | `dsc_extractor` | ✅ 4696/4770 个带符号 dylib |
| 用户态按名对齐差分 | `tools/namediff.py` | ✅ |
| 内核缓存解压（IM4P+LZFSE） | `out/lzfse` + `harness/lzfse.swift` | ✅ 22MB→75MB |
| kext 级差分 | `tools/kdiff.py` | ✅ 301 kext 全量 |
| 内核函数定位 / 形状配对 | `tools/kpair.py` / `tools/kshapepair.py` | ✅ |
| 真机 PoC 框架 | `harness/{imgpoc,fontpoc,avedos,usdpoc,reach}` | ✅ 签名/安装/日志回传全通 |

⚠️ 签名前必须：
```bash
security unlock-keychain -p "" ~/Library/Keychains/dev.keychain-db
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "" ~/Library/Keychains/dev.keychain-db
```

## 二、app 可达性实测（真机）

| IOKit 服务 | 实例 | 可开性 |
|---|---|---|
| H1xANELoadBalancer | 1 | ✅ type=1 |
| AppleM2ScalerCSCDriver | 1 | ✅ type=0 |
| AppleJPEGDriver | 1 | ✅ type=0 |
| AppleCLCD2 | 2 | ✅ type=0 |
| AppleH16ANEInterface | **0** | 无实例（229 处改动但本机不加载）|
| AppleSEPKeyStore | 0 | 无实例 |
| ANEClientHints / AppleT8150ANEHAL | 1/1 | ❌ 0xe00002c7 |
| IOSkywalkNetworkInterface | 16 | ❌ 0xe00002c7 |
| AppleSPUHIDDevice / HIDTransport / ANS2NVMe | 30/3/1 | ❌ 0xe00002e2 |
| AppleSEPManager | 1 | ❌ 0xe00002c2 |

## 三、「可达 ∩ 有改动」矩阵 —— 决定性结论

| 可开的驱动 | 27.2 改动 | 深挖结果 |
|---|---|---|
| **AppleM2ScalerCSCDriver** | 36 改 / 41 新增 | **电源/时钟管理重构**（插入 power state 设置 + 标志检查）|
| **AppleJPEGDriver** | **0** | 两版完全相同，无修复 |
| AppleCLCD2 / H1xANELoadBalancer | — | 非独立 kext，本缓存内无对应 bundle |

→ **app 可触达的内核驱动在 27.2 里几乎没有安全相关改动。**

## 四、全部已确认发现

| 发现 | 严重性 | 状态 |
|---|---|---|
| AVE `NumberOfTemporalLayers ≥ 8` → 编码器永不出帧 → app 被 SIGKILL | 低（自伤） | ✅ 真机 3/3，四组实验定性 |
| `nat464_translate_64` 新增边界检查 | 中（NAT64 网关路径）| ✅ 反汇编确认，app 不可达 |
| sandbox 新增 `kTCCServiceMotionSensors` 等策略 | 低（隐私收紧）| ✅ 字符串确证 |
| FontParser `sbit_GetBitMapInfo` 两处修补 | — | ✅ 逆向到判据级，**证明 iOS 27 上不可达** |
| ImageIO/PSD/KTX/DDS/USDZ 畸形输入 | — | ✅ 约 70 个输入全部安全 |

## 五、已证明「不可达」的路径（避免后人重复劳动）

1. **`sbit_*` 嵌入位图路径**：iOS 27 完全忽略 EBDT/EBLC/EBSC
   （`eb_nooutline.ttf` 渲染 0 墨迹为证）；sbix 也不经过该路径
2. **退化变换矩阵**：`CGAffineTransform` 恒 w=1，永远取不到 `M3x3Flags()==7`
3. **`rowBytes*height` 溢出**：需 dest 宽 >524288，与位图触发条件互斥
4. **ASTC/BC/KTX 那批「修补点」**：实为 27.2 新增 DDS 格式支持，非安全修复
5. **朴素畸形输入**：现代解析器对字段极值普遍有安全退出；USDZ 中央目录损坏会降级为顺序扫描

## 六、下一步建议（按性价比）

| 方向 | 成本 | 说明 |
|---|---|---|
| **真机覆盖率引导 fuzz**（ImageIO/CoreText harness + libFuzzer/AFL） | 高 | 唯一能自动找到「结构矛盾」输入的方法 |
| 深挖 `com.apple.kernel` 报文路径剩余函数 | 中 | `netif_gso_tcp_segment_mbuf`(68)、`nd6_na_input`(147) 未做形状配对定性 |
| `frag6_input` 重新配对 | 低 | 当前 0.11 匹配度是错的 |
| 接受现状 | — | 27.0.1 用户态与 app 可达内核面已充分加固 |

## 七、今日纠错记录（方法论教训）
1. 把「改动大」当成「修补重」→ ASTC/BC/KTX 实为功能新增
2. sbix 打错表 → `sbit_*` 是 EBDT/EBLC 不是 sbix（子代理纠正）
3. 按序号配对内核函数 → 漂移严重，必须用形状相似度
4. 误采信子代理「sbix 包围盒必挂死」→ 我 3 字体 × 3 API 复现失败，已剔除
5. 签名失败误判为打包问题 → 实为钥匙串重新上锁导致 `errSecInternalComponent`
