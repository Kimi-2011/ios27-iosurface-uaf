# 全部 301 个 kext 差分（27.0.1 → 27.2）—— app 可触达面清单

## 突破：拿到 27.0.1 完整内核缓存
```
IPSW: kernelcache.release.v54 (22MB, IM4P{"krnl", LZFSE})
  → harness/lzfse.swift 解压 → 78,135,296 字节 Mach-O arm64e fileset
  → out/kc.27.0.1.full  (301 个 kext，与 27.2 完全对等)
```
之前只有单 kext，无法做 kext 级对比；现在可以了。

## 改动最多的 45 个 kext

| kext | 改动 | 新增 | 总函数 | 攻击面 |
|---|---|---|---|---|
| com.apple.kernel | 449 | 485 | 21792 | 报文路径 |
| **AppleH16ANEInterface** | **229** | **287** | 4958 | **ANE 用户客户端** |
| **AppleH16CameraInterface** | 225 | 224 | 1821 | 相机 |
| IOSkywalkFamily | 108 | 108 | 2165 | 网络驱动 |
| RTBuddy | 53 | 86 | 2425 | 固件通道 |
| FairPlayIOKit | 65 | 66 | 461 | DRM |
| corecrypto | 52 | 77 | 1947 | 密码学 |
| **IOUSBHostFamily** | 61 | 63 | 1976 | **USB 用户客户端** |
| AGXG18P | 57 | 64 | 3420 | GPU |
| AppleSARService | 43 | 54 | 1865 | 射频 |
| apfs | 47 | 50 | 2395 | 文件系统 |
| **IOHIDFamily** | 45 | 45 | 2807 | **HID 用户客户端** |
| AppleDisplayCrossbar | 29 | 50 | 2262 | 显示 |
| **AppleM2ScalerCSCDriver** | 36 | 41 | 10261 | **实测可开** |
| ASIOKit | 35 | 35 | 95 | 音频 |
| **AppleAVE2** | 31 | 34 | 2991 | 已知（自伤 DoS）|
| IOTimeSyncFamily | 35 | 28 | 1487 | 时钟 |
| IOBiometricFamily | 28 | 28 | 508 | 生物识别 |
| **sandbox** | 23 | 22 | 658 | **策略 +11.9KB** |
| SecureRTBuddyProxy | 13 | 31 | 299 | 安全代理 |
| **AppleSEPKeyStore** | 19 | 20 | 1056 | **实测可开** |
| IOPCIFamily | 19 | 19 | 722 | PCI |
| AppleDCP | 11 | 21 | 204 | 显示协处理器 |
| AppleSEPCredentialManager | 14 | 18 | 1020 | 凭据 |
| DiskImages.UDIFDiskImage | 15 | 15 | 190 | 磁盘镜像 |
| tmpfs | 10 | 11 | 152 | **+306KB（增长异常）** |

## 之前可达性实测（复述，用于优先级）
| 驱动 | 结果 |
|---|---|
| AppleM2ScalerCSCDriver | **用户客户端可开** |
| AppleSEPKeyStore | **可开** |
| AppleJPEGDriver | **可开** |
| AppleCLCD2 | **可开** |
| H1xANELoadBalancer | **可开（type 1 和 4）** |
| AppleAVD | 0xE00002C1 NotPrivileged（客户端存在）|
| ANEExclaveProxy / AppleT8150ANEHAL / H11ANEIn | Unsupported |

## 下一步优先级（app 直接可达 × 改动量大）
1. **AppleM2ScalerCSCDriver**（可开 + 36 改动）— 最高优先
2. **AppleH16ANEInterface**（229 改动，需先测可达性）
3. **IOHIDFamily**（45 改动，HID 用户客户端普遍可开）
4. **AppleSEPKeyStore**（可开 + 19 改动）
5. **sandbox**（+11.9KB 策略变更，可能泄露新限制项）

## 工具
- `out/lzfse`（IM4P+LZFSE 解压，来自 harness/lzfse.swift）
- `tools/kdiff.py`（kext 级差分）
- `tools/kpair.py` / `tools/kshapepair.py`（函数级定位 + 形状配对）

---

## 逐个深挖结果

### AppleM2ScalerCSCDriver（app 实测可开，最高优先）
函数级差分（哈希筛未变 + 形状配对）：
```
A=10262 B=10276  仅A=36  仅B=41
改动聚集在两簇：3504–3532 与 3698–3710（成组 = 同一类外部方法）
最大者：#3515 → #3521  351→364 条
```
**新增代码（第 298 条处插入 13 条）**：
```asm
ldr  x0, [x19, #0x128]
mov  w1, #0 ; w2, #0 ; w3, #1 ; x4, #0 ; w5, #5
bl   <func>                ; 设置某状态（w5=5 疑为 power state）
ldr  x0, [x19, #0x128]
ldr  w8, [x0, #0x6c]
cbnz w8, ...               ; 检查标志位
```
**判读：电源/时钟管理重构，不是安全修复。**

### 网络路径（com.apple.kernel）
见 `out/NETPATH-ANALYSIS.md`：
- **`nat464_translate_64`**：确认新增 `cmp x,w,sxtw; b.hs` 边界检查（唯一实质安全改动），
  但仅 NAT64 网关路径可达，app 触不到
- `tcp6_input`：新增统计计数器 `0x02070031` + 控制流重构，非修复
- `ip6_process_hopopts` / `pf_normalize_tcpopt` / `rip6_input`：噪声

## 产出评估
| 项 | 结果 |
|---|---|
| 27.0.1 完整内核缓存 | ✅ 解出（IM4P+LZFSE → 75MB fileset） |
| 301 个 kext 全量差分 | ✅ 完成，含每个 kext 的改动函数数 |
| app 可触达面清单 | ✅ 已按"实测可开 × 改动量"排序 |
| 已确认的安全修复 | **1 个**（nat464_translate_64，NAT64 专用） |
| app 可触达的内核漏洞 | 尚未找到 |
| 深挖过的 kext | AppleM2ScalerCSCDriver（电源重构）、com.apple.kernel（报文路径） |

## 下一步候选（尚未深挖，按优先级）
1. **AppleH16ANEInterface**（229 处改动，最大非内核 kext）— 需先测用户客户端可达性
2. **IOHIDFamily**（45 处）— HID 用户客户端普遍可开
3. **AppleSEPKeyStore**（19 处，实测可开）
4. **sandbox**（+11.9KB 策略变更）— 可从二进制里提取新增的拒绝规则，反推被限制的能力
5. **tmpfs**（+306KB 异常增长）— 可能是新功能或新增校验
