# 内核通道可达性实测 v2（补 type 0..16 扫描）

## 方法与修正
此前只试了 `IOServiceOpen(type=0)`，得出"仅 5 个服务可打开"。
本次对每个服务遍历 **type 0..16**，结果显著不同。

## 结果（真机 iPhone18,2 / 27.0.1）

| 服务 | 结果 | 说明 |
|---|---|---|
| **H1xANELoadBalancer** | **type 1 / 4 打开成功** | ⚠️ **ANE 相关服务可被 app 打开**，此前判断有误 |
| AppleJPEGDriver | type 0..16 全部成功 | ImageIO 路径 |
| AppleCLCD2 | type 0..16 全部成功 | 显示控制器 |
| AppleKeyStore | type 0..16 全部成功 | 密钥库 |
| AppleM2ScalerCSCDriver | type 0..16 全部成功 | 缩放/色彩转换 |
| **AppleAVD** | 全部返回 `0xE00002C1`（NotPrivileged） | **服务存在且有 user client，仅缺 entitlement** |
| IOSurfaceRoot | type 0 成功 | |
| ANEClientHints | 全部 Unsupported | 无 user client |
| ANEExclaveProxy | 全部 Unsupported | 无 user client |
| AppleT8150ANEHAL | 全部 Unsupported | 无 user client |
| H11ANEIn | 全部 Unsupported | 无 user client |
| AppleH16ANEInterface / AppleAVE2 | NO_SERVICE | 类名不对，实际类名是 H11ANEIn / 其它 |

## 三点关键修正

1. **"ANE 完全不可达"不成立**：`H1xANELoadBalancer` 的 type 1/4 user client 可由普通 app 打开。
   需要进一步确认该 user client 暴露哪些 external method、是否可影响 ANE 内部状态。
2. **AppleAVD 不是"无 user client"，而是"有但需 entitlement"**（`0xE00002C1` = NotPrivileged）。
   这意味着若能拿到对应 entitlement（或借道持权进程），AVD 是可达的。
3. **`IOServiceOpen` 的 type 参数必须扫全**：只试 type 0 会漏掉真实存在的 user client。

## 与 27.2 改动的交集
| 服务 | 27.0.1→27.2 改动函数数 | 备注 |
|---|---|---|
| AppleJPEGDriver | 0 | ImageIO 的 7 条 CVE 修在用户态 |
| AppleM2ScalerCSCDriver | 34 | **可打开且改动多，尚未分析** |
| IOSurface | 3 | 已分析（UAF 修复但不可达） |
| AppleAVD | 6 | 仅内联重构 |

→ **`AppleM2ScalerCSCDriver`（可打开 + 34 处改动）是新的高优先目标。**

---

## AppleM2ScalerCSCDriver 差分（可打开 + 改动多）

`A=10261 funcs, B=10275 funcs`，**34 个配对改动（6 个未对齐丢弃）**。

| 27.0.1 | 27.2 | dInsn | dChk | 尺寸 |
|---|---|---|---|---|
| `0x1ba1130` | `0x1bdd8e0` | +9 | 1 | 232→268 |
| `0x1b1d718` | `0x1b59b7c` | +6 | 1 | 196→220 |
| `0x1b72708` | `0x1baee58` | +6 | 1 | 216→240 |
| `0x1b77044` | `0x1bb37dc` | 0 | 1 | 1052→1100 |
| `0x1bb7fdc` | `0x1bf47e0` | 0 | 1 | 6912→6920 |
| `0x1c35eac` | `0x1c72778` | 0 | 1 | 476→460 |

**特点**：多数是"指令数不变、尺寸略增 + 1 处新检查"，
形态与 IOStorageFamily/IOSkywalk 的内联重构相似，**但也可能是边界检查**，需逐个确认。

**注意**：该 kext 有 10261 个函数（远多于普通驱动），
很可能是把大量 GPU/显示相关的公共代码编进来了，34 个改动占比极小（0.33%）。
