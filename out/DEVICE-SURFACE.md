# 真机攻击面实测（iPhone18,2 / iOS 27.0.1 / 24A446）

> 方法：自签 Ad Hoc app（installation_proxy 安装，devicectl 启动），以 uid=501 运行，
> 枚举 IORegistry 并对每个类尝试 `IOServiceOpen`，再对可打开的服务扫 selector。

## 1. 全局结果

| 指标 | 值 |
|---|---|
| IORegistry 服务总数 | 1479 |
| 去重类数 | 327 |
| **IOServiceOpen 成功** | **5** |

可打开的服务：`AppleCLCD2`、`AppleJPEGDriver`、`AppleKeyStore`、`AppleM2ScalerCSCDriver`、`IOSurfaceRoot`

其余全部拒绝，错误码分布：
- `0xE00002E2` NotPermitted（如 IOHIDDevice）
- `0xE00002C2` NotPrivileged（如 IOHIDEventService、AppleSEPManager、IOBiometricService）
- `0xE00002C7` Unsupported（如 IOGPU、AGXAccelerator、AppleDisplayCrossbar）

**ANE 结论**：`AppleH16ANEInterface` 服务实例数为 **0**，普通 app 连匹配都匹配不到——静态分析的门控判断在真机得到证实。

## 2. 逐个深挖

### IOSurfaceRoot（重要修正）
- `IOServiceOpen(type=0)` → 成功
- 但对 selector 0–95 的所有调用均返回 `0xE00002C2` NotPrivileged
- `type=1..5` → `0xE00002C7` Unsupported，无法打开
- **结论：内核侧的 IOSurface user client 方法对普通 app 全部拒绝。**
  我们的 app 能用 `IOSurfaceCreate`，是因为走的是用户态 broker，不是 direct kext path。
- 因此 27.2 的 IOSurface UAF 加固**不是第一跳**，只能作为拿到有权限进程后的第二跳

### AppleM2ScalerCSCDriver（新发现）
- `IOServiceOpen(type=0)` → 成功
- selector 0 → Unsupported
- selector 1–10 → NotPrivileged
- **selector 11 → 0（成功），且无需任何输入参数**

这是目前找到的**唯一一个无授权 app 可实际调用的内核入口**，所在 kext 在 27.2 有 3 处改动。

## 3. 未完成

- selector 11 的语义（需要定位 switch 表；kext 内 `cmp #0xb` 无命中，可能用跳转表或 bounds check + 间接跳转）
- 27.2 在该 kext 的 3 处改动的准确配对（形状相似度 0.95 有三个候选，需靠操作数区分）
- 压力测试：8 线程 × 12 秒，1260 万次 IOSurface 建/映射/释放，无 panic（但走的是用户态 broker，打不到内核路径）
