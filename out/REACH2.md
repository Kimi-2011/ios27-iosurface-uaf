# 可达性 v2：候选 → 分发表祖先（校正版）

## 为什么有 v2
v1 直接检验候选函数是否在数据表里，结果 32 条里绝大多数是**巧合命中**——放宽解码后任何 32 位值都可能等于某函数偏移。
加两条校验后归零：① PAC 标签必须在**高 16 位**（`0x8011/0x8010/0x8012`），② 槽位附近至少 2 个邻居也指向函数起点。
同时发现真正的结构：**候选函数本身几乎都不在表里，在表里的是它们的祖先**（ANE：候选 → wrapper → 状态机表）。

## 结果：187 候选 → **41** 个在 3 跳内触达分发表祖先，分布 12 个 kext

| kext | 数量 |
|---|---|
| `com.apple.kernel` | 16 |
| `com.apple.driver.AppleH16ANEInterface` | 9 |
| `com.apple.security.sandbox` | 4 |
| `com.apple.driver.IOAudioCodecs` | 2 |
| `com.apple.filesystems.apfs` | 2 |
| `com.apple.driver.AppleT8110DART` | 2 |
| `com.apple.driver.AppleDiskImages2` | 1 |
| `com.apple.iokit.IOGPUFamily` | 1 |
| `com.apple.driver.ApplePPMCPMS` | 1 |
| `com.apple.driver.AppleM2ScalerCSCDriver` | 1 |
| `com.apple.iokit.IOSCSIArchitectureModelFamily` | 1 |
| `com.apple.driver.ApplePearlSEPDriver` | 1 |

## 与链相关性最高的几组

- sandbox：候选 `0x2d9873c` → 祖先 `0x2d7dabc`（slot `0x141b640`，深度 2）
- sandbox：候选 `0x2d9c9b4` → 祖先 `0x2d9d6d4`（slot `0x141ce88`，深度 3）
- sandbox：候选 `0x2d86eb4` → 祖先 `0x2d877c4`（slot `0x141bfa8`，深度 1）
- sandbox：候选 `0x2d90450` → 祖先 `0x2d7ff80`（slot `0x141b630`，深度 3）

ANE 那三条与手工验证一致（`0x18107c8 → 0x1810784 @ 0x104cf50`），说明管线正确。

## 下一步

1. 对 sandbox 的 4 条祖先做反编译，确认是策略求值还是策略加载路径；
2. apfs / DiskImages2 / IOAudioCodecs 同理；
3. 每条都按 ANE 的三步法补：表上下文字符串 → 类名 → 授权需求。