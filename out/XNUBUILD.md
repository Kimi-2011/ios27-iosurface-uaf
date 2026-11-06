# XNU 源码构建（为符号还原准备）— 进度存档

## 目标
编译出 arm64 release 内核 → 用 Ghidra BSim 给 iOS kernelcache 批量还原符号。

## 当前状态：**未完成**，24 次构建迭代，剩 4 个错误

产物路径（若成功）：`fw/xnu/BUILD/obj/RELEASE_ARM64/kernel.release`

## 已解决的 8 个障碍（全部已打补丁，可复现）

| # | 问题 | 解决方式 |
|---|---|---|
| 1 | `Could not determine xnu version` | `export RC_DARWIN_KERNEL_VERSION=12377.0.0.0.0` |
| 2 | 缺 `availability.pl`（内部 SDK 工具） | 改 `bsd/sys/make_symbol_aliasing.sh`，缺失时用内置版本列表桩 |
| 3 | `-Wmissing-include-dirs` 被当错误 | 改 `makedefs/MakeInc.def` 第 161 行：`WERROR :=`（清空） |
| 4 | 缺 `iBoot/boot_args_abi.h` | 自建 `EXTERNAL_HEADERS/iBoot/boot_args_abi.h`（只需 `IBOOT_MAX_ENV_VAR_DATA_SIZE`） |
| 5 | 缺 `os/firehose_buffer_private.h` | 从 libdispatch 源码取真件放入 `EXTERNAL_HEADERS/os/`，并补 `#ifndef OS_FIREHOSE_SPI #define OS_FIREHOSE_SPI 1` |
| 6 | 缺 `CoreEntitlements/V2/API.h`、`Kernel.h` | 自建 shim：引用真实 v1 头 + 补 `CEKernelAPI_t` 前置声明 |
| 7 | `EntitlementsPriv.h` 的私有 API `#error` | 定义 `CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING 1` |
| 8 | 缺 `AppleFeatures.h` | 自建空桩 |

## 剩余问题：`TrustCache/API.h` 桩的形状不匹配
苹果未公开该头，只能从使用处反推。已补：
- 类型：`TCReturn_t`（含 component/error/unique/uniqueError 成员）、`TrustCache_t`、`TrustCacheRuntime_t`（含 allowEngineeringTC/allowSecondStaticTC）、`TrustCacheQueryToken_t`、`TrustCacheMutableRuntime_t`
- 常量：`kTCType*`、`kTCReturn*`、`kTCCapability*`、`kTCQueryType*`、`TCTypeConfig[]`
- 函数：`trustCacheInitializeRuntime`（6 参数）

仍有 4 个错误在 `bsd/kern/kern_trustcache.c`，属"补一个暴露下一个"的形态。

## 结论
xnu 用公开 SDK 编译是可行的（已越过绝大多数坑），但**私有头依赖（CoreEntitlements / TrustCache / CodeSignature）
需要完整重建其 API，是个体力活**，当前估计还需 30–90 分钟不定。

## 若继续，下一步
1. 集中攻 `kern_trustcache.c`：逐个对齐 `TrustCacheRuntime_t` 的真实布局（可从 iOS kernelcache 里
   AppleT8140/8150 相关 kext 的字符串与结构推断）
2. 或者：临时把 `kern_trustcache.c` 的编译降级（该文件只影响 trust cache 相关符号，缺了不影响其余 90% 的 BSim 匹配）

---

## 最新进展（次日 08:30）：编译全部通过，卡在链接

**923 个 C/C++ 目标文件全部编译成功，0 编译错误。**
失败只发生在最后一步链接：

```
ld: library 'firehose_kernel' not found          ← 已解决（自建替身静态库）
ld: symbol(s) not found for architecture arm64e.kernel   ← 388 个符号
```

### 已解决
- `libfirehose_kernel` 缺失 → 用 xnu 自带的 `tests/unit/mocks/mock_3rd_party.c` 里的实现
  编译出 `/tmp/stublib/libfirehose_kernel.a`，并在 `makedefs/MakeInc.def` 第 861 行
  追加 `LDFLAGS_KERNEL_SDK += -L/tmp/stublib`

### 真正的墙：388 个符号来自 Apple 内部 arm64 平台库
```
_CleanPoC_Dcache / _CleanPoU_Dcache / _FlushPoC_DcacheRegion / _InvalidatePoU_Icache
_Switch_context / _Idle_context / _Shutdown_context / _ResetHandlerData
__bcopyin / __bcopyout / __copyin_atomic32 / _LowResetVectorBase / __start ...
```
这些本应由 `$(SDKROOT)/usr/local/lib/kernel/platform` 提供（内部 SDK / KDK）。

xnu 源码里虽有 22 个 `.s` 文件（含 `osfmk/arm64/cswitch.s`），但在 VMAPPLE 配置下
**只编译出了 5 个目标文件**，其余未纳入构建。

### 结论
**公开的 xnu 源码无法独立链接出 arm64 内核**，必须要有 KDK。

### 最优解：直接下载 KDK
KDK（Kernel Debug Kit）本身就带**完整 DWARF 符号的 macOS 内核**，
拿到后完全不需要自己编译：
- 地址：https://developer.apple.com/download/all/ 搜索 "Kernel Debug Kit"
- 装到 `/Library/Developer/KDKs/`
- 之后直接用它的 `kernel` + `.dSYM` 生成 BSim 签名库
