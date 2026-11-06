# IOSurface：27.2 新增的销毁标记与映射门控（候选发现 #1）

> 状态：**语义已确认，可达已确认，触发未成功**
> 日期：2026-10-24

## 1. 结论

iOS 27.2 在 `com.apple.iokit.IOSurface` 里新增了一个**"owner 正在销毁"标记**，并在映射路径上加了对该标记的检查。27.0.1（设备当前版本）没有这个标记。这是典型的 **UAF 加固**模式，且 `IOSurfaceRoot` 对普通 app 开放（真机实测）。

## 2. 证据（27.0.1 vs 27.2 反编译对照）

### 映射路径（27.0.1 `FUN_fffffe000a3460f0`，29 bytes 差）
27.0.1：直接遍历映射链表并插入新项
```c
plVar3 = *(long **)(param_1 + 0x188);
if (plVar3) { do {
   if (plVar3[4] == param_3[1] && plVar3[0xb] == param_4) { uVar5 = 0xe00002c9; goto out; }
   plVar3 = *plVar3;
} while (plVar3); }
plVar3 = alloc(...);   /* 插入 */
```

27.2：整段被包进新条件
```c
if ((*(byte *)(param_4 + 0xf1) & 1) == 0) {
    /* 原逻辑 */
} else {
    uVar5 = 0xe00002d8;      /* kIOReturnNotPermitted */
}
```

### 销毁路径（27.0.1 `FUN_fffffe000a346364`）
27.2 在函数开头新增一行：
```c
*(undefined1 *)(param_2 + 0xf1) = 1;   /* 标记 owner 已销毁 */
```
其余逻辑不变。

### 调用关系
- 销毁路径由 `FUN_fffffe000a34b2dc` 调用（该函数也是 27.2 改动点之一，`dInsn=0` 仅引用变化）
- 三个函数在内核里**都没有静态调用者/指针引用**——它们是 C++ 虚方法，vtable 运行期构造

## 3. 真机可达性（已实测）

| 项 | 结果 |
|---|---|
| IORegistry 枚举 | 1479 服务 / 327 类 |
| `IOSurfaceRoot` IOServiceOpen | **kr=0（成功）** |
| 与其他类对比 | 327 类中仅 5 个可打开 |

## 4. 触发尝试（未成功）

| 尝试 | 规模 | 结果 |
|---|---|---|
| 8 线程各自建/映射/释放 surface | 553,402 次 | 无错误、无 panic |
| 8 线程共享同一 surface，map/unmap/purge 争用 | 12,605,334 次迭代 / 191,238 次端口映射 | 无错误、无 panic |

结论：单纯并发 map/unmap 打不到。修补点保护的是 **owner 销毁期间**的映射，需要 client/task 生命周期事件与映射并发。

## 5. 下一步

1. **定位 user client ABI**：`IOSurfaceRootUserClient` 用 switch 而非静态 dispatch 表（已扫描确认无 `IOExternalMethodDispatch` 数组），需要逆向 `getTargetAndMethodForIndex`
2. **构造 client 销毁竞态**：显式 `IOServiceOpen("IOSurfaceRoot")` → 线程 A 反复 `IOServiceClose`，线程 B 并发映射
3. **跨进程路径**：surface 通过 mach port 传给第二个进程，一方退出时另一方映射（需要第二个 App ID）

## 6. 重要修正（真机实测后）

后续用自签 app 实测发现：**IOSurfaceRoot 的内核 user client 方法对无授权 app 全部返回
`0xE00002C2` NotPrivileged**（type=1..5 直接 Unsupported）。app 能用的 `IOSurfaceCreate`
走的是用户态 broker，不经过这条内核路径。

因此：
- **可达性降级**：该修补点不是第一跳，只能作为拿到有权限进程后的第二跳原语
- 前面的 1260 万次压测也没有意义（打的是 broker，不是 kext）

## 7. 风险与定级（修正后）

- 性质：真实的 UAF 加固，语义清晰
- 可达性：**需要特权进程**（详见 `DEVICE-SURFACE.md`）
- 当前：**假设 + 强证据，未复现，非第一跳**
