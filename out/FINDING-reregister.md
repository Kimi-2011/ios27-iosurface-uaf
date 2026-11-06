# FINDING：iOS 27.0.1 允许对「已注销的 IOSurfaceRoot user client」再注册

> **一句话**：在 iOS 27.0.1 上，`sel17` 注册 → `sel18` 注销 → `sel17` 再注册，三步全部返回 `SUCCESS`；
> 27.2 增加了 `+0xf1` 粘滞标志来封堵这个动作。**这是与官方补丁一一对应的实测路径。**
>
> 级别：**状态机可达性实证**。不是内存破坏原语（见 §5）。

---

## 1. 实测返回码（iPhone18,2 / iOS 27.0.1 24A446，40 次全一致）

同一个 `io_connect_t`、同一份 `structureInput = {1,2,3}`（24 字节），全程不换连接：

| 步 | 调用 | 返回码 | 名称 |
|---|---|---|---|
| 1 | `sel17` **异步** | **`0x0`** | `SUCCESS` |
| 2 | `sel17` 异步（重复） | **`0xE00002C9`** | `kIOReturnInternalError`（dup，证明节点在表里） |
| 3 | `sel18` **同步** | **`0x0`** | `SUCCESS`（注销成功） |
| 4 | `sel17` 异步（再注册） | **`0x0`** | **`SUCCESS` —— 27.0.1 不做「已注销」检查** |

对照：`replant2K1` 40/40、`seq4I` 20/20、`replantG` 60/60 —— 三种独立的实施均复现同一组返回码。

## 2. 调用契约（这两条踩错就全盘失败）

### `sel17` = 注册，**必须异步**

```
派发表项：scalarIn=0, structIn=24, scalarOut=0, structOut=0, 有 asyncWakeTarget
handler 0xa3498f4:  ldr x1,[args+0x10] ; cbz x1 -> 0xE00002C2
```

`args+0x10` 是 **reference 数组指针**，只有 `IOConnectCallAsyncMethod`（`referenceCnt >= 1` 且指针非空）才会填。
同步 `IOConnectCallMethod` 恒返回 `0xE00002C2`。

### `sel18` = 注销，**必须同步**（本项目曾在此错两轮）

```
派发表项：scalarIn=0, structIn=24(scalarOut=0, structOut=0), 无 asyncWakeTarget
handler 0xa34991c -> 0xa3461f4(root, structureInput, client)
```

每元素匹配条件（静态）：

```
*(u64*)(structureInput + 8) == node+0x20        ; key
client                      == node+0x58        ; owner（user client）
命中 -> 摘链 + destroy(node+0x10) + free(node) -> SUCCESS
未命中 / 链表空 -> 0xE00002C2
```

正确调用形态：

```c
uint64_t in[3] = {1,2,3};
kern_return_t kr = IOConnectCallMethod(c, 18, NULL, 0, in, 24, NULL, NULL, NULL, NULL);
```

用 `IOConnectCallAsyncMethod` 打 `sel18` 会被 IOKit 的前置参数校验挡在 handler 之外，返回 `0xE00002C2` —— 与「没匹配到节点」**返回码相同**，极易误判为「节点不存在」。

## 3. 27.2 的封堵（静态）

```
0xa394500  ldrb w8,[x21,#0xf1]   ; 注册路径锁内检查
           tbz  -> 继续注册
           add  w20,w20,#0x1b    ; 0xE00002BD + 0x1B = 0xE00002D8 kIOReturnNotAttached
0xa394774  strb w8,[x20,#0xf1]   ; 注销路径（#802 对应体）函数最开头打永久标记
```

`+0xf1` 字节访问统计（可复核的机械事实）：**27.0.1 = 0 处，27.2 = 2 处**。

## 4. 为什么标志放在 `+0xf1`

`+0xf0` 是 32 位计数的低字节（`strb w0,[x19,#0xf0]` = 注册计数置 1），**析构路径 `0xa34373c` 用 `str wzr` 把这个 32 位字整个清零**。标志必须活过清零，所以只能放在 `+0xf1`。

## 5. 这条发现**不是**什么（边界，勿过度解读）

| 不是 | 说明 |
|---|---|
| 任意地址读/写 | 无。再注册只是插回一个注册表节点 |
| 提权 / 沙箱逃逸 | 无。全程停留在 IOSurface 用户客户端的正常方法面内 |
| 内存破坏原语 | 无。**「允许再注册」这个动作本身在纯用户态无法转化成内存破坏** —— 见 `IOSURFACE-RACE.md` §16：注册/注销/再注册 + 关闭连接 + 引用归零 + Metal 真实 GPU 提交，2000+ 用例零 panic |

**它是**：一个与 Apple 官方修复精确对应的**状态机可达性实证**，可用作 27.0.1 与 27.2 行为差异的活体判据（同一段代码在 27.2 上第 4 步应返回 `0xE00002D8`，**该推论为静态，尚无 27.2 真机实测**）。

## 6. 复现片段

```c
io_connect_t c; IOServiceOpen(svc, mach_task_self(), 0, &c);   // type 必须为 0
uint64_t in[3] = {1,2,3}, ref = 0x1122334455667788ULL;
uint32_t soc = 0; mach_port_t wp;
mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wp);

// 1 注册（异步）
IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL); // -> 0
// 2 重复 -> 0xE00002C9
IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL);
// 3 注销（同步！0 标量、精确 24 字节、无输出）
IOConnectCallMethod(c, 18, NULL, 0, in, 24, NULL, NULL, NULL, NULL);                  // -> 0
// 4 再注册（异步）
IOConnectCallAsyncMethod(c, 17, wp, &ref, 1, NULL, 0, in, 24, NULL, &soc, NULL, NULL); // -> 0  ← 27.2 应为 0xE00002D8
```
