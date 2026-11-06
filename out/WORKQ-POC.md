# workq_exit 竞态可达性验证（子 agent 实验，中途被中断）

> 状态：agent 在 E4（大规模重复启动）阶段被中断，未留最终报告。
> 以下由现有产物（`harness/workq-poc/results/*.log`）与其过程中的汇报整理而成。

## 一、假设
27.0.1 的 `workq_exit`（偏移 `0x40969fc`）不检查 `WQPTR_IS_INITING_VALUE` 哨兵，
若与 `proc_init_wqptr_or_wait()` 的创建窗口重叠，会把 `~(uintptr_t)0` 当合法指针解引用。
27.2 为此加了 `p_mlock` 锁。

## 二、实测数据（iOS 27.0.1 / iPhone18,2，每次新进程）

### 计时（关键）
| 场景 | 耗时 |
|---|---|
| `main()` 里**首次** `dispatch_async` | **13.9µs**（n=10，12.5~14.8µs） |
| 之后 10 次 dispatch 平均 | **1.85µs** |
| 先 sleep 5 秒再首次 dispatch | **53µs**（n=5，45~66µs） |
| `__attribute__((constructor))` 里首次 dispatch | **413ns** |
| 直接调私有 `_pthread_workqueue_init()` | **2~4.2µs** |

**推论**
- 5 秒等待没让首次变快 → "创建"不是启动时一次性完成，而是绑定在首次 dispatch 上
- `constructor` 里 dispatch 只要 413ns → **workqueue 在 constructor 之前就已存在**
- 直接调 `_pthread_workqueue_init` 2~4.2µs → **INITING 窗口本身 ≤ 2~4µs**

### 能否重复制造窗口
`exec.log` 实测：
```
fork()                    = -1  errno=1  (EPERM)
posix_spawn(...)          =  1  (EPERM)
execve(app bundle helper) = -1  errno=13 (EACCES)
execve('/usr/bin/true')   = -1  errno=2  (ENOENT)
```
→ 换进程的所有途径均被拒绝。`execve` 返回 EACCES 说明请求被 **MACF/沙箱在
`load_machfile` 之前**拦下，因此 `mach_loader.c:942` 的 `workq_exit(p)` 不会被触发。

### 源码层确认
全树只有两处写 `p_wqptr`：
1. `workq_open()` → `proc_set_wqptr()`（`proc_init_wqptr_or_wait` 是唯一置哨兵处）
2. `workq_exit()` → 置 NULL（只在 `proc_exit` 与 exec 的 loader 路径）
**进程存活期间不会被清空。**

## 三、最强的反驳（源码级，agent 提出）

> `workq_exit` 由 `proc_exit` 调用，而 `proc_exit` 只在
> `task->active_thread_count` 归零（最后一个线程）时执行（`osfmk/kern/thread.c:609`）；
> 线程只能在返回用户态时经 `thread_terminate_self` 真正终止。
> **也就是说"置哨兵的线程"必然先完成 `workq_open` 的收尾（`proc_set_wqptr`）才可能消失，
> `workq_exit` 观察不到哨兵。**

→ 27.2 加的 proc 锁更可能是在堵另一条路：
**`workq_open` 在 exit 已把 `p_wqptr` 置 NULL 之后又重建一个 workqueue**（生命周期/泄漏问题），
而不是哨兵解引用。

## 四、结论

| 项 | 结论 |
|---|---|
| `workq_exit` 缺哨兵检查 | ✅ 反汇编与本机源码均确认 |
| 27.2 新增 `p_mlock` 加锁 | ✅ 确认（DWARF 验证 `p_mlock` 偏移 0x50） |
| **app 可触发性** | ❌ **不可达**：INITING 窗口 ≤4µs 且在 constructor 之前；换进程被 EPERM 封死；且 last-thread 论证从源码层面排除 |
| 作为越狱第一跳 | ❌ 放弃 |

## 五、若他人接手
1. 若要继续，唯一未验证的是"`workq_open` 在 exit 之后重建"这条路是否真能造成可观测后果
   （需要能进入 `exec` 成功路径的进程，普通 app 不可得）
2. 实验框架在 `harness/workq-poc/`（`main.c` 支持多 mode、`run.sh`/`e1_timing.sh`/`e4_race.sh`）
3. 结果原文在 `harness/workq-poc/results/`
