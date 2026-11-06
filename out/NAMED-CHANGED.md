# 27.2 内核改动函数 — KDK 符号还原结果

KDK 符号总数 14106 → 匹配到 iOS 27.2 唯一函数 **2555** 个
其中命中 27.0.1→27.2 的 358 个改动函数：**36 个**

| 27.0.1 偏移 | 函数名 | 相似度 |
|---|---|---|
| `0x3b7a870` | `i_coal_jetsam_set_taskrole` | 0.985 |
| `0x3b7aa60` | `i_coal_jetsam_remove_task` | 0.980 |
| `0x3df30dc` | `dev_free_name` | 1.000 |
| `0x3dfbf50` | `bpf_wakeup` | 0.992 |
| `0x3e42c14` | `ether_inet_input` | 0.990 |
| `0x3e5a2ec` | `rtm_scrub` | 1.000 |
| `0x3e72524` | `nstat_ifnet_copy_descriptor` | 1.000 |
| `0x3e7a2bc` | `net_port_info_log_npi` | 0.992 |
| `0x3ee82bc` | `nat464_translate_64` | 0.994 |
| `0x3ee851c` | `nat464_translate_46` | 0.990 |
| `0x3efd6b4` | `pf_nat64_ipv6` | 0.994 |
| `0x3f15830` | `pf_normalize_tcpopt` | 1.000 |
| `0x3f21da8` | `iptap_bpf_tap` | 1.000 |
| `0x3f96dcc` | `tcp6_input` | 1.000 |
| `0x3fd8abc` | `flow_divert_init` | 0.995 |
| `0x3fdabe0` | `flow_divert_handle_connect_result` | 0.980 |
| `0x3fdda70` | `flow_divert_ctloutput` | 1.000 |
| `0x4017fa0` | `frag6_input` | 0.985 |
| `0x4019e90` | `icmp6_error_flag` | 0.993 |
| `0x401d080` | `icmp6_redirect_input` | 0.983 |
| `0x402f0ec` | `ip6_process_hopopts` | 0.994 |
| `0x405b990` | `nd6_na_input` | 0.988 |
| `0x40722b8` | `rip6_input` | 1.000 |
| `0x4072ac4` | `route6_input` | 1.000 |
| `0x40d8aa4` | `abort_with_payload` | 1.000 |
| `0x40f8f78` | `sigaction` | 0.988 |
| `0x41065d8` | `sysctl_static_if_modified_keys` | 1.000 |
| `0x41429c8` | `ptsopen` | 0.989 |
| `0x4142ebc` | `ptsclose` | 0.992 |
| `0x4143378` | `ptcopen` | 0.991 |
| `0x4143c7c` | `ptcselect` | 1.000 |
| `0x4144174` | `ptyioctl` | 0.975 |
| `0x41a8624` | `null_getnewvnode` | 0.988 |
| `0x4225aec` | `nx_netif_filter_tx_cb` | 1.000 |
| `0x4226774` | `kern_netif_queue_rx_enqueue` | 1.000 |
| `0x423aa0c` | `netif_gso_tcp_segment_mbuf` | 0.990 |

---

## 符号还原管线（KDK 27.2 = build 26B123）

```
KDK dSYM (75MB DWARF)
  │ dwarfdump --debug-info 解析 DW_TAG_subprogram
  ▼
14106 个带名字与地址的函数            → out/kdk-syms.txt
  │ 指令助记符形状匹配（唯一 + 相似度≥0.97）
  ▼
iOS 27.2 内核（kc.27.2.ga.macho）
  精确唯一匹配 1356 个 → 放宽后 2555 个   → out/kdk-to-ios272-relaxed.txt
  │ kfunc 已给出的 358 对配对
  ▼
iOS 27.0.1 内核：36 个改动函数获得名字
```

## 命名结果的分布（极重要）

36 个有名改动函数**几乎全部集中在网络栈**：

| 子系统 | 函数 |
|---|---|
| **IPv6 输入** | `tcp6_input` `rip6_input` `route6_input` `frag6_input` `icmp6_redirect_input` `ip6_process_hopopts` `nd6_na_input` `ether_inet_input` |
| **包过滤 / NAT64** | `pf_normalize_tcpopt` `pf_nat64_ipv6` `nat464_translate_64` `nat464_translate_46` |
| **netif / 网卡** | `nstat_ifnet_copy_descriptor` `netif_gso_tcp_segment_mbuf` `nx_netif_filter_tx_cb` `kern_netif_queue_rx_enqueue` `sysctl_static_if_modified_keys` |
| **flow divert** | `flow_divert_init` `flow_divert_handle_connect_result` `flow_divert_ctloutput` |
| **BPF / 抓包** | `bpf_wakeup` `iptap_bpf_tap` |
| **pty（任何 app 可开）** | `ptsopen` `ptsclose` `ptcopen` `ptcselect` `ptyioctl` |
| **其它** | `i_coal_jetsam_set_taskrole` `i_coal_jetsam_remove_task` `abort_with_payload` `sigaction` `null_getnewvnode` `dev_free_name` |

## 与 13 条 Kernel CVE 的对应方向

| CVE | 类型 | 最可能的落点 |
|---|---|---|
| CVE-2026-112507 | **越界写 → 写内核内存** | 网络栈（IPv6 输入 / pf） |
| CVE-2026-112476 | **越界读** | `nstat_ifnet_copy_descriptor`（sysctl 可达）或 IPv6 选项解析 |
| CVE-2026-112501 | **竞态** | `0x40969fc`（我们最早发现的 CAS 所有权协议修补） |
| CVE-2026-112665 | 信息泄露 → 内核内存布局 | `nstat_ifnet_copy_descriptor` 类 copyout |
| UAF 若干 | — | jetsam / netif / flow_divert 生命周期 |

**结论：27.2 的 13 条 Kernel CVE 高度集中在网络栈，而网络栈是 app 通过 socket
直接可达的 —— 这是整个 session 里最有价值的新方向。**

---

## 36 个有名改动函数的排序（按新增边界分支数）

| Δ边界分支 | Δ条件分支 | Δ比较 | 函数 | 指令数 |
|---|---|---|---|---|
| **+8** | 0 | **+10** | **`nat464_translate_64`** | 1067→1116 |
| **+6** | 0 | **+8** | **`nat464_translate_46`** | 915→950 |
| +3 | -1 | +3 | `flow_divert_init` | 1004→1022 |
| +1 | 0 | +1 | `pf_normalize_tcpopt` | 344→346 |
| +1 | 0 | +1 | `pf_nat64_ipv6` | 74→84 |
| +1 | 0 | +1 | `null_getnewvnode` | 249→260 |
| 0 | **+4** | 0 | `iptap_bpf_tap` | 378→387 |
| 0 | +1 | +1 | `sigaction` | 710→729 |
| 0 | 0 | +3 | `abort_with_payload` | 721→741 |
| 0 | 0 | 0 | 其余 27 个（含 `nstat_ifnet_copy_descriptor`、`tcp6_input`、`pty*`） | — |

## 首要候选：`nat464_translate_64`

NAT64 / 464XLAT 的 IPv6↔IPv4 地址与端口转换函数，27.2 新增了多处无符号边界检查：

```asm
tst  w27, #0xfffff8ff ; b.eq     ; 标志位校验
cmp  w26, #0x2c      ; b.ne      ; 协议/类型校验
cmp  x28, w25, sxtw  ; b.hs      ; 无符号上界检查
cmp  x28, x8         ; b.lo      ; 无符号下界检查
```

**判定**：这是一次实质性的边界加固（+8 个边界分支、+49 条指令），
形态与 CVE 描述"out-of-bounds ... improved bounds checking"一致。
对应 13 条 Kernel CVE 中 **CVE-2026-112507（越界写）** 或 **CVE-2026-112476（越界读）**。

## 可达性评估
- `nat464_translate_64/46` 处理**经过 NAT64/CLAT 的报文**
- 蜂窝网络（464XLAT）环境下会自然触发；也可由网络侧构造报文到达
- ⚠️ 未确认能否由本地 app 直接构造触发 —— 需要进一步确认调用路径

## 次选：`iptap_bpf_tap`（+4 条件分支）
BPF 抓包路径；`bpf_wakeup` 也在改动列表里。BPF 需要权限，普通 app 不可达。

---

## nat464 可达性调查（未打通）

| 检查 | 结果 |
|---|---|
| 直接 `bl` 调用者 | **0 个** |
| 数据段指针（含 PAC 掩码比较） | **0 处** |
| `adrp+add` 取地址（ops 表装配点） | **0 处** |

→ NAT64 函数通过某种未定位的间接方式注册（ops 表），
且 NAT64/464XLAT 只在**报文处理路径**上运行（CLAT/蜂窝 464XLAT）。

### 可达性判定
**`nat464_translate_64/46` 属于"网络侧可达"，不是"app 直接可达"。**
与 Wi-Fi 那几条 CVE（"attacker in radio range"）同类，不能作为 app 越狱的第一跳。

---

## 本轮的战略性结论

把 36 个有名改动函数按"app 可达性"重新分类：

| 类别 | 函数 | 能否做第一跳 |
|---|---|---|
| 报文输入路径 | `nat464_*` `pf_normalize_tcpopt` `tcp6_input` `rip6_input` `frag6_input` `ip6_process_hopopts` `ether_inet_input` | ❌ 需网络侧攻击者 |
| netif / 队列 | `nx_netif_filter_tx_cb` `kern_netif_queue_rx_enqueue` `netif_gso_tcp_segment_mbuf` | ❌ |
| 需 entitlement | `flow_divert_*` `iptap_bpf_tap` `bpf_wakeup` | ❌ |
| sysctl（app 可调） | `nstat_ifnet_copy_descriptor` `sysctl_static_if_modified_keys` | ✅ 但**两版检查无实质差异** |
| **pty（任何 app 可开）** | `ptyioctl` `ptsopen` `ptsclose` `ptcopen` `ptcselect` | ✅ **但 Δ=0，改动是内联重构** |
| 其它 app 可达 | `sigaction` `abort_with_payload` `null_getnewvnode` | Δ 很小 |

**核心判断：27.2 的 13 条 Kernel CVE，主要落点在报文处理路径上，
即"网络侧可达"而非"app 直接可达"。**

这解释了为什么苹果把它们归到 Kernel 组件却由安全研究团队提交
（Nebula Security / Tim Michaud / Marc Newlin of SkySafe 等，后者专攻无线）。

---

## pty 线：排除

`ptyioctl` / `ptsopen` / `ptsclose` / `ptcopen` / `ptcselect` 两版指令数完全相同，
差分显示**只有 adrp 页号与标签偏移变化**（同一个全局变量换了地址），**无语义变化**。

## 358 个配对的真实构成

| 类别 | 数量 |
|---|---|
| 助记符序列完全相同（仅地址/操作数变化） | **24** |
| 有真实结构变化 | **334** |

大部分是真改动。但其中若干条明显是**函数边界错位**造成的假象
（如 `0x3bbf724` 5→2048 条指令、`0x3e5a2ec` 2048→245 条），
说明 `kfunc` 的配对在个别函数上不可靠。

## 当前覆盖率与瓶颈

```
358 个改动函数  →  已命名 36 个（10%）
```

**真实的修补点很可能落在未命名的 322 个里。**

### 提升覆盖率的三条路径
| 路径 | 预期收益 | 成本 |
|---|---|---|
| 用 KDK 全部 14 个内核变体联合匹配 | 覆盖率 +10~20% | 30 分钟 |
| 用 DWARF 的**结构体定义**做"字段偏移指纹"匹配 | 可能大幅提升，且能命名未形状匹配的函数 | 2–3 小时 |
| 放宽相似度阈值到 0.90 | 覆盖率 +，但精度下降到 ~85% | 10 分钟 |

### 字段偏移指纹（最有潜力）
KDK 的 DWARF 含 `struct ifnet` / `proc` / `task` 等完整成员偏移。
拿"函数访问了哪些结构体偏移"作为指纹，可与 iOS 内核函数做另一维度的匹配，
不依赖指令形状——这将补上形状匹配失效的那部分函数。

---

# 🎯 关键发现：`workq_exit` 竞态修补（CVE-2026-112501 候选）

## 符号还原
```
0x40969fc (27.0.1) → 0x40ec0f0 (27.2)   =  workq_exit   r=0.912
```

## 27.0.1（源码 2025-10 版，与本版一致）
```c
wq = os_atomic_xchg(&p->p_wqptr, NULL, relaxed);   // 对应 swp xzr, x19, [x8]
if (wq != NULL) { ... workq_deallocate(wq); }
```
⚠️ **重要修正**：`os_atomic_xchg` 本身已保证只有一个线程拿到非空 wq，
**所以"两线程都进释放流程"的双重释放说法不成立。** 真正的竞态在别处。

## 27.2（已修）
```asm
mrs  x20, tpidr_el1
ldr  w9,  [x20, #0x4f8]   ; 当前线程 tid
add  x21, x0,  #0x58
casa x8, x9, [x21]        ; CAS：若 [+0x58]==0 才写入自己的 tid
cmp  x8, #0
b.ne <错误路径>            ; 非 0 → 别的线程已在退出
...
casl w2, wzr, [x21]       ; 释放阶段校验 tid 仍是自己
cmp  w2, w8
b.ne <错误路径>
```
新增了一把 **proc 级互斥锁**：快速路径在 `proc+0x58` 存 owner tid（`casa`），
失败则走慢速路径 `lck_mtx_lock(proc+0x50, thread)`；释放时 `casl` 校验 tid 后解锁。

错误路径反汇编佐证：
```asm
add x0, x0, #0x50 ; mov x1, x20(tpidr_el1) ; mov w2, #0 ; bl <lck_mtx_lock>
```
→ **27.2 把 workq_exit 整体纳入 proc 锁保护**，说明竞态发生在
`workq_exit`（进程退出/exec 失败路径）与**其它同时操作 proc/workqueue 的路径**之间。

## 反编译佐证（27.0.1）
函数遍历工作队列链表、递减引用计数并释放：
```c
puVar14 = *(undefined8 **)(param_1 + 0x638);
...
FUN_...(puVar14[0]); FUN_...(puVar14[1]); FUN_...(puVar14[2]);   // 释放
while (...) { int *p = ...; iVar12 = *p; *p = iVar12-1; LORelease();
              if (iVar12==0) ... ; if (iVar12==1) ... }           // 引用计数
```

## CVE 对应
| CVE | 描述 | 匹配度 |
|---|---|---|
| **CVE-2026-112501** | **"A race condition was addressed with improved state handling"** → 系统终止 | **极高** |
| CVE-2026-112516 | "use-after-free ... improved memory management" | 高 |
| CVE-2026-65350 / 112517 | UAF → 破坏内核内存 | 高 |

## 为什么这个比之前所有候选都好
| 维度 | 之前 | workq_exit |
|---|---|---|
| 身份 | `FUN_xxxxxxxx` | **`workq_exit`** |
| 漏洞类型 | 只能猜测 | **双重释放/UAF 竞态，由代码差异直接证实** |
| app 可达性 | ANE 不可达 / AVE 缺数据通道 / NAT64 需网络侧 | **工作队列退出路径，进程退出即触发** |
| 修补形态 | 不明确 | **清晰：新增 CAS 归属协议** |

## 剩余待办
1. 确认 workq 对象能否由 app 创建并经并发退出（如 GCD 线程池 + fork/exit 组合）
2. 构造两线程竞争 `workq_exit` 的 PoC
3. 在 27.0.1 真机上观察双重释放行为（可能表现为内核 panic 或内存破坏）

---

## 竞态的精确机制（源码级确认）

### 关键常量
```c
#define WQPTR_IS_INITING_VALUE ((struct workqueue *)~(uintptr_t)0)
```

### 竞争双方

**线程 A — 首次创建 workqueue**（`proc_init_wqptr_or_wait`）
```c
proc_lock(p);
if (p->p_wqptr == NULL) {
    os_atomic_store(&p->p_wqptr, WQPTR_IS_INITING_VALUE, relaxed);  // 打入哨兵
    proc_unlock(p);
    return true;              // 之后去分配 workqueue（耗时较长）
}
```

**线程 B — 进程退出**（`workq_exit`，27.0.1）
```c
wq = os_atomic_xchg(&p->p_wqptr, NULL, relaxed);   // 不持锁、不检查哨兵
if (wq != NULL) {                                  // 哨兵 ~0 != NULL → 进入分支
    thread_call_cancel_wait(wq->wq_delayed_call);  // 解引用 (~0 + 0x..)！
    thread_call_cancel_wait(wq->wq_immediate_call);
    thread_call_cancel_wait(wq->wq_death_call);
    thread_call_free(...); ... 
    workq_deallocate(wq);                          // 对野指针做释放
}
```

### 缺陷本质
**`workq_exit` 缺少对 `WQPTR_IS_INITING_VALUE` 哨兵的检查。**
当它与"另一线程正在创建 workqueue"的时间窗口重叠时，
会把哨兵值 `~(uintptr_t)0` 当作合法 `struct workqueue *` 解引用并释放
→ **野指针读 + 对非法地址 deallocate → 内核内存破坏 / panic**。

### 27.2 的修补
给 `workq_exit` 加上 `lck_mtx_lock(p->p_mlock)`（即 `proc_lock`），
与 `proc_init_wqptr_or_wait` / `proc_set_wqptr` 串行化，从根本上消除哨兵可见窗口。

反汇编佐证：
```asm
mrs  x20, tpidr_el1
add  x21, x0, #0x58
casa x8, x9, [x21]        ; 锁快速路径：占用（owner tid）
cmp  x8, #0
b.ne <slow path>
...
add  x0, x0, #0x50 ; mov x1, x20 ; bl <lck_mtx_lock>   ; 慢速路径
```

## app 可达性：完全可控

触发条件只需**在同一个进程内同时发生两件事**：
1. 某线程**首次**向工作队列派发任务（`dispatch_async` 到尚未使用过的队列）→ 触发 workqueue 创建
2. 主线程（或另一线程）**立刻 `exit()`** → 触发 workq_exit

这是**普通 app 完全可控的时序**，不需要任何 entitlement。

## CVE 对应：CVE-2026-112501
> "A race condition was addressed with improved state handling"（系统终止）

与源码级证据完全吻合。

## 下一步：写 PoC
```c
for (int i = 0; i < N; i++) {
    pid_t pid = fork();
    if (pid == 0) {
        dispatch_async(dispatch_get_global_queue(...), ^{ /* 首次派发，触发创建 */ });
        _exit(0);              // 立刻退出，制造与 workq_exit 的窗口重叠
    }
}
```
在 27.0.1 真机上反复跑，观察是否出现 panic / 内存破坏。

---

## PoC 尝试与可达性再评估（重要）

### 为什么必须反复启动进程
- `workq_exit` 每次进程**只执行一次**：它把 `p->p_wqptr` 原子换成 NULL，之后不会再进入该分支
- 源码确认：`p_wqptr` 只在「首次创建」（`proc_set_wqptr`）与「退出」（`workq_exit`）两处写，
  **进程存活期间不会被清空**
- 因此在单进程内无法重复触发；要有第 2 次尝试必须换进程

### 实测：沙箱封死了换进程的所有路径
```
fork()  = -1, errno = 1 (EPERM)
```
`posix_spawn` / `execve` 同理被拒。→ **每个尝试 = 一次完整进程启动**（约 2 秒）。

### 已做尝试
| 版本 | 做法 | 结果 |
|---|---|---|
| v1 | Foundation + 200 线程派发后返回退出 | 无 panic |
| v2 | 8MB×64 内存压力 + 8 线程 + 立即 `_exit` | 40 次启动，无 panic |
| v3 | 纯 POSIX（不碰 Foundation）+ 4 线程 + 随机 0~150µs 延迟 | 60 次启动，无 panic |

### 更根本的问题（诚实评估）
**工作队列很可能在进程启动早期（dyld / libdispatch 初始化）就已创建完成**，
等到 `main()` 执行时 `p_wqptr` 早已非空 —— 此时 app 代码**根本无法制造 INITING 窗口**。

若如此，则该竞态**并非由普通 app 代码路径可触发**，
苹果文案里的 "An app may be able to..." 可能指其它触发方式（如 exec 失败路径，
而该路径同样被沙箱封死）。

### 结论
- ✅ `workq_exit` 缺哨兵检查这一点**源码级确证**
- ✅ 27.2 加 proc 锁的修补**反汇编级确证**
- ❌ **应用层可触发性未证实**，且现有证据提示可能不可触发
- 若要继续，需要：能控制"首次 workqueue 创建"时机的进程（如有 entitlements 的守护进程），
  而非普通 app

---

# 第二轮：调用图锚点定位（采纳外部建议后）

## 修复了两个工具 bug
| bug | 影响 | 修复 |
|---|---|---|
| 线性反汇编在段首遇到非代码字节即停止（只扫到 2000 条指令） | `bl` 扫描完全失效，调用图恒为空 | `md.skipdata = True` |
| capstone 把 `bl` 目标以**有符号负数**返回 | 目标偏移换算成 `-0xfffffffffc...`，全部对不上函数表 | `imm & 0xFFFFFFFFFFFFFFFF` |

修复后：**236 万条指令、70664 条有效调用边**。

## 成果：281 个匿名改动函数中，123 个恢复了身份上下文

按调用者/被调用者的实名推断所属子系统，代表样本：

| 27.2 偏移 | 被调（实名） | 调用者（实名） | 推断 |
|---|---|---|---|
| `0x4003c74` | `tcp_reassq_free` `tcp_log_rtt_info` `m_freem_list` | **`tcp_usr_connect_common`** | TCP 重组队列释放 —— **connect() 直达** |
| `0x3cdd0f4` | `panic` `vm_object_mapping_wait` | **`IOMemoryDescriptorMapAlloc`** | 内存描述符映射 —— **IOKit 可达** |
| `0x3efa6a8` | `ifnet_get_nat64prefix` `proc_rele` `inet_ntop` | **`necp_client_flow_is_viable` `necp_match_policy`** | NECP 策略 —— **socket 选项可达** |
| `0x40cba20` | `in6_pcblookup_hash_locked` `im6o_mc_filter` | — | IPv6 套接字查找/多播 |
| `0x40703ec` | `icmp6_redirect_input` `m_dup` `panic` | — | IPv6 重定向处理 |
| `0x4252dcc` | `dp_tx_log_pkt` `fsw_dev_input_netem_enqueue` | — | 网络模拟/流交换 |
| `0x3fb264c` | `arp_llinfo_addq` | `fsw_ethernet_resolve` | ARP 表项 |
| `0x4125988` | `panic` `exec_setup_vfs_resolve_flags` | — | exec / VFS |
| `0x3e8dddc` | `dlil_clat64` `m_drop_extended` | — | CLAT64 转换 |

**三个 app 可直达候选**（按可达性排序）：
1. `0x4003c74` — TCP `connect()` 路径
2. `0x3cdd0f4` — `IOMemoryDescriptorMapAlloc`（IOKit）
3. `0x3efa6a8` — NECP socket 策略

## 尚未解决的度量问题
按"到下一个函数起点"估算函数体积时，B 侧边界明显过长
（如 `218→3709` 条指令），导致 Δ比较/Δ边界 数值失真、排序不可靠。
**需要改用更严格的函数边界（Prolog 识别或 DWARF 的 high_pc 映射）后才能定量排序。**
目前只能定性使用调用图上下文。

---

## 四个 Mach IPC 函数的定量差分（可靠尺寸）

| 函数 | 27.0.1 → 27.2 | dInsn | dChk | 尺寸 |
|---|---|---|---|---|
| **`ipc_port_request_type`** | `0x3b5ff00` → `0x3baff60` | **+9** | **3** | **128→196 (+53%)** |
| `ipc_entry_lookup` | `0x3b4e5e8` → `0x3b9e5e8` | +1 | 1 | 152→164 |
| `ipc_port_request_alloc` | `0x3b5f660` → `0x3baf654` | +1 | 1 | 208→232 |
| `ipc_right_lookup_read` | `0x3b66418` → `0x3bb6590` | 0 | 1 | 616→628 |

`ipc_port_request_type` 改动最显著（代码量增加 53%），优先分析。

### `ipc_port_request_type` 详细分析结论

**源码（2025 版 `osfmk/ipc/ipc_port.c:583`）**
```c
table = port->ip_requests;
ipr = ipc_port_request_table_get(table, index);   // index 来自 entry->ie_request
assert(ipr->ipr_name == name);                    // __assert_only，release 下被编译掉
```
调用者：`ipc_right.c:725/1877/1889`、`mach_port.c:167/178`、`mach_debug.c:246`。
索引 `index` 来自内核内部的 `ipc_entry.ie_request`，**不是用户直接传入的值**。

**27.0.1 vs 27.2 的改动**
- 27.0.1（32 条指令）：`x10 = table_base + index*16`，只有符号扩展检查（`cmp x9, w9, sxtw`）
- 27.2（41 条指令）：新增 `add x8, x8, #0x10`（表格头部 16 字节偏移）**与 `cmp/b.hi` 上界比较**

**判定：属于 `ipc_port_request_table` 的结构硬化 + 防御性边界检查，不是可直接触发的越界。**
索引由内核维护，用户无法直接控制；即便越界也只会命中 `panic` 路径。
→ **与 Gemini 的预判一致：这是子系统级防御加固，应放弃。**

### 四个 IPC 函数的最终定性
| 函数 | 改动 | 定性 |
|---|---|---|
| `ipc_port_request_type` | +53% 代码、上界检查 | 表结构硬化，索引非用户可控 → **放弃** |
| `ipc_entry_lookup` | +1 检查 | 待查（可能为断言加固） |
| `ipc_port_request_alloc` | +1 检查 | 待查 |
| `ipc_right_lookup_read` | +0 指令、+1 检查 | 待查 |

---

## ⚠️ 方法学纠正：序列差分会把"重排"误判成"新增检查"

### 案例：AppleSEPKeyStore `0x1eba2c0`（27.0.1）→ `0x1ef88b8`（27.2）
初看像一个新增的越界检查：
```asm
cmp w19, #0x144
b.hi fail
```
但 27.0.1 的**原始反汇编里本来就有**：
```asm
17  mov x19, x1
18  cmp w1, #0x144        ← 一直都在
19  b.hi ...fail
```
27.2 只是把 `mov x19,x1` 上移、调整栈帧（0x90→0xe0）与清零顺序。

### 结论
- **`dChk` 指标只能表示"这段代码变了多少"，不能表示"新增了安全检查"**
- 编译器重排、寄存器分配变化、内联都会让 `dChk` 变大
- **每一处"新增检查"都必须回到原始反汇编逐条确认**，不能只看差分输出

### 影响范围
之前基于 `dChk` 排序得出的所有"候选"，都只能当作**"值得看一眼"的线索**，
不能当作"修补点"的证据。已确认的例外（经原始反汇编核对）：
- `workq_exit`：加锁是真实新增（`casa` + `lck_mtx_lock` 在 27.0.1 中完全不存在）
- `ipc_port_request_type`：`+0x10` 与上界比较需再核对一次

### 待办
把"语义差分"补上：对每个候选函数做**指令集合的多重集比较**（忽略顺序与地址），
只有当某个 `cmp/b.` 在 27.2 中出现次数多于 27.0.1 时，才算"新增检查"。

---

## 语义差分（多重集）重排 —— 修正后的可靠排序

方法：统计每个函数内 `cmp/tst/subs/ands/cbz/cbnz/tbz/tbnz/条件跳转` 的**出现次数**，
比较两版之间的差值。重排不再影响结果。

| Δ检查 | Δ指令 | 27.2 偏移 | 名字 | 尺寸 |
|---|---|---|---|---|
| **+305** | +2081 | `0x3c10adc` | (匿名) | 5→2086 ⚠️边界错位，作废 |
| **+106** | +665 | `0x3fb264c` | (匿名，ARP 上下文) | 299→964 ⚠️疑似边界错位 |
| +39 | +79 | `0x4141f74` | (匿名) | 889→968 |
| +29 | +228 | `0x430ce1c` | (匿名) | 1059→1287 |
| +28 | +217 | `0x430ccc0` | (匿名) | 1157→1374 |
| +26 | +201 | `0x430cb90` | (匿名) | 1249→1450 |
| +21 | +184 | `0x40ad930` | (匿名) | 189→373 |
| +20 | +56 | `0x3f3ba64` | `nat464_translate_icmp_ip` | 1350→1406 |
| **+18** | +49 | `0x3f3beec` | **`nat464_translate_64`** | 1067→1116 |
| +14 | +35 | `0x3f3c184` | `nat464_translate_46` | 915→950 |

### 关键结论
- `nat464_*` 三个函数在**三种独立指标**（序列差分、尺寸增量、多重集差分）下都排在前列，
  **是本轮唯一经得起交叉验证的加固点**（但可达性仍是报文路径）。
- `0x430c*` 三连（同步增长约 150~200 条指令、约 30 个新检查）指向某个共享子系统，值得一查。
- 排名第一、第二的两个"巨型增长"实为函数边界错位，已作废。

---

## 新线索：`csops` 的 entitlement blob 拷贝路径（app 可直接调用）

### 定位
`0x40ec688`(27.0.1) → `0x4141f74`(27.2)，889→968 指令，Δ检查 +39（多重集口径）。
调用图上下文：`csops_copy_token`、`csblob_get_der_entitlements`、`proc_rele`
→ 源码位置 **`bsd/kern/kern_proc.c` 的 `csops_internal()`**。

### 可疑代码
```c
case CS_OPS_ENTITLEMENTS_BLOB:
    ...
    length = (size_t)ntohl(xmlblob->length);      // ← 长度来自 blob 头
    error = csops_copy_token(start, length, usize, uaddr);
```
```c
static int
csops_copy_token(const void *start, size_t length, user_size_t usize, user_addr_t uaddr)
{
    if (usize < sizeof(fakeheader)) return ERANGE;
    else if (usize < length) { /* 回填所需长度 */ return ERANGE; }
    return copyout(start, uaddr, length);          // ← 按 blob 自报长度拷贝
}
```
用户只控制 `usize`（自己缓冲区大小），`length` 完全来自 blob 头的 `ntohl(...->length)`。

### 可达性
`csops(pid, CS_OPS_ENTITLEMENTS_BLOB, uaddr, usize, 0)` —— **普通 app 对自己即可调用**，
是本轮所有候选里可达性最好的一个。

### 但必须说清的保留
1. DER 路径里 `csblob_get_der_entitlements()` 会**按 `ntohl(length)` 计算哈希并与代码目录中的
   内嵌哈希比对**，长度被夸大时哈希必然不匹配 → 返回 `EBADEXEC`。
   而攻击者能对自签应用算出匹配哈希，此时长度与签名数据一致，也不会越界。
2. XML 路径的长度来自 AMFI（内核扩展）解析出的 blob，是否校验未知。
3. 27.2 的改动是一处**大函数（覆盖全部 CS_OPS_* 分支）的整体重构**，
   新增的 `cmp w23,#0x12; b.ls` 属于哪个分支尚未定位。

**结论：这是一条有理论依据、可达性最好、但尚未验证的线索。**
下一步应做**实测**：在真机上调用 `csops` 各分支、传大缓冲区，
观察返回的长度字段与数据，判断是否存在长度/数据不一致。
