# S2 攻关总盘

**更新**：2026-11-01 11:10　**指挥**：主 agent

## 0. 目标
挖出一个**可在真机上复现的内核内存破坏 PoC**，打通 S2。
S1 已有（dev-signed app + WKWebView）。S4 已有做法（等 r/w）。S5 架构性堵死（与 S2 无关）。

## 1. 当前掌握的事实（不重复验证）

| 资产 | 内容 | 位置 |
|---|---|---|
| 实测可达面 | 17 个可打开的 user client 类 | `out/REACH-MEASURED.md` |
| 静态普查 | 2266 selector / 245 表 / 85 kext | `out/census.json` |
| 真函数表 | `LC_FUNCTION_STARTS`，301/301 自证 | `out/METHOD-AUTHORITATIVE-TABLE.md` |
| 指针解码 | `va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)` | 同上 |
| 符号桩 | 19,938 桩 / 4,153 目标 / 4 个已命名 | `out/stubs-named.json` |
| **CVE 情报** | **131 CVE，24 条影响内核内存** | `out/advisory-27.2.json` |

## 2. 核心判据（这一轮改的）

**dChk 只看得见 OOB 类修复，看不见 UAF 和竞态。**

| 公告措辞 | 编译产物 | dChk |
|---|---|---|
| improved **bounds checking** | `cmp` + `b.hi` | ✅ |
| improved **input validation** | 校验分支 | ✅ |
| improved **memory management** | retain/release → **`bl`** | ❌ |
| improved **locking** | lock/unlock → **`bl`** | ❌ |

→ 判据改为 **「桩调用差分化」**：数 27.2 相对 27.0.1 新增了几次
`0xb266a30`(retain) / `0xb264d84`(release) / `0xabd3390`(lock) / `0xabd3f78`(unlock)。

## 3. 靶子排序（按「公告点名 × 实测可达 × 修复可定位」）

| 优先 | 靶子 | 公告 | 实测可达 | 为什么排这个位置 |
|---|---|---|---|---|
| **P0** | **Apple Neural Engine** | 2× **OOB write → 写内核内存** | ✅ `H1xANELoadBalancer` type=1 | 唯一的**写**原语 + 可达已证 + `bounds checking` 可被 dChk 定位 |
| P1 | Kernel (XNU) | 6 条，UAF/竞态/1 OOB write | ✅ 系统调用面 | 条目最多，但要靠桩差分定位 |
| P2 | AVEVideoEncoder | 5 条 OOB write/read | 待确认 | 条目多，可达性未证 |
| P3 | IOSurface | 1 条**竞态** | ✅ type=0 | 之前找错了类型（不是长度索引） |
| P4 | IOMobileFrameBuffer | 1 条**竞态** | ✅ `AppleCLCD2` 0-3 | 可达且完全没审 |
| P5 | IOHIDFamily | 1 条 OOB read | ✅ ×27 | 可达实例最多 |
| P6 | AppleKeyStore | 未点名 | ✅ 0-3 | 普查盲区，另一路在跑 |

## 4. 路线图

### 阶段 A：定位补丁（进行中）
- B：ANE 2 条 + AVE 5 条，按 `bounds checking` 定向差分
- A：Kernel 6 条，按桩调用差分

**产出判据**：能给出 `(组件, CVE, 函数 27.0.1→27.2, 新增的校验指令, 用户可控输入在哪)`

### 阶段 B：动态验证（本轮新建，关键）
建一个**通用 selector 调用器**：给定 `(类名, type, selector, scalars, structIn)`，
打开 → `IOConnectCallScalarMethod` / `IOConnectCallStructMethod` → 记录返回。
- 目的：把「静态认为可达」变成「实测调用成功」
- 目的：用边界值（0 / -1 / 大值 / 不匹配的 count）触发候选路径，看是否 panic
- **panic 就是候选确认**，重启后记录

### 阶段 C：原语化
OOB write → 控制偏移与数据 → 破坏相邻对象 → r/w。
这一阶段需要：目标对象的堆布局、可控字段、稳定的 groom 手段。

## 5. 指挥纪律
1. **每条结论标三档**：【设备实测】/【镜像已证实】/【推断】
2. **假阳性必须手读**。本工程自动判据假阳性史累计 9+ 类
3. **「没找到」必须区分「审了没有」和「没审到」**
4. 公告的修复措辞是一手先验，优先于任何自行推断
5. 不许把 dChk=0 当「没修补」

## 6. 当前并行线
| 线 | 负责人 | 目标 |
|---|---|---|
| ANE / AVE | 子代理 B | 按 bounds checking 定位 7 个 CVE |
| Kernel UAF | 子代理 A | 桩调用差分找 6 条 CVE |
| AppleKeyStore | 子代理 C | 普查盲区，keybag 解析 |
| **动态调用器** | 新建 | 通用 selector 调用 + 边界值测试 |
