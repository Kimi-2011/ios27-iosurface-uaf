# GPU-PROBE — 逐个调用 `AGXAcceleratorG18P` 用户客户端 selector（真机 iPhone，iOS 27.0.1）

> 目标：`IOServiceOpen("AGXAcceleratorG18P", mach_task_self(), 1, &conn)` 拿到的 user client，
> 把 selector **0..167 全试一遍**，逐个记录返回码。
> 设备 `DEVICE-UDID`，跑前 `passcodeRequired: false`（已解锁亮屏），
> 全程不重启设备。
> 代码：`harness/gpuprobe/main.m` + `harness/gpuprobe/run.sh`（新建；`harness/israce/` 与既有 Payload 一行未动）。

---

## 0. 一句话结论

1. **外方法表实际只有 56 条：selector 0..55 存在，56..167 全部 `0xE00002C7 Unsupported`。**
   ⇒ `out/GPU-USERCLIENT.md` §7 那个「两张表 112+56 找不到引用」的疑点当场闭合：
   **56 条的 B 表（= A 表的前 56 条）是活的，112 条 A 表在索引 55 之后是死的。**
2. **14 个 selector 返回 `SUCCESS`**：`0,1,2,3,4,5,16,17,19,21,23,28,41,42`。
3. **3 个返回 `NotPrivileged`**：`32,33,34` —— 存在但被 entitlement 门挡住，是明确的「有权就能过」的目标。
4. **`sel = 55` 的内核 handler 永不返回**（`0xa0240cc`）：进程活着、心跳继续、调用不回来，靠看门狗退出。
   **这不是 panic。**
5. **零 panic**：`out/panics/*.ips` 5 → 5；设备端 `systemCrashLogs` 最新 panic-full 仍是 14:57:57。

---

## 1. 五态（build / sign / install / launch / 跑完）分开写

以全量那一轮（`run2`，15:40:38–15:43:17）为准：

| 态 | 时间 | 结果 | 证据 |
|---|---|---|---|
| **build** | 15:40:38 | OK | `size=89272 sha256=fc7bcb07…967b` |
| **sign** | 15:40:38 | OK | `Identifier=com.example.ios27poc` `TeamIdentifier=DFH8ZCU6D4` |
| **install** | 15:40:39 | OK | `installationURL=…/3621DB8C-…/UC.app/` |
| **launch** | 15:40:39 → 15:43:17 | `console rc=3`（**看门狗退出，不是崩溃**） | `!! watchdog 150s 到期（卡在 sel=55 的内核调用里），强制退出` |
| **跑完** | 15:43:18 | 取回全成功 | `ndjson copy rc=0 size=13982` / `log rc=0 size=13982` / `hb rc=0 size=24095` |

装前指纹（纪律 1）：`strings Payload/UC.app/UC | grep GPUPROBE-20261101-sel168-a71c4e` → **命中 = 1**，
同时确认 `diag1-portdiag`（israce）= 0、`SVCPROBE-…`（上一轮探针）= 0 ⇒ 装进去的确实是本轮新二进制。

`devicectl device copy from` 的 stderr 走独立变量单独打印（脚本里 `2>&1 >/dev/null` 只吞 stdout），
三份文件的 `rc` 与 `size` 都在上面，没有一处被 `2>/dev/null` 吞掉。

---

## 2. 契约数组是怎么填的（要求说明）

`out/gpu_selectors.txt` 共 112（A）+ 56（B）= 168 行，正好对齐 168 个 selector：

| selector 区间 | 来源 |
|---|---|
| `0 .. 111` | 表 **A** 的 idx `0 .. 111` |
| `112 .. 167` | 表 **B** 的 idx `0 .. 55`（B 索引与 A 重叠，**整体平移到 112 起**） |

- 用脚本从 txt 直接生成 `g_sIn[168] / g_stIn[168] / g_sOut[168] / g_stOut[168]`，外加
  `g_tabName[168] / g_tabIdx[168] / g_hdl[168]`，**硬编码**进 `main.m`（不是运行时读文件）。
- 生成后又把 `main.m` 里的数组反解出来跟 txt 逐项比对：**168 项 × 7 列，0 处不一致**。
- `0xFFFFFFFF`（wildcard）在数组里原样保留，**传给内核时按规则换成 0**
  （`pStIn = (dStIn==WILD) ? 0 : dStIn`，`pStOut` 同理）；`@pre` 行里 `dXxx` 是声明值、`pXxx` 是实际传的值，
  两者都落盘，方便核对。

第一遍传参恒等式：`inputCnt=dIn`、`inputStructCnt=dStIn`、`outputCnt=dOut`(容量，上限 32)、
`outputStructCnt=dStOut`（wildcard → 0，上限 4096）。标量个数最大 4、结构长度最大 536，都在 32/4096 缓冲内。

---

## 3. 主表：selector 0..55（存在的那 56 条）

| sel | 表[idx] | handler | 契约 sIn/stIn/sOut/stOut | 第一遍 kr | 第二遍 kr | 含义 |
|---|---|---|---|---|---|---|
| 0 | A[0] | `0xfffffe000a021ee8` | 0/0/0/64 | 0x0 | — | 进入 handler 并正常返回 |
| 1 | A[1] | `0xfffffe000a021ffc` | 0/0/0/64 | 0x0 | — | 进入 handler 并正常返回 |
| 2 | A[2] | `0xfffffe000a022030` | 0/0/0/536 | 0x0 | — | 进入 handler 并正常返回 |
| 3 | A[3] | `0xfffffe000a022100` | 0/0/0/8 | 0x0 | — | 进入 handler 并正常返回 |
| 4 | A[4] | `0xfffffe000a022134` | 0/0/0/32 | 0x0 | — | 进入 handler 并正常返回 |
| 5 | A[5] | `0xfffffe000a022210` | 0/0/0/16 | 0x0 | — | 进入 handler 并正常返回 |
| 6 | A[6] | `0xfffffe000a022274` | 0/wild/0/16 | 0xe00002c2 | 0xe00002c2 | 参数/尺寸不符，handler 侧拒绝 |
| 7 | A[7] | `0xfffffe000a022578` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 8 | A[8] | `0xfffffe000a02260c` | 0/wild/0/wild | 0xe00002c2 | 0xe00002c2 | 参数/尺寸不符，handler 侧拒绝 |
| 9 | A[9] | `0xfffffe000a022794` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 10 | A[10] | `0xfffffe000a0227a8` | 2/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 11 | A[11] | `0xfffffe000a0227c0` | 2/0/1/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 12 | A[12] | `0xfffffe000a0227e0` | 2/0/0/16 | 0xe00002bd | — | handler 内部资源不足 |
| 13 | A[13] | `0xfffffe000a022808` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 14 | A[14] | `0xfffffe000a02281c` | 2/0/0/16 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 15 | A[15] | `0xfffffe000a02283c` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 16 | A[16] | `0xfffffe000a022850` | 0/0/0/8 | 0x0 | — | 进入 handler 并正常返回 |
| 17 | A[17] | `0xfffffe000a022860` | 0/0/0/4 | 0x0 | — | 进入 handler 并正常返回 |
| 18 | A[18] | `0xfffffe000a022870` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 19 | A[19] | `0xfffffe000a022884` | 1/0/0/24 | 0x0 | — | 进入 handler 并正常返回 |
| 20 | A[20] | `0xfffffe000a02289c` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 21 | A[21] | `0xfffffe000a0228b0` | 0/0/0/48 | 0x0 | — | 进入 handler 并正常返回 |
| 22 | A[22] | `0xfffffe000a0228c0` | 0/0/0/wild | 0xe00002c7 | 0xe00002c2 | 该 selector 不存在（外方法表只有 0..55） |
| 23 | A[23] | `0xfffffe000a0228d0` | 0/0/1/0 | 0x0 | — | 进入 handler 并正常返回 |
| 24 | A[24] | `0xfffffe000a0228e0` | 2/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 25 | A[25] | `0xfffffe000a02299c` | 4/wild/1/0 | 0xe00002c2 | 0xe00002c2 | 参数/尺寸不符，handler 侧拒绝 |
| 26 | A[26] | `0xfffffe000a022c2c` | 1/12/1/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 27 | A[27] | `0xfffffe000a022cd4` | 1/4/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 28 | A[28] | `0xfffffe000a022d78` | 0/0/2/0 | 0x0 | — | 进入 handler 并正常返回 |
| 29 | A[29] | `0xfffffe000a022dac` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 30 | A[30] | `0xfffffe000a022de4` | 2/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 31 | A[31] | `0xfffffe000a022eb4` | 1/0/2/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 32 | A[32] | `0xfffffe000a022f8c` | 2/0/0/0 | 0xe00002c1 | — | handler 存在，被**权限/entitlement** 拦下 |
| 33 | A[33] | `0xfffffe000a022fc8` | 2/0/0/0 | 0xe00002c1 | — | handler 存在，被**权限/entitlement** 拦下 |
| 34 | A[34] | `0xfffffe000a023004` | 1/0/1/0 | 0xe00002c1 | — | handler 存在，被**权限/entitlement** 拦下 |
| 35 | A[35] | `0xfffffe000a02306c` | 2/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 36 | A[36] | `0xfffffe000a023084` | 3/0/1/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 37 | A[37] | `0xfffffe000a023120` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 38 | A[38] | `0xfffffe000a023134` | 0/24/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 39 | A[39] | `0xfffffe000a023144` | 0/24/1/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 40 | A[40] | `0xfffffe000a023194` | 1/0/2/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 41 | A[41] | `0xfffffe000a0232c8` | 1/0/0/0 | 0x0 | — | 进入 handler 并正常返回 |
| 42 | A[42] | `0xfffffe000a0232f4` | 2/0/2/0 | 0x0 | — | 进入 handler 并正常返回 |
| 43 | A[43] | `0xfffffe000a0234d8` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 44 | A[44] | `0xfffffe000a02355c` | 2/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 45 | A[45] | `0xfffffe000a0236ac` | 1/wild/0/0 | 0xe00002c2 | 0xe00002c2 | 参数/尺寸不符，handler 侧拒绝 |
| 46 | A[46] | `0xfffffe000a023918` | 1/0/2/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 47 | A[47] | `0xfffffe000a0239d4` | 2/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 48 | A[48] | `0xfffffe000a023a90` | 2/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 49 | A[49] | `0xfffffe000a023b4c` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 50 | A[50] | `0xfffffe000a023bf4` | 1/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 51 | A[51] | `0xfffffe000a023c98` | 3/0/0/0 | 0xe00002c2 | — | 参数/尺寸不符，handler 侧拒绝 |
| 52 | A[52] | `0xfffffe000a023d58` | 2/wild/0/0 | 0xe00002c2 | 0xe00002c2 | 参数/尺寸不符，handler 侧拒绝 |
| 53 | A[53] | `0xfffffe000a023ee8` | 2/wild/0/0 | 0xe00002c2 | 0xe00002c2 | 参数/尺寸不符，handler 侧拒绝 |
| 54 | A[54] | `0xfffffe000a024078` | 2/0/1/0 | 0xe00002e2 | — | 非标准码 0xe00002e2（IOGPU 私有，见 §6） |
| 55 | A[55] | `0xfffffe000a0240cc` | 0/0/0/0 | **挂起** | — | **内核 handler 永不返回（阻塞）** |

---

## 4. 主表：selector 56..167（全部不存在）

112 条**没有一条**能落到 handler：dispatcher 层面就返回 `0xE00002C7`。为完整性逐条列在下面（契约列是当时按 §2 的填法传的，因此这些行本身不具契约意义，只证明「该 selector 不存在」）。

| sel | 表[idx] | handler | 当时传的 sIn/stIn/sOut/stOut | 第一遍 kr | 第二遍 kr（若该 sel 属 wildcard） |
|---|---|---|---|---|---|
| 56 | A[56] | `0xfffffe000a021ee8` | 0/0/0/64 | 0xe00002c7 | — |
| 57 | A[57] | `0xfffffe000a021ffc` | 0/0/0/64 | 0xe00002c7 | — |
| 58 | A[58] | `0xfffffe000a022030` | 0/0/0/536 | 0xe00002c7 | — |
| 59 | A[59] | `0xfffffe000a022100` | 0/0/0/8 | 0xe00002c7 | — |
| 60 | A[60] | `0xfffffe000a022134` | 0/0/0/32 | 0xe00002c7 | — |
| 61 | A[61] | `0xfffffe000a022210` | 0/0/0/16 | 0xe00002c7 | — |
| 62 | A[62] | `0xfffffe000a022274` | 0/wild/0/16 | 0xe00002c7 | 0xe00002c7 |
| 63 | A[63] | `0xfffffe000a022578` | 1/0/0/0 | 0xe00002c7 | — |
| 64 | A[64] | `0xfffffe000a02260c` | 0/wild/0/wild | 0xe00002c7 | 0xe00002c7 |
| 65 | A[65] | `0xfffffe000a022794` | 1/0/0/0 | 0xe00002c7 | — |
| 66 | A[66] | `0xfffffe000a0227a8` | 2/0/0/0 | 0xe00002c7 | — |
| 67 | A[67] | `0xfffffe000a0227c0` | 2/0/1/0 | 0xe00002c7 | — |
| 68 | A[68] | `0xfffffe000a0227e0` | 2/0/0/16 | 0xe00002c7 | — |
| 69 | A[69] | `0xfffffe000a022808` | 1/0/0/0 | 0xe00002c7 | — |
| 70 | A[70] | `0xfffffe000a02281c` | 2/0/0/16 | 0xe00002c7 | — |
| 71 | A[71] | `0xfffffe000a02283c` | 1/0/0/0 | 0xe00002c7 | — |
| 72 | A[72] | `0xfffffe000a022850` | 0/0/0/8 | 0xe00002c7 | — |
| 73 | A[73] | `0xfffffe000a022860` | 0/0/0/4 | 0xe00002c7 | — |
| 74 | A[74] | `0xfffffe000a022870` | 1/0/0/0 | 0xe00002c7 | — |
| 75 | A[75] | `0xfffffe000a022884` | 1/0/0/24 | 0xe00002c7 | — |
| 76 | A[76] | `0xfffffe000a02289c` | 1/0/0/0 | 0xe00002c7 | — |
| 77 | A[77] | `0xfffffe000a0240d8` | 0/0/0/48 | 0xe00002c7 | — |
| 78 | A[78] | `0xfffffe000a0228c0` | 0/0/0/wild | 0xe00002c7 | 0xe00002c7 |
| 79 | A[79] | `0xfffffe000a0228d0` | 0/0/1/0 | 0xe00002c7 | — |
| 80 | A[80] | `0xfffffe000a0228e0` | 2/0/0/0 | 0xe00002c7 | — |
| 81 | A[81] | `0xfffffe000a02299c` | 4/wild/1/0 | 0xe00002c7 | 0xe00002c7 |
| 82 | A[82] | `0xfffffe000a022c2c` | 1/12/1/0 | 0xe00002c7 | — |
| 83 | A[83] | `0xfffffe000a0240d8` | 1/4/0/0 | 0xe00002c7 | — |
| 84 | A[84] | `0xfffffe000a0240d8` | 0/0/2/0 | 0xe00002c7 | — |
| 85 | A[85] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 86 | A[86] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 87 | A[87] | `0xfffffe000a0240d8` | 1/0/2/0 | 0xe00002c7 | — |
| 88 | A[88] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 89 | A[89] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 90 | A[90] | `0xfffffe000a0240d8` | 1/0/1/0 | 0xe00002c7 | — |
| 91 | A[91] | `0xfffffe000a02306c` | 2/0/0/0 | 0xe00002c7 | — |
| 92 | A[92] | `0xfffffe000a0240d8` | 3/0/1/0 | 0xe00002c7 | — |
| 93 | A[93] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 94 | A[94] | `0xfffffe000a0240d8` | 0/24/0/0 | 0xe00002c7 | — |
| 95 | A[95] | `0xfffffe000a0240d8` | 0/24/1/0 | 0xe00002c7 | — |
| 96 | A[96] | `0xfffffe000a0240d8` | 1/0/2/0 | 0xe00002c7 | — |
| 97 | A[97] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 98 | A[98] | `0xfffffe000a0240d8` | 2/0/2/0 | 0xe00002c7 | — |
| 99 | A[99] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 100 | A[100] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 101 | A[101] | `0xfffffe000a0240d8` | 1/wild/0/0 | 0xe00002c7 | 0xe00002c7 |
| 102 | A[102] | `0xfffffe000a0240d8` | 1/0/2/0 | 0xe00002c7 | — |
| 103 | A[103] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 104 | A[104] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 105 | A[105] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 106 | A[106] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 107 | A[107] | `0xfffffe000a0240d8` | 3/0/0/0 | 0xe00002c7 | — |
| 108 | A[108] | `0xfffffe000a0240d8` | 2/wild/0/0 | 0xe00002c7 | 0xe00002c7 |
| 109 | A[109] | `0xfffffe000a0240d8` | 2/wild/0/0 | 0xe00002c7 | 0xe00002c7 |
| 110 | A[110] | `0xfffffe000a0240d8` | 2/0/1/0 | 0xe00002c7 | — |
| 111 | A[111] | `0xfffffe000a0240cc` | 0/0/0/0 | 0xe00002c7 | — |
| 112 | B[0] | `0xfffffe000a021ee8` | 0/0/0/64 | 0xe00002c7 | — |
| 113 | B[1] | `0xfffffe000a021ffc` | 0/0/0/64 | 0xe00002c7 | — |
| 114 | B[2] | `0xfffffe000a022030` | 0/0/0/536 | 0xe00002c7 | — |
| 115 | B[3] | `0xfffffe000a022100` | 0/0/0/8 | 0xe00002c7 | — |
| 116 | B[4] | `0xfffffe000a022134` | 0/0/0/32 | 0xe00002c7 | — |
| 117 | B[5] | `0xfffffe000a022210` | 0/0/0/16 | 0xe00002c7 | — |
| 118 | B[6] | `0xfffffe000a022274` | 0/wild/0/16 | 0xe00002c7 | 0xe00002c7 |
| 119 | B[7] | `0xfffffe000a022578` | 1/0/0/0 | 0xe00002c7 | — |
| 120 | B[8] | `0xfffffe000a02260c` | 0/wild/0/wild | 0xe00002c7 | 0xe00002c7 |
| 121 | B[9] | `0xfffffe000a022794` | 1/0/0/0 | 0xe00002c7 | — |
| 122 | B[10] | `0xfffffe000a0227a8` | 2/0/0/0 | 0xe00002c7 | — |
| 123 | B[11] | `0xfffffe000a0227c0` | 2/0/1/0 | 0xe00002c7 | — |
| 124 | B[12] | `0xfffffe000a0227e0` | 2/0/0/16 | 0xe00002c7 | — |
| 125 | B[13] | `0xfffffe000a022808` | 1/0/0/0 | 0xe00002c7 | — |
| 126 | B[14] | `0xfffffe000a02281c` | 2/0/0/16 | 0xe00002c7 | — |
| 127 | B[15] | `0xfffffe000a02283c` | 1/0/0/0 | 0xe00002c7 | — |
| 128 | B[16] | `0xfffffe000a022850` | 0/0/0/8 | 0xe00002c7 | — |
| 129 | B[17] | `0xfffffe000a022860` | 0/0/0/4 | 0xe00002c7 | — |
| 130 | B[18] | `0xfffffe000a022870` | 1/0/0/0 | 0xe00002c7 | — |
| 131 | B[19] | `0xfffffe000a022884` | 1/0/0/24 | 0xe00002c7 | — |
| 132 | B[20] | `0xfffffe000a02289c` | 1/0/0/0 | 0xe00002c7 | — |
| 133 | B[21] | `0xfffffe000a0240d8` | 0/0/0/48 | 0xe00002c7 | — |
| 134 | B[22] | `0xfffffe000a0228c0` | 0/0/0/wild | 0xe00002c7 | 0xe00002c7 |
| 135 | B[23] | `0xfffffe000a0228d0` | 0/0/1/0 | 0xe00002c7 | — |
| 136 | B[24] | `0xfffffe000a0228e0` | 2/0/0/0 | 0xe00002c7 | — |
| 137 | B[25] | `0xfffffe000a02299c` | 4/wild/1/0 | 0xe00002c7 | 0xe00002c7 |
| 138 | B[26] | `0xfffffe000a022c2c` | 1/12/1/0 | 0xe00002c7 | — |
| 139 | B[27] | `0xfffffe000a0240d8` | 1/4/0/0 | 0xe00002c7 | — |
| 140 | B[28] | `0xfffffe000a0240d8` | 0/0/2/0 | 0xe00002c7 | — |
| 141 | B[29] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 142 | B[30] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 143 | B[31] | `0xfffffe000a0240d8` | 1/0/2/0 | 0xe00002c7 | — |
| 144 | B[32] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 145 | B[33] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 146 | B[34] | `0xfffffe000a0240d8` | 1/0/1/0 | 0xe00002c7 | — |
| 147 | B[35] | `0xfffffe000a02306c` | 2/0/0/0 | 0xe00002c7 | — |
| 148 | B[36] | `0xfffffe000a0240d8` | 3/0/1/0 | 0xe00002c7 | — |
| 149 | B[37] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 150 | B[38] | `0xfffffe000a0240d8` | 0/24/0/0 | 0xe00002c7 | — |
| 151 | B[39] | `0xfffffe000a0240d8` | 0/24/1/0 | 0xe00002c7 | — |
| 152 | B[40] | `0xfffffe000a0240d8` | 1/0/2/0 | 0xe00002c7 | — |
| 153 | B[41] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 154 | B[42] | `0xfffffe000a0240d8` | 2/0/2/0 | 0xe00002c7 | — |
| 155 | B[43] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 156 | B[44] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 157 | B[45] | `0xfffffe000a0240d8` | 1/wild/0/0 | 0xe00002c7 | 0xe00002c7 |
| 158 | B[46] | `0xfffffe000a0240d8` | 1/0/2/0 | 0xe00002c7 | — |
| 159 | B[47] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 160 | B[48] | `0xfffffe000a0240d8` | 2/0/0/0 | 0xe00002c7 | — |
| 161 | B[49] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 162 | B[50] | `0xfffffe000a0240d8` | 1/0/0/0 | 0xe00002c7 | — |
| 163 | B[51] | `0xfffffe000a0240d8` | 3/0/0/0 | 0xe00002c7 | — |
| 164 | B[52] | `0xfffffe000a0240d8` | 2/wild/0/0 | 0xe00002c7 | 0xe00002c7 |
| 165 | B[53] | `0xfffffe000a0240d8` | 2/wild/0/0 | 0xe00002c7 | 0xe00002c7 |
| 166 | B[54] | `0xfffffe000a0240d8` | 2/0/1/0 | 0xe00002c7 | — |
| 167 | B[55] | `0xfffffe000a0240cc` | 0/0/0/0 | 0xe00002c7 | — |

---

## 5. 哪些 selector 返回 `SUCCESS`（最重要）

**14 个**，且**全部落在 0..55 的真实范围内**：

| sel | handler | 契约 sIn/stIn/sOut/stOut | 返回时 oc / sc | 说明 |
|---|---|---|---|---|
| 0 | `0xa021ee8` | 0/0/0/**64** | 0 / 64 | 无入参，吐 64 字节 |
| 1 | `0xa021ffc` | 0/0/0/**64** | 0 / 64 | 无入参，吐 64 字节（与 0 相邻，像同一个结构的两半） |
| 2 | `0xa022030` | 0/0/0/**536** | 0 / 536 | 无入参，**吐 536 字节（全表最大输出）** |
| 3 | `0xa022100` | 0/0/0/8 | 0 / 8 | 无入参 |
| 4 | `0xa022134` | 0/0/0/32 | 0 / 32 | 无入参 |
| 5 | `0xa022210` | 0/0/0/16 | 0 / 16 | 无入参 |
| 16 | `0xa022850` | 0/0/0/8 | 0 / 8 | 无入参 |
| 17 | `0xa022860` | 0/0/0/4 | 0 / 4 | 无入参 |
| 19 | `0xa022884` | 1/0/0/24 | 0 / 24 | 1 个标量入，吐 24 字节 |
| 21 | `0xa0228b0` | 0/0/0/48 | 0 / 48 | 无入参，吐 48 字节 |
| 23 | `0xa0228d0` | 0/0/1/0 | **1** / 0 | 无入参，回 1 个标量 |
| 28 | `0xa022d78` | 0/0/2/0 | **2** / 0 | 无入参，回 2 个标量 |
| 41 | `0xa0232c8` | 1/0/0/0 | 0 / 0 | 1 个标量入，纯成功返回 |
| 42 | `0xa0232f4` | 2/0/2/0 | **2** / 0 | 2 进 2 出 |

**读法：**
- 前 10 个（有结构输出的 0/1/2/3/4/5/16/17/19/21）是**纯「零入参即可成功、并向调用方缓冲区拷数据」**的方法。
  它们**全部用全零参数就过了**，说明其内部没有依赖前置状态或对象 ID。
- 23/28/42 回填标量（`oc > 0`），说明**输出标量确实被写进来了**，读出来就是驱动侧的值。
- **本轮没有 dump 返回缓冲区的内容**（`@sel` 只记了 `kr/oc/sc`）。这是最直接的下一步（见 §9.1）——
  尤其 `sel 2` 的 536 字节与 `sel 0/1` 的 64 字节。

---

## 6. 错误码分组（全 168 条）

| 返回码 | 个数 | selector |
|---|---|---|
| `0x0` **SUCCESS** | **14** | 0,1,2,3,4,5,16,17,19,21,23,28,41,42 |
| `0xE00002C7` Unsupported | **113** | 56..167（112 条）+ **22** |
| `0xE00002C2` BadArgument | **35** | 6,7,8,9,10,11,13,14,15,18,20,24,25,26,27,29,30,31,35,36,37,38,39,40,43,44,45,46,47,48,49,50,51,52,53 |
| `0xE00002C1` NotPrivileged | **3** | **32, 33, 34** |
| `0xE00002BD` NoMemory | **1** | **12** |
| `0xE00002E2`（非标准） | **1** | **54** |
| 挂起（永不返回） | **1** | **55** |

### 6.1 `sel 22` 是唯一的「存在但报 Unsupported」

它的 handler `0xa0228c0` 在 0..55 范围内（dispatcher 不会拒它），契约是 `sOut=0 / stOut=wildcard`。
我们按规则传 `outputStructCnt=0`，**handler 自己**返回了 `kIOReturnUnsupported`。
⇒ 这是「handler 内部判定本次调用形态不支持」，不是「selector 不存在」。
（第二遍用 `soutCnt=1` 再打一次，仍是 `0xE00002C7` ⇒ 它对输出尺寸有要求，不是越界写点。）

### 6.2 `sel 8`（`0xa02260c`，输入输出双 wildcard）—— 真机把静态结论钉死了

| 遍 | 实际传 | 结果 |
|---|---|---|
| 第一遍 | `stIn=0, stOut=0` | `0xE00002C2 BadArgument` |
| 第二遍 | `sinCnt=1, soutCnt=1` | `0xE00002C2 BadArgument` |

`out/GPU-USERCLIENT.md` §6.2 的静态结论是「wildcard 只是 IOKit 这层不管，handler 自己在 `0xa0414b0` 里
先 `cmp x3,#0x58` 再校验输出长度」。**这次真机两次调用都停在 BadArgument，与该静态结论一致**：
0 字节和 1 字节都进不到 handler 主路径。⇒ **wildcard ≠ 不校验，8 个 wildcard handler 的展开方向可以降权。**

### 6.3 `sel 12` → `NoMemory` 说明它真的走到底了

`0xa0227e0`（契约 `2/0/0/16`）返回 `0xE00002BD`：参数已经通过、进到了分配/取对象那一步，是**深的**。
它比一堆 BadArgument 更值得看。

### 6.4 `sel 32/33/34` → `NotPrivileged`：唯一的三道 entitlement 门

| sel | handler | 契约 |
|---|---|---|
| 32 | `0xa022f8c` | 2/0/0/0 |
| 33 | `0xa022fc8` | 2/0/0/0 |
| 34 | `0xa023004` | 1/0/1/0 |

这三个**参数校验都过了**（因为返回码不是 BadArgument），卡在权限判断上。
它们三个在派发表里连续、handler 也连续（`0xa022f8c/0xa022fc8/0xa023004`）。
⇒ 值得直接反汇编这三处，看它查的是哪个 entitlement / 哪个 entitlement 位。

### 6.5 `sel 54` → `0xE00002E2`

`0xa024078`（契约 `2/0/1/0`）返回 `0xE00002E2`，这是个**不在标准 IOReturn 表里**的值
（标准表里 `0xe00002d7` 是 Timeout、`0xe00002d8` 是 Offline）。全表只有这一个非标准码，
按 IOGPU/IOSurface 的私有约定它通常表示「对象还没准备好 / 需要先初始化」。**单独记一笔，未定性。**

---

## 7. panic：**零**。但 `sel 55` 把内核调用挂死了

### 7.1 三次计数都是 5 → 5

```
跑前基线 = 5   跑后 = 5      （每一轮 run.sh 都数）
```

设备端 `systemCrashLogs` 域最新一份 `panic-full` 仍然是 **14:57:57**，本轮 15:33–15:45 的六次安装/启动
**没有新增任何 panic-full，也没有本 App 的崩溃报告**。

### 7.2 `sel 55` 不是 panic，是「调用不返回」

`sel 55` = `A[55]` = `B[55]`，handler `0xfffffe000a0240cc`，契约 `0/0/0/0`。

心跳线程每 200 ms 往 `gpuprobe.hb` 写一行 `{"k":"@hb","t":<ms>,"sel":<当前 sel>}`（每行 fsync）。
`run2` 的心跳尾部：

```json
{"k":"@hb","t":156574,"sel":55}
{"k":"@hb","t":156779,"sel":55}
{"k":"@hb","t":156985,"sel":55}
{"k":"@hb","t":157190,"sel":55}
{"k":"@hb","t":157396,"sel":55}
```

也就是说：**t=50 ms 进到 sel 55，之后 157 秒进程一直活着（心跳没断），主线程一直没从
`IOConnectCallMethod` 回来**，最后是 App 自己的 150 s 看门狗 `exit(3)`。
`launch console rc=3`、`ndjson` 里 sel 55 只有 `@pre` 没有 `@sel`，两处互相印证。

### 7.3 `sel 55` 隔离复现（全新连接、第一个调用就是它）

`run6`：`./run.sh 55 56 20 1`（全新 `IOServiceOpen`，`sel=55` 是**第一个**调用，看门狗 20 s）

```json
{"k":"@start","fp":"GPUPROBE-20261101-sel168-a71c4e","build":"Nov  1 2026 15:45:14","nsel":168}
{"k":"@match","svc":"AGXAcceleratorG18P","port":24883}
{"k":"@open","type":1,"kr":0,"krh":"0x0","conn":28675}
{"k":"@pass1","n":168,"from":55,"to":56}
{"k":"@pre","t":35,"sel":55,"tab":"A","idx":55,"dIn":0,"dStIn":0,"dOut":0,"dStOut":0,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240cc"}
```

心跳到 `t=21027 ms` 仍是 `sel=55`。
⇒ **与前置状态无关、与调用顺序无关**：只要调 `sel 55` 就挂。
三次独立复现（15:36:19 / 15:43:18 / 15:45:37 三轮）。

按纪律：**没有重跑同一个 selector 去打它**（第三次是隔离定性，不是重复轰炸），
结论记为「**sel=55 处挂起（内核 handler 不返回）**」，后续实验全部绕开它。

### 7.4 关于「第二遍」的一处偏离，单独声明

用户规则：**第二遍仅当第一遍完整跑完、无 panic 才做**。
实际情况：第一遍**无法**完整跑完 —— `sel 55` 永久阻塞（不是 panic），必须靠看门狗收尾。
但这个阻塞点**不是 wildcard selector**（`55` 的契约是 `0/0/0/0`），不影响第二遍的目标集合。

因此第二遍是在「第一遍除 `sel 55` 外 0..167 全覆盖」的前提下**单独跑**的（`mode=2`，只跑第二遍），
对 21 个 wildcard selector 逐个 `@pre2` + fflush + `sinCnt=1, soutCnt=1`：

- 范围内的 7 个（`6,8,22,25,45,52,53`）→ **全部 `0xE00002C2 BadArgument`**
- 范围外的 14 个（`62,64,78,81,101,108,109,118,120,134,137,157,164,165`）→ `0xE00002C7`（selector 不存在）
- **无 panic，无越界写迹象**

---

## 8. 与 `out/GPU-USERCLIENT.md` §7 的闭环

§7 留的问题是：112 + 56 两张表在静态上找不到任何引用，只能靠真机判定死活。

**判定结果：**

| 表 | 条目 | 真机判定 |
|---|---|---|
| **B**（`0x12f29f0`，56 条） | idx 0..55 | **活的** —— 0..54 返回真实码，55 是挂起 |
| **A**（`0x12f24b0`，112 条） | idx 0..55 | 与 B **逐条相同**，无法区分来源 |
| **A** | idx 56..111 | **死的** —— selector ≥56 在 dispatcher 层被 `0xE00002C7` 拒，**一次都没进到 handler** |

推论：
1. 这路 type-1 client 的外方法数 = **56**，与 B 表长度严丝合缝。
2. A 表尾段那批 handler —— 包括**出现 28 次的 `0xa0240d8`**（本项目此前反复怀疑的「stub」）——
   在本路 client 上**完全不可达**。`0xa0240d8` 可以降级。
3. 唯一还活着的 A 表尾段痕迹是 `0xa0240cc`：它**同时**是 `B[55]` 和 `A[111]`，而且**挂起**。
   ⇒ 它不是死条目，是 B 表最后一条真实方法。
4. A 表若真有其用，只能是**另一个 client type**（type 0 打不开、type 2/3 本轮没试）。这是 §9.5。

---

## 9. 下一步（按性价比排序）

1. **dump SUCCESS 那 10 个的输出缓冲区。** 本轮只记了 `kr/oc/sc`，没用上 `sout`。
   零入参就能吐 536/64/48 字节，是最便宜的信息面。改法：调用成功后把 `sout` 前 `sc` 字节 hexdump 进 ndjson。
2. **`sel 8` 按 `stIn=0x58` 打一次。** 静态那边写明 `cmp x3,#0x58`，我们只试过 0 和 1。
   88 字节零填充很可能直接把它送进 `0xa0414b0`，那才是真正值得看的路径。
3. **反汇编 `0xa022f8c / 0xa022fc8 / 0xa023004`**（`sel 32/33/34`）：这是唯一三个参数校验通过、
   只卡权限的 handler。看它查哪个 entitlement 位，比继续磨 wildcard 那条线更划算。
4. **`sel 12`（`0xa0227e0`，NoMemory）**：它已经走到底了，看它分配什么、要多少。
5. **`sel 55`（`0xa0240cc`）定性**：翻静态看是不是 workloop/semaphore 等待。
   若要再验，先调 `0/1` 建立状态再打 `55`（按纪律本轮没做）。
6. **若 A 表属于别的 client type**：`IOServiceOpen(type=2)` 再扫 56..111，一次性验证 A 表死活。

---

## 10. 原始 ndjson（逐字）

> `@pre` 行 = 调用**前**落盘（panic/挂起时最后一行就是罪魁），`@sel` = 返回后落盘。
> `@hb` = 200 ms 心跳（只在 `.hb` 文件里，用来证明「进程活着但调用没回来」）。
> 所有行都 `fflush + fsync` 过。`t` 是从进程启动算起的毫秒数。

### run2（第一遍 0..54，卡在 55）

文件：`harness/gpuprobe/results/gpuprobe-20261101-154318.ndjson`

```json
{"k":"@start","fp":"GPUPROBE-20261101-sel168-a71c4e","build":"Nov  1 2026 15:40:38","nsel":168}
{"k":"@match","svc":"AGXAcceleratorG18P","port":24579}
{"k":"@open","type":1,"kr":0,"krh":"0x0","conn":25859}
{"k":"@pass1","n":168,"from":0,"to":168}
{"k":"@pre","t":34,"sel":0,"tab":"A","idx":0,"dIn":0,"dStIn":0,"dOut":0,"dStOut":64,"pIn":0,"pStIn":0,"pOut":0,"pStOut":64,"hdl":"0xfffffe000a021ee8"}
{"k":"@sel","t":34,"sel":0,"kr":0,"krh":"0x0","oc":0,"sc":64,"name":"SUCCESS"}
{"k":"@pre","t":35,"sel":1,"tab":"A","idx":1,"dIn":0,"dStIn":0,"dOut":0,"dStOut":64,"pIn":0,"pStIn":0,"pOut":0,"pStOut":64,"hdl":"0xfffffe000a021ffc"}
{"k":"@sel","t":35,"sel":1,"kr":0,"krh":"0x0","oc":0,"sc":64,"name":"SUCCESS"}
{"k":"@pre","t":35,"sel":2,"tab":"A","idx":2,"dIn":0,"dStIn":0,"dOut":0,"dStOut":536,"pIn":0,"pStIn":0,"pOut":0,"pStOut":536,"hdl":"0xfffffe000a022030"}
{"k":"@sel","t":35,"sel":2,"kr":0,"krh":"0x0","oc":0,"sc":536,"name":"SUCCESS"}
{"k":"@pre","t":35,"sel":3,"tab":"A","idx":3,"dIn":0,"dStIn":0,"dOut":0,"dStOut":8,"pIn":0,"pStIn":0,"pOut":0,"pStOut":8,"hdl":"0xfffffe000a022100"}
{"k":"@sel","t":35,"sel":3,"kr":0,"krh":"0x0","oc":0,"sc":8,"name":"SUCCESS"}
{"k":"@pre","t":35,"sel":4,"tab":"A","idx":4,"dIn":0,"dStIn":0,"dOut":0,"dStOut":32,"pIn":0,"pStIn":0,"pOut":0,"pStOut":32,"hdl":"0xfffffe000a022134"}
{"k":"@sel","t":35,"sel":4,"kr":0,"krh":"0x0","oc":0,"sc":32,"name":"SUCCESS"}
{"k":"@pre","t":36,"sel":5,"tab":"A","idx":5,"dIn":0,"dStIn":0,"dOut":0,"dStOut":16,"pIn":0,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a022210"}
{"k":"@sel","t":36,"sel":5,"kr":0,"krh":"0x0","oc":0,"sc":16,"name":"SUCCESS"}
{"k":"@pre","t":36,"sel":6,"tab":"A","idx":6,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":16,"pIn":0,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a022274"}
{"k":"@sel","t":36,"sel":6,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":16,"name":"BadArgument"}
{"k":"@pre","t":37,"sel":7,"tab":"A","idx":7,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022578"}
{"k":"@sel","t":37,"sel":7,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":38,"sel":8,"tab":"A","idx":8,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":4294967295,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02260c"}
{"k":"@sel","t":39,"sel":8,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":39,"sel":9,"tab":"A","idx":9,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022794"}
{"k":"@sel","t":39,"sel":9,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":39,"sel":10,"tab":"A","idx":10,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0227a8"}
{"k":"@sel","t":39,"sel":10,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":39,"sel":11,"tab":"A","idx":11,"dIn":2,"dStIn":0,"dOut":1,"dStOut":0,"pIn":2,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0227c0"}
{"k":"@sel","t":39,"sel":11,"kr":-536870206,"krh":"0xe00002c2","oc":1,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":39,"sel":12,"tab":"A","idx":12,"dIn":2,"dStIn":0,"dOut":0,"dStOut":16,"pIn":2,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a0227e0"}
{"k":"@sel","t":39,"sel":12,"kr":-536870211,"krh":"0xe00002bd","oc":0,"sc":16,"name":"kIOReturnNoMemory"}
{"k":"@pre","t":40,"sel":13,"tab":"A","idx":13,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022808"}
{"k":"@sel","t":40,"sel":13,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":40,"sel":14,"tab":"A","idx":14,"dIn":2,"dStIn":0,"dOut":0,"dStOut":16,"pIn":2,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a02281c"}
{"k":"@sel","t":40,"sel":14,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":16,"name":"BadArgument"}
{"k":"@pre","t":40,"sel":15,"tab":"A","idx":15,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02283c"}
{"k":"@sel","t":40,"sel":15,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":40,"sel":16,"tab":"A","idx":16,"dIn":0,"dStIn":0,"dOut":0,"dStOut":8,"pIn":0,"pStIn":0,"pOut":0,"pStOut":8,"hdl":"0xfffffe000a022850"}
{"k":"@sel","t":40,"sel":16,"kr":0,"krh":"0x0","oc":0,"sc":8,"name":"SUCCESS"}
{"k":"@pre","t":40,"sel":17,"tab":"A","idx":17,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4,"pIn":0,"pStIn":0,"pOut":0,"pStOut":4,"hdl":"0xfffffe000a022860"}
{"k":"@sel","t":40,"sel":17,"kr":0,"krh":"0x0","oc":0,"sc":4,"name":"SUCCESS"}
{"k":"@pre","t":40,"sel":18,"tab":"A","idx":18,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022870"}
{"k":"@sel","t":40,"sel":18,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":40,"sel":19,"tab":"A","idx":19,"dIn":1,"dStIn":0,"dOut":0,"dStOut":24,"pIn":1,"pStIn":0,"pOut":0,"pStOut":24,"hdl":"0xfffffe000a022884"}
{"k":"@sel","t":40,"sel":19,"kr":0,"krh":"0x0","oc":0,"sc":24,"name":"SUCCESS"}
{"k":"@pre","t":40,"sel":20,"tab":"A","idx":20,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02289c"}
{"k":"@sel","t":40,"sel":20,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":41,"sel":21,"tab":"A","idx":21,"dIn":0,"dStIn":0,"dOut":0,"dStOut":48,"pIn":0,"pStIn":0,"pOut":0,"pStOut":48,"hdl":"0xfffffe000a0228b0"}
{"k":"@sel","t":41,"sel":21,"kr":0,"krh":"0x0","oc":0,"sc":48,"name":"SUCCESS"}
{"k":"@pre","t":41,"sel":22,"tab":"A","idx":22,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4294967295,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0228c0"}
{"k":"@sel","t":41,"sel":22,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":23,"tab":"A","idx":23,"dIn":0,"dStIn":0,"dOut":1,"dStOut":0,"pIn":0,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0228d0"}
{"k":"@sel","t":41,"sel":23,"kr":0,"krh":"0x0","oc":1,"sc":0,"name":"SUCCESS"}
{"k":"@pre","t":41,"sel":24,"tab":"A","idx":24,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0228e0"}
{"k":"@sel","t":42,"sel":24,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":43,"sel":25,"tab":"A","idx":25,"dIn":4,"dStIn":4294967295,"dOut":1,"dStOut":0,"pIn":4,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a02299c"}
{"k":"@sel","t":43,"sel":25,"kr":-536870206,"krh":"0xe00002c2","oc":1,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":43,"sel":26,"tab":"A","idx":26,"dIn":1,"dStIn":12,"dOut":1,"dStOut":0,"pIn":1,"pStIn":12,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a022c2c"}
{"k":"@sel","t":43,"sel":26,"kr":-536870206,"krh":"0xe00002c2","oc":1,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":43,"sel":27,"tab":"A","idx":27,"dIn":1,"dStIn":4,"dOut":0,"dStOut":0,"pIn":1,"pStIn":4,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022cd4"}
{"k":"@sel","t":43,"sel":27,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":43,"sel":28,"tab":"A","idx":28,"dIn":0,"dStIn":0,"dOut":2,"dStOut":0,"pIn":0,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a022d78"}
{"k":"@sel","t":45,"sel":28,"kr":0,"krh":"0x0","oc":2,"sc":0,"name":"SUCCESS"}
{"k":"@pre","t":45,"sel":29,"tab":"A","idx":29,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022dac"}
{"k":"@sel","t":45,"sel":29,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":45,"sel":30,"tab":"A","idx":30,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022de4"}
{"k":"@sel","t":46,"sel":30,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":46,"sel":31,"tab":"A","idx":31,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a022eb4"}
{"k":"@sel","t":46,"sel":31,"kr":-536870206,"krh":"0xe00002c2","oc":2,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":46,"sel":32,"tab":"A","idx":32,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022f8c"}
{"k":"@sel","t":46,"sel":32,"kr":-536870207,"krh":"0xe00002c1","oc":0,"sc":0,"name":"kIOReturnNotPrivileged"}
{"k":"@pre","t":46,"sel":33,"tab":"A","idx":33,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022fc8"}
{"k":"@sel","t":46,"sel":33,"kr":-536870207,"krh":"0xe00002c1","oc":0,"sc":0,"name":"kIOReturnNotPrivileged"}
{"k":"@pre","t":46,"sel":34,"tab":"A","idx":34,"dIn":1,"dStIn":0,"dOut":1,"dStOut":0,"pIn":1,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a023004"}
{"k":"@sel","t":46,"sel":34,"kr":-536870207,"krh":"0xe00002c1","oc":1,"sc":0,"name":"kIOReturnNotPrivileged"}
{"k":"@pre","t":46,"sel":35,"tab":"A","idx":35,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02306c"}
{"k":"@sel","t":46,"sel":35,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":46,"sel":36,"tab":"A","idx":36,"dIn":3,"dStIn":0,"dOut":1,"dStOut":0,"pIn":3,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a023084"}
{"k":"@sel","t":46,"sel":36,"kr":-536870206,"krh":"0xe00002c2","oc":1,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":46,"sel":37,"tab":"A","idx":37,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023120"}
{"k":"@sel","t":47,"sel":37,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":47,"sel":38,"tab":"A","idx":38,"dIn":0,"dStIn":24,"dOut":0,"dStOut":0,"pIn":0,"pStIn":24,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023134"}
{"k":"@sel","t":47,"sel":38,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":47,"sel":39,"tab":"A","idx":39,"dIn":0,"dStIn":24,"dOut":1,"dStOut":0,"pIn":0,"pStIn":24,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a023144"}
{"k":"@sel","t":47,"sel":39,"kr":-536870206,"krh":"0xe00002c2","oc":1,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":47,"sel":40,"tab":"A","idx":40,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a023194"}
{"k":"@sel","t":47,"sel":40,"kr":-536870206,"krh":"0xe00002c2","oc":2,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":47,"sel":41,"tab":"A","idx":41,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0232c8"}
{"k":"@sel","t":47,"sel":41,"kr":0,"krh":"0x0","oc":0,"sc":0,"name":"SUCCESS"}
{"k":"@pre","t":47,"sel":42,"tab":"A","idx":42,"dIn":2,"dStIn":0,"dOut":2,"dStOut":0,"pIn":2,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0232f4"}
{"k":"@sel","t":47,"sel":42,"kr":0,"krh":"0x0","oc":2,"sc":0,"name":"SUCCESS"}
{"k":"@pre","t":47,"sel":43,"tab":"A","idx":43,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0234d8"}
{"k":"@sel","t":47,"sel":43,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":48,"sel":44,"tab":"A","idx":44,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02355c"}
{"k":"@sel","t":48,"sel":44,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":48,"sel":45,"tab":"A","idx":45,"dIn":1,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0236ac"}
{"k":"@sel","t":48,"sel":45,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":48,"sel":46,"tab":"A","idx":46,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a023918"}
{"k":"@sel","t":48,"sel":46,"kr":-536870206,"krh":"0xe00002c2","oc":2,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":48,"sel":47,"tab":"A","idx":47,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0239d4"}
{"k":"@sel","t":48,"sel":47,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":48,"sel":48,"tab":"A","idx":48,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023a90"}
{"k":"@sel","t":48,"sel":48,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":49,"sel":49,"tab":"A","idx":49,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023b4c"}
{"k":"@sel","t":49,"sel":49,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":49,"sel":50,"tab":"A","idx":50,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023bf4"}
{"k":"@sel","t":49,"sel":50,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":49,"sel":51,"tab":"A","idx":51,"dIn":3,"dStIn":0,"dOut":0,"dStOut":0,"pIn":3,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023c98"}
{"k":"@sel","t":49,"sel":51,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":49,"sel":52,"tab":"A","idx":52,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023d58"}
{"k":"@sel","t":49,"sel":52,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":50,"sel":53,"tab":"A","idx":53,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a023ee8"}
{"k":"@sel","t":50,"sel":53,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":0,"name":"BadArgument"}
{"k":"@pre","t":50,"sel":54,"tab":"A","idx":54,"dIn":2,"dStIn":0,"dOut":1,"dStOut":0,"pIn":2,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a024078"}
{"k":"@sel","t":50,"sel":54,"kr":-536870174,"krh":"0xe00002e2","oc":1,"sc":0,"name":"OTHER"}
{"k":"@pre","t":50,"sel":55,"tab":"A","idx":55,"dIn":0,"dStIn":0,"dOut":0,"dStOut":0,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240cc"}
```

### run3（第一遍 56..110）

文件：`harness/gpuprobe/results/gpuprobe-20261101-154411.ndjson`

```json
{"k":"@start","fp":"GPUPROBE-20261101-sel168-a71c4e","build":"Nov  1 2026 15:44:08","nsel":168}
{"k":"@match","svc":"AGXAcceleratorG18P","port":29955}
{"k":"@open","type":1,"kr":0,"krh":"0x0","conn":29699}
{"k":"@pass1","n":168,"from":56,"to":111}
{"k":"@pre","t":26,"sel":56,"tab":"A","idx":56,"dIn":0,"dStIn":0,"dOut":0,"dStOut":64,"pIn":0,"pStIn":0,"pOut":0,"pStOut":64,"hdl":"0xfffffe000a021ee8"}
{"k":"@sel","t":26,"sel":56,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":64,"name":"Unsupported"}
{"k":"@pre","t":26,"sel":57,"tab":"A","idx":57,"dIn":0,"dStIn":0,"dOut":0,"dStOut":64,"pIn":0,"pStIn":0,"pOut":0,"pStOut":64,"hdl":"0xfffffe000a021ffc"}
{"k":"@sel","t":26,"sel":57,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":64,"name":"Unsupported"}
{"k":"@pre","t":26,"sel":58,"tab":"A","idx":58,"dIn":0,"dStIn":0,"dOut":0,"dStOut":536,"pIn":0,"pStIn":0,"pOut":0,"pStOut":536,"hdl":"0xfffffe000a022030"}
{"k":"@sel","t":27,"sel":58,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":536,"name":"Unsupported"}
{"k":"@pre","t":29,"sel":59,"tab":"A","idx":59,"dIn":0,"dStIn":0,"dOut":0,"dStOut":8,"pIn":0,"pStIn":0,"pOut":0,"pStOut":8,"hdl":"0xfffffe000a022100"}
{"k":"@sel","t":30,"sel":59,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":8,"name":"Unsupported"}
{"k":"@pre","t":30,"sel":60,"tab":"A","idx":60,"dIn":0,"dStIn":0,"dOut":0,"dStOut":32,"pIn":0,"pStIn":0,"pOut":0,"pStOut":32,"hdl":"0xfffffe000a022134"}
{"k":"@sel","t":30,"sel":60,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":32,"name":"Unsupported"}
{"k":"@pre","t":30,"sel":61,"tab":"A","idx":61,"dIn":0,"dStIn":0,"dOut":0,"dStOut":16,"pIn":0,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a022210"}
{"k":"@sel","t":30,"sel":61,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":30,"sel":62,"tab":"A","idx":62,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":16,"pIn":0,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a022274"}
{"k":"@sel","t":30,"sel":62,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":31,"sel":63,"tab":"A","idx":63,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022578"}
{"k":"@sel","t":31,"sel":63,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":31,"sel":64,"tab":"A","idx":64,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":4294967295,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02260c"}
{"k":"@sel","t":31,"sel":64,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":32,"sel":65,"tab":"A","idx":65,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022794"}
{"k":"@sel","t":33,"sel":65,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":33,"sel":66,"tab":"A","idx":66,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0227a8"}
{"k":"@sel","t":33,"sel":66,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":67,"tab":"A","idx":67,"dIn":2,"dStIn":0,"dOut":1,"dStOut":0,"pIn":2,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0227c0"}
{"k":"@sel","t":34,"sel":67,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":68,"tab":"A","idx":68,"dIn":2,"dStIn":0,"dOut":0,"dStOut":16,"pIn":2,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a0227e0"}
{"k":"@sel","t":34,"sel":68,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":69,"tab":"A","idx":69,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022808"}
{"k":"@sel","t":34,"sel":69,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":70,"tab":"A","idx":70,"dIn":2,"dStIn":0,"dOut":0,"dStOut":16,"pIn":2,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a02281c"}
{"k":"@sel","t":34,"sel":70,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":71,"tab":"A","idx":71,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02283c"}
{"k":"@sel","t":34,"sel":71,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":72,"tab":"A","idx":72,"dIn":0,"dStIn":0,"dOut":0,"dStOut":8,"pIn":0,"pStIn":0,"pOut":0,"pStOut":8,"hdl":"0xfffffe000a022850"}
{"k":"@sel","t":37,"sel":72,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":8,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":73,"tab":"A","idx":73,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4,"pIn":0,"pStIn":0,"pOut":0,"pStOut":4,"hdl":"0xfffffe000a022860"}
{"k":"@sel","t":37,"sel":73,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":4,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":74,"tab":"A","idx":74,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022870"}
{"k":"@sel","t":37,"sel":74,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":75,"tab":"A","idx":75,"dIn":1,"dStIn":0,"dOut":0,"dStOut":24,"pIn":1,"pStIn":0,"pOut":0,"pStOut":24,"hdl":"0xfffffe000a022884"}
{"k":"@sel","t":38,"sel":75,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":24,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":76,"tab":"A","idx":76,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02289c"}
{"k":"@sel","t":38,"sel":76,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":77,"tab":"A","idx":77,"dIn":0,"dStIn":0,"dOut":0,"dStOut":48,"pIn":0,"pStIn":0,"pOut":0,"pStOut":48,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":38,"sel":77,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":48,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":78,"tab":"A","idx":78,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4294967295,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0228c0"}
{"k":"@sel","t":38,"sel":78,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":79,"tab":"A","idx":79,"dIn":0,"dStIn":0,"dOut":1,"dStOut":0,"pIn":0,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0228d0"}
{"k":"@sel","t":38,"sel":79,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":80,"tab":"A","idx":80,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0228e0"}
{"k":"@sel","t":38,"sel":80,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":81,"tab":"A","idx":81,"dIn":4,"dStIn":4294967295,"dOut":1,"dStOut":0,"pIn":4,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a02299c"}
{"k":"@sel","t":38,"sel":81,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":82,"tab":"A","idx":82,"dIn":1,"dStIn":12,"dOut":1,"dStOut":0,"pIn":1,"pStIn":12,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a022c2c"}
{"k":"@sel","t":39,"sel":82,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":83,"tab":"A","idx":83,"dIn":1,"dStIn":4,"dOut":0,"dStOut":0,"pIn":1,"pStIn":4,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":83,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":84,"tab":"A","idx":84,"dIn":0,"dStIn":0,"dOut":2,"dStOut":0,"pIn":0,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":84,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":85,"tab":"A","idx":85,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":85,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":86,"tab":"A","idx":86,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":86,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":87,"tab":"A","idx":87,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":87,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":88,"tab":"A","idx":88,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":88,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":40,"sel":89,"tab":"A","idx":89,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":40,"sel":89,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":40,"sel":90,"tab":"A","idx":90,"dIn":1,"dStIn":0,"dOut":1,"dStOut":0,"pIn":1,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":40,"sel":90,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":40,"sel":91,"tab":"A","idx":91,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02306c"}
{"k":"@sel","t":40,"sel":91,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":40,"sel":92,"tab":"A","idx":92,"dIn":3,"dStIn":0,"dOut":1,"dStOut":0,"pIn":3,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":40,"sel":92,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":40,"sel":93,"tab":"A","idx":93,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":40,"sel":93,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":40,"sel":94,"tab":"A","idx":94,"dIn":0,"dStIn":24,"dOut":0,"dStOut":0,"pIn":0,"pStIn":24,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":94,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":95,"tab":"A","idx":95,"dIn":0,"dStIn":24,"dOut":1,"dStOut":0,"pIn":0,"pStIn":24,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":95,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":96,"tab":"A","idx":96,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":96,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":97,"tab":"A","idx":97,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":97,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":98,"tab":"A","idx":98,"dIn":2,"dStIn":0,"dOut":2,"dStOut":0,"pIn":2,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":98,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":99,"tab":"A","idx":99,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":99,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":100,"tab":"A","idx":100,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":42,"sel":100,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":42,"sel":101,"tab":"A","idx":101,"dIn":1,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":42,"sel":101,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":42,"sel":102,"tab":"A","idx":102,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":42,"sel":102,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":42,"sel":103,"tab":"A","idx":103,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":42,"sel":103,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":43,"sel":104,"tab":"A","idx":104,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":43,"sel":104,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":43,"sel":105,"tab":"A","idx":105,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":43,"sel":105,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":43,"sel":106,"tab":"A","idx":106,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":43,"sel":106,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":43,"sel":107,"tab":"A","idx":107,"dIn":3,"dStIn":0,"dOut":0,"dStOut":0,"pIn":3,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":43,"sel":107,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":43,"sel":108,"tab":"A","idx":108,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":43,"sel":108,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":43,"sel":109,"tab":"A","idx":109,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":43,"sel":109,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":44,"sel":110,"tab":"A","idx":110,"dIn":2,"dStIn":0,"dOut":1,"dStOut":0,"pIn":2,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":44,"sel":110,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pass1done","from":56,"to":111}
{"k":"@done","fp":"GPUPROBE-20261101-sel168-a71c4e"}
```

### run4（第一遍 111..167）

文件：`harness/gpuprobe/results/gpuprobe-20261101-154430.ndjson`

```json
{"k":"@start","fp":"GPUPROBE-20261101-sel168-a71c4e","build":"Nov  1 2026 15:44:28","nsel":168}
{"k":"@match","svc":"AGXAcceleratorG18P","port":23311}
{"k":"@open","type":1,"kr":0,"krh":"0x0","conn":28419}
{"k":"@pass1","n":168,"from":111,"to":168}
{"k":"@pre","t":27,"sel":111,"tab":"A","idx":111,"dIn":0,"dStIn":0,"dOut":0,"dStOut":0,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240cc"}
{"k":"@sel","t":27,"sel":111,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":27,"sel":112,"tab":"B","idx":0,"dIn":0,"dStIn":0,"dOut":0,"dStOut":64,"pIn":0,"pStIn":0,"pOut":0,"pStOut":64,"hdl":"0xfffffe000a021ee8"}
{"k":"@sel","t":27,"sel":112,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":64,"name":"Unsupported"}
{"k":"@pre","t":27,"sel":113,"tab":"B","idx":1,"dIn":0,"dStIn":0,"dOut":0,"dStOut":64,"pIn":0,"pStIn":0,"pOut":0,"pStOut":64,"hdl":"0xfffffe000a021ffc"}
{"k":"@sel","t":27,"sel":113,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":64,"name":"Unsupported"}
{"k":"@pre","t":27,"sel":114,"tab":"B","idx":2,"dIn":0,"dStIn":0,"dOut":0,"dStOut":536,"pIn":0,"pStIn":0,"pOut":0,"pStOut":536,"hdl":"0xfffffe000a022030"}
{"k":"@sel","t":28,"sel":114,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":536,"name":"Unsupported"}
{"k":"@pre","t":28,"sel":115,"tab":"B","idx":3,"dIn":0,"dStIn":0,"dOut":0,"dStOut":8,"pIn":0,"pStIn":0,"pOut":0,"pStOut":8,"hdl":"0xfffffe000a022100"}
{"k":"@sel","t":28,"sel":115,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":8,"name":"Unsupported"}
{"k":"@pre","t":28,"sel":116,"tab":"B","idx":4,"dIn":0,"dStIn":0,"dOut":0,"dStOut":32,"pIn":0,"pStIn":0,"pOut":0,"pStOut":32,"hdl":"0xfffffe000a022134"}
{"k":"@sel","t":28,"sel":116,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":32,"name":"Unsupported"}
{"k":"@pre","t":28,"sel":117,"tab":"B","idx":5,"dIn":0,"dStIn":0,"dOut":0,"dStOut":16,"pIn":0,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a022210"}
{"k":"@sel","t":28,"sel":117,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":28,"sel":118,"tab":"B","idx":6,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":16,"pIn":0,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a022274"}
{"k":"@sel","t":28,"sel":118,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":29,"sel":119,"tab":"B","idx":7,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022578"}
{"k":"@sel","t":29,"sel":119,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":30,"sel":120,"tab":"B","idx":8,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":4294967295,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02260c"}
{"k":"@sel","t":30,"sel":120,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":30,"sel":121,"tab":"B","idx":9,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022794"}
{"k":"@sel","t":30,"sel":121,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":30,"sel":122,"tab":"B","idx":10,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0227a8"}
{"k":"@sel","t":30,"sel":122,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":30,"sel":123,"tab":"B","idx":11,"dIn":2,"dStIn":0,"dOut":1,"dStOut":0,"pIn":2,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0227c0"}
{"k":"@sel","t":31,"sel":123,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":32,"sel":124,"tab":"B","idx":12,"dIn":2,"dStIn":0,"dOut":0,"dStOut":16,"pIn":2,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a0227e0"}
{"k":"@sel","t":32,"sel":124,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":32,"sel":125,"tab":"B","idx":13,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022808"}
{"k":"@sel","t":33,"sel":125,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":33,"sel":126,"tab":"B","idx":14,"dIn":2,"dStIn":0,"dOut":0,"dStOut":16,"pIn":2,"pStIn":0,"pOut":0,"pStOut":16,"hdl":"0xfffffe000a02281c"}
{"k":"@sel","t":34,"sel":126,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":16,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":127,"tab":"B","idx":15,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02283c"}
{"k":"@sel","t":34,"sel":127,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":128,"tab":"B","idx":16,"dIn":0,"dStIn":0,"dOut":0,"dStOut":8,"pIn":0,"pStIn":0,"pOut":0,"pStOut":8,"hdl":"0xfffffe000a022850"}
{"k":"@sel","t":34,"sel":128,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":8,"name":"Unsupported"}
{"k":"@pre","t":34,"sel":129,"tab":"B","idx":17,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4,"pIn":0,"pStIn":0,"pOut":0,"pStOut":4,"hdl":"0xfffffe000a022860"}
{"k":"@sel","t":34,"sel":129,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":4,"name":"Unsupported"}
{"k":"@pre","t":35,"sel":130,"tab":"B","idx":18,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a022870"}
{"k":"@sel","t":35,"sel":130,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":35,"sel":131,"tab":"B","idx":19,"dIn":1,"dStIn":0,"dOut":0,"dStOut":24,"pIn":1,"pStIn":0,"pOut":0,"pStOut":24,"hdl":"0xfffffe000a022884"}
{"k":"@sel","t":36,"sel":131,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":24,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":132,"tab":"B","idx":20,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02289c"}
{"k":"@sel","t":36,"sel":132,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":133,"tab":"B","idx":21,"dIn":0,"dStIn":0,"dOut":0,"dStOut":48,"pIn":0,"pStIn":0,"pOut":0,"pStOut":48,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":36,"sel":133,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":48,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":134,"tab":"B","idx":22,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4294967295,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0228c0"}
{"k":"@sel","t":36,"sel":134,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":135,"tab":"B","idx":23,"dIn":0,"dStIn":0,"dOut":1,"dStOut":0,"pIn":0,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0228d0"}
{"k":"@sel","t":36,"sel":135,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":136,"tab":"B","idx":24,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0228e0"}
{"k":"@sel","t":36,"sel":136,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":137,"tab":"B","idx":25,"dIn":4,"dStIn":4294967295,"dOut":1,"dStOut":0,"pIn":4,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a02299c"}
{"k":"@sel","t":36,"sel":137,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":138,"tab":"B","idx":26,"dIn":1,"dStIn":12,"dOut":1,"dStOut":0,"pIn":1,"pStIn":12,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a022c2c"}
{"k":"@sel","t":36,"sel":138,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":139,"tab":"B","idx":27,"dIn":1,"dStIn":4,"dOut":0,"dStOut":0,"pIn":1,"pStIn":4,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":36,"sel":139,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":140,"tab":"B","idx":28,"dIn":0,"dStIn":0,"dOut":2,"dStOut":0,"pIn":0,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":36,"sel":140,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":36,"sel":141,"tab":"B","idx":29,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":141,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":142,"tab":"B","idx":30,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":142,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":143,"tab":"B","idx":31,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":143,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":144,"tab":"B","idx":32,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":144,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":145,"tab":"B","idx":33,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":145,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":146,"tab":"B","idx":34,"dIn":1,"dStIn":0,"dOut":1,"dStOut":0,"pIn":1,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":146,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":147,"tab":"B","idx":35,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a02306c"}
{"k":"@sel","t":37,"sel":147,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":148,"tab":"B","idx":36,"dIn":3,"dStIn":0,"dOut":1,"dStOut":0,"pIn":3,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":148,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":37,"sel":149,"tab":"B","idx":37,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":37,"sel":149,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":150,"tab":"B","idx":38,"dIn":0,"dStIn":24,"dOut":0,"dStOut":0,"pIn":0,"pStIn":24,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":38,"sel":150,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":151,"tab":"B","idx":39,"dIn":0,"dStIn":24,"dOut":1,"dStOut":0,"pIn":0,"pStIn":24,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":38,"sel":151,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":152,"tab":"B","idx":40,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":38,"sel":152,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":153,"tab":"B","idx":41,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":38,"sel":153,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":154,"tab":"B","idx":42,"dIn":2,"dStIn":0,"dOut":2,"dStOut":0,"pIn":2,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":38,"sel":154,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":38,"sel":155,"tab":"B","idx":43,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":38,"sel":155,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":156,"tab":"B","idx":44,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":156,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":157,"tab":"B","idx":45,"dIn":1,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":39,"sel":157,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":39,"sel":158,"tab":"B","idx":46,"dIn":1,"dStIn":0,"dOut":2,"dStOut":0,"pIn":1,"pStIn":0,"pOut":2,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":40,"sel":158,"kr":-536870201,"krh":"0xe00002c7","oc":2,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":40,"sel":159,"tab":"B","idx":47,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":40,"sel":159,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":160,"tab":"B","idx":48,"dIn":2,"dStIn":0,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":160,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":161,"tab":"B","idx":49,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":161,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":162,"tab":"B","idx":50,"dIn":1,"dStIn":0,"dOut":0,"dStOut":0,"pIn":1,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":162,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":163,"tab":"B","idx":51,"dIn":3,"dStIn":0,"dOut":0,"dStOut":0,"pIn":3,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":163,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":164,"tab":"B","idx":52,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":41,"sel":164,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":41,"sel":165,"tab":"B","idx":53,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":42,"sel":165,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":42,"sel":166,"tab":"B","idx":54,"dIn":2,"dStIn":0,"dOut":1,"dStOut":0,"pIn":2,"pStIn":0,"pOut":1,"pStOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel","t":42,"sel":166,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":0,"name":"Unsupported"}
{"k":"@pre","t":42,"sel":167,"tab":"B","idx":55,"dIn":0,"dStIn":0,"dOut":0,"dStOut":0,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240cc"}
{"k":"@sel","t":42,"sel":167,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":0,"name":"Unsupported"}
{"k":"@pass1done","from":111,"to":168}
{"k":"@done","fp":"GPUPROBE-20261101-sel168-a71c4e"}
```

### run5（第二遍：wildcard，sinCnt=1 soutCnt=1）

文件：`harness/gpuprobe/results/gpuprobe-20261101-154450.ndjson`

```json
{"k":"@start","fp":"GPUPROBE-20261101-sel168-a71c4e","build":"Nov  1 2026 15:44:48","nsel":168}
{"k":"@match","svc":"AGXAcceleratorG18P","port":23827}
{"k":"@open","type":1,"kr":0,"krh":"0x0","conn":27411}
{"k":"@pass2","note":"wildcard only, sinCnt=1 soutCnt=1"}
{"k":"@pre2","t":28,"sel":6,"tab":"A","idx":6,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":16,"pIn":0,"pOut":0,"hdl":"0xfffffe000a022274"}
{"k":"@sel2","t":28,"sel":6,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":1,"name":"BadArgument"}
{"k":"@pre2","t":28,"sel":8,"tab":"A","idx":8,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":4294967295,"pIn":0,"pOut":0,"hdl":"0xfffffe000a02260c"}
{"k":"@sel2","t":28,"sel":8,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":1,"name":"BadArgument"}
{"k":"@pre2","t":28,"sel":22,"tab":"A","idx":22,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4294967295,"pIn":0,"pOut":0,"hdl":"0xfffffe000a0228c0"}
{"k":"@sel2","t":28,"sel":22,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":1,"name":"BadArgument"}
{"k":"@pre2","t":29,"sel":25,"tab":"A","idx":25,"dIn":4,"dStIn":4294967295,"dOut":1,"dStOut":0,"pIn":4,"pOut":1,"hdl":"0xfffffe000a02299c"}
{"k":"@sel2","t":29,"sel":25,"kr":-536870206,"krh":"0xe00002c2","oc":1,"sc":1,"name":"BadArgument"}
{"k":"@pre2","t":31,"sel":45,"tab":"A","idx":45,"dIn":1,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":1,"pOut":0,"hdl":"0xfffffe000a0236ac"}
{"k":"@sel2","t":32,"sel":45,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":1,"name":"BadArgument"}
{"k":"@pre2","t":35,"sel":52,"tab":"A","idx":52,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pOut":0,"hdl":"0xfffffe000a023d58"}
{"k":"@sel2","t":35,"sel":52,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":1,"name":"BadArgument"}
{"k":"@pre2","t":35,"sel":53,"tab":"A","idx":53,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pOut":0,"hdl":"0xfffffe000a023ee8"}
{"k":"@sel2","t":35,"sel":53,"kr":-536870206,"krh":"0xe00002c2","oc":0,"sc":1,"name":"BadArgument"}
{"k":"@pre2","t":35,"sel":62,"tab":"A","idx":62,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":16,"pIn":0,"pOut":0,"hdl":"0xfffffe000a022274"}
{"k":"@sel2","t":35,"sel":62,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":35,"sel":64,"tab":"A","idx":64,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":4294967295,"pIn":0,"pOut":0,"hdl":"0xfffffe000a02260c"}
{"k":"@sel2","t":35,"sel":64,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":35,"sel":78,"tab":"A","idx":78,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4294967295,"pIn":0,"pOut":0,"hdl":"0xfffffe000a0228c0"}
{"k":"@sel2","t":35,"sel":78,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":35,"sel":81,"tab":"A","idx":81,"dIn":4,"dStIn":4294967295,"dOut":1,"dStOut":0,"pIn":4,"pOut":1,"hdl":"0xfffffe000a02299c"}
{"k":"@sel2","t":35,"sel":81,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":35,"sel":101,"tab":"A","idx":101,"dIn":1,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":1,"pOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel2","t":36,"sel":101,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":108,"tab":"A","idx":108,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel2","t":36,"sel":108,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":109,"tab":"A","idx":109,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel2","t":36,"sel":109,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":118,"tab":"B","idx":6,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":16,"pIn":0,"pOut":0,"hdl":"0xfffffe000a022274"}
{"k":"@sel2","t":36,"sel":118,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":120,"tab":"B","idx":8,"dIn":0,"dStIn":4294967295,"dOut":0,"dStOut":4294967295,"pIn":0,"pOut":0,"hdl":"0xfffffe000a02260c"}
{"k":"@sel2","t":36,"sel":120,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":134,"tab":"B","idx":22,"dIn":0,"dStIn":0,"dOut":0,"dStOut":4294967295,"pIn":0,"pOut":0,"hdl":"0xfffffe000a0228c0"}
{"k":"@sel2","t":36,"sel":134,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":137,"tab":"B","idx":25,"dIn":4,"dStIn":4294967295,"dOut":1,"dStOut":0,"pIn":4,"pOut":1,"hdl":"0xfffffe000a02299c"}
{"k":"@sel2","t":36,"sel":137,"kr":-536870201,"krh":"0xe00002c7","oc":1,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":157,"tab":"B","idx":45,"dIn":1,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":1,"pOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel2","t":36,"sel":157,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":36,"sel":164,"tab":"B","idx":52,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel2","t":37,"sel":164,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pre2","t":37,"sel":165,"tab":"B","idx":53,"dIn":2,"dStIn":4294967295,"dOut":0,"dStOut":0,"pIn":2,"pOut":0,"hdl":"0xfffffe000a0240d8"}
{"k":"@sel2","t":37,"sel":165,"kr":-536870201,"krh":"0xe00002c7","oc":0,"sc":1,"name":"Unsupported"}
{"k":"@pass2done"}
{"k":"@done","fp":"GPUPROBE-20261101-sel168-a71c4e"}
```

### run6（sel 55 单点隔离，全新连接首个调用）

文件：`harness/gpuprobe/results/gpuprobe-20261101-154537.ndjson`

```json
{"k":"@start","fp":"GPUPROBE-20261101-sel168-a71c4e","build":"Nov  1 2026 15:45:14","nsel":168}
{"k":"@match","svc":"AGXAcceleratorG18P","port":24883}
{"k":"@open","type":1,"kr":0,"krh":"0x0","conn":28675}
{"k":"@pass1","n":168,"from":55,"to":56}
{"k":"@pre","t":35,"sel":55,"tab":"A","idx":55,"dIn":0,"dStIn":0,"dOut":0,"dStOut":0,"pIn":0,"pStIn":0,"pOut":0,"pStOut":0,"hdl":"0xfffffe000a0240cc"}
```

---

## 11. 产物与边界

| 东西 | 位置 |
|---|---|
| 探针源码 | `harness/gpuprobe/main.m`（含硬编码的 4 张契约表 + 表名/索引/handler 数组） |
| 构建/部署脚本 | `harness/gpuprobe/run.sh`（五态分开、指纹校验、copy stderr 单独打印、panic 计数） |
| 每轮原始档 | `harness/gpuprobe/results/gpuprobe-*.{ndjson,log,hb}`（6 轮全留） |
| 报告 | `out/GPU-PROBE.md`（本文件，新建） |

边界确认：`harness/israce/main.m` 与 `harness/israce/Payload/` **未改动**；
`out/` 既有文件一个没动（只新建了本报告）；全程不重启设备；`out/panics/*.ips` 数量 5 → 5。
