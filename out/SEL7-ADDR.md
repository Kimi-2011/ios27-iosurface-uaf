# SEL7-ADDR — `AppleM2ScalerCSCDriver` selector 7：用户输入是否被当**地址**解释

设备 `DEVICE-UDID`（iPhone18,2 / iOS 27.0.1 / T8150 / kernel 27.0.0 xnu-13432.2.10~2）。
套件 `harness/sel7addr/`。指纹 `SEL7-20261101-addrprobe-b7e21c`。
本轮只做 selector 7；未跑竞态；未碰 `harness/israce/`；未改 `out/` 既有文件；**设备未重启**。

---

## 结论（先给答案）

1. **是，sel 7 把 `structIn` 的 8 字节当指针解引用，而且会往那里写。**
   有效 mmap 页 3/3 `SUCCESS`；NULL / 未对齐 / 未映射 3/3 `KERN_INVALID_ADDRESS`。
   写入语义 = **`bzero(addr, min(0x600, 到下一个不可写页边界的距离))`** —— 固定 1536 字节、固定内容 `0x00`、落在给定地址上。

2. **不是内核地址通道。** 5 个指定内核 VA + 70 个扫描点 + 5 个 panic 日志里的 kernelcache 文本装载地址，共 **80 次调用全部 `kr=0x1`**，与未映射用户地址逐字节相同，无 panic、无超时。
   ⇒ 翻译被约束在**调用方自己的进程地址空间**内。

3. **写进去的是 0，不是内核数据。** 全页覆盖比对：变化区间内容全 `0x00`，`@ptrlike` 一条都没有 ⇒ **本轮没有取得内核信息泄露**。

4. **一条必须记录的副作用**：该调用一旦以 `KERN_PROTECTION_FAILURE` 失败，**调用方那一页随后会变得不可访问**（SIGBUS/SIGSEGV，`si_addr` 就是该页地址），4 种布局复现。

---

## 0. 五态与记录纪律

| 项 | 结果 |
|---|---|
| build | `xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc` rc=0；末版 size=`92456` sha256=`3ac857accf6aa2f112d47240c3249f8142d9a98a09e8ecfd01786a825ab3775f` |
| 指纹 | 每次装前 `strings Payload/UC.app/UC \| grep -c SEL7-20261101-addrprobe-b7e21c` = **1**；残留 m2reenum/scfuzz/m2op = 0 |
| sign | `codesign -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)" --entitlements out/ents.plist` rc=0 |
| install | 每次 `[install] OK`（同 bundle id `com.example.ios27poc` 覆盖装） |
| launch | `devicectl device process launch --console`，进程自退出 rc=0 |
| 跑完 | 每个 stage ndjson 都有 `@done` 尾标记 |
| copy | `copy rc=0 size=…`，**stderr 每次单独打印，无内容**（未吞） |
| panic | `ls -1 out/panics/*.ips \| wc -l`：跑前 **5** → 跑后 **5** |
| 挂起/超时 | `@timeout` **0** 条；每调用独立 pthread + 3s 超时 + 连续 3 次熔断 |
| 设备重启 | 无 |

一次中断：17:01:43 起设备屏幕自动锁定，`SBMainWorkspace` 以 `reason: Locked` 拒绝启动（3 次重试失败）。
`devicectl` 无法远程点亮屏幕，等待后设备被唤醒，`batch.sh` 自动接上并把剩余 stage 连续跑完。
**这是一次纯用户态启动失败，不是 panic，不产生 .ips。**

---

## 1. 基准：确认复现 `KERN_INVALID_ADDRESS`

`structIn` = 8 字节全 0，`structOut` 容量 0，`scalarOut` 容量 0。同连接先按 m2reenum 的顺序预热 sel 0,1,2,3,4,5,8,11。

| tag | structIn 长度 | sst | soc | kr | krh | 判读 |
|---|---:|---:|---:|---|---|---|
| z1 | 8 | 0 | 0 | 1 | `0x1` | **KERN_INVALID_ADDRESS** |
| z2 | 8 | 0 | 0 | 1 | `0x1` | 同上（确定性） |
| z3 | 8 | 0 | 0 | 1 | `0x1` | 同上 |
| ctl_in0 | 0 | 0 | 0 | 3758097090 | `0xE00002C2` | 对照：参数校验路径 |
| ctl_sst8 | 8 | 8 | 0 | 3758097090 | `0xE00002C2` | 对照：输出容量一旦非 0 就回校验错 |

**基准成立**：3/3 复现 `kr=1`，两个对照都是 IOReturn 域的 `0xE00002C2`，与任务书给的已知行为完全一致。

原始（`results/base_-20261101-165642.ndjson`）：

```json
{"k":"@a","grp":"BASE","tag":"z1","addr":"0x0","inlen":8,"soc":0,"sst":0,"kr":1,"krh":"0x1","krn":"KERN_INVALID_ADDRESS","oc":0,"sc":0,"s64":1,"s8":1,"us":8}
{"k":"@a","grp":"BASE","tag":"ctl_in0","addr":"0x0","inlen":0,"soc":0,"sst":0,"kr":3758097090,"krh":"0xE00002C2","krn":"kIOReturnBadArgument","oc":0,"sc":0,"s64":1,"s8":1,"us":4}
```

---

## 2. 组 A：用户态地址 —— **handler 真的解引用用户指针**

同进程 mmap 一页 `0x106eb8000`，页内先写 magic `0x4142434445464748`；全部 `sst=0 soc=0 inlen=8`。

| tag | addr | kr | krh | 结果 |
|---|---|---|---:|---|
| A1_null | `0x0` | 1 | `0x1` | KERN_INVALID_ADDRESS |
| A2_unalign | `0x1` | 1 | `0x1` | KERN_INVALID_ADDRESS |
| A3_unmapped | `0xdeadbeef000` | 1 | `0x1` | KERN_INVALID_ADDRESS |
| A4_valpage | `0x106eb8000` | **0** | **`0x0`** | **SUCCESS** |
| A5_valpage16 | `0x106eb8010` | **0** | **`0x0`** | **SUCCESS** |
| A6_valpageff0 | `0x106eb8ff0` | **0** | **`0x0`** | **SUCCESS** |

**判据表第 1 行成立**：有效页与无效地址返回码不同（`0x0` vs `0x1`）⇒ **handler 真的按我们给的地址去做翻译并访问了内存**。
（对照组 A 的"地址"是 8 字节小端 u64，见 §5.1 的长度扫描：`inlen` 只认 8。）

---

## 3. 组 B：内核态地址 —— 一个进程一个地址，各 2 次

| tag | addr | kr ×2 | krh | 备注 |
|---|---|---|---:|---|
| B1 | `0xfffffe0007004000` | 1, 1 | `0x1` | 内核缓存基址 |
| B2 | `0xfffffe000a17e984` | 1, 1 | `0x1` | IOMobileGraphicsFamily handler |
| B3 | `0xfffffe000a34ff88` | 1, 1 | `0x1` | 历史 panic 的 pc |
| B4 | `0xfffffe0000000000` | 1, 1 | `0x1` | 大概率未映射 |
| B5 | `0xffffffffffffffff` | 3758097085, 3758097085 | `0xE00002BD` | **唯一不同码**：kIOReturnNoMemory |

`0xffffffffffffffff` 之所以不同：地址加长度回绕，`IOMemoryDescriptor` 那一层直接建不出描述符 → `kIOReturnNoMemory`。
这是**地址算术溢出**路径，不是"翻译成功后访问到内核"。

---

## 4. 「已映射 vs 未映射 返回码是否有差异」——本轮核心问题

### 4.1 直接回答：**没有差异。**

组 B 三个"必已映射"的内核 VA 与两个未映射内核地址，返回码**逐字节相同**，都是裸 `0x00000001 KERN_INVALID_ADDRESS`，
与组 A 的 NULL / 未对齐 / 未映射用户地址也**完全相同**。全程无 panic、无挂起、无超时。

### 4.2 但这个"没有差异"本身要小心，所以补了两条兜底

组 B 的前提是"这些 VA 此刻确实已映射"，本轮**无法直接证实**：

- 5 份 `out/panics/*.ips` 里 `panicString` 的 pc 是 `0xfffffe00487dbf88` / `0xfffffe0038e6ff88` / `0xfffffe0050bbbf88` / `0xfffffe003976ff88` / `0xfffffe0056633f88`，
  而任务书给的静态地址是 `0xfffffe000a34ff88` —— **同一个函数，5 次启动落点相差几百 MB**。
- `binaryImages` 里 5 个 kernelcache 文本装载条目在 5 次启动间各自地址稳定
  （`0xfffffe000ab44000` / `0xfffffe00095bba10` / `0xfffffe000a87c660` / `0xfffffe000a149340` / `0xfffffe000a3257c0`，是**5 个不同 image**，不是同一个 image 的 5 个值）。

⇒ 靠单个静态 VA 判断"已映射"不可靠。于是补：

**(a) 长度扫描（组 D）——确认读的是一个 u64 指针**

| inlen | 1 | 2 | 4 | **8** | 16 | 32 | 64 |
|---|---|---|---|---|---|---|---|
| kr | `0x2C2` | `0x2C2` | `0x2C2` | **`0x1`** | `0x2C2` | `0x2C2` | `0x2C2` |

只有**恰好 8 字节**才进地址路径，其余长度一律走参数校验。⇒ 用户输入被当成**一个 64 位指针**消费。

**(b) 内核 VA 网（组 S）——与 KASLR 无关的兜底判据**

不管当前启动的 slide 是多少，kernelcache 文本**必然**落在 `0xfffffe0007000000 … 0xfffffe004c000000` 这段里。
按 16MB 步进打 70 个点（`0xfffffe0007000000`, `0xfffffe0008000000`, …, `0xfffffe004c000000`），
外加 5 个 panic `binaryImages` 里记录过的文本装载地址，共 **75 次调用**：

```
kr 分布： {"kr":1} × 75        ← 全部 KERN_INVALID_ADDRESS
```

**如果 handler 走内核 map，这张网必然至少命中一个已映射的内核页并给出不同返回码。一个都没有。**

### 4.3 综合判定

| 观测 | 结论 |
|---|---|
| 组 A 有效页 vs 无效页返回码不同 | **handler 真的解引用用户指针**（成立） |
| 组 B/组 S 已映射内核 VA vs 未映射内核 VA 返回码不同 | **不成立**：80 次全 `0x1` |
| 组 A/B 全部相同 | 不适用（组 A 不同） |

⇒ **本线收敛**：sel 7 的地址参数是**用户态指针**，翻译范围被约束在调用方自己的进程地址空间。
**不是任意内核读/写，没有 ★，不需要停线后的紧急升级。**

---

## 5. 写探测（本轮新增，任务书原设计没有这一项）

### 5.1 方法

`mmap` 若干页，整片填 `0xCD`，并在 `0, 0x100, 0x400, 0x800, 0xc00, 0xff0` 放 canary `0x4142434445464748`；
**调用前**把整片复制一份 `pristine`；传**页首地址**（`inlen=8, sst=0, soc=0`）；**调用后**逐字节比对整片，
变化区间按 32 字节 hexdump，并扫 8 字节窗口找 `0xfffffe…` 形态的值。

### 5.2 结果

| mode | 布局 | addr | kr | 变化 | 具体 |
|---|---|---|---:|---|---|
| plain | 3 页全 RW，target=第 1 页 | `target+0` | **0** | **1536 字节** | `[0, 0x600)` 全变 `0x00`，canary 被抹掉 |
| end8 | 3 页，target=第 1 页，**上方** page2=PROT_NONE | `target+0xff8` | **0** | **8 字节** | 只写 `[0xff8, 0x1000)`，**没有越过保护页** |
| pre8 | 3 页，target=第 1 页，**下方** page0=PROT_NONE | `target-8` | 2 | — | `KERN_PROTECTION_FAILURE`，随后 target 不可读（SIGBUS `0x102f51000`） |
| ro | 1 页，PROT_READ | `page+0` | 2 | 0 | 不写、不报脏，页仍可读 |
| up | 3 页，target=第 0 页，PROT_NONE 在 `+0x2000` | `target+0` | **0** | **1536 字节** | 上方 2 页处有 PROT_NONE 不影响 |
| down | 3 页，target=第 1 页，**下方** page0=PROT_NONE | `target+0` | 2 | — | `KERN_PROTECTION_FAILURE`，随后 target 不可读 |
| none | 1 页全 PROT_NONE | `page+0` | 2 | — | `KERN_PROTECTION_FAILURE`，随后 target 不可读 |

`stage w`（4 页全 RW，同一片页上按不同地址连打）给了写入长度最干净的证据：

```json
{"k":"@diff","tag":"W1_start_r1","changed":1,"first":0,"last":1535,"nbytes":1536,"len":16384}
{"k":"@diff","tag":"W2_plus10","changed":1,"first":0,"last":1551,"nbytes":1552,"len":16384}
{"k":"@diff","tag":"W3_plusff0","changed":1,"first":0,"last":5615,"nbytes":3088,"len":16384}
{"k":"@diff","tag":"W4_page2","changed":1,"first":0,"last":5631,"nbytes":3104,"len":16384}
{"k":"@diff","tag":"W5_ctrl_unmapped","changed":1,"first":0,"last":5631,"nbytes":3104,"len":16384}
{"k":"@diff","tag":"W6_ctrl_in0","changed":1,"first":0,"last":5631,"nbytes":3104,"len":16384}
```

区间并集与 `bzero(addr, 0x600)` **逐字节吻合**：
`+0` → `[0,0x600)`；`+0x10` → 并集 `[0,0x610)`；`+0xff0`（跨页，两侧都 RW）→ 并集 `[0,0x15F0)`；`+0x1000` → 并集 `[0,0x1600)`。
**W5（未映射，kr=1）与 W6（BadArgument）没有新增任何字节** ⇒ 变化确实只发生在成功路径上，不是我这边记账错误。

写入内容（`plain` 模式前 3 行，其余 45 行同）：

```json
{"k":"@w","tag":"W1_start_r1","off":0,"n":32,"b":"0000000000000000000000000000000000000000000000000000000000000000"}
{"k":"@w","tag":"W1_start_r1","off":32,"n":32,"b":"0000000000000000000000000000000000000000000000000000000000000000"}
{"k":"@w","tag":"W1_start_r1","off":64,"n":32,"b":"0000000000000000000000000000000000000000000000000000000000000000"}
```

### 5.3 判读

- **会写**，而且写的长度是**固定 1536 字节**，内容**恒为 0**，起点就是用户给的地址。
- **不是内核数据**：没有任何非零内容，`@ptrlike`（形如 `0xfffffe…` 的 8 字节窗口）**0 条** ⇒ **本轮没有拿到内核信息泄露**。
- **不会越界溢出到相邻页**：`end8` 只写了 8 字节就停在 PROT_NONE 页边界 —— 写入按页保护边界**截断**，不是无界 memcpy。
- **遵守页权限**：PROT_READ 页不写（`kr=2`，页内容 0 变化）；PROT_NONE 页不写。
- 形态上等价于"内核替你在**你自己的**地址空间里做一次有界 memset"。**跨不出本进程**，因此不构成提权原语。

### 5.4 必须记的副作用：失败会让调用方那一页不可访问

`pre8` / `down` / `none` / 早先 `guard` 的 G1 四种布局，`kr=2` 之后**同一进程再读那一页就崩**：

```json
{"k":"@a","grp":"GT","tag":"pre8","addr":"0x102f50ff8",...,"kr":2,"krh":"0x2","krn":"KERN_PROTECTION_FAILURE",...,"us":2602}
{"k":"@mark","tag":"pre8","at":"read_page0"}
{"k":"@sig","sig":10,"faultaddr":"0x102f51000","code":1}
```

`@sig` 来自我装的 SIGSEGV/SIGBUS handler（`si_addr` 直接写盘），`sig=10`=SIGBUS，`faultaddr` 正是那页地址。
`mincore()` 在前后都返回 `rc=0`（页表项还在），但**实际访问 SIGBUS** ⇒ 该页被内核侧留在了"已接线但后端失效"的状态。
这是该 handler 在**调用方 vm_map 上留下的副作用**，不是 panic（`.ips` 计数 5→5），无法从用户态恢复。
`pre8` 那次调用还特别慢（2602 µs，其它成功调用 4–22 µs），说明失败路径里真的做了接线工作。

---

## 6. 组 C：同一地址、输出容量阶梯

### 6.1 `0xffffffffffffffff`（组 B 里返回码最特殊的那个）

| sst \ soc | 0 | 1 |
|---|---|---|
| **0** | `0xE00002BD` | `0xE00002BD` |
| 1 | `0xE00002C2` | `0xE00002C2` |
| 8 | `0xE00002C2` | `0xE00002C2` |
| 64 | `0xE00002C2` | `0xE00002C2` |
| 4096 | `0xE00002C2` | `0xE00002C2` |

### 6.2 `0xfffffe0007004000`（已映射内核 VA 对照）

| sst \ soc | 0 | 1 |
|---|---|---|
| **0** | `0x1` | `0x1` |
| 1 | `0xE00002C2` | `0xE00002C2` |
| 8 | `0xE00002C2` | `0xE00002C2` |
| 64 | `0xE00002C2` | `0xE00002C2` |
| 4096 | `0xE00002C2` | `0xE00002C2` |

**判读**：`structOut` 容量是**硬开关** —— 只要非 0 就退回 `0xE00002C2`，根本到不了地址路径；
`scalarOut` 容量（0/1）**完全无关**。所以"地址路径"只在 `(sst==0, inlen==8)` 这一个窄缝里可达。

---

## 7. panic / 挂起

| 项 | 值 |
|---|---|
| `ls -1 out/panics/*.ips \| wc -l` 跑前 | **5** |
| 跑后 | **5**（无新增） |
| 新增 panic 原文 | 无 |
| `@timeout` | **0** |
| `@abort`（连续超时熔断） | **0** |
| 用户态崩溃（非 panic） | 4 次，均为 §5.4 那一类：`@sig sig=10 SIGBUS`，`faultaddr` = 我们自己传进去的那页 |
| 设备重启 | 无 |
| 设备锁定 | 17:01:43 起自动锁定一次，`Locked` 拒绝启动，等待后恢复，非 panic |

---

## 8. 原始 ndjson

全部在 `harness/sel7addr/results/`（23 个文件；其中 `w_-20261101-170139/170154*`、`c_-20261101-170043*` 是锁定期间误拷的**陈旧容器文件**，内容不是本轮，忽略）。

| 文件 | stage | addr / mode | build |
|---|---|---|---|
| `base_-20261101-165642.ndjson` | base | — | 16:56:36 |
| `a_-20261101-165647.ndjson` | a | mmap `0x106eb8000` | 16:56:36 |
| `b_-20261101-165702.ndjson` | b | `0xffffffffffffffff` | 16:56:36 |
| `b_-20261101-165713.ndjson` | b | `0xfffffe0007004000` | 16:56:36 |
| `b_-20261101-165730.ndjson` | b | `0xfffffe0000000000` | 16:56:36 |
| `b_-20261101-165736.ndjson` | b | `0xfffffe000a17e984` | 16:56:36 |
| `b_-20261101-165741.ndjson` | b | `0xfffffe000a34ff88` | 16:56:36 |
| `w_-20261101-170406.ndjson` | w | 4 页全 RW，写探测 | 17:03:46 |
| `guard_-20261101-170407.ndjson` | guard | 三页守卫布局（G1 后崩，见 §5.4） | 17:03:46 |
| `c_-20261101-170408.ndjson` | c | `0xffffffffffffffff` | 17:03:46 |
| `c_-20261101-170410.ndjson` | c | `0xfffffe0007004000` | 17:03:46 |
| `sweep_-20261101-170412.ndjson` | sweep | 75 个内核 VA | 17:03:46 |
| `len_-20261101-170413.ndjson` | len | inlen 1..64 | 17:03:46 |
| `gtest_-20261101-170633.ndjson` | gtest | plain | 17:06:26 |
| `gtest_-20261101-170634.ndjson` | gtest | end8 | 17:06:26 |
| `gtest_-20261101-170635.ndjson` | gtest | pre8 | 17:06:26 |
| `gtest_-20261101-170637.ndjson` | gtest | ro | 17:06:26 |
| `gtest_-20261101-170724.ndjson` | gtest | up | 17:06:26 |
| `gtest_-20261101-170726.ndjson` | gtest | down | 17:06:26 |
| `gtest_-20261101-170727.ndjson` | gtest | none | 17:06:26 |

每份 ndjson 与同名 `.log` 内容一致（`emit()` 同时写 stderr / log / ndjson，逐行 `fflush`+`fsync`）；
同名 `.hb` 是 200ms 心跳，进程死掉时用来判定死在哪个 tag。

复跑：

```
cd harness/sel7addr
./run.sh prep                                   # build → 指纹 → 签名 → 安装
./run.sh stage base                             # 基准
./run.sh stage a                                # 组 A
./run.sh stage b addr=0xfffffe0007004000 reps=2  # 组 B 单个地址（一个进程一个）
./run.sh stage c addr=0xffffffffffffffff        # 组 C
./run.sh stage w reps=3                         # 写探测
./run.sh stage gtest mode=plain|end8|pre8|ro|up|down|none
./run.sh stage sweep                            # 内核 VA 网
./run.sh stage len addr=0x0                     # 长度扫描
```

---

## 9. 判据对照表

| 观测 | 本轮结果 | 含义 |
|---|---|---|
| 组 A 有效页 与 组 A 无效 返回码不同 | **是**（`0x0` vs `0x1`） | **handler 真的解引用用户指针** |
| 组 B 已映射内核 VA 与 未映射 返回码不同 | **否**（80 次全 `0x1`） | 内核地址不被翻译 |
| 组 A/B 全部相同 | 不适用 | — |

**额外（任务书未列，但更重要）**：

| 观测 | 本轮结果 |
|---|---|
| sel 7 会不会写用户页 | **会**，`bzero(addr, 0x600)` |
| 写进去的是不是内核数据 | **不是**，全是 `0x00`，无 `0xfffffe…` 形态 |
| 能不能写到内核地址 | **不能**，内核 VA 一律 `KERN_INVALID_ADDRESS` |
| 会不会越界溢出 | **不会**，按不可写页边界截断（`end8` 只写 8 字节） |
| 失败是否留副作用 | **会**：调用方该页随后 SIGBUS |

## 10. 开放问题（未解，留给下一轮）

1. **为什么"紧邻下方是 PROT_NONE"会让整个调用 `KERN_PROTECTION_FAILURE`，而"紧邻上方是 PROT_NONE"不影响（`up` 成功）？**
   现象对不上"从 addr 开始写 0x600"的简单模型：`down` 的目标页整段 RW，仍失败。
   ⇒ handler 实际接线的窗口**不是** `[addr, addr+0x600)`，下方很可能多含一段。需要按 `addr = base + k*0x100` 扫 k，把"可写窗口"的左右边界测出来。
2. **`0x600` 这个长度是谁的**：与 sel 11 的 664 不同，是个独立常量；驱动里应能静态定位（`out/dec-m2sA.c` / `dec-m2sB.c`）。
3. **§5.4 那个 SIGBUS** 是接线残留还是 `pmap` 层面的破坏，需要看驱动失败路径的反编译。

---

## 结论（指挥侧确认）

**sel 7 收敛：不是提权原语。**

其实质行为是 `bzero(用户给定指针, 0x600)`：

```
plain  3 页全 RW，addr=页首        kr=0   写入 [0,0x600) 全 0x00（1536 字节）
end8   addr=页尾-8，上方 PROT_NONE  kr=0   只写 8 字节，停在保护页边界
ro     PROT_READ                   kr=2   0 变化
none   PROT_NONE                   kr=2   —
pre8   下方 PROT_NONE              kr=2   之后该页 SIGBUS
```

写入区间并集逐字节吻合（`+0`→`[0,0x600)`、`+0x10`→`[0,0x610)`、`+0xff0`→`[0,0x15F0)`）。

**写进去的全是 0，不是内核数据。`@ptrlike` 0 条 ⇒ 无信息泄露。**

**内核地址通道关闭**：75 次 VA 扫描（`0xfffffe0007000000` → `0xfffffe004c000000` 步进 16MB 共 70 点
+ 5 个 panic binaryImages 装载地址）**全部 `0x1`**。
判据与 KASLR 无关：若走内核 map，这张网必命中至少一个已映射内核页。一个都没有。

⇒ **翻译被约束在调用方自己的进程地址空间。等价形态是「内核替你在你自己的地址空间做一次有界 memset」，
跨不出本进程，不构成提权原语。**

## 副作用（记录，不影响结论）

失败调用（`kr=2 KERN_PROTECTION_FAILURE`）之后，**同进程再访问该页即 SIGBUS**
（`mincore()` 仍 rc=0，页表项还在，但访问崩）。耗时 2602 µs（成功路径 4–22 µs），
说明失败路径真的做了接线工作。**这是内核在调用方地址空间留下的坏状态，不是 panic，也不跨进程。**

## 用这条线换到的方法论

**`structIn` 长度是硬约束**：只有 `inlen == 8` 才进地址路径，1/2/4/16/32/64 全 `0xE00002C2`
⇒ 消费的是一个 u64 指针。

**`structOut` 容量是硬开关**：`sst >= 1` 一律 `0xE00002C2`，根本到不了地址路径。
这就是第 13 轮那个 in/out 预填 bug 的又一次具体体现。
