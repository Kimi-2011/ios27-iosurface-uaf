# TEARREG 运行报告

设备 `DEVICE-UDID`（iPhone 17 Pro Max / iPhone18,2 / iOS 27.0.1）
协议：不重启（除 unreachable / panic）、`MK()` no-op、不 sleep 拉长时序、copy 只读取回。

**当前结论：`teardown ∥ register` 竞态在 IOKit 用户态 API 面上不可达（情况 A，已实测判定）。**

---

## 0. 上一轮 `完成=0 / 偏移集=[]` 定案：三处故障叠加，不是竞态阴性

### 0.1 上一次跑根本没进变体（设备侧证据）

设备容器 `tmp/israce.ndjson` 末尾（14:43）最后 8 次启动全部是：

```ndjson
{"k":"@calib","ph":"note","t":0.031,"shape":3,"pat":1,"rc":3758097090,"rcn":"kIOReturnBadArgument","so0":0}
{"k":"@abort","ph":"note","t":0.032,"why":"calibration failed"}
{"k":"@summary","ph":"note","t":0.032,"ran":0,"ends":0,"skips":0,"ok0":0,"t":0.03,"shape":-1}
```

`ran:0 ends:0 shape:-1` = 校准失败直接 abort。全文件累计 62 条 `@abort`。

### 0.2 那批记录不是当前 `main.m` 产出的

这些行带 `"pat"` / `"so0"`，当前 `main.m` 写的是 `"shape"` / `"rcn"`。带 `so0` 的唯一来源：

```
$ grep -rln 'so0' --include=*.m .
./harness/israce/main-repro.m
```

⇒ 装的是 `main-repro.m` 的旧二进制，其校准契约（pat 0/1）在真机恒 `kIOReturnBadArgument`，每次启动必 abort。

### 0.3 脚本把「没匹配到」写成了 0

`/tmp/tear.sh` 用 `startswith(f'g{n}t')`（n=尝试序号 1..8）过滤，而 plan 标签硬编码 `g2t0..g2t4`；
且所有 `devicectl copy` 的 stderr 被 `2>/dev/null` 吞掉 ⇒ copy 失败与「文件为空」不可区分。

**⇒ `panic=5 / 完成=0 / 偏移集=[]` 属于「未执行 / 没记录」，不是阴性。**

---

## 1. 第 0 步冒烟：变体真跑、记录真落盘、sel17 自检 = 0

改动只碰迭代数 / 偏移 / 标签 / 心跳，**漏洞路径逻辑未改**。二进制内含指纹 `smoke0-tearreg`、`tear.enter`、`tear.exit`、`s0t0`（strings 已验证）。

原始 ndjson（设备新增段，逐字）：

```ndjson
{"k":"@build","ph":"note","t":0.016,"id":"smoke0-tearreg","d":"Nov  1 2026","tm":"14:47:12","v":30}
{"k":"@calib","ph":"note","t":0.023,"shape":0,"rc":3758097090,"rcn":"kIOReturnBadArgument"}
{"k":"@calib","ph":"note","t":0.024,"shape":1,"rc":0,"rcn":"SUCCESS"}
{"k":"s0b-N0-I0000","ph":"begin","t":0.028,"v":0,"n":0,"i":0,"shape":1}
{"k":"s0b-N0-I0000","ph":"end","t":0.028,"v":0,"ms":0,"spam":0,"rc0":0,"n0":"SUCCESS"}
{"k":"s0t0-N0-I0000","ph":"begin","t":0.029,"v":30,"n":0,"i":0,"shape":1}
{"k":"@tear.enter","ph":"note","t":0.030,"off":0,"i":0,"conn":24099,"surf":1}
{"k":"@tear.exit","ph":"note","t":0.035,"off":0,"try":568,"ok":1,"lastrc":268435459}
{"k":"s0t0-N0-I0000","ph":"end","t":0.138,"v":30,"ms":109,"spam":568,"rc0":1,"rc1":568,"rc3":1,"rc4":268435459,"n4":"MIG_BAD_ARGUMENTS"}
{"k":"@summary","ph":"note","t":1.667,"ran":18,"ends":18,"skips":0,"ok0":3,"t":1.67,"shape":1}
```

`ran:18 ends:18` 全配对。**判定：有记录、`rc0` 有值 ⇒ 变体在跑。**

`sel17` 自检（`V_BASELINE`，close 之前无条件单次注册）：`s0b` ×3 全部 `rc0=0 SUCCESS`
⇒ 异步契约（wake port + referenceCnt=1 + structureInput 恰 24 字节）成立，**不是调用契约问题**。

未 panic、无 app 自崩日志、正常走到 `@summary` 后 exit。

---

## 2. 指标口径修正（原判据会产出假阳性）

`rc1` 是 8 个灌线程的 while 循环圈数（几百~几千），**恒非零是必然，不是「窗口存在」的证据**。
原始任务书判据 `rc1 > 0 ⇒ 窗口存在` 已撤回。

新增字段：`rc3` = sel17 累计 SUCCESS 次数，`rc5` = **close 那一刻的成功数快照（pre）**，
`post = rc3 − rc5` 才是窗口证据。另修 `rcName` 错标：`0x10000003` 原写 `MIG_BAD_ARGUMENTS`，
实为 **`MACH_SEND_INVALID_DEST`**（`mach/message.h:828`）。

---

## 3. 决定性探测 `V_PORTDIAG`：close 之后端口在用户态已死

每次：open conn →（可选 +1 send 引用）→ sel17(pre) → `mach_port_type` → `IOServiceClose`
→ `mach_port_type` → `mach_port_mod_refs(SEND,+1)` → sel17(post)

原始 ndjson（逐字）：

```ndjson
{"k":"@portdiag","ph":"note","t":0.030,"extra":0,"pre":0,"ptb":65536,"krpt":15,"pta":0,"krmod":15,"post":268435459}
{"k":"@portdiag","ph":"note","t":0.031,"extra":1,"pre":0,"ptb":65536,"krpt":0,"pta":1048576,"krmod":17,"post":268435459}
```

| 组 | close 前额外引用 | rc0 sel17(pre) | rc1 `mach_port_type` 前 | rc2 kr_pt 后 | rc3 pt 后 | rc4 mod_refs 后 | rc5 sel17(post) |
|---|---|---|---|---|---|---|---|
| s1pA ×3 | 无 | 0 SUCCESS | 65536 = `0x10000` SEND | 15 `KERN_INVALID_NAME` | 0 | 15 `KERN_INVALID_NAME` | 268435459 |
| s1pB ×3 | +1 SEND | 0 SUCCESS | 65536 = `0x10000` SEND | 0 SUCCESS | 1048576 = `0x100000` DEAD_NAME | 17 `KERN_INVALID_RIGHT` | 268435459 |

常量已对 SDK 核验：`KERN_INVALID_NAME 15`（kern_return.h:143）、`KERN_INVALID_RIGHT 17`（:151）、
`MACH_PORT_TYPE_SEND = 1<<16 = 0x10000`、`MACH_PORT_TYPE_DEAD_NAME = 1<<20 = 0x100000`（port.h:205-217）。

**读法：**

- **不加引用**：close 之后连端口名都没了（`mach_port_type` 直接 `KERN_INVALID_NAME`，pt=0），
  `mod_refs` 同样 `KERN_INVALID_NAME`。
- **加引用**：端口名被保住，但已退化成 **DEAD_NAME**（0x100000）；`mod_refs` 报 `KERN_INVALID_RIGHT`
  （死名不能加引用）；**sel17 仍 `0x10000003 MACH_SEND_INVALID_DEST`**。

`MACH_SEND_INVALID_DEST` 是**发送路径**在目的端口已死时产生的返回码 ⇒
**消息根本进不到内核 userclient，更到不了 #799 注册 handler。**
**⇒ 归属为情况 A（客户端侧失效），不是情况 B（内核 MIG 参数错）。**

---

## 4. `V_TEARREG` 的 pre / post 拆分：post 恒 0

原始 ndjson（逐字，5 个偏移各 1 次）：

```ndjson
{"k":"@tear.exit","ph":"note","t":0.038,"off":0,"try":2300,"ok":0,"pre":0,"post":0,"lastrc":268435459}
{"k":"s1t0-N0-I0000","ph":"end","t":0.141,"v":30,"ms":109,"spam":2300,"rc0":1,"rc1":2300,"rc2":0,"rc3":0,"rc4":268435459,"n4":"MACH_SEND_INVALID_DEST","rc5":0}
{"k":"@tear.exit","ph":"note","t":0.144,"off":50,"try":5227,"ok":1,"pre":1,"post":0,"lastrc":268435459}
{"k":"s1t1-N1-I0000","ph":"end","t":0.249,"v":30,"ms":108,"spam":5227,"rc0":1,"rc1":5227,"rc2":50,"rc3":1,"rc4":268435459,"n4":"MACH_SEND_INVALID_DEST","rc5":1}
{"k":"@tear.exit","ph":"note","t":0.253,"off":100,"try":2365,"ok":1,"pre":1,"post":0,"lastrc":268435459}
{"k":"@tear.exit","ph":"note","t":0.361,"off":200,"try":998,"ok":1,"pre":1,"post":0,"lastrc":268435459}
{"k":"@tear.exit","ph":"note","t":0.469,"off":500,"try":1541,"ok":1,"pre":1,"post":0,"lastrc":268435459}
{"k":"@summary","ph":"note","t":0.574,"ran":11,"ends":11,"skips":0,"ok0":6,"t":0.57,"shape":1}
```

| 偏移 | try（循环圈数） | pre（close 前成功） | post（close 后成功） |
|---|---|---|---|
| 0 µs | 2300 | 0 | **0** |
| 50 µs | 5227 | 1 | **0** |
| 100 µs | 2365 | 1 | **0** |
| 200 µs | 998 | 1 | **0** |
| 500 µs | 1541 | 1 | **0** |

**`post` 五档恒 0。** 上一轮冒烟看到的 `rc3=1` 是 **close 之前的预热调用**，不是窗口内的命中——
与第 3 节端口判定完全一致。`off=0` 时连 pre 都是 0（close 抢在任何调用完成之前）。

---

## 5. 结论

```
teardown ∥ register（IOServiceClose ∥ sel17）：
  close 之后 connect 端口在用户态即失效（mach_port_type / mod_refs 实测，
  加额外 send 引用也只剩 DEAD_NAME），sel17 一律 MACH_SEND_INVALID_DEST
  => 该竞态在 IOKit 用户态 API 面上不可达（情况 A）
```

**必须同时如实写明的一件事：那 5 次历史 panic 的成因至今未证。**

- 崩溃进程从来不是本 app；
- 本变体在用户态不可达 ⇒ **这 5 次 panic 不能归因于本代码路径**；
- 它们的成因仍是未定的，不应再被本实验「继承」。

---

## 6. 运行过程记录（有效性判定）

| 事件 | 判定 |
|---|---|
| 14:47 冒烟（18 次） | ✅ 有效，`ran:18 ends:18` |
| 装机后首次 launch（14:57:26） | ⚠ 启动成功但**零记录**：设备 14:57:59 掉线、约 15:58 回线，app 被中断 |
| 14:57:59 掉线 | **设备重启，无 panic 日志**（panic 总数仍 5，最新 `panic-full-2026-11-01-123030`）。成因未定，不计为命中 |
| 15:02:51 launch（诊断 11 次） | ✅ 有效，`ran:11 ends:11` |

注：设备锁屏会拒绝 launch（`SBMainWorkspace ... Locked`），并使 DDI 无法挂载
（`kAMDMobileImageMounterDeviceLocked`）⇒ 取数前必须保持解锁亮屏。

---

## 7. 未做的事 / 下一步选项

- **未跑第 2 步 200 次**：`post` 恒 0 已定案，跑 200 次只会得到 200 个 `post=0`。
- 若要继续找 S2，需换「不依赖 close 后发消息」的触发面：
  在 close **之前**让 sel17 处于已投递未处理状态（多个 conn / 抢占 workloop），
  或改从 surface 析构侧触发 teardown（对象归属仍未定，`node+0x58` 是否 user client 无定论）。
