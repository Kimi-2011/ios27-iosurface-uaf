# PORT-PROBE — `0x10000003` 归因（客户端 stub vs 内核 MIG stub）

## 结论

**情况 A：`0x10000003` 由客户端 stub 产生，不是内核 MIG stub。**

本支的同任务探针未执行。答案已由另一支的 `V_PORTDIAG` 变体取得（结果见 `out/TEARREG-RUN.md` §3，
原始 ndjson 见该文件第 91–92 行）：`IOServiceClose` 之后 `mach_port_type` 直接返回
**`KERN_INVALID_NAME`(15)**、ptype=0 —— 连端口名都没了；若在 close 前额外持有一个 send 引用，端口名虽被保住，
但已退化为 **`DEAD_NAME`(0x100000)**，`mach_port_mod_refs(SEND,+1)` 返回 **`KERN_INVALID_RIGHT`(17)**；
两种情况下 close 后的 `sel17` 一律返回 **`268435459 = 0x10000003` = `MACH_SEND_INVALID_DEST`**。
即消息在用户态 `mach_msg_send` 阶段就被丢弃，根本没有进到内核 userclient，`sel17` 的内核窗口在
close 之后不可从用户态触达 —— S2 不可触发。（`pre` 两行均为 0，说明契约自检通过、close 前注册成功；
5 档起跑偏移下 `post` 恒为 0，先前看到的那个「1」是 close 前预热，不是窗口。）

| 组 | close 前额外引用 | sel17(pre) | kr_pt（close 后 `mach_port_type`） | ptype（close 后） | mod_refs(SEND,+1) | sel17(post) |
|---|---|---|---|---|---|---|
| s1pA | 无 | 0 SUCCESS | **15 `KERN_INVALID_NAME`** | 0 | **15 `KERN_INVALID_NAME`** | `0x10000003` |
| s1pB | +1 SEND | 0 SUCCESS | 0 SUCCESS | **`0x100000` DEAD_NAME** | **17 `KERN_INVALID_RIGHT`** | `0x10000003` |

## 留档（未运行）

- `harness/israce/probe.m` —— 精简探针（不改 `main.m`）：对照「不 close 反复调 sel17」+ 用户指定 1–10 步
  + 去掉第 4 步的纯读数序列；异步 `referenceCnt=1` 且 ref 非 0、`structureInput` 精确 24 字节、scalarIn=0。
  指纹 `PORTPROBE-20261101-7c3f9d`，编译通过、`strings` 命中 1 次（`main.m` 的 `diag1-portdiag` 命中 0）。
- `harness/israce/probe-run.sh` —— build → 指纹校验 → 签名 → 装前 `lockState` 检查 → 安装 → `--console` 启动 → 取回。

两者**未在设备上执行**（设备已自行锁屏 `passcodeRequired: true`，按要求不再解锁、不再碰设备、不再轮询）。
`Payload/UC.app/UC` 内当时留下的是 probe 二进制，已按备份还原为 `main.m` 产物并重签
（sha256 `17493125be7340859674f080f72f985e113c5ff036d58f96e114c92a5fbbe549`）。
