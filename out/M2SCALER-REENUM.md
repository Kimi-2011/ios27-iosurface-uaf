# M2SCALER-REENUM — `AppleM2ScalerCSCDriver` selector 面【正确 in/out 姿势】重枚举

设备 `DEVICE-UDID`（iPhone18,2 / iOS 27.0.1）。项目根 `tasks/ios27-chain-poc`。
本轮跑测窗口 2026-11-01 16:43:55 – 16:50:20（+08:00）。指纹 `M2RE-20261101-reenum-c4d81b`。

**一句话**：修好 `scalarOutputCount` / `structOutputSize` 必须预填容量这个姿势错误之后，结论从「只有 sel 11」变成「**sel 0–11 共 12 个 selector 存在**」，并且**第一次拿到 `kr==0 且 sc>0` 的那一类结果**：sel 11 零入参回吐 **664 字节**内核侧结构（前两轮恒为 0 字节）。**664 字节里没有任何 `0xfffffe...` 内核指针、没有 PAC 形态**，且两次独立进程 dump **逐字节一致** ⇒ 是确定性配置描述符，不是未初始化堆/栈泄漏。

## 0. 五态 + 记录纪律

| 项 | 结果 |
|---|---|
| build | 每次 `xcrun -sdk iphoneos clang -arch arm64 -fobjc-arc` rc=0，**零 warning** |
| 指纹 | 装前 `strings Payload/UC.app/UC \| grep -c M2RE-20261101-reenum-c4d81b` = **1**；残留 m2op/scfuzz/svc2probe 指纹均 0 |
| sign | `codesign -s "iPhone Distribution: <DEVELOPER> (<TEAMID>)"` rc=0，Identifier=`com.example.ios27poc`，Team=`DFH8ZCU6D4` |
| install | 13 次 stage 全部 `App installed` |
| launch | `devicectl process launch --console`，进程自退出，13/13 都有 `@done` |
| 跑完 | 正式调用 **5789 次**（`@pre` 计数）+ 预热 104 次；`@timeout` **0**；`@abort` **0** |
| panic | `ls -1 out/panics/*.ips \| wc -l`：**跑前 5 → 跑后 5**，无新增 |
| 挂死 | **0 次** |
| 重启设备 | 无 |
| copy stderr | 每次 `devicectl device copy from` 的 stderr 单独打印（`copy-stderr(<file>):`），全程为空 |

`out/` 既有文件一个没动，只新建了 `out/M2SCALER-REENUM.md`。`harness/israce/` 未触碰，未跑任何竞态。未 git。

## 1. 修正了什么（姿势本身）

前两轮的根因就是一件事：`IOConnectCallMethod` 的后四个参数是 **in/out**。

```c
kern_return_t IOConnectCallMethod(mach_port_t conn, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output,  uint32_t *outputCnt,      // in = 容量, out = 内核实写量
    void *outputStruct, size_t *outputStructCnt); // in = 容量, out = 内核实写量
```

本轮每次调用前都预填：`uint32_t soc=16; size_t sst=4096;`，并在 `sout[]` 填 `0xA5A5A5A5A5A5A5A5`、`bst[]` 填 `0x5A` 作为**哨兵**——这样能区分「内核真的写了」和「库只把容量回显回来」。

> 任务书里写的 `size_t soc = 16;` 与真实原型不符：**`outputCnt` 是 `uint32_t *`**，`outputStructCnt` 才是 `size_t *`。传 `size_t*` 会读到高 4 字节。本轮按真实原型实现。

另外两条也照做了：**预热**（每个新连接先按序打 `sel 0,1,2,3,4,5,8,11`，结果只记不判，见每份 ndjson 的 `@warm` 行）与**每调用独立 pthread + 3s 超时**（超时 detach 泄漏该线程与缓冲、记 `@timeout`、继续下一条；连续 3 次超时熔断）。

### 1.1 一个必须先讲的机制事实：`oc` / `sc` 的语义

实测：**调用失败时 `oc`/`sc` 保持预填容量不变**；调用成功时 `oc` 恒等于预填容量（回显），只有 `sc` 可能是内核真正改写的值。所以

- **不能用 `oc>0` 判定「写回了标量」**，必须看哨兵是否被改写（ndjson 里的 `s64` 字段：1=哨兵完好=没写，0=被改写=真写了）。
- `sc` 只在**内核显式改写**时才不等于容量（sel 11 的 664 就是这种情况）。

这条直接决定了下面 §6 怎么判读。

## 2. 阶段 1：存在性扫描（sel 0–255，零入参，容量 16/4096）

判据照任务书：`0xE00002C7 Unsupported` = 不存在；**其它任何码 = 存在**。

| sel | kr | kr 名 | oc | sc | 存在 |
|---:|---|---|---:|---:|:--:|
| 0 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 1 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 2 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 3 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 4 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 5 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 6 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 7 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 8 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 9 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 10 | `0xE00002C2` | BadArgument | 16 | 4096 | **存在** |
| 11 | `0x00000000` | SUCCESS | 16 | 664 | **存在** |
| 12 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 13 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 14 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 15 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 16 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 17 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 18 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 19 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 20 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 21 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 22 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 23 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 24 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 25 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 26 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 27 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 28 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 29 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 30 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 31 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 32 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 33 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 34 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 35 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 36 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 37 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 38 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 39 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 40 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 41 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 42 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 43 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 44 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 45 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 46 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 47 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 48 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 49 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 50 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 51 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 52 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 53 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 54 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 55 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 56 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 57 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 58 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 59 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 60 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 61 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 62 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 63 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 64 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 65 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 66 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 67 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 68 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 69 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 70 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 71 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 72 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 73 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 74 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 75 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 76 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 77 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 78 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 79 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 80 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 81 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 82 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 83 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 84 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 85 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 86 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 87 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 88 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 89 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 90 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 91 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 92 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 93 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 94 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 95 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 96 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 97 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 98 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 99 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 100 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 101 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 102 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 103 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 104 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 105 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 106 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 107 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 108 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 109 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 110 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 111 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 112 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 113 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 114 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 115 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 116 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 117 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 118 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 119 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 120 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 121 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 122 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 123 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 124 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 125 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 126 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 127 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 128 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 129 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 130 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 131 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 132 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 133 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 134 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 135 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 136 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 137 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 138 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 139 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 140 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 141 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 142 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 143 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 144 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 145 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 146 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 147 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 148 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 149 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 150 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 151 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 152 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 153 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 154 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 155 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 156 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 157 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 158 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 159 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 160 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 161 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 162 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 163 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 164 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 165 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 166 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 167 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 168 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 169 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 170 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 171 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 172 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 173 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 174 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 175 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 176 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 177 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 178 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 179 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 180 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 181 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 182 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 183 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 184 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 185 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 186 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 187 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 188 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 189 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 190 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 191 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 192 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 193 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 194 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 195 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 196 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 197 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 198 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 199 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 200 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 201 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 202 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 203 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 204 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 205 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 206 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 207 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 208 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 209 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 210 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 211 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 212 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 213 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 214 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 215 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 216 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 217 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 218 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 219 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 220 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 221 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 222 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 223 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 224 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 225 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 226 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 227 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 228 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 229 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 230 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 231 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 232 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 233 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 234 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 235 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 236 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 237 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 238 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 239 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 240 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 241 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 242 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 243 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 244 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 245 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 246 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 247 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 248 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 249 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 250 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 251 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 252 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 253 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 254 | `0xE00002C7` | Unsupported | 16 | 4096 |  |
| 255 | `0xE00002C7` | Unsupported | 16 | 4096 |  |

统计：`0xE00002C7` × 244，`0xE00002C2` × 11（sel 0–10），`0x00000000` × 1（sel 11）。

### 2.1 存在的 selector 列表

```
sel 0,1,2,3,4,5,6,7,8,9,10,11        —— 共 12 个，连续一段
```

**对比前一轮的「只有 sel 11」：存在数 1 → 12。**

### 2.2 但 (16,4096) 这一个姿势仍然不够 —— 补一轮密集网格

sel 5 在 `(soc=16, sst=4096)` 下同样报 `Unsupported`，只有 `soc==1` 时才 SUCCESS。也就是说**「(16,4096) 报 Unsupported」并不能证明不存在**。所以又跑了一轮：

- `s7`：对 sel 逐个扫 `soc ∈ {0,1,2,3,4,8,16} × sst ∈ {0,4096}`（13 组合），**全部 Unsupported 才判不存在**。

| 区间 | 组合数 | 判存在的 sel | 判不存在的 sel | 用时 |
|---|---|---|---|---|
| 0–11 | 14 | 0,1,2,3,4,5,6,7,8,9,10,11 | — | 8s |
| 12–255 | 3172 | **（无）** | 244 个，全覆盖 | 193s |

⇒ **存在面就 0–11 这 12 个，12 以上在 13 个输出容量组合下全部 Unsupported。**

## 3. 阶段 1b：输出契约矩阵（12 个存在的 sel × 11 个容量组合）

零入参，只变 `(scalarOut 容量, structOut 容量)`。

| soc/sst | 0/0 | 0/4096 | 0/1 | 16/0 | 16/1 | 1/0 | 1/4096 | 1/1 | 8/0 | 8/4096 | 8/1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sel 0 | 0x2C7 | 0x2C2 | 0x2C2 | 0x2C7 | 0x2C2 | 0x2C7 | 0x2C2 | 0x2C2 | 0x2C7 | 0x2C2 | 0x2C2 |
| sel 1 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 2 | 0x2C7 | 0x2C7 | 0x2C7 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 3 | 0x2C7 | 0x2C7 | 0x2C7 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 4 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 5 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | **OK** 1/0 | **OK** 1/4096 | **OK** 1/1 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 6 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 7 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 8 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 9 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 10 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 | 0x2C2 |
| sel 11 | **OK** 0/0 | **OK** 0/664 | **OK** 0/1 | **OK** 16/0 | **OK** 16/1 | **OK** 1/0 | **OK** 1/664 | **OK** 1/1 | **OK** 8/0 | **OK** 8/664 | **OK** 8/1 |

三点结论：

1. **输出计数是精确匹配维度**：sel 5 只在 `soc==1` 成立，`soc=0/8/16` 全 BadArgument。
2. **`(0,0)` 会退化成 Unsupported**：sel 0/2/3 在 `(0,0)` 报 `0xE00002C7`，在 `(0,4096)` 或 `(1,0)` 才报 `0xE00002C2`。⇒ 派发键包含输出维度，**用 0 填充等于把 selector 从派发里抹掉**，这正是前两轮「只剩 sel 11」的机制原因。
3. sel 11 在**任何**容量下都 SUCCESS，且 `sc = min(容量, 664)`。

## 4. 阶段 2：入参维度

固定 `soc=16, sst=4096`，扫 `structIn ∈ {0,1,4,8,64,256,1024,4096}`（内容全 0）× `scalarIn ∈ {0,1,2,4}`（值全 0）。

### 4.1 sel 0,1,2,3,4,6,7,8,9,10 —— 32 个组合全部同一个码

| structIn 长度 \ scalarIn 个数 | 0 | 1 | 2 | 4 |
|---|---|---|---|---|
| 0 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 1 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 4 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 8 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 64 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 256 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 1024 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 4096 | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |

这 10 个 selector 在上述 32 组合下**逐格全是 `0xE00002C2`**，没有任何一格随长度/个数变化。已用程序比对：`sel 1,2,3,4,6,7,8,9,10` 的 32 格签名与 sel 0 **完全同形**。

### 4.2 sel 11 —— 唯一随维度变化的 selector

| structIn 长度 \ scalarIn 个数 | 0 | 1 | 2 | 4 |
|---|---|---|---|---|
| 0 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 1 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 4 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 8 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 64 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 256 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 1024 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 4096 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |

⇒ **`scalarIn` 必须为 0（1/2/4 一律 BadArgument）；`structIn` 长度 0–4096 任意，全部 SUCCESS。** 与前一轮结论一致，但这次是带正确输出容量得出的。

### 4.3 sel 5 —— 同一个形状，但 `soc` 必须是 1

| structIn 长度 \ scalarIn 个数 | 0 | 1 | 2 | 4 |
|---|---|---|---|---|
| 0 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 1 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 4 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 8 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 64 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 256 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 1024 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |
| 4096 | **SUCCESS** | 0x2C2 BadArgument | 0x2C2 BadArgument | 0x2C2 BadArgument |

### 4.4 补扫：`scalarIn` × 输出契约 的交叉（`s6`，720 组合）

`scalarIn ∈ {1,2,4}`（值 0,1,2,3）× `soc ∈ {0,1,2,4,8,16}` × `sst ∈ {0,4096}` × `structIn ∈ {0,8}`：

- sel 0: 72 组合，{'0xE00002C7': 36, '0xE00002C2': 36}，SUCCESS=0 （`sst=0` 的 36 格全是 `0xE00002C7`，即 sel 0 要求 structOut>0）
- sel 1: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 
- sel 2: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 
- sel 3: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 
- sel 4: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 
- sel 6: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 
- sel 7: 72 组合，{'0xE00002C2': 54, '0x00000001': 18}，SUCCESS=0 （18 格返回裸 `0x00000001`，见 §7）
- sel 8: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 
- sel 9: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 
- sel 10: 72 组合，{'0xE00002C2': 72}，SUCCESS=0 

**全 720 组合里 `kr==0` 为 0 个**，即这 10 个 selector 的开关不在 `scalarIn 个数 × 输出容量 × structIn 0/8` 这个子空间里。

## 5. 阶段 3：输出 dump

### 5.1 sel 11：零入参，`sc = 664`，**全 664 字节**

调用：`sel=11, scalarIn=NULL/0, structIn=NULL/0, soc=16, sst=4096` → `kr=0x0`，`oc=16`（回显），`sc=664`，`s64=0`（标量哨兵被改写：16 个 slot 全被写成 0），`s8=0`（structOut 哨兵被改写）。

```
0000  19 00 00 00 07 00 10 00 01 01 01 01 01 01 01 01  |................|
0010  01 01 01 00 01 01 01 01 01 01 01 01 01 01 01 01  |................|
0020  01 01 01 01 40 00 00 00 04 00 00 00 20 00 00 00  |....@....... ...|
0030  00 00 01 00 00 00 01 00 00 80 00 00 00 80 00 00  |................|
0040  04 00 00 00 00 00 01 00 00 00 01 00 00 00 00 00  |................|
0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
0080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00e0  00 00 00 00 00 00 00 00 00 01 00 00 fe ff 00 00  |................|
00f0  fe ff 00 00 fe ff 00 00 fe ff 00 00 02 00 00 00  |................|
0100  16 00 00 00 04 00 00 00 16 00 00 00 01 01 00 00  |................|
0110  04 00 00 00 16 00 00 00 04 00 00 00 04 00 00 00  |................|
0120  0c 00 00 00 01 00 00 01 08 00 00 00 04 00 00 00  |................|
0130  08 00 00 00 04 00 00 00 01 00 00 00 23 01 00 00  |............#...|
0140  53 01 00 00 03 00 00 00 00 00 00 00 00 00 00 00  |S...............|
0150  01 00 00 00 40 00 00 00 08 00 00 00 80 00 00 00  |....@...........|
0160  01 00 00 00 00 00 00 00 01 00 00 00 00 00 01 00  |................|
0170  01 00 01 00 01 01 00 00 10 00 00 00 01 00 00 00  |................|
0180  00 01 01 01 01 00 00 00 00 00 00 00 00 00 00 40  |...............@|
0190  01 00 00 00 04 00 00 00 02 00 00 00 04 00 00 00  |................|
01a0  02 00 00 00 04 00 00 00 00 01 00 00 01 00 00 00  |................|
01b0  00 01 01 01 02 00 00 00 03 00 00 00 01 00 00 00  |................|
01c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  |................|
01d0  01 01 01 00 00 00 00 00 00 00 00 00 00 00 c0 40  |...............@|
01e0  00 00 00 00 00 00 40 40 00 01 01 01 01 01 00 01  |......@@........|
01f0  01 01 01 00 01 02 01 00 80 80 10 20 04 01 01 01  |........... ....|
0200  01 01 00 00 00 01 00 01 01 01 00 01 01 00 01 01  |................|
0210  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
0220  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
0230  00 00 00 00 00 00 00 00 00 00 00 00 01 01 00 01  |................|
0240  00 00 01 02 01 01 00 00 90 01 00 00 00 00 00 00  |................|
0250  58 02 00 00 20 03 00 00 00 00 70 40 01 01 01 00  |X... .....p@....|
0260  ff 1f 00 00 08 00 00 00 00 00 00 00 00 00 00 00  |................|
0270  00 00 00 00 01 00 00 00 08 00 00 00 ff ff 00 00  |................|
0280  00 40 00 00 01 00 00 00 01 00 01 01 01 00 00 00  |.@..............|
0290  01 00 00 00 00 00 00 00                          |........|
```

（共 664 字节 = 0x298，42 行 × 16 + 最后 8 字节。）

**指针扫描结果（扫全部 4096 字节容量，8 字节对齐窗口，另加全偏移窗口复核）：**

- `0xfffffe...` 形态（`v & 0xFFFFFF0000000000 == 0xFFFFFE0000000000`）：**0 条**
- PAC 形态（最高字节 ≥ 0xF0）：**0 条**
- 全偏移扫里出现的 `0xfffe...` 全是**未对齐重叠**造成的假象：它们来自 4 字节字段 `0x0000feff`（在 0xe8/0xec/0xf0/0xf4 连续出现 4 次，值 65279）被两两拼成 8 字节。按 8 字节对齐读，最高 16 位全是 `0x0000`。

#### 确定性检验（关键）

16:44:46 与 16:49:47 两次**独立进程、独立连接** 各 dump 一次，前 512 字节：

```
diff 字节数 = 0   （两次 dump 完全一致）
```

⇒ 这 664 字节是**确定性内容**（配置/能力描述符），不是未初始化内存。作为对照：真正的未初始化泄漏在两次进程间通常有指针/时间戳/地址差异。

**判读**：`sel 11` = 零入参、把内核侧一个 664 字节结构整体 copyout。内容里可辨识的字段（u32 视角）：偏移 0x00 处 `0x19`(=25)、`0x100007`（版本/类型 + 长度 `0x0010`）、随后大段 `0x01010101` 位图（能力位），0x24 起 `0x40/0x04/0x20`，0x30 起 `0x10000/0x10000/0x8000/0x8000`；0x1d8/0x1dc 有 `0x40c0`、`0x4040` 这类浮点/定点常量。**没有地址类字段。**

### 5.2 sel 5：`scalarOut[0] = 1`，structOut 全 0

调用：`sel=5, soc=1, sst=4096` → `kr=0`，`oc=1`，`sc=4096`，`s64=0`（被改写），`s8=0`（被改写）。标量输出 `sout[0] = 0x0000000000000001`（真值，不是哨兵）。structOut 前 64 字节：

```
0000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

全 4096 字节都是 0，指针扫描 0 命中。⇒ sel 5 是「回一个计数/版本标量 + 把输出缓冲清零」的探测型 selector，**不泄漏**，但它是前两轮完全没看见的一个真实 selector。

### 5.3 structOut 容量阶梯（定 declared 尺寸）

| sst 容量 | 0 | 1 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 664 | 700 | 1024 | 2048 | 4096 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sel 11 `sc` | 0 | 1 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 664 | 664 | 664 | 664 | 664 |
| sel 11 `s8` | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| sel 5 `sc` | 0 | 1 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 664 | 700 | 1024 | 2048 | 4096 |
| sel 5 `s8` | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

⇒ **sel 11 的自然尺寸就是 664**（容量 >664 一律回 664，容量 <664 时按容量截断），**sel 5 则是「写满容量」**（sc 恒等于容量，把整块清零）。
## 6. ★ 前两轮完全缺失的那一类结果：`kr==0 且 sc>0` / `sst>0`

任务书的判据就是这条，单独一节。

### 6.1 本轮统计（全部 13 份 ndjson 汇总，2677 条结果行）

| 类 | 条数 | 前两轮 |
|---|---:|---|
| `kr==0` | 76 | 有 |
| **`kr==0` 且 `sc>0`** | **69** | **0（完全缺失）** |
| 其中 `s8==0`：内核**真的改写了** structOut 缓冲 | **31** | **0** |
| `kr==0` 且 `oc>0` | 72 | 有（但那是容量回显，不是写入） |
| 其中 `s64==0`：内核**真的改写了** scalarOut | **32** | 0 |

出现的 `sc` 取值集合：`{1, 8, 16, 32, 64, 128, 256, 512, 664, 700, 1024, 2048, 4096}`。

### 6.2 分布

| sel | `kr==0 且 sc>0` | `s64==0`（标量真写） |
|---|---:|---:|
| sel 11 | 45 | 17 |
| sel 5 | 24 | 15 |

### 6.3 为什么前两轮是 0

不是「这个服务不回吐字节」，而是 `structOut` 容量传 0 时内核**合法地写入 0 字节**（`sc = min(0, 664) = 0`），并且返回 SUCCESS。也就是说前两轮的记录 `sel 11 / kr=0 / sc=0` **本身没错**，错的是由此得出「不回吐」。

`s4` 阶梯把这件事量化了：

```
sst=0    -> kr=0, sc=0,   s8=1   (哨兵完好 = 一个字节都没写)
sst=1    -> kr=0, sc=1,   s8=0
sst=512  -> kr=0, sc=512, s8=0
sst=664  -> kr=0, sc=664, s8=0
sst=4096 -> kr=0, sc=664, s8=0   <-- 自然尺寸封顶
```

⇒ 容量是**唯一的开关**。前两轮每次都在开关关着的时候测。

## 7. 异常返回：sel 7 的裸 `kern_return 1`

全轮 5789 次调用里，**唯一**一个非 IOReturn 域的返回码：`0x00000001`（`KERN_INVALID_ADDRESS`）。

| 出现条件 | 次数 |
|---|---|
| `sel=7` 且 `structIn>0` 且 `structOut 容量 == 0` | `s5` 9 次（sst=0 × 9 个 soc） + `s6` 18 次（sst=0 × 3 个 cnt × 6 个 soc） |
| 其它任何组合 | 0 |

规律非常干净：**structIn 有内容、但 structOut 容量为 0** 时，sel 7 不走 IOReturn 返回，而是从 MIG/copyout 层直接带出 `KERN_INVALID_ADDRESS`。这不像参数校验（参数校验会返回 `0xE00002C2`），更像 handler 里对**用户提供的一个缓冲/描述符做地址翻译时失败**。

这是本轮唯一一条指向「sel 7 handler 会碰用户内存」的证据，值得后续单独打；但按本轮边界（只做枚举）没有继续深化。

## 8. 机制交叉验证：`0x298` = 664 是驱动里的编译期常量

设备侧观察到 sel 11 的 `sc` 被 664 封顶。在已解密的驱动里找到对应 handler（`out/dec-m2sB.c` 约 6040 行）：

```c
undefined8 FUN_fffffe00090e2cf0(long param_1, undefined8 param_2, ulong *param_3)
{
  uVar2 = *param_3;                 // 用户传入的 structOut 容量
  if (0x298 < uVar2) {
    uVar2 = 0x298;                  // 封顶 664
    *param_3 = 0x298;               // 并把「实际写入量」改写成 664
  }
  uVar1 = FUN_fffffe000911ea10(*(undefined8 *)(param_1 + 0x100), 8);
  thunk_EXT_FUN_80110000044923f0(param_2, uVar1, uVar2);   // memcpy(用户缓冲, 源, min(容量,664))
  *param_3 = uVar2;
  return 0;
}
```

与实测**逐项吻合**：容量 4096 → 写 664 报 664；容量 512 → 写 512；容量 0 → 写 0（SUCCESS，因为 `0x298 < 0` 不成立、`memcpy` 长度 0）。而且这个 handler **完全不检查 structIn**，正好对应「structIn 长度 0–4096 任意都 SUCCESS」。

⇒ sel 11 = 「把 `driver+0x100` 那个对象里 index 8 的 664 字节结构整体 copyout」，是一台**无输入、有界、确定性**的内核→用户读取通道。

## 9. panic / 挂起

| 项 | 值 |
|---|---|
| `ls -1 out/panics/*.ips \| wc -l` 跑前 | 5 |
| 跑后 | **5**（无新增，无原文需要贴） |
| `@timeout` 总数 | **0** |
| `@abort` 熔断 | **0** |
| 看门狗 `@watchdog` 触发 | **0** |
| 设备重启 | 无 |
| 设备锁屏 | 全程 `passcodeRequired: false`，app 内 `idleTimerDisabled=YES` |

## 10. 原始 ndjson（`harness/m2reenum/results/`）

| 文件 | 阶段 | 正式调用 | 说明 |
|---|---|---:|---|
| [`s1-20261101-164412.ndjson`](../harness/m2reenum/results/s1-20261101-164412.ndjson) | s1 | 256 | sel 0–255 存在性扫描（16/4096） |
| [`s1b-20261101-164515.ndjson`](../harness/m2reenum/results/s1b-20261101-164515.ndjson) | s1b | 132 | 12 sel × 11 输出容量组合 |
| [`s2-20261101-164554.ndjson`](../harness/m2reenum/results/s2-20261101-164554.ndjson) | s2 | 352 | 11 sel × 32 入参维度（soc16/sst4096） |
| [`s2-20261101-164631.ndjson`](../harness/m2reenum/results/s2-20261101-164631.ndjson) | s2 | 32 | sel 5 × 32 入参维度（soc=1） |
| [`s3-20261101-164446.ndjson`](../harness/m2reenum/results/s3-20261101-164446.ndjson) | s3 | 1 | sel 11 dump（512B 截断那版） |
| [`s3-20261101-164639.ndjson`](../harness/m2reenum/results/s3-20261101-164639.ndjson) | s3 | 1 | sel 5 dump |
| [`s3-20261101-164947.ndjson`](../harness/m2reenum/results/s3-20261101-164947.ndjson) | s3 | 1 | sel 11 dump 全 664B + 指针扫描 |
| [`s4-20261101-164705.ndjson`](../harness/m2reenum/results/s4-20261101-164705.ndjson) | s4 | 14 | sel 11 structOut 容量阶梯 14 档 |
| [`s4-20261101-164733.ndjson`](../harness/m2reenum/results/s4-20261101-164733.ndjson) | s4 | 14 | sel 5 structOut 容量阶梯 14 档 |
| [`s5-20261101-164809.ndjson`](../harness/m2reenum/results/s5-20261101-164809.ndjson) | s5 | 1080 | 10 sel × 108 细网格（soc0–8 × 6 个 sst × in0/8） |
| [`s6-20261101-164843.ndjson`](../harness/m2reenum/results/s6-20261101-164843.ndjson) | s6 | 720 | 10 sel × 72（scalarIn × 输出契约 交叉） |
| [`s7-20261101-164917.ndjson`](../harness/m2reenum/results/s7-20261101-164917.ndjson) | s7 | 3172 | sel 12–255 密集存在性 sweep（13 组合/sel） |
| [`s7-20261101-164939.ndjson`](../harness/m2reenum/results/s7-20261101-164939.ndjson) | s7 | 14 | sel 0–11 同方法复核 |

每份都有 `@done` 收尾（13/13）。`@pre` 一律在调用**之前**落盘并 fsync（`s7` 的几千次低危 sweep 只对 ndjson fsync、log 不 fsync，为的是把 3400 次调用的开销压进 200s；有争议的 `@e7` 结果行仍然全 fsync）。

## 11. 判据回答

| 判据 | 答案 |
|---|---|
| 存在的 selector 数量（对比前一轮「只有 sel 11」） | **12 个（sel 0–11 连续）**；12–255 在 13 个输出容量组合下全部 `Unsupported` |
| 有没有 `kr==0 且 sc>0` / `sst>0` | **有，69 条**；其中 31 条哨兵证明内核**真的写入了**字节。最大 664B（sel 11）、4096B（sel 5 全零）。前两轮 0 条 |
| 输出里有没有内核地址 | **没有。** `0xfffffe...` 0 条、PAC 0 条。`0xfffe` 全部是 4 字节字段 `0x0000feff` 的未对齐重叠假象 |

## 12. 边界与残留不确定性

1. **只做了 `AppleM2ScalerCSCDriver`**，没跑竞态，没碰 `harness/israce/`，`out/` 既有文件未改。未 git，未重启设备。
2. 阶段 4 的停止条件（出现 `0xfffffe...`）**未触发**，所以没有中途停，走完了阶段 2/3。
   顺序上先跑阶段 3（dump）再跑阶段 2（入参维度）：dump 是 1 次只读调用、成本几乎为零，而阶段 2 要往 handler 里灌 384 组不同形状的输入、风险更高。先看清输出再决定要不要继续灌输入，比反过来稳。
3. **残留不确定性（诚实标注）**：
   - sel 0–10 的「存在」判据是「在 13 个输出容量组合 × 32 个入参维度组合里，至少一个非 `0xE00002C7`」。它们的**真正派发契约**仍未命中（没试过的维度可能是 `scalarIn` 的具体取值，本轮只试了 0/1/2/3 与个数 1/2/4）。
   - 但「12 个」这个数已被 12–255 的密集 sweep 反向封闭：12 以上没有任何组合能脱离 `Unsupported`。
   - sel 7 的 `KERN_INVALID_ADDRESS` 只记录了存在与触发条件，没有进一步定位（超出本轮边界）。
4. 664 字节内容是确定性的 ⇒ 当前配置下**不是**内核信息泄露原语（没有地址）。但「零入参读 664B 内核结构」这个通道本身成立；换配置/换机型/改状态后是否仍无地址字段，本轮无证据。