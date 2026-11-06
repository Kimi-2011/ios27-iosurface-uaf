# 本项目的工作纪律（长期有效）

> 用户明确要求过、且违反过会造成不可恢复损失的规则。**每次动手前先看这一页。**

## R1. 迭代版本只新建，绝不覆盖 ★（2026-11-06 用户强调）

**任何代码/脚本/文档的迭代，一律新建文件，不原地改写。**

### 命名

| 目录 | 规则 |
|---|---|
| `harness/<名>/` | 源码 `main.v1.m`、`main.v2.m`、`main.v3.m` … **每个迭代一个新号** |
| `harness/<名>/main.m` | **只作为「当前装到设备上的那一份」的副本存在，永不直接编辑** |
| `out/patches/` | 报告带日期或版本号，如 `MFB-CONTRACT.v2.md` |
| `tools/` | `kdiff_all.v2.py` 形式，旧版保留 |

### 为什么

2026-11-01 12:09:58 有一版 `harness/israce/main.m` 在真机上打出了**内核 UAF**
（4/4 复现，`0xa34ff88` 同一条指令）。后来那版被原地改写覆盖，
**整个 S2 唯一的确证线索丢了三天**，靠翻 `~/.dsh/sessions/` 的会话 JSON 才逐字找回。

代价：一个已经验证过的内核内存破坏点，被一行 `>` 覆盖掉。

### 操作

```bash
# ✅ 正确
N=$(ls harness/israce/main.v*.m 2>/dev/null | sed 's/.*v\([0-9]*\)\.m/\1/' | sort -n | tail -1)
NEW="harness/israce/main.v$((N+1)).m"
cp harness/israce/main.v$N.m "$NEW"   # 从上一版复制
$EDITOR "$NEW"                        # 改新的
cp "$NEW" harness/israce/main.m       # 装之前才同步到 main.m

# ❌ 禁止
$EDITOR harness/israce/main.m         # 直接改 main.m
cat > harness/israce/main.m <<'X'     # 直接覆盖
```

### 例外

**只增不改的追加**（如 `out/*.md` 末尾加一节）可以用 `>>`，因为它不销毁旧内容。
**但如果要修正旧结论，仍然新建 `*.v2.md` 并在旧文件顶部加一行指过去，不改旧正文。**

---

## R2. 覆盖前先备份为可辨识的名字

临时备份不要用 `.bak` / `.old` 这种无信息后缀（`main.m.bak` 三天后没人知道是哪一版）。
用 `main.v3.m`；实在要临时，用 `main.v3.m.before-disposition-fix`。

## R3. 结论必须分级

「读到」= 反汇编原文 / 实测数据；「推断」= 有指令形态支撑但未验证；「未证」= 需要实验。
**不得把「未定性」写成「可疑」，更不得把「换了个形态」当成「找到了」。**

## R4. 任何「搜索返回 0」必须对照已知正例验证

检测器可能看不见（`bl` 计数看不见内联 `casa`/`casl`；`kdiff` 把分支位移变化当成新增指令）。
见 `out/TOOLING-PITFALLS.md`。

## R5. 五态分开写

build / install / launch / zero-records / ran-to-completion，不得混为一谈。
「装上了」不等于「跑完了」；「跑完了」不等于「有数据」。

## R6. 停顿即记录

每轮结束前把状态写进 `out/` 的 md，**不要依赖对话上下文**（上下文会被压缩、会被丢）。
