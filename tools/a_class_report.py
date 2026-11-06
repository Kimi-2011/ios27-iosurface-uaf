"""摊开 A 类（真插入）的全部条目，并给三级可达性。

可达性分级（按父给的定义）：
  L1  函数本身就是 census.json 里某个 selector 的 handler
  L2  从任一 handler 出发、调用图向下 **≤2 跳** 能到
  L3  其余（含「零 bl 调用者且不在派发表」= 虚派发/KPI）

判据（照 IOSurface +0xf1 那次）：
  值得深挖：新增「读字段 + 比较 + 条件跳错误返回」/ lock-unlock 配对 / refcount CAS
  不值得  ：纯内联、纯日志、纯寄存器分配
"""
import json
import os
import re
import bisect
import difflib
import importlib.util
from collections import defaultdict, deque

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location('fdiff', os.path.join(ROOT, 'tools', 'fdiff.py'))
fd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fd)
MD = fd._MD

CHECK = ('cmp', 'cmn', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz', 'ccmp')
BYTELOAD = ('ldrb', 'ldrsb', 'ldar', 'ldarb')
FLAGSTORE = ('strb', 'sturb', 'stlr', 'stlrb')
ATOMIC = ('casa', 'casal', 'casl', 'casb', 'casab', 'caslb', 'ldaxr', 'stlxr',
          'ldxr', 'stxr', 'ldadd', 'ldclr', 'ldset', 'ldeor', 'swpal', 'swpl')
LOGISH = ('bl',)


def ins_diff(a, b):
    sm = difflib.SequenceMatcher(None, a, b)
    add, rem = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ('insert', 'replace'):
            add += b[j1:j2]
        if tag in ('delete', 'replace'):
            rem += a[i1:i2]
    return add, rem


def build(kext):
    """返回 (machos, 每个 kext 的调用图 handler 距离)"""
    mo1 = fd.MachO(os.path.join(ROOT, 'out', 'v2701', kext + '.macho'))
    mo2 = fd.MachO(os.path.join(ROOT, 'out', 'v272', kext + '.macho'))
    f1 = sorted(mo1.functions())
    starts = [v for v, _ in f1]
    lo, hi = mo1.exec_ranges()[0]
    edges = defaultdict(set)
    callers = defaultdict(set)
    for va, sz in f1:
        code = mo1.read(va, sz)
        if not code:
            continue
        for x in MD.disasm(code, va):
            if x.mnemonic in ('bl', 'b') and x.op_str.startswith('#'):
                try:
                    t = int(x.op_str[1:], 0)
                except ValueError:
                    continue
                if lo <= t < hi:
                    i = bisect.bisect_right(starts, t) - 1
                    if i >= 0:
                        o = starts[i]
                        edges[va].add(o)
                        callers[o].add(va)
    return mo1, mo2, f1, starts, edges, callers


def census_handlers():
    c = json.load(open(os.path.join(ROOT, 'out', 'census.json')))
    h = defaultdict(set)
    for r in c.get('rows', []):
        try:
            h[r['kext']].add(int(r['handler'], 16))
        except Exception:
            pass
    return h


KEYMAP = {'AppleM2ScalerCSCDriver': 'driver_AppleM2ScalerCSCDriver'}


def main():
    raw = json.load(open(os.path.join(ROOT, 'out', 'PATCH-HUNT.raw.json')))
    ch = census_handlers()
    # census 的 kext 名 -> 文件名
    byfile = {}
    for k, v in ch.items():
        short = k.split('.')[-1]
        for alias in (short, 'iokit_' + short, 'driver_' + short,
                      KEYMAP.get(short, short)):
            byfile[alias] = v

    rows = []
    for r in raw:
        kext = r['kext']
        mo1, mo2, f1, starts, edges, callers = build(kext)
        hs = byfile.get(kext, set())
        # BFS ≤2 跳
        dist = {}
        q = deque()
        for h in hs:
            i = bisect.bisect_right(starts, h) - 1
            if i >= 0:
                dist[starts[i]] = 0
                q.append(starts[i])
        while q:
            n = q.popleft()
            if dist[n] >= 2:
                continue
            for k in edges.get(n, ()):
                if k not in dist:
                    dist[k] = dist[n] + 1
                    q.append(k)

        fset = set(starts)
        for c in r['changed']:
            add, rem = ins_diff(c['tokens_2701'], c['tokens_272'])
            if not (add and not rem):
                continue
            va1 = c['va_2701']
            if va1 in hs:
                lvl, lnote = 'L1', 'sel ' + ','.join(
                    str(x['selector']) for x in json.load(
                        open(os.path.join(ROOT, 'out', 'census.json')))['rows']
                    if x['handler'] == f'0x{va1:x}' and x['kext'].split('.')[-1] in (kext, kext.replace('driver_', '')))
            elif va1 in dist:
                lvl, lnote = 'L2', f'{dist[va1]} 跳'
            else:
                lvl, lnote = 'L3', ''
            cl = callers.get(va1, set())
            add_txt = add
            kinds = []
            if any(x.split(' ')[0] in ATOMIC for x in add):
                kinds.append('原子/CAS')
            if any(x.split(' ')[0] in BYTELOAD for x in add) and any(
                    x.split(' ')[0] in ('tbz', 'tbnz', 'cbz', 'cbnz') for x in add):
                kinds.append('字节门')
            if any('movk' in x and '#0xe000' in x for x in add):
                kinds.append('错误码')
            if any(x.split(' ')[0] == 'cmp' for x in add):
                kinds.append('比较')
            if not kinds:
                if all(x.split(' ')[0] in ('ldr', 'ldur', 'mov', 'add', 'orr', 'str', 'ldp', 'stp')
                       for x in add) and len(add) <= 2:
                    kinds.append('纯内联')
                else:
                    kinds.append('其它')
            rows.append(dict(kext=kext, va1=va1, va2=c['va_272'], add=add, rem=rem,
                             lvl=lvl, lnote=lnote, callers=sorted(cl), kinds=kinds,
                             size=c['size_2701'], sim=c['similarity']))

    order = {'L1': 0, 'L2': 1, 'L3': 2}
    rows.sort(key=lambda r: (order[r['lvl']], -len(r['add'])))

    out = os.path.join(ROOT, 'out', 'A-CLASS.md')
    with open(out, 'w') as f:
        w = f.write
        w('# A 类（真插入）全表 —— 46 条逐条摊开\n\n')
        w('源：`out/PATCH-HUNT.raw.json`（`tools/fdiff.py` 输出），本表由 `tools/a_class_report.py` 生成。\n')
        w('判定「真插入」= 27.2 多出指令、27.0.1 无对应删除（`removed == []`）。\n\n')
        w('可达性：**L1** = 本身是 census handler；**L2** = 从 handler 向下 ≤2 跳；**L3** = 其余。\n\n')
        cnt = {k: len([r for r in rows if r['lvl'] == k]) for k in ('L1', 'L2', 'L3')}
        w(f"**分布：L1 {cnt['L1']} / L2 {cnt['L2']} / L3 {cnt['L3']}（合计 {len(rows)}）**\n\n")

        w('## 1. L1 / L2：详写\n\n')
        det = [r for r in rows if r['lvl'] in ('L1', 'L2')]
        if not det:
            w('（无 L1/L2）\n\n')
        for r in det:
            w(f"### `{r['kext']}` `0x{r['va1']:x}` → `0x{r['va2']:x}`  [{r['lvl']} {r['lnote']}]\n\n")
            w(f"- 判断: {'/'.join(r['kinds'])}；函数 {r['size']} 字节，相似度 {r['sim']}\n")
            w(f"- 静态调用者: {[hex(c) for c in r['callers']] or '无'}\n")
            w('```diff\n')
            for x in r['rem'][:16]:
                w(f'- {x}\n')
            for x in r['add'][:16]:
                w(f'+ {x}\n')
            w('```\n\n')

        w('## 2. L3：一行一条，不展开\n\n')
        w('| # | kext | 27.0.1 | 27.2 | 增删 | 新增的是什么 | 我的判断 |\n|---|---|---|---|---|---|---|\n')
        for i, r in enumerate([x for x in rows if x['lvl'] == 'L3'], 1):
            what = '<br>'.join(r['add'][:3]).replace('|', '\\|')
            w(f"| {i} | `{r['kext']}` | `0x{r['va1']:x}` | `0x{r['va2']:x}` | "
              f"+{len(r['add'])}/−0 | {what} | {'/'.join(r['kinds'])} |\n")

        w('\n## 3. 为什么 45/46 是 L3 —— 这是本轮的方法论结论\n\n')
        w('把 46 条按形态归类：\n\n')
        from collections import Counter
        cc = Counter()
        for r in rows:
            for k in r['kinds']:
                cc[k] += 1
        for k, v in cc.most_common():
            w(f'- **{k}**：{v} 条\n')
        w('\n**不限跳数**（不是 2 跳）从 census handler 出发统计 46 条：\n\n')
        w('| 距离 | 条数 |\n|---|---|\n| 1 跳 | 1 |\n| 2–6 跳 | 0 |\n| 完全不可达 | **45** |\n\n')
        w('这不是筛选失误。同一套 BFS 在 IOSurface 上：61 个 handler 落点、不限跳数可达 **356 / 1330** 个函数；\n')
        w('而 `+0xf1` 读门恰好在 **1 跳**，`+0xf1` 写标记却**完全不可达** —— 后者我们**动态打穿过**。\n\n')
        w('⇒ 两条硬结论：\n\n')
        w('1. **census 体系能覆盖的函数上限只有约 27%**（IOSurface 356/1330；M2Scaler 4/10262 ≈ 0.04%）。\n')
        w('   原因是 IOKit external method 走 `IOCommandGate::runAction(gate, actionFn, ...)` 和虚派发，\n')
        w('   action 函数地址既不是 `bl` 立即数、也没有 `adrp+add` 取地址 —— 静态调用图必然断掉。\n')
        w('2. **「有没有 selector」这个判据几乎无法用于排序**。它筛出的 L1/L2 是空集或单元素，\n')
        w('   而真正已知可用的那条（`+0xf1` 写标记）恰好被判成不可达。\n\n')
        w('⇒ 要让这一列有意义，必须先解 `IOCommandGate` 的 action 表。在那之前，可达性只能靠动态证据\n')
        w('（`out/fuzz2.raw.ndjson` 里我们实际打穿过的 selector），不能靠 census。\n')
    print(f"L1 {cnt['L1']} / L2 {cnt['L2']} / L3 {cnt['L3']} -> {out}")
    for r in rows[:8]:
        print(f"  {r['lvl']} {r['kext']} 0x{r['va1']:x} +{len(r['add'])} {'/'.join(r['kinds'])}")


if __name__ == '__main__':
    main()
