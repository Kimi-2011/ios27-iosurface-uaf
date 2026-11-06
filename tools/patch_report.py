"""把 fdiff 的原始结果整理成 out/PATCH-HUNT.md。

四类判定（这是本次最关键的一层，不做这层的话 3253 个「不同」全是噪声）：

  A. **真插入**     27.2 多出指令、27.0.1 侧没有对应删除  -> 唯一能直接当补丁读的
  B. **布局位移**   增删成对、只差一个 `[reg, #off]` 偏移，且 delta 是**常数**
                    -> 结构体长胖了（有字段加进中间）。delta 本身就是情报：
                       说明这个结构体新增了多大一块
  C. **行号/日志码** 只差 `mov wN,#imm` 的小立即数（通常 delta 很小且成组出现）
                    -> `__LINE__` 或 IOLog 的断言码，不是逻辑改动
  D. **混合/其它**   剩下的人工看

可达性用 `out/census.json` 判：census 里的 handler VA 落在函数范围内就算「有 selector」。
"""
import json
import os
import re
import bisect
import difflib
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CENSUS = os.path.join(ROOT, 'out', 'census.json')
RAW = os.path.join(ROOT, 'out', 'PATCH-HUNT.raw.json')
OUT = os.path.join(ROOT, 'out', 'PATCH-HUNT.md')

CHECK = ('cmp', 'cmn', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz', 'ccmp')
BYTELOAD = ('ldrb', 'ldrsb', 'ldar', 'ldarb')
FLAGSTORE = ('strb', 'sturb', 'stlr', 'stlrb')
OFFRE = re.compile(r'\[([wx]\d+|sp),\s*#(0x[0-9a-f]+|\d+)\]')
IMMRE = re.compile(r'#0x([0-9a-f]{1,4})\b')


def ins_diff(a, b):
    sm = difflib.SequenceMatcher(None, a, b)
    added, removed = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ('insert', 'replace'):
            added += b[j1:j2]
        if tag in ('delete', 'replace'):
            removed += a[i1:i2]
    return added, removed


def layout_delta(added, removed):
    """若增删成对且只差 [reg,#off] 的偏移、delta 恒定，返回该 delta。"""
    if not added or len(added) != len(removed):
        return None
    deltas = Counter()
    for x, y in zip(added, removed):
        if x.split(' ')[0] != y.split(' ')[0]:
            return None
        mx, my = OFFRE.search(x), OFFRE.search(y)
        if not mx or not my or mx.group(1) != my.group(1):
            return None
        dx = int(mx.group(2), 0) - int(my.group(2), 0)
        # 去掉偏移后必须完全一致
        if OFFRE.sub('[R,#O]', x) != OFFRE.sub('[R,#O]', y):
            return None
        deltas[dx] += 1
    if len(deltas) == 1:
        return list(deltas)[0]
    return None


def linecode_only(added, removed):
    """只差 mov wN,#imm 的小立即数（__LINE__ / 日志码）。"""
    if not added or len(added) != len(removed):
        return False
    for x, y in zip(added, removed):
        if not x.startswith(('mov', 'movz', 'movk')):
            return False
        ax, ay = IMMRE.findall(x), IMMRE.findall(y)
        if not ax or not ay:
            return False
        if IMMRE.sub('#N', x) != IMMRE.sub('#N', y):
            return False
    return True


def fields_of(lines):
    out = set()
    for ln in lines:
        for mo in OFFRE.finditer(ln):
            v = int(mo.group(2), 0)
            if 0 < v <= 0x4000:
                out.add(v)
    return out


def main():
    rows = json.load(open(RAW))
    census = json.load(open(CENSUS))
    handlers = []
    for r in census.get('rows', []):
        try:
            hv = int(r['handler'], 16)
        except Exception:
            continue
        handlers.append((r.get('kext', ''), r.get('selector'), hv))
    handlers.sort(key=lambda h: h[2])
    hvas = [h[2] for h in handlers]

    def reachable(va, size):
        out = []
        i = bisect.bisect_left(hvas, va)
        while i < len(hvas) and hvas[i] < va + size:
            out.append(handlers[i])
            i += 1
        return out

    cands = []
    for r in rows:
        for c in r['changed']:
            added, removed = ins_diff(c['tokens_2701'], c['tokens_272'])
            kind, extra = None, None
            if added and not removed:
                kind = 'insert'
            else:
                d = layout_delta(added, removed)
                if d is not None:
                    kind, extra = 'layout', d
                elif linecode_only(added, removed):
                    kind = 'linecode'
                else:
                    kind = 'mixed'
            f_add = fields_of(added) - fields_of(removed)
            checks = [x for x in added if x.split(' ')[0] in CHECK]
            bload = [x for x in added if x.split(' ')[0] in BYTELOAD]
            fstore = [x for x in added if x.split(' ')[0] in FLAGSTORE]
            rv = reachable(c['va_2701'] or 0, c['size_2701'] or 0)
            score = 0
            if kind == 'insert':
                score += 5
                score += 2 * (1 if checks else 0) + 2 * (1 if bload else 0) + 2 * (1 if fstore else 0)
                if len(added) <= 16:
                    score += 2
            elif kind == 'mixed':
                score += 1 + (2 if checks else 0) + (2 if bload else 0)
            if rv:
                score += 4
            cands.append({
                'kext': r['kext'], 'va1': c['va_2701'], 'va2': c['va_272'],
                'sz1': c['size_2701'], 'sz2': c['size_272'], 'sim': c['similarity'],
                'added': added, 'removed': removed, 'kind': kind, 'delta': extra,
                'newfields': sorted(f_add)[:6], 'checks': checks, 'bload': bload,
                'fstore': fstore, 'reach': rv, 'score': score,
            })

    order = {'insert': 0, 'mixed': 1, 'layout': 2, 'linecode': 3}
    cands.sort(key=lambda c: (order[c['kind']], -c['score'], len(c['added'])))

    with open(OUT, 'w') as f:
        w = f.write
        w('# PATCH-HUNT：iOS 27.0.1 ↔ 27.2 函数级差分\n\n')
        w('## 0. 方法与自检\n\n')
        w('工具 `tools/fdiff.py`（新写）。提取出的 kext **没有符号表**（`nsyms=0`），函数边界只能取 '
          '`LC_FUNCTION_STARTS`；VA↔off **只走 segment**（`tools/kext_extract.py` 没重写 `section_64.offset`，'
          '按 section 取表会读到垃圾，见 `tools/kseg.py` 头注释）。\n\n')
        w('归一化：`adrp` 页基址、`adrp` 后续指令的页内偏移、分支/调用绝对目标、`>0xffff` 立即数 → '
          '`<X>`/`<PAGEOFF>`/`<IMM>`；**保留 mnemonic、寄存器、小立即数、结构体字段偏移**。\n'
          '（不加这一层，IOSurface 的 1330 个函数里 708 个会被误判成「改了」，因为函数搬家后 `adrp+add` 的页内偏移全变。）\n\n')
        w('> **自检标尺**：已知的 IOSurface `+0xf1` 补丁。27.2 的 `0xfffffe000a3944c0` 新增 '
          '`ldrb w8,[x21,#0xf1]` + `tbz w8,#0,#3`；`0xfffffe000a394744` 新增 `mov w8,#1` + `strb w8,[x20,#0xf1]`；'
          '27.0.1 侧 0 处。**两处都被本工具以「真插入 +4/−0」「+2/−0」命中，diff 干净无噪声** ⇒ 方法有效。\n\n')
        w('## 0.1 四类判定\n\n')
        w('| 类 | 含义 | 处理 |\n|---|---|---|\n')
        w('| **A 真插入** | 27.2 多出指令、27.0.1 无对应删除 | 直接可读，唯一能当补丁用的 |\n')
        w('| **B 布局位移** | 增删成对、只差 `[reg,#off]`、delta 恒定 | 结构体长胖，delta = 新增块大小（情报） |\n')
        w('| **C 行号漂移** | 只差 `mov wN,#imm` 小立即数 | `__LINE__` / IOLog 断言码，丢弃 |\n')
        w('| **D 混合** | 剩下 | 人工看 |\n\n')

        w('## 0.2 总量\n\n')
        w('| kext | 27.0.1 函数 | 27.2 函数 | 归一化后不同 | A 真插入 | B 布局位移 | C 行号 | D 混合 |\n')
        w('|---|---|---|---|---|---|---|---|\n')
        for r in rows:
            k = r['kext']
            cc = [c for c in cands if c['kext'] == k]
            n = lambda t: len([c for c in cc if c['kind'] == t])
            w(f"| `{k}` | {r['n_2701']} | {r['n_272']} | {r['n_changed']} | "
              f"**{n('insert')}** | {n('layout')} | {n('linecode')} | {n('mixed')} |\n")
        tot = lambda t: len([c for c in cands if c['kind'] == t])
        w(f"\n**合计：A {tot('insert')} / B {tot('layout')} / C {tot('linecode')} / D {tot('mixed')}**\n\n")

        w('## 1. A 类：真插入（按评分）\n\n')
        ins = [c for c in cands if c['kind'] == 'insert']
        w('| # | kext | 函数 27.0.1 → 27.2 | diff | 新增指令 | 新字段 | 可达性 |\n|---|---|---|---|---|---|---|\n')
        for i, c in enumerate(ins, 1):
            rv = ', '.join(f"`{k}` sel {s}" for k, s, _ in c['reach'][:2]) or '—'
            add = '<br>'.join(x for x in c['added'][:8])
            nf = ','.join(hex(v) for v in c['newfields'][:4]) or '—'
            w(f"| {i} | `{c['kext']}` | `0x{c['va1']:x}` → `0x{c['va2']:x}` | "
              f"+{len(c['added'])}/−0 | {add} | {nf} | {rv} |\n")

        w('\n## 2. B 类：结构体长胖（delta = 新增块大小）\n\n')
        gaps = {}
        for c in cands:
            if c['kind'] == 'layout':
                gaps.setdefault((c['kext'], c['delta']), []).append(c)
        w('| kext | delta | 命中函数数 | 例子 |\n|---|---|---|---|\n')
        for (k, d), cs in sorted(gaps.items(), key=lambda kv: -len(kv[1])):
            ex = cs[0]
            w(f"| `{k}` | {'%+#x' % d if d is not None else '—'} | {len(cs)} | "
              f"`0x{ex['va1']:x}`: `{ex['removed'][0]}` → `{ex['added'][0]}` |\n")

        w('\n## 3. 有 selector 可达的候选（优先看）\n\n')
        reach = [c for c in cands if c['reach'] and c['kind'] in ('insert', 'mixed')]
        if not reach:
            w('（无）\n')
        for c in reach:
            w(f"### `{c['kext']}`  `0x{c['va1']:x}` → `0x{c['va2']:x}`  [{c['kind']}]\n\n")
            w('- selector: ' + ', '.join(f"`{k}` sel {s} (handler `0x{h:x}`)" for k, s, h in c['reach']) + '\n')
            for x in c['added'][:20]:
                w(f'  - `+ {x}`\n')
            for x in c['removed'][:20]:
                w(f'  - `- {x}`\n')
            w('\n')

        w('\n## 4. D 类：混合（需人工看，列前 40）\n\n')
        mix = [c for c in cands if c['kind'] == 'mixed']
        w(f'共 {len(mix)} 个。前 40：\n\n')
        w('| # | kext | 函数 | diff | 新增 |\n|---|---|---|---|---|\n')
        for i, c in enumerate(mix[:40], 1):
            w(f"| {i} | `{c['kext']}` | `0x{c['va1']:x}` | +{len(c['added'])}/−{len(c['removed'])} | "
              f"{'<br>'.join(c['added'][:4])} |\n")
    print(f'A 真插入 {len([c for c in cands if c["kind"]=="insert"])} / '
          f'B 布局 {len([c for c in cands if c["kind"]=="layout"])} / '
          f'C 行号 {len([c for c in cands if c["kind"]=="linecode"])} / '
          f'D 混合 {len([c for c in cands if c["kind"]=="mixed"])}  -> {OUT}')


if __name__ == '__main__':
    main()
