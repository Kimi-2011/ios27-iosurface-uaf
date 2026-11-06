"""扫描「27.2 新增了拒绝路径」的改动 —— 这是补丁猎取里信息量最高的一类。

三个指纹：
  1. 新增指令里构造 IOReturn 错误码（`mov wN,#0x2c2|0x2bc|0x2e2|0x2c1` + `movk wN,#0xe000,lsl #16`）
     -> 新增了一条「本来能过、现在被拒」的路径
  2. 原本写 0（成功）的分支改成写错误码 -> 静默成功变成显式失败
  3. 新增 `ldrb wN,[Xb,#off]` + `tbz/tbnz` 且 27.0.1 侧没有该偏移
     -> 新增「粘滞字节」门（与已知的 IOSurface +0xf1 同型）

输出：`out/PATCH-HUNT-errorpaths.md`，由 `out/PATCH-HUNT.md` 引用。
"""
import json
import os
import re
import difflib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, 'out', 'PATCH-HUNT.raw.json')
OUT = os.path.join(ROOT, 'out', 'PATCH-HUNT-errorpaths.md')

IORET = {'0x2c2': 'kIOReturnBadArgument', '0x2bc': 'kIOReturnError',
         '0x2c7': 'kIOReturnUnsupported', '0x2e2': 'kIOReturnNotPermitted',
         '0x2c1': 'kIOReturnNotPrivileged', '0x2bd': 'kIOReturnNoMemory',
         '0x2d8': 'kIOReturnNotOpen/自定义', '0x2d9': '自定义'}
ERRSEQ = re.compile(r'mov w(\d+),#(0x[0-9a-f]{1,4})')
MOVK = re.compile(r'movk w(\d+),#0xe000')


def diff(c):
    a, b = c['tokens_2701'], c['tokens_272']
    sm = difflib.SequenceMatcher(None, a, b)
    add, rem = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ('insert', 'replace'):
            add += b[j1:j2]
        if tag in ('delete', 'replace'):
            rem += a[i1:i2]
    return add, rem


def error_codes(lines):
    """找 mov wN,#lo + movk wN,#0xe000 成对 => 0xE0000<lo>"""
    regs = {}
    out = []
    for ln in lines:
        m = ERRSEQ.match(ln)
        if m:
            regs[m.group(1)] = m.group(2)
            continue
        m = MOVK.match(ln)
        if m and m.group(1) in regs:
            lo = regs[m.group(1)]
            try:
                v = 0xE0000000 | int(lo, 16)
            except ValueError:
                continue
            out.append(v)
    return out


def byte_gates(add, rem, old_tokens):
    """新增的 ldrb/tbz 组合及其字段偏移。

    严格条件（照 IOSurface +0xf1 的判定标准）：这个 **字段偏移** 在 27.0.1 的同一函数里
    必须一次都没被访问过。否则只是重排后 ldrb 落进了 diff 窗口，是假阳性。
    """
    gates = []
    for i, ln in enumerate(add):
        if not ln.startswith(('ldrb', 'ldrsb')):
            continue
        m = re.search(r'#(0x[0-9a-f]+|\d+)\]', ln)
        if not m:
            continue
        off = m.group(1)
        if any(off + ']' in t and ('ldrb' in t or 'ldrsb' in t or 'strb' in t) for t in old_tokens):
            continue                      # 27.0.1 也访问过这个偏移 => 不是新字段门
        nxt = ' '.join(add[i + 1:i + 3])
        if 'tbz' in nxt or 'tbnz' in nxt or 'cbz' in nxt or 'cbnz' in nxt:
            gates.append((off, ln, nxt))
    return gates


def main():
    rows = json.load(open(RAW))
    err, gates, bounds = [], [], []
    for r in rows:
        for c in r['changed']:
            add, rem = diff(c)
            if not add:
                continue
            ec_add = error_codes(add)
            ec_rem = error_codes(rem)
            base = {'kext': r['kext'], 'va1': c['va_2701'], 'va2': c['va_272'],
                    'add': add, 'rem': rem}
            if ec_add and len(add) <= 30 and len(rem) <= 30:
                err.append(dict(base, codes=ec_add, old=ec_rem,
                                pre=sorted(set(error_codes(c['tokens_2701'])))))
            g = byte_gates(add, rem, c['tokens_2701'])
            # 真插入才可能是「新增门」；重排出来的大 diff 不算
            if len(add) <= 12 and len(rem) <= 6:
                pass
            else:
                g = []
            if g:
                gates.append(dict(base, gates=g))
            # 新增边界检查：cmp #imm 或 b.hi/b.hs/b.lo/b.ls
            cmp_add = [x for x in add if x.startswith('cmp ') and '#' in x]
            if cmp_add and len(add) <= 24 and not ec_add:
                bounds.append(dict(base, cmps=cmp_add))

    with open(OUT, 'w') as f:
        w = f.write
        w('# 新增拒绝路径 / 字节门（27.2 相对 27.0.1）\n\n')
        w('由 `tools/errorpath_scan.py` 从 `out/PATCH-HUNT.raw.json` 生成。\n\n')

        w(f'## A. 新增了 IOReturn 错误路径（{len(err)} 处）\n\n')
        for e in err:
            w(f"### `{e['kext']}`  `0x{e['va1']:x}` → `0x{e['va2']:x}`\n\n")
            w('- 27.2 新增错误码: ' + ', '.join(f'`0x{v:08X}`' for v in e['codes']) + '\n')
            if e['old']:
                w('- 27.0.1 原本: ' + ', '.join(f'`0x{v:08X}`' for v in e['old']) + '\n')
            elif e.get('pre'):
                w('- 27.0.1 同函数里已有的错误码: ' + ', '.join(f'`0x{v:08X}`' for v in e['pre']) + '（本路径原本不返回错误）\n')
            else:
                w('- 27.0.1 原本: **无错误码**（该路径原本不返回错误）\n')
            w('```diff\n')
            for x in e['rem'][:25]:
                w(f'- {x}\n')
            for x in e['add'][:25]:
                w(f'+ {x}\n')
            w('```\n\n')

        w(f'## B. 新增字节门（`ldrb`+`tbz`，与 IOSurface `+0xf1` 同型）（{len(gates)} 处）\n\n')
        for g in gates:
            fields = sorted({x[0] for x in g['gates']})
            w(f"- `{g['kext']}` `0x{g['va1']:x}` → `0x{g['va2']:x}`  "
              f"字段 {', '.join('`'+x+'`' for x in fields)}  "
              f"（`{g['gates'][0][1]}` / `{g['gates'][0][2]}`）\n")
        w('\n')

        w(f'## C. 新增边界比较（小改动，{len(bounds)} 处，列前 25）\n\n')
        w('| kext | 函数 27.0.1 → 27.2 | 新增比较 | diff |\n|---|---|---|---|\n')
        for b in bounds[:25]:
            w(f"| `{b['kext']}` | `0x{b['va1']:x}` → `0x{b['va2']:x}` | "
              f"{'<br>'.join(b['cmps'][:4])} | +{len(b['add'])}/−{len(b['rem'])} |\n")
    print(f'新增错误路径 {len(err)} / 字节门 {len(gates)} / 边界比较 {len(bounds)} -> {OUT}')


if __name__ == '__main__':
    main()
