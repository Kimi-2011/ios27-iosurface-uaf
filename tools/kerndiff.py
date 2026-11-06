#!/usr/bin/env python3
"""桩/目标调用次数差分：27.0.1 vs 27.2。

关键：桩目标的 VA 在不同构建里会漂移，所以**不能按 VA 沿用**，
必须在每个构建里按函数体形状重新认一遍，认到了才用。
"""
import hashlib
import json
import sys
from bisect import bisect_left
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF


def fend(c, bundle, va, starts):
    i = bisect_left(starts, va)
    if i >= len(starts) or starts[i] != va:
        return None
    vm, vs, fo, sz = c.kseg(bundle, '__TEXT_EXEC')
    return (starts[i + 1] if i + 1 < len(starts) else vm + sz), fo + (va - vm), vm


def insns(c, bundle, va, starts, cap=2000):
    r = fend(c, bundle, va, starts)
    if not r:
        return []
    end, off, vm = r
    return list(md.disasm(c.d[off:off + min(end - va, cap * 4)], va))


def find_targets(c, bundle, starts):
    """按函数体形状在本构建里重新认这 4 个目标。"""
    got = {}
    for va in starts:
        il = insns(c, bundle, va, starts, cap=14)
        if not il:
            continue
        txt = ' | '.join(f'{i.mnemonic} {i.op_str}' for i in il)
        if 'lock' not in got and 'casa' in txt and 'tpidr_el1' in txt and '#0x4f8' in txt:
            got['lock'] = va
        if 'unlock' not in got and 'casl' in txt and 'wzr' in txt and 'tpidr_el1' in txt:
            got['unlock'] = va
        if 'rcinc' not in got and 'ldadd' in txt and 'add x9, x0, #0x24' in txt:
            got['rcinc'] = va
        if 'rcdec' not in got and 'ldadd' in txt and 'mov w8, #-1' in txt:
            got['rcdec'] = va
        if len(got) == 4:
            break
    return got


def masked(il):
    """位置无关签名：助记符 + 操作数形状，立即数全部抹掉。"""
    out = []
    for i in il:
        parts = []
        for o in i.operands:
            if o.type == ARM64_OP_REG:
                n = i.reg_name(o.reg)
                parts.append('zr' if n in ('wzr', 'xzr') else
                             'sp' if n == 'sp' else
                             'r' + n[1:] if n[:1] in ('x', 'w') else n)
            elif o.type == ARM64_OP_MEM:
                b = i.reg_name(o.mem.base) if o.mem.base else '-'
                ix = i.reg_name(o.mem.index) if o.mem.index else ''
                parts.append('[%s%s%s%s]' % ('sp' if b == 'sp' else ('r' + b[1:] if b != '-' else ''),
                                             ('+' + ix) if ix else '',
                                             '' if (o.mem.disp == 0) else ',#', ''))
            elif o.type == ARM64_OP_IMM:
                parts.append('#')
            else:
                parts.append('?')
        out.append(i.mnemonic + ' ' + ','.join(parts))
    return hashlib.sha1(';'.join(out).encode()).hexdigest()[:16]


def calls(c, bundle, starts, targets, stubmap):
    res = {}
    tset = {v: k for k, v in targets.items()}
    for va in starts:
        il = insns(c, bundle, va, starts, cap=1200)
        if not il:
            continue
        cnt = Counter()
        for i in il:
            if i.mnemonic in ('bl', 'b') and i.operands and i.operands[0].type == ARM64_OP_IMM:
                t = i.operands[0].imm & M
                t2 = stubmap.get(t, t)
                if t2 in tset:
                    cnt[tset[t2]] += 1
        if cnt:
            res[va] = cnt
    return res


def main():
    out = {}
    for tag, path in (('2701', 'out/kc.27.0.1.full'), ('272', '/tmp/kc272.bin')):
        c = Cache(path)
        b = 'com.apple.kernel'
        s, ok, _ = func_starts(c, b)
        print(tag, 'kernel 函数数', len(s), 'fstarts ok', ok)
        t = find_targets(c, b, s)
        print(tag, '按形状重新认到的目标:', {k: '0x%x' % v for k, v in t.items()})
        stubs = json.load(open('out/stubs.json')) if tag == '2701' else None
        sm = {}
        if stubs and b in stubs:
            sm = {int(k, 16): int(v, 16) for k, v in stubs[b].items() if v}
        cc = calls(c, b, s, t, sm)
        sig = {}
        for va in s:
            il = insns(c, b, va, s, cap=800)
            if il:
                sig.setdefault(masked(il), []).append(va)
        out[tag] = dict(targets=t, calls=cc, sig={k: v for k, v in sig.items() if len(v) == 1})
        print(tag, '唯一签名函数数:', len(out[tag]['sig']), ' 有目标调用的函数:', len(cc))
    json.dump({k: dict(targets={kk: hex(vv) for kk, vv in v['targets'].items()},
                       calls={hex(a): dict(b) for a, b in v['calls'].items()},
                       sig=v['sig'])
               for k, v in out.items()},
              open('/tmp/kerndiff.json', 'w'))
    # 配对
    a, b2 = out['2701'], out['272']
    common = set(a['sig']) & set(b2['sig'])
    print('\n可配对函数:', len(common))
    rows = []
    for sg in common:
        va1 = a['sig'][sg][0]
        va2 = b2['sig'][sg][0]
        c1 = a['calls'].get(va1, Counter())
        c2 = b2['calls'].get(va2, Counter())
        d = {k: c2.get(k, 0) - c1.get(k, 0) for k in ('rcinc', 'rcdec', 'lock', 'unlock')}
        if any(d.values()):
            rows.append(dict(f1='0x%x' % va1, f2='0x%x' % va2,
                             c1={k: c1.get(k, 0) for k in d}, c2={k: c2.get(k, 0) for k in d},
                             d=d))
    rows.sort(key=lambda r: -sum(abs(x) for x in r['d'].values()))
    print('调用差分非零的函数:', len(rows))
    json.dump(rows, open('/tmp/kerndiff_rows.json', 'w'), indent=1)
    for r in rows[:20]:
        print('  %s → %s  Δ=%s  (前 %s 后 %s)' % (r['f1'], r['f2'], r['d'], r['c1'], r['c2']))


if __name__ == '__main__':
    main()
