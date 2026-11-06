#!/usr/bin/env python3
"""给桩目标做语义分类：先取函数体，再抽特征，最后按证据命名。"""
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


class Index:
    def __init__(self, c):
        self.c = c
        self.rows = []
        for fo, b in c.entries:
            s, ok, _ = func_starts(c, b)
            if not s:
                continue
            vm, vs, foff, sz = c.kseg(b, '__TEXT_EXEC')
            self.rows.append((vm, vm + sz, foff, b, s, set(s)))

    def owner(self, va):
        for vm, ve, fo, b, s, ss in self.rows:
            if vm <= va < ve:
                return b, vm, fo, s, ss, ve
        return None

    def body(self, va, maxb=0x400):
        o = self.owner(va)
        if not o:
            return None, None, False
        b, vm, fo, s, ss, ve = o
        exact = va in ss
        i = bisect_left(s, va)
        if exact:
            end = s[i + 1] if i + 1 < len(s) else ve
        else:
            end = s[i] if i < len(s) else ve     # 非起点：截到下一个起点前
        off = fo + (va - vm)
        n = min(end - va, maxb)
        return list(md.disasm(self.c.d[off:off + n], va)), b, exact


def feats(il):
    ms = [i.mnemonic for i in il]
    txt = ' '.join(i.op_str for i in il)
    f = {}
    f['n'] = len(il)
    f['brk'] = 'brk' in ms
    f['sev'] = 'sev' in ms
    f['wfe'] = 'wfe' in ms
    f['dmb'] = any(x in ms for x in ('dmb', 'dsb', 'isb'))
    f['ldadd'] = 'ldadd' in ms or 'ldadda' in ms or 'stadd' in ms
    f['ldxr'] = 'ldxr' in ms or 'ldaxr' in ms
    f['stxr'] = 'stxr' in ms or 'stlxr' in ms
    f['cas'] = any(x.startswith('cas') for x in ms)
    f['daif'] = 'daifclr' in txt or 'daifset' in txt
    f['q'] = sum(1 for x in ms if x in ('ldp', 'stp')) and 'q' in txt
    f['neg'] = any(m == 'ldr' and o.type == ARM64_OP_MEM and o.mem.disp < 0
                   for m, o in zip(ms, [i.operands[1] if len(i.operands) > 1 else None
                                        for i in il]) if o is not None)
    f['tailb'] = len(il) <= 2 and ms and ms[0] == 'b'
    f['panicstr'] = False
    f['inc1'] = 'mov w8, #1' in txt or 'mov w9, #1' in txt
    f['dec1'] = 'mov w8, #-1' in txt or 'mov w9, #-1' in txt
    f['calls'] = sum(1 for x in ms if x in ('bl',))
    f['vcall'] = sum(1 for x in ms if x in ('blraa', 'braa'))
    return f


def main():
    c = Cache('out/kc.27.0.1.full')
    idx = Index(c)
    stubs = json.load(open('out/stubs.json'))
    users = Counter()
    per = defaultdict(set)
    for b, m in stubs.items():
        for t in set(m.values()):
            if t:
                users[int(t, 16)] += 1
                per[int(t, 16)].add(b)
    print('桩目标去重后:', len(users))
    rows = []
    hit = 0
    for va, nk in users.most_common():
        il, b, exact = idx.body(va)
        if il is None:
            rows.append(dict(va='0x%x' % va, kexts=nk, inkext=None, exact=False, feat=None))
            continue
        hit += 1
        rows.append(dict(va='0x%x' % va, kexts=nk, inkext=b, exact=exact,
                         feat=feats(il),
                         head=[f'{i.mnemonic} {i.op_str}' for i in il[:8]]))
    print('能取到函数体:', hit, '/', len(rows))
    json.dump(rows[:400], open('/tmp/stub_feats.json', 'w'), indent=1)
    print()
    print('%-18s %4s %-5s %s' % ('目标', 'kext', 'len', '特征'))
    for r in rows[:36]:
        f = r['feat']
        if not f:
            print('%-18s %4d  --   <取不到>' % (r['va'], r['kexts']))
            continue
        tags = [k for k in ('brk', 'ldadd', 'ldxr', 'stxr', 'cas', 'daif', 'sev', 'wfe',
                            'dmb', 'neg', 'tailb', 'inc1', 'dec1') if f.get(k)]
        print('%-18s %4d %-5d %s' % (r['va'], r['kexts'], f['n'], ','.join(tags)))


if __name__ == '__main__':
    main()
