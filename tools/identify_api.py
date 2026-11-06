#!/usr/bin/env python3
"""在所有桩目标里按函数体特征认出 lock / unlock / retain / release 一族。"""
import json
import sys
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True


def main():
    c = Cache('out/kc.27.0.1.full')
    stubs = json.load(open('out/stubs.json'))
    users = Counter()
    for b, m in stubs.items():
        for t in set(m.values()):
            if t:
                users[int(t, 16)] += 1
    # 目标 → 所属 kext 的函数起点背包
    starts = {}
    for fo, b in c.entries:
        s, ok, _ = func_starts(c, b)
        if s:
            starts[b] = s
    def body(va):
        for b, s in starts.items():
            vm, vs, fo, sz = c.kseg(b, '__TEXT_EXEC')
            if vm <= va < vm + sz:
                i = bisect_left(s, va)
                if i < len(s) and s[i] == va:
                    end = s[i + 1] if i + 1 < len(s) else vm + sz
                    off = fo + (va - vm)
                    return list(md.disasm(c.d[off:fo + (end - vm)], va)), b
        return [], None
    buckets = defaultdict(list)
    for va, nk in users.most_common(4000):
        il, b = body(va)
        if not il:
            continue
        ms = [i.mnemonic for i in il]
        ops = ' '.join(i.op_str for i in il)
        tag = None
        if any(m == 'msr' and ('daifclr' in i.op_str or 'daifset' in i.op_str)
               for m, i in zip(ms, il)):
            tag = 'daif(简单锁)'
        elif 'sev' in ms and ('stlr' in ms or 'ldaxr' in ms or 'stxr' in ms):
            tag = 'mutex(sev+stlr)'
        elif 'ldadd' in ms and ("#-1" in ops or 'w8, w9' in ops or 'w8, w10' in ops):
            tag = 'ldadd(N)'
        elif len(il) <= 3 and ms and ms[0] == 'b':
            tag = 'tail-b(%s)' % il[0].op_str
        if tag:
            buckets[tag].append((va, nk, len(il), b, [f'{i.mnemonic} {i.op_str}' for i in il[:6]]))
    for tag, rows in buckets.items():
        print('==', tag, len(rows))
        for r in rows[:12]:
            print('   0x%-16x %3d kext  len=%-4d %-40s %s' % (r[0], r[1], r[2], r[3] or '', ' | '.join(r[4][:4])))
    json.dump({k: [dict(va='0x%x' % r[0], kexts=r[1], size=r[2], inkext=r[3], head=r[4])
                   for r in v] for k, v in buckets.items()},
              open('/tmp/api_buckets.json', 'w'), indent=1)


if __name__ == '__main__':
    main()
