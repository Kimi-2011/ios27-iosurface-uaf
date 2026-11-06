#!/usr/bin/env python3
"""全 kext 的桩目标调用次数差分：27.0.1 vs 27.2。"""
import json
import sys
from bisect import bisect_left
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts
import stubs as ST

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF

T27 = {  # 每个构建里按形状重新认出来的目标（见 tools/kerndiff.py 输出）
 '2701': dict(lock=0xfffffe000ab4e274, unlock=0xfffffe000abd3f78,
              rcinc=0xfffffe000b266a30, rcdec=0xfffffe000ab5c2a8),
 '272': dict(lock=0xfffffe000ab9e274, unlock=0xfffffe000ac25344,
             rcinc=0xfffffe000b2bcb34, rcdec=0xfffffe000abac278),
}


def sweep(c, tag):
    tgt = {v: k for k, v in T27[tag].items()}
    res = {}
    for fo, b in c.entries:
        s, ok, _ = func_starts(c, b)
        if not s:
            continue
        sm = {}
        try:
            sm = {k: int(v, 16) for k, v in ST.stubs_of(c, b).items() if v}
        except Exception:
            pass
        vm, vs, foff, sz = c.kseg(b, '__TEXT_EXEC')
        cnt = Counter()
        for i, va in enumerate(s):
            end = s[i + 1] if i + 1 < len(s) else vm + sz
            off = foff + (va - vm)
            for ins in md.disasm(c.d[off:min(off + (end - va), off + 4000)], va):
                if ins.mnemonic in ('bl', 'b') and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
                    t = ins.operands[0].imm & M
                    t = sm.get(t, t)
                    if t in tgt:
                        cnt[tgt[t]] += 1
        if cnt:
            res[b] = dict(cnt)
    return res


def main():
    for tag, path in (('2701', 'out/kc.27.0.1.full'), ('272', '/tmp/kc272.bin')):
        c = Cache(path)
        r = sweep(c, tag)
        json.dump(r, open('/tmp/kextcall_%s.json' % tag, 'w'), indent=1)
        print(tag, '有目标调用的 kext 数:', len(r),
              ' 合计:', dict(sum((Counter(v) for v in r.values()), Counter())))


if __name__ == '__main__':
    main()
