#!/usr/bin/env python3
"""单个 kext 的加锁差分：目标集合按构建各自重认（VA 会漂移）。"""
import json
import sys
from bisect import bisect_left
from collections import Counter

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF


def walk(buf, va):
    out, i = [], 0
    while i + 4 <= len(buf):
        for ins in md.disasm(buf[i:i + 4], va + i):
            out.append(ins)
        i += 4
    return out


def body(c, b, va, starts):
    i = bisect_left(starts, va)
    vm, vs, fo, sz = c.kseg(b, '__TEXT_EXEC')
    end = starts[i + 1] if i + 1 < len(starts) else vm + sz
    return walk(c.d[fo + (va - vm):fo + (end - vm)], va)


def strings_of(c, b, va, starts, limit=200):
    out = set()
    for ins in body(c, b, va, starts):
        if ins.mnemonic in ('adrp',) and len(ins.operands) == 2 and ins.operands[1].type == 2:
            page = ins.operands[1].imm & M
            for nm, svm, svs, sfo, ssz in c.segs:
                if svm <= page < svm + svs:
                    o = sfo + (page - svm)
                    z = c.d[o:o + limit].find(b'\x00')
                    if z > 6:
                        try:
                            t = c.d[o:o + z].decode()
                        except Exception:
                            break
                        if all(32 <= ord(x) < 127 for x in t):
                            out.add(t)
                    break
    return out


def sweep(c, b, targets, tag):
    s, ok, _ = func_starts(c, b)
    _st = json.load(open('out/stubs.json' if tag == '2701' else '/tmp/stubs272.json'))
    sm = {int(k, 16): int(v, 16) for k, v in _st.get(b, {}).items() if v}
    vm, vs, fo, sz = c.kseg(b, '__TEXT_EXEC')
    cnt, sig = {}, {}
    for va in s:
        il = body(c, b, va, s)
        cc = Counter()
        for x in il:
            if x.mnemonic in ('bl', 'b') and x.operands and x.operands[0].type == 2:
                t = x.operands[0].imm & M
                t = sm.get(t, t)
                if t in targets:
                    cc[targets[t]] += 1
        if cc:
            cnt[va] = dict(cc)
    return s, cnt


def main():
    b = sys.argv[1] if len(sys.argv) > 1 else 'com.apple.iokit.IOSurface'
    tg = json.load(open('/tmp/broad2.json'))
    res = {}
    for tag, path in (('2701', 'out/kc.27.0.1.full'), ('272', '/tmp/kc272.bin')):
        c = Cache(path)
        T = {int(k, 16): v for k, v in tg[tag]['tg'].items()}
        s, cnt = sweep(c, b, T, tag)
        st = {va: strings_of(c, b, va, s) for va in s}
        res[tag] = dict(cnt={('0x%x' % k): v for k, v in cnt.items()},
                        str={('0x%x' % k): sorted(v) for k, v in st.items() if v})
        print(tag, b, '函数', len(s), '有锁调用', len(cnt),
              dict(sum((Counter(v) for v in cnt.values()), Counter())))
    json.dump(res, open('/tmp/kextlock_%s.json' % b.replace('.', '_'), 'w'))
    a, b2 = res['2701'], res['272']
    inv = {}
    for va, ss in b2['str'].items():
        for x in ss:
            inv.setdefault(x, []).append(va)
    ca = {int(k, 16): v for k, v in a['cnt'].items()}
    rows = []
    for va, c2 in b2['cnt'].items():
        v = int(va, 16)
        st = b2['str'].get(va)
        if not st:
            continue
        cand = {}
        for x in st:
            for k, sv in a['str'].items():
                if x in sv:
                    cand[k] = cand.get(k, 0) + 1
        if not cand:
            continue
        best = max(cand.values())
        top = [k for k, n in cand.items() if n == best]
        if len(top) != 1:
            continue
        c1 = ca.get(int(top[0], 16), {})
        d = {k: c2.get(k, 0) - c1.get(k, 0) for k in set(c1) | set(c2)}
        if any(x > 0 for x in d.values()):
            rows.append((sum(x for x in d.values() if x > 0), va, top[0], c1, c2, d))
    rows.sort(reverse=True)
    print('新增锁调用的候选:', len(rows))
    for r in rows:
        print('  +%d  27.2 %s ← 27.0.1 %s  %s → %s' % (r[0], r[1], r[2], r[3], r[4]))


if __name__ == '__main__':
    main()
