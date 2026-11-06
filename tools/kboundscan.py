#!/usr/bin/env python3
"""扫描内核改动函数，筛出「新增边界检查」候选（用尺寸索引加速，避免 O(n^2)）。"""
import sys, os, difflib, re, bisect, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kpair as KP
NUM = re.compile(r'#?-?0x[0-9a-fA-F]+|#?-?\d+')
CHK = ('cmp ', 'cmn ', 'tst ', 'subs ', 'ands ', 'ccmp', 'cbz ', 'cbnz', 'tbz ', 'tbnz')

def dis(s, i):
    off = s['offs'][i]; va = s['vmaddr'] + off
    st = KP.va2off(s, va)
    nxt = s['offs'][i+1] if i+1 < len(s['offs']) else off + 0x4000
    en = KP.va2off(s, s['vmaddr'] + nxt) or (st + 0x8000)
    return [f"{x.mnemonic} {x.op_str}" for x in
            KP.md.disasm(s['data'][st:min(en, st + 0x20000)], va)]

def nchk(ins):
    return sum(1 for l in ins if any(l.startswith(c) for c in CHK))

def main():
    A = KP.build('out/kc.27.0.1.full'); B = KP.build('out/kernelcache.27.2.ga')
    sa = A['com.apple.kernel']; sb = B['com.apple.kernel']
    # B 的字节长度索引
    nb = len(sb['offs'])
    blen = []
    for ib in range(nb):
        ob = sb['offs'][ib]
        blen.append((sb['offs'][ib+1]-ob) if ib+1 < nb else 0)
    order = sorted(range(nb), key=lambda i: blen[i])
    sorted_len = [blen[i] for i in order]
    hits = []
    n = len(sa['offs'])
    for ia in range(n):
        oa = sa['offs'][ia]
        la = (sa['offs'][ia+1]-oa) if ia+1 < n else 0
        if la < 48 or la > 3600:          # 12..900 条指令
            continue
        a = dis(sa, ia); an = [NUM.sub('#', x) for x in a]
        lo, hi = int(la*0.90), int(la*1.15)+16
        i0 = bisect.bisect_left(sorted_len, lo); i1 = bisect.bisect_right(sorted_len, hi)
        best = (0, 0)
        for k in range(i0, i1):
            ib = order[k]
            b = dis(sb, ib)
            if len(b) < len(a)*0.88 or len(b) > len(a)*1.18+4:
                continue
            r = difflib.SequenceMatcher(None, an, [NUM.sub('#', x) for x in b]).ratio()
            if r > best[0]:
                best = (r, ib)
        if best[0] < 0.85:
            continue
        ib = best[1]; b = dis(sb, ib)
        d = nchk(b) - nchk(a)
        if d > 0 and len(b) > len(a):
            hits.append((d, best[0], oa, sb['offs'][ib], len(a), len(b)))
        if ia % 4000 == 0:
            print(f"  ...{ia}/{n}", file=sys.stderr)
    hits.sort(reverse=True)
    print(f"\n新增检查且变长的候选 {len(hits)} 个：")
    print(f"{'Δ检查':>5} {'相似':>6} {'旧':>10} {'新':>10} {'指令':>14}")
    for d, r, oa, ob, la2, lb in hits[:40]:
        print(f"{d:5d} {r:6.3f} {oa:#10x} {ob:#10x} {la2:6d}→{lb:<6d}")

if __name__ == '__main__':
    main()
