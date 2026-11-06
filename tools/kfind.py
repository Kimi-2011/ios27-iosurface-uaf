#!/usr/bin/env python3
"""用助记符直方图找内核函数的对应版本（对指令重排鲁棒）。
用法: kfind.py <27.0.1偏移> [候选数]
"""
import sys, os, collections, difflib, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kpair as KP
NUM = re.compile(r'#?-?0x[0-9a-fA-F]+|#?-?\d+')
CACHE = 'out/.kfind_cache'

def dis(s, i):
    off = s['offs'][i]; va = s['vmaddr'] + off
    st = KP.va2off(s, va)
    nxt = s['offs'][i+1] if i+1 < len(s['offs']) else off + 0x4000
    en = KP.va2off(s, s['vmaddr'] + nxt) or (st + 0x8000)
    return [f"{x.mnemonic} {x.op_str}" for x in
            KP.md.disasm(s['data'][st:min(en, st + 0x20000)], va)]

def hist(ins):
    c = collections.Counter(l.split()[0] for l in ins)
    tot = sum(c.values()) or 1
    return {k: v/tot for k, v in c.items()}

def cos(h1, h2):
    ks = set(h1) | set(h2)
    return sum(h1.get(k,0)*h2.get(k,0) for k in ks)

def main():
    tgt = int(sys.argv[1], 16); topn = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    B = KP.build('out/kernelcache.27.2.ga'); sb = B['com.apple.kernel']
    A = KP.build('out/kc.27.0.1.full'); sa = A['com.apple.kernel']
    ia = sa['offs'].index(tgt)
    a = dis(sa, ia); ha = hist(a)
    print(f"目标 {tgt:#x}: {len(a)} 条")
    cands = []
    for ib in range(len(sb['offs'])):
        b = dis(sb, ib)
        if not b: continue
        cands.append((cos(ha, hist(b)), ib, len(b)))
    cands.sort(reverse=True)
    print("直方图最相似的前 5：")
    best = None
    for h, ib, lb in cands[:5]:
        b = dis(sb, ib)
        r = difflib.SequenceMatcher(None, [NUM.sub('#',x) for x in a],
                                    [NUM.sub('#',x) for x in b]).ratio()
        print(f"   {sb['offs'][ib]:#x}  直方图 {h:.3f}  序列 {r:.4f}  {lb} 条")
        if best is None or r > best[0]:
            best = (r, sb['offs'][ib], lb, ib)
    r, off, lb, ib = best
    print(f"\n采用 {off:#x}  序列相似 {r:.4f}  {len(a)}→{lb} 条\n")
    b = dis(sb, ib)
    an=[NUM.sub('#',x) for x in a]; bn=[NUM.sub('#',x) for x in b]
    tot=0
    for tag,i1,i2,j1,j2 in difflib.SequenceMatcher(None,an,bn).get_opcodes():
        if tag=='equal': continue
        tot += max(i2-i1, j2-j1)
        print(f"[{tag}] 旧[{i1}:{i2}] → 新[{j1}:{j2}]")
        for l in a[i1:i2][:10]: print("   -",l[:96])
        for l in b[j1:j2][:10]: print("   +",l[:96])
        print()
    print(f"总差异 ≈ {tot} 条")

if __name__ == '__main__':
    main()
