#!/usr/bin/env python3
"""按指令形状相似度在 27.2 中找 27.0.1 某函数的对应版本（应对序号漂移）。"""
import sys, os, difflib, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kpair as KP

NUM = re.compile(r'#?-?0x[0-9a-fA-F]+|#?-?\d+')
def norm(op):
    return NUM.sub('#', op)

def shape(s, idx):
    off = s['offs'][idx]
    va = s['vmaddr'] + off
    start = KP.va2off(s, va)
    nxt = s['offs'][idx+1] if idx+1 < len(s['offs']) else off + 0x800
    end = KP.va2off(s, s['vmaddr'] + nxt) or (start + 0x2000)
    out = []
    for i in KP.md.disasm(s['data'][start:min(end, start+0x6000)], va):
        out.append(i.mnemonic + ' ' + norm(i.op_str))
    return out

if __name__ == '__main__':
    A = KP.build(sys.argv[1]); B = KP.build(sys.argv[2])
    tgt = int(sys.argv[3], 16)
    sa = A['com.apple.kernel']; sb = B['com.apple.kernel']
    ia = sa['offs'].index(tgt)
    a = shape(sa, ia)
    print(f"27.0.1 目标 {tgt:#x}: {len(a)} 条")
    lo, hi = int(len(a)*0.6), int(len(a)*1.6)+8
    best = []
    for ib in range(len(sb['offs'])):
        off = sb['offs'][ib]
        n = (sb['offs'][ib+1] - off) if ib+1 < len(sb['offs']) else 0
        if not (lo*3 <= n <= hi*3):   # 每条指令 4 字节，粗筛
            continue
        b = shape(sb, ib)
        if not (lo <= len(b) <= hi):
            continue
        r = difflib.SequenceMatcher(None, a, b).ratio()
        best.append((r, off, len(b)))
    best.sort(reverse=True)
    print("最相似的前 5 个：")
    for r, off, n in best[:5]:
        print(f"   {off:#x}  相似度 {r:.4f}  {n} 条")
