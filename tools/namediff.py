#!/usr/bin/env python3
"""按函数名对齐的两版差分：同名但形状不同 = 被修改。"""
import sys, os, collections, difflib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwdiff as F

def collect(path):
    D = F.analyze(path)
    starts = D['starts']; syms = D['syms']
    out = {}
    for i, va in enumerate(starts):
        nm = syms.get(va)
        if not nm: continue
        end = starts[i+1] if i+1 < len(starts) else va+0x4000
        s = F.shape_at(D['d'], D['segs'], va, end)
        if s: out[nm] = s
    return out

def main(a, b):
    A = collect(a); B = collect(b)
    common = set(A) & set(B)
    onlyA = set(A) - set(B)
    onlyB = set(B) - set(A)
    modified = [n for n in common if A[n] != B[n]]
    print(f"== {os.path.basename(a)} ==")
    print(f"  28.0.1 函数 {len(A)} | 27.2 函数 {len(B)}")
    print(f"  同名同形 {len(common)-len(modified)} | 同名异形(改动) {len(modified)} | 仅旧版 {len(onlyA)} | 仅新版 {len(onlyB)}")
    if modified:
        modified.sort(key=lambda n: -abs(len(B[n])-len(A[n])))
        print("  改动最大的前 15 个：")
        for n in modified[:15]:
            print(f"    {n[:58]:58} {len(A[n])}→{len(B[n])} 条指令")
    return modified, onlyA, onlyB

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
