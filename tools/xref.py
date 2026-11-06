#!/usr/bin/env python3
"""在某个 dylib 里找指向目标函数的所有直接 bl 调用 + 数据段里的指针引用。"""
import sys, struct, bisect
sys.path.insert(0, __import__('os').path.dirname(__file__))
import fwdiff as F
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def main(path, target, name):
    D = F.analyze(path)
    d = D['d']; segs = D['segs']; starts = D['starts']; syms = D['syms']
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    calls = []
    for i, va in enumerate(starts):
        end = starts[i+1] if i+1 < len(starts) else va + 0x1000
        o = F.va2off(segs, va); e = F.va2off(segs, end) or (o + 0x4000)
        if o is None: continue
        for ins in md.disasm(d[o:min(e, o+0x4000)], va):
            if ins.mnemonic in ('bl', 'b') and ins.operands:
                op = ins.operands[0]
                if op.type == 2 and op.imm == target:      # ARM64_OP_IMM
                    caller = syms.get(va, f"sub_{va:x}")
                    calls.append((ins.address, ins.mnemonic, caller))
    print(f"[直接调用] {len(calls)} 处")
    for a, m, c in calls[:20]:
        print(f"   {a:#x} {m}  ← {c[:70]}")
    # 数据段指针
    tgt = struct.pack('<Q', target)
    ptrs = []
    pos = 0
    while True:
        k = d.find(tgt, pos)
        if k < 0: break
        ptrs.append(k); pos = k + 1
    print(f"\n[数据段指针] 命中 {len(ptrs)} 处")
    for k in ptrs[:10]:
        va = None
        for sva, sfs, sfo, ssize in segs:
            if sfo <= k < sfo + ssize:
                va = sva + (k - sfo); break
        print(f"   fileoff {k:#x}  va {va if va is None else hex(va)}")

if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2], 16), sys.argv[3] if len(sys.argv) > 3 else '')
