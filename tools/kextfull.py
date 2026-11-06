#!/usr/bin/env python3
"""单 kext 全函数差分：字符串交叉引用配对 + 逐函数指令序列 diff。

配对必须对「插入指令」免疫，所以用字符串引用集，不用指令序列签名。
"""
import difflib
import json
import sys
from bisect import bisect_left

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF
LOCKOPS = ('casa', 'casl', 'casal', 'cas', 'swp', 'swpal', 'ldaxr', 'stlxr', 'ldxr', 'stxr',
           'ldadd', 'ldadda', 'ldclr', 'ldset', 'stadd', 'stclr')


def walk(buf, va):
    out, i = [], 0
    while i + 4 <= len(buf):
        for ins in md.disasm(buf[i:i + 4], va + i):
            out.append(ins)
        i += 4
    return out


def load(path, b):
    c = Cache(path)
    s, _, _ = func_starts(c, b)
    vm, vs, fo, sz = c.kseg(b, '__TEXT_EXEC')
    bodies, strs = {}, {}
    for i, va in enumerate(s):
        end = s[i + 1] if i + 1 < len(s) else vm + sz
        il = walk(c.d[fo + (va - vm):fo + (end - vm)], va)
        bodies[va] = il
        out = set()
        for ins in il:
            if ins.mnemonic == 'adrp' and len(ins.operands) == 2 and ins.operands[1].type == 2:
                page = ins.operands[1].imm & M
                for nm, svm, svs, sfo, ssz in c.segs:
                    if svm <= page < svm + svs:
                        o = sfo + (page - svm)
                        z = c.d[o:o + 200].find(b'\x00')
                        if z > 6:
                            try:
                                t = c.d[o:o + z].decode()
                            except Exception:
                                break
                            if all(32 <= ord(x) < 127 for x in t):
                                out.add(t)
                        break
        if out:
            strs[va] = out
    return s, bodies, strs


def main():
    b = sys.argv[1]
    s1, b1, t1 = load('out/kc.27.0.1.full', b)
    s2, b2, t2 = load('/tmp/kc272.bin', b)
    print('函数', len(s1), len(s2), ' 有字符串引用', len(t1), len(t2))
    inv1 = {}
    for va, ss in t1.items():
        for x in ss:
            inv1.setdefault(x, []).append(va)
    pairs, unp = {}, []
    for va, ss in t2.items():
        cand = {}
        for x in ss:
            for v in inv1.get(x, ()):
                cand[v] = cand.get(v, 0) + 1
        if not cand:
            unp.append(va)
            continue
        best = max(cand.values())
        top = [v for v, n in cand.items() if n == best]
        if len(top) == 1:
            pairs[va] = top[0]
        else:
            unp.append(va)
    print('配对成功', len(pairs), ' 未配对(有串)', len(unp))
    rows = []
    for va2, va1 in pairs.items():
        A = ['%s %s' % (i.mnemonic, i.op_str) for i in b1[va1]]
        B = ['%s %s' % (i.mnemonic, i.op_str) for i in b2[va2]]
        if len(A) == len(B) and A == B:
            continue
        add, rm = [], []
        for line in difflib.unified_diff(A, B, n=0, lineterm=''):
            if line.startswith('+') and not line.startswith('+++'):
                add.append(line[1:])
            elif line.startswith('-') and not line.startswith('---'):
                rm.append(line[1:])
        lockish = [x for x in add if x.split()[0] in LOCKOPS]
        rows.append(dict(f1='0x%x' % va1, f2='0x%x' % va2, n1=len(A), n2=len(B),
                         add=len(add), rm=len(rm), lock=len(lockish), addl=add[:24], rml=rm[:24]))
    rows.sort(key=lambda r: (-r['lock'], -(r['add'] + r['rm'])))
    print('有差异的函数对', len(rows), ' 其中新增原子/锁指令的', sum(1 for r in rows if r['lock']))
    json.dump(rows, open('/tmp/kextfull_%s.json' % b.replace('.', '_'), 'w'), indent=1)
    for r in rows[:12]:
        print('  lock+%d  改 %d/%d  0x%s → 0x%s (len %d→%d)' % (r['lock'], r['add'], r['rm'], r['f1'], r['f2'], r['n1'], r['n2']))


if __name__ == '__main__':
    main()
