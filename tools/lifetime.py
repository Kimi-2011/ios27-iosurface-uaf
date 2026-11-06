#!/usr/bin/env python3
"""在 2266 个 selector handler 上找生命周期缺陷（三种静态形态）。"""
import json
import sys
from bisect import bisect_right
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF


def fend(starts, va, c=None, bundle=None):
    i = bisect_right(starts, va)
    return starts[i] if i < len(starts) else va + 0x4000


def insns_of(c, bundle, va, starts):
    te = c.kseg(bundle, '__TEXT_EXEC')
    vm, vs, fo, sz = te
    end = fend(starts, va)
    off = fo + (va - vm)
    return list(md.disasm(c.d[off:fo + (end - vm)], va)), (vm, sz)


def classify_atomic(ins_list):
    """返回 ('inc'|'dec'|None, 偏移) —— 依据 [x0,#0x8] 上的原子读改写。"""
    off = None
    kind = None
    for ins in ins_list:
        m = ins.mnemonic
        ops = ins.operands
        if m in ('ldaxr', 'ldxr', 'ldadd', 'ldadda', 'ldaddal', 'ldclr', 'ldset',
                 'stlxr', 'stxr', 'stadd', 'staddl'):
            if len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
                mem = ops[1].mem
                if ins.reg_name(mem.base) == 'x0' and mem.disp in (0x8, 0xc, 0x4):
                    off = mem.disp
        if m in ('add', 'sub') and len(ops) == 3 and ops[0].type == ARM64_OP_REG \
                and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM \
                and ins.reg_name(ops[1].reg) in ('w8', 'w9', 'w10'):
            kind = 'inc' if m == 'add' else 'dec'
    if off is None:
        return None, None
    return kind, off


def pick_lifetime(c):
    """在 com.apple.kernel 里按引用计数原子操作形态认出 retain / release。"""
    starts, ok, _ = func_starts(c, 'com.apple.kernel')
    cand = []
    for v in starts:
        n = fend(starts, v) - v
        if n <= 0 or n > 0x100:
            continue
        il, _ = insns_of(c, 'com.apple.kernel', v, starts)
        kind, off = classify_atomic(il)
        if kind:
            cand.append((v, kind, off, n))
    return starts, cand


def main():
    mode = sys.argv[1]
    c = Cache('out/kc.27.0.1.full')
    if mode == 'ident':
        starts, cand = pick_lifetime(c)
        print('候选 retain/release 函数（kernel 内小函数 + 原子 RC 操作）:', len(cand))
        cnt = Counter()
        # 统计全 cache bl 引用数
        for fo, bundle in c.entries:
            s, ok, _ = func_starts(c, bundle)
            if not s:
                continue
            te = c.kseg(bundle, '__TEXT_EXEC')
            vm, vs, foff, sz = te
            bl = s[0]
            for ins in md.disasm(c.d[foff:foff + sz], vm):
                if ins.mnemonic in ('bl', 'b') and ins.operands \
                        and ins.operands[0].type == ARM64_OP_IMM:
                    cnt[ins.operands[0].imm & M] += 1
        rows = []
        for v, kind, off, n in cand:
            rows.append((cnt.get(v, 0), v, kind, off, n))
        rows.sort(reverse=True)
        print('%-8s %-18s %-4s %-6s %s' % ('bl数', '地址', 'kind', 'off', 'len'))
        for r in rows[:20]:
            print('%-8d 0x%-16x %-4s 0x%-4x %d' % r)
        json.dump([dict(refs=r[0], va='0x%x' % r[1], kind=r[2], off=r[3], size=r[4])
                   for r in rows], open('/tmp/lifetime_ident.json', 'w'), indent=1)
    return


if __name__ == '__main__':
    main()
