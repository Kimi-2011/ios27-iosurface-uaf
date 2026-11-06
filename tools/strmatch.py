#!/usr/bin/env python3
"""用「函数引用的字符串集合」跨构建配对——插入 retain/lock 不改变字符串引用，
所以这种配对不会被我们想找的补丁本身破坏（指令序列签名会被破坏，已证伪）。
"""
import json
import sys
from bisect import bisect_left
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF


def segof(c, va):
    for nm, vm, vs, fo, sz in c.segs:
        if vm <= va < vm + vs:
            return nm, vm, vs, fo, sz
    return None


def cstr(c, va, maxlen=160):
    s = segof(c, va)
    if not s:
        return None
    nm, vm, vs, fo, sz = s
    off = fo + (va - vm)
    buf = c.d[off:off + maxlen]
    z = buf.find(b'\x00')
    if z < 8:
        return None
    try:
        t = buf[:z].decode('utf-8')
    except Exception:
        return None
    if not all(32 <= ord(ch) < 127 for ch in t):
        return None
    return t


def strings_of(c, va, starts):
    i = bisect_left(starts, va)
    if i >= len(starts) or starts[i] != va:
        return None
    vm, vs, fo, sz = c.kseg('com.apple.kernel', '__TEXT_EXEC')
    end = starts[i + 1] if i + 1 < len(starts) else vm + sz
    off = fo + (va - vm)
    il = list(md.disasm(c.d[off:off + min(end - va, 4000)], va))
    page = {}
    refs = set()
    for ins in il:
        m = ins.mnemonic
        if m == 'adrp' and len(ins.operands) == 2 and ins.operands[0].type == ARM64_OP_REG:
            d = ins.reg_name(ins.operands[0].reg)
            if ins.operands[1].type == ARM64_OP_IMM:
                page[d] = ins.operands[1].imm & M
        elif m == 'add' and len(ins.operands) == 3 and ins.operands[0].type == ARM64_OP_REG \
                and ins.operands[1].type == ARM64_OP_REG and ins.operands[2].type == ARM64_OP_IMM:
            d, s2 = ins.reg_name(ins.operands[0].reg), ins.reg_name(ins.operands[1].reg)
            if s2 in page and d == s2:
                refs.add(page[s2] + (ins.operands[2].imm & M))
        elif m in ('ldr', 'ldrb') and len(ins.operands) == 2 and ins.operands[0].type == ARM64_OP_REG \
                and ins.operands[1].type == ARM64_OP_MEM:
            b = ins.reg_name(ins.operands[1].mem.base)
            if b in page:
                refs.add(page[b] + ins.operands[1].mem.disp)
    out = set()
    for r in refs:
        st = cstr(c, r)
        if st:
            out.add(st)
    return out


def main():
    res = {}
    for tag, path in (('2701', 'out/kc.27.0.1.full'), ('272', '/tmp/kc272.bin')):
        c = Cache(path)
        s, _, _ = func_starts(c, 'com.apple.kernel')
        idx = defaultdict(set)
        n = 0
        for va in s:
            st = strings_of(c, va, s)
            if st:
                n += 1
                for x in st:
                    idx[x].add(va)
        res[tag] = idx
        print(tag, '有字符串引用的函数:', n, ' 不同字符串:', len(idx))
    json.dump({k: {sk: sorted(v) for sk, v in d.items()} for k, d in res.items()},
              open('/tmp/stridx.json', 'w'))


if __name__ == '__main__':
    main()
