#!/usr/bin/env python3
"""kext 的符号桩（adrp x17,slot / add / ldr x16,[x17] / braa x16,x17）→ 真实目标 VA。"""
import json
import sys
from bisect import bisect_right
from collections import Counter

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts, decode_ptr

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True


def stubs_of(c, bundle):
    """返回 {stub_va: target_va or None}。"""
    vm, vs, fo, sz = c.kseg(bundle, '__TEXT_EXEC')
    blob = c.d[fo:fo + sz]
    out = {}
    ins = list(md.disasm(blob, vm))
    for i in range(len(ins) - 3):
        a, b, d, e = ins[i], ins[i + 1], ins[i + 2], ins[i + 3]
        if a.mnemonic != 'adrp' or a.operands[0].type != ARM64_OP_REG or \
                a.reg_name(a.operands[0].reg) != 'x17':
            continue
        if b.mnemonic != 'add' or len(b.operands) != 3 or \
                b.reg_name(b.operands[0].reg) != 'x17' or \
                b.reg_name(b.operands[1].reg) != 'x17':
            continue
        if d.mnemonic != 'ldr' or d.operands[1].type != ARM64_OP_MEM or \
                d.reg_name(d.operands[1].mem.base) != 'x17' or d.operands[1].mem.disp != 0:
            continue
        if e.mnemonic not in ('braa', 'bra'):
            continue
        page = int(a.op_str.split('#')[-1], 16) if '#' in a.op_str else None
        if page is None:
            continue
        imm = int(b.op_str.split('#')[-1], 16)
        slot = page + imm
        word = None
        fp = None
        for nm, svm, svs, sfo, ssz in c.segs:
            if svm <= slot < svm + ssz:
                fp = sfo + (slot - svm)
                break
        word = int.from_bytes(c.d[fp:fp + 8], 'little') if fp is not None else None
        tgt = decode_ptr(word) if word is not None else None
        out[a.address] = tgt
    return out


def main():
    c = Cache('out/kc.27.0.1.full')
    allstub = {}
    tgtcount = Counter()
    for fo, b in c.entries:
        s = stubs_of(c, b)
        allstub[b] = {('0x%x' % k): ('0x%x' % v if v else None) for k, v in s.items()}
        for k, v in s.items():
            if v:
                tgtcount[v] += 1
    json.dump(allstub, open('out/stubs.json', 'w'))
    print('kext 有桩:', sum(1 for v in allstub.values() if v),
          ' 桩总数:', sum(len(v) for v in allstub.values()),
          ' 解出目标:', sum(1 for v in allstub.values() for x in v.values() if x))
    print('被最多 kext 桩指向的目标（跨 kext 才说明是公共 API）:')
    for v, n in tgtcount.most_common(16):
        print('   %4d kext  0x%x' % (n, v))


if __name__ == '__main__':
    main()
