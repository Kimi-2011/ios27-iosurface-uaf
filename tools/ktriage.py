"""Triage scanner: user-input-fed arithmetic / indexing inside one kext.

For every function of a kext's __TEXT_EXEC, flag the shapes that matter for
external-method auditing:

  IDX   - load from memory used as a *scaled array index*
          (`add xA,xB,xC,lsl#n` / `ldr xT,[xB,xC,lsl#n]` / `madd`) and no
          `cmp/ccmp/tst` against the index register in the same function
  LEN   - value loaded from memory multiplied/shifted, then reaching a
          `bl` argument register other than x0, with no bound compare
  MUL   - `mul`/`umull`/`madd` whose inputs were loaded from memory

Reported offsets are octets relative to the function start so they can be
re-found with `kva.KC.dis`.

Usage: python3 ktriage.py KC KEXT_BUNDLE
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

PACIBSP = 0xD503237F
BTI = 0xD503245F


def func_starts(kc, bundle):
    vm, vs, fo, fs = kc.kseg(bundle, "__TEXT_EXEC")
    blob = kc.d[fo:fo + fs]
    S = set()
    for i in range(0, len(blob) - 7, 4):
        w = struct.unpack_from("<I", blob, i)[0]
        if w == PACIBSP:
            S.add(i)
        elif w == BTI and struct.unpack_from("<I", blob, i + 4)[0] != PACIBSP:
            S.add(i)
    return sorted(S), vm, blob


def analyse(kc, bundle, noise_cmp=True):
    starts, vm, blob = func_starts(kc, bundle)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    bounds = starts + [len(blob)]
    rows = []
    for k in range(len(starts)):
        s, e = starts[k], bounds[k + 1]
        if e - s > 0x4000 or e - s < 16:
            continue
        insns = list(md.disasm(blob[s:e], vm + s))
        if not insns:
            continue
        tainted = {}        # reg -> offset index where it came from memory
        checked = set()     # regs compared against an immediate
        flags = []
        for idx, ins in enumerate(insns):
            m = ins.mnemonic
            ops = ins.operands
            # record compares
            if m in ("cmp", "cmn", "subs", "ands", "tst", "ccmp", "ccmn"):
                for o in ops:
                    if o.type == ARM64_OP_REG:
                        checked.add(ins.reg_name(o.reg))
            # loads from memory taint the destination
            if m.startswith("ldr") or m in ("ldur", "ldurh", "ldurb", "ldursw"):
                if ops and ops[0].type == ARM64_OP_REG:
                    dst = ins.reg_name(ops[0].reg)
                    tainted[dst] = idx
                    if len(ops) > 1 and ops[1].type == ARM64_OP_MEM:
                        mm = ops[1].mem
                        if mm.index != 0:
                            ir = ins.reg_name(mm.index)
                            if not noise_cmp or not _checked_like(checked, ir):
                                flags.append((idx, "IDX", ins))
            elif m in ("mul", "umull", "smull", "madd", "msub", "umaddl", "smaddl"):
                srcs = [ins.reg_name(o.reg) for o in ops if o.type == ARM64_OP_REG]
                if any(_taints(tainted, r) for r in srcs):
                    if not any(_checked_like(checked, r) for r in srcs):
                        flags.append((idx, "MUL", ins))
                if ops and ops[0].type == ARM64_OP_REG:
                    tainted[ins.reg_name(ops[0].reg)] = idx
            elif m == "add" and len(ops) == 4 and ops[3].type == ARM64_OP_LSHIFT:
                # add xD, xB, xC, lsl #n   -> scaled index
                idxr = ins.reg_name(ops[2].reg)
                if _taints(tainted, idxr) and not _checked_like(checked, idxr):
                    flags.append((idx, "IDX", ins))
                if ops[0].type == ARM64_OP_REG:
                    tainted[ins.reg_name(ops[0].reg)] = idx
            elif m in ("lsl",) and len(ops) == 3:
                if _taints(tainted, ins.reg_name(ops[1].reg)):
                    tainted[ins.reg_name(ops[0].reg)] = idx
            elif m in ("bl", "b") and ops and ops[0].type == ARM64_OP_IMM:
                for o in ops[1:]:
                    pass
                # length-ish argument registers
                for rn in ("x2", "w2", "x3", "w3", "x4", "w4"):
                    pass
                for oi, o in enumerate(ins.operands):
                    if o.type == ARM64_OP_REG and oi in (1, 2, 3, 4):
                        r = ins.reg_name(o.reg)
                        if _taints(tainted, r) and not _checked_like(checked, r):
                            flags.append((idx, "LEN", ins))
                            break
            elif m == "str" or m.startswith("str") or m.startswith("stp"):
                if len(ops) > 1 and ops[1].type == ARM64_OP_MEM and ops[1].mem.index != 0:
                    ir = ins.reg_name(ops[1].mem.index)
                    if not _checked_like(checked, ir):
                        flags.append((idx, "IDX", ins))
        if flags:
            rows.append((vm + s, e - s, flags))
    return rows


def _taints(tainted, r):
    for t in tainted:
        if r == t:
            return True
        # wN / xN alias
        if len(r) > 1 and len(t) > 1 and r[1:] == t[1:] and r[0] in "wx" and t[0] in "wx":
            return True
    return False


def _checked_like(checked, r):
    """True when some compare in this function named r or its alias."""
    for c in checked:
        if c == r:
            return True
        if len(r) > 1 and len(c) > 1 and r[1:] == c[1:] and r[0] in "wx" and c[0] in "wx":
            return True
    return False


if __name__ == "__main__":
    from kva import KC
    kc = KC(sys.argv[1])
    for va, size, flags in analyse(kc, sys.argv[2]):
        print("%#x  size=%#x  flags=%d" % (va, size, len(flags)))
        for idx, kind, ins in flags[:12]:
            print("    +%#05x %-3s %-8s %s" % (0, kind, ins.mnemonic, ins.op_str))
