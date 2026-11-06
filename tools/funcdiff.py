"""Unified diff of two functions (address-normalized), for eyeballing patches.

Usage:
  python3 funcdiff.py A B --kext NAME --off_a 0x... --off_b 0x... [--context 3]
"""
import argparse
import difflib
import re

import kdiff
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
NUM = re.compile(r"#?-?0x[0-9a-fA-F]+|#?-?\d+")


def norm(text):
    return NUM.sub("<I>", text)


def disasm(data, base, size, limit=600):
    out = []
    for i in md.disasm(data[base:base + size], 0):
        out.append(f"{i.mnemonic:12} {i.op_str}")
        if i.mnemonic in ("ret", "retaa", "retab") or len(out) >= limit:
            break
    return out


def find(data, kext, off):
    fo, size, _ = [x for x in kdiff.slices(data) if x[2] == kext][0]
    _to, _vm, fns = kdiff.macho_info(data, fo)
    nxt = next((f for f in fns if f > off), off + 0x800)
    return fo + off, nxt - off


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--kext", required=True)
    ap.add_argument("--off_a", required=True)
    ap.add_argument("--off_b", required=True)
    ap.add_argument("--context", type=int, default=2)
    a = ap.parse_args()

    da, db = kdiff.load(a.a), kdiff.load(a.b)
    ba, sa = find(da, a.kext, int(a.off_a, 16))
    bb, sb = find(db, a.kext, int(a.off_b, 16))
    ia = disasm(da, ba, sa)
    ib = disasm(db, bb, sb)
    print(f"{a.kext}  A@{a.off_a} ({len(ia)} insns)  vs  B@{a.off_b} ({len(ib)} insns)\n")

    na = [norm(x) for x in ia]
    nb = [norm(x) for x in ib]
    diff = difflib.unified_diff(na, nb, fromfile="27.0.1", tofile="27.2", n=a.context, lineterm="")
    shown = 0
    for line in diff:
        print(line)
        shown += 1
        if shown > 200:
            print("... (truncated)")
            break


if __name__ == "__main__":
    main()
