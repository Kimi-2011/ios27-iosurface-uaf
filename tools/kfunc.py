"""Locate changed functions inside one kext and rank them by "added check" shape.

kdiff gives per-kext counts. This goes one level deeper: it aligns the function
sequences of A and B (difflib on shape hashes), pairs replaced functions by
position, and scores each pair by how many conditional-branch / compare
instructions were ADDED. A new bounds check shows up as a positive check delta.

Usage:
  python3 kfunc.py A.kcache B.kcache --kext com.apple.kernel [--top 15] [--disasm]

Output: offset, size delta, instruction delta, check delta, and for the top
candidates a short side-by-side of the first instructions.
"""
import argparse
import difflib
import sys
from collections import Counter

import kdiff
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

CHECK_MNEMONICS = ("cmp", "cmn", "ccmp", "ccmn", "tbz", "tbnz", "cbz", "cbnz", "csel", "csinc", "csinv")


def is_check(mnemonic):
    return mnemonic.startswith("b.") or mnemonic in CHECK_MNEMONICS


def extract(path, kext_name):
    data = kdiff.load(path)
    for fo, size, name in kdiff.slices(data):
        if name != kext_name:
            continue
        text_off, _vm, fns = kdiff.macho_info(data, fo)
        out = []
        for i, fn in enumerate(fns):
            start = fo + fn
            end = fo + fns[i + 1] if i + 1 < len(fns) else min(len(data), fo + size)
            if end <= start or end - start > 0x8000:
                continue
            code = data[start:end]
            # bounded window: stop at the function's own return, cap at 64 insns
            insns = []
            for x in md.disasm(code, 0):
                insns.append(x)
                if x.mnemonic in ("ret", "retaa", "retab") or len(insns) >= 64:
                    break
            checks = sum(1 for x in insns if is_check(x.mnemonic))
            out.append({
                "off": fn,
                "file": start,
                "size": end - start,
                "hash": kdiff.func_hash(code),
                "n": len(insns),
                "checks": checks,
                "code": code,
            })
        return out, data
    return [], b""


def head(code, k=10):
    return "; ".join(f"{i.mnemonic} {i.op_str}" for i in list(md.disasm(code, 0))[:k]) or "(empty)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--kext", default="com.apple.kernel")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--disasm", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()

    A, da = extract(a.a, a.kext)
    B, db = extract(a.b, a.kext)
    print(f"{a.kext}: A={len(A)} funcs, B={len(B)} funcs")

    sm = difflib.SequenceMatcher(a=[x["hash"] for x in A], b=[x["hash"] for x in B], autojunk=False)
    pairs = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        n = min(i2 - i1, j2 - j1)
        for k in range(n):
            pairs.append((A[i1 + k], B[j1 + k]))
        for k in range(i1 + n, i2):
            pairs.append((A[k], None))
        for k in range(j1 + n, j2):
            pairs.append((None, B[k]))

    scored = []
    dropped = 0
    for fa, fb in pairs:
        if fa is None or fb is None:
            continue
        # a real in-place patch keeps the function roughly the same size; huge
        # deltas are alignment artefacts from insertions shifting the sequence
        if abs(fb["size"] - fa["size"]) > 96 or abs(fb["n"] - fa["n"]) > 16:
            dropped += 1
            continue
        scored.append({
            "off_a": fa["off"], "off_b": fb["off"],
            "size_a": fa["size"], "size_b": fb["size"],
            "d_insn": fb["n"] - fa["n"],
            "d_check": fb["checks"] - fa["checks"],
            "a": fa, "b": fb,
        })
    scored.sort(key=lambda r: (-r["d_check"], -r["d_insn"]))

    print(f"changed/paired functions: {len(scored)}  (dropped {dropped} misaligned)\n")
    print(f"{'off_a':>8} {'off_b':>8} {'dInsn':>6} {'dChk':>5} {'size_a':>7} {'size_b':>7}")
    for r in scored[: a.top]:
        print(f"{r['off_a']:8x} {r['off_b']:8x} {r['d_insn']:6} {r['d_check']:5} "
              f"{r['size_a']:7} {r['size_b']:7}")
        if a.disasm:
            print(f"    A: {head(r['a']['code'], 8)}")
            print(f"    B: {head(r['b']['code'], 8)}")

    if a.json:
        import json
        rows = [{k: v for k, v in r.items() if k not in ("a", "b")} for r in scored]
        with open(a.json, "w") as fh:
            json.dump(rows, fh, indent=1)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
