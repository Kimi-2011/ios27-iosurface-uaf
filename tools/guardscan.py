"""Scan for ADDED pointer/zero guards between two kernelcaches.

Signal that survives layout noise: a load `ldr x?, [xN, ...]` that in 27.2 is
preceded by `cbz/cbnz xN` (or `cmp xN,#0; b.eq`), but in 27.0.1 had no guard.
That is the shape of a null/zero-check fix.

Usage:
  python3 guardscan.py A.kcache B.kcache [--top 15] [--json OUT] [--kext NAME]
"""
import argparse
import difflib
import json

import kdiff
import pairing
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
LOADS = ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsw")
MAX_INSNS = 400


def disasm(code):
    out = []
    for i in md.disasm(code, 0):
        out.append(i)
        if i.mnemonic in ("ret", "retaa", "retab") or len(out) >= MAX_INSNS:
            break
    return out


def load_base(ins):
    """Return the base register name of a load, or None if not [reg, ...]."""
    mem = ins.operands[-1]
    if mem.type != 3:  # ARM64_OP_MEM
        return None
    if mem.mem.base == 0:
        return None
    name = ins.reg_name(mem.mem.base)
    if name in ("sp", "xzr", "wzr", None):
        return None
    return name


def guarded_loads(insns):
    n = 0
    for idx, ins in enumerate(insns):
        if ins.mnemonic not in LOADS:
            continue
        reg = load_base(ins)
        if not reg:
            continue
        window = insns[max(0, idx - 3):idx]
        hit = False
        for w in window:
            if w.mnemonic in ("cbz", "cbnz") and w.op_str.split(",")[0].strip() == reg:
                hit = True
            if w.mnemonic in ("tbz", "tbnz") and w.op_str.split(",")[0].strip() == reg:
                hit = True
        if not hit:
            for j in range(len(window) - 1):
                a, b = window[j], window[j + 1]
                if (a.mnemonic == "cmp" and "#0" in a.op_str
                        and a.op_str.split(",")[0].strip() == reg
                        and b.mnemonic in ("b.eq", "b.ne")):
                    hit = True
        n += 1 if hit else 0
    return n


def scan(path, kext):
    data = kdiff.load(path)
    for fo, size, name in kdiff.slices(data):
        if name != kext:
            continue
        _to, _vm, fns = kdiff.macho_info(data, fo)
        out = []
        for i, fn in enumerate(fns):
            start = fo + fn
            end = fo + fns[i + 1] if i + 1 < len(fns) else min(len(data), fo + size)
            if end <= start or end - start > 0x8000:
                continue
            code = data[start:end]
            out.append({"off": fn, "size": end - start,
                        "hash": kdiff.func_hash(code),
                        "ops": pairing.ops_of(disasm(code)),
                        "guards": guarded_loads(disasm(code))})
        return out
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--kext")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--json")
    a = ap.parse_args()

    kexts = [n for _f, _s, n in kdiff.slices(kdiff.load(a.a))]
    if a.kext:
        kexts = [k for k in kexts if a.kext in k]

    rows = []
    for kext in kexts:
        fa, fb = scan(a.a, kext), scan(a.b, kext)
        if not fa or not fb:
            continue
        ha = {x["hash"] for x in fa}
        hb = {y["hash"] for y in fb}
        ca = [x for x in fa if x["hash"] not in hb]
        cb = [y for y in fb if y["hash"] not in ha]
        for x, y, _r in pairing.pair(ca, cb):
            d = y["guards"] - x["guards"]
            if d > 0:
                rows.append({"kext": kext, "off_a": x["off"], "off_b": y["off"],
                             "guards_a": x["guards"], "guards_b": y["guards"],
                             "size_a": x["size"], "size_b": y["size"], "d": d})

    rows.sort(key=lambda r: (-r["d"], -(r["size_b"] - r["size_a"])))
    print(f"kexts scanned: {len(kexts)}   functions with ADDED guards: {len(rows)}\n")
    print(f"{'d':>3} {'gA':>3} {'gB':>3} {'size':>12}  {'kext':36} off_a")
    for r in rows[: a.top]:
        print(f"{r['d']:3} {r['guards_a']:3} {r['guards_b']:3} "
              f"{r['size_a']:5}->{r['size_b']:<5}  {r['kext'][:36]:36} {r['off_a']:#x}")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rows, fh, indent=1)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
