"""Scan for ADDED bounds checks and bit tests between two kernelcaches.

Patterns counted per function:
  bounds : `cmp <reg>, #imm` immediately followed by an unsigned branch
           (b.hi / b.hs / b.lo / b.ls / b.cs / b.cc)  -> new upper/lower bound
  bittest: `tbnz / tbz <reg>, #imm`                    -> new flag/bit validation

Ranking = (bounds_delta * 2 + bittest_delta), then size delta.

Usage:
  python3 checkscan.py A B [--top 25] [--kext NAME] [--userclient] [--json OUT]
"""
import argparse
import difflib
import json
import sys

import kdiff
import pairing
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
UNSIGNED_BR = ("b.hi", "b.hs", "b.lo", "b.ls", "b.cs", "b.cc")
MAX_INSNS = 500


def disasm(code):
    out = []
    for i in md.disasm(code, 0):
        out.append(i)
        if i.mnemonic in ("ret", "retaa", "retab") or len(out) >= MAX_INSNS:
            break
    return out


def count_checks(insns):
    bounds = bits = 0
    for i, ins in enumerate(insns):
        if ins.mnemonic in ("tbnz", "tbz"):
            bits += 1
        elif ins.mnemonic == "cmp" and i + 1 < len(insns):
            nxt = insns[i + 1]
            if nxt.mnemonic in UNSIGNED_BR:
                # only count a real bound: an immediate that is not #0
                ops = ins.op_str.split(",")
                if len(ops) >= 2 and ops[1].strip() not in ("#0", "#0x0"):
                    bounds += 1
    return bounds, bits


def has_userclient(data, fo):
    """Cheap reachability proxy: does this kext contain IOUserClient strings?"""
    blob = data[fo:fo + 0x20000]
    return b"UserClient" in blob or b"IOExternalMethod" in blob


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
            b, t = count_checks(disasm(code))
            out.append({"off": fn, "size": end - start,
                        "hash": kdiff.func_hash(code),
                        "ops": pairing.ops_of(disasm(code)),
                        "bounds": b, "bits": t})
        return out
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--kext")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--userclient", action="store_true", help="only kexts containing UserClient strings")
    ap.add_argument("--json")
    a = ap.parse_args()

    data_a = kdiff.load(a.a)
    kexts = [n for _f, _s, n in kdiff.slices(data_a)]
    if a.kext:
        kexts = [k for k in kexts if a.kext in k]
    if a.userclient:
        keep = []
        for k in kexts:
            fo = [f for f, _s, n in kdiff.slices(data_a) if n == k][0]
            if has_userclient(data_a, fo):
                keep.append(k)
        kexts = keep
        print(f"(userclient filter: {len(kexts)} kexts)")

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
            db, dt = y["bounds"] - x["bounds"], y["bits"] - x["bits"]
            score = db * 2 + dt
            if score > 0:
                rows.append({"kext": kext, "off_a": x["off"], "off_b": y["off"],
                             "bounds_a": x["bounds"], "bounds_b": y["bounds"],
                             "bits_a": x["bits"], "bits_b": y["bits"],
                             "size_a": x["size"], "size_b": y["size"], "score": score})

    rows.sort(key=lambda r: (-r["score"], -(r["size_b"] - r["size_a"])))
    print(f"kexts scanned: {len(kexts)}   functions with ADDED checks: {len(rows)}\n")
    print(f"{'sc':>3} {'bA':>3} {'bB':>3} {'tA':>3} {'tB':>3} {'size':>12}  {'kext':34} off_a")
    for r in rows[: a.top]:
        print(f"{r['score']:3} {r['bounds_a']:3} {r['bounds_b']:3} {r['bits_a']:3} {r['bits_b']:3} "
              f"{r['size_a']:5}->{r['size_b']:<5}  {r['kext'][:34]:34} {r['off_a']:#x}")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rows, fh, indent=1)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
