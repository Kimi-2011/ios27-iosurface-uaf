"""Batch reachability triage for every candidate function.

Three cheap signals, no decompilation:
  1. dispatch slot  - is the function referenced from a data table?
  2. table context  - strings adjacent to that table name the subsystem
  3. entitlement    - does the kext's strings carry a privileged gate
                      (com.apple.*.allow / iokit / private)?

Usage: python3 batch_reach.py KC --cands out/checks2.json --json out/reach.json
"""
import argparse
import json
import re
import struct

import kdiff
import vtable

STR = re.compile(rb"[ -~]{4,64}")


def cstr(data, off, limit):
    if not (0 <= off < limit):
        return None
    end = data.find(b"\0", off, off + 96)
    if end < 0:
        return None
    raw = data[off:end]
    return raw.decode("ascii", "replace") if STR.fullmatch(raw) else None


def kext_facts(data, fo, cand_offs):
    try:
        segs = vtable.segments(data, fo)
    except Exception:
        return None
    _to, _vm, fns = kdiff.macho_info(data, fo)
    fset = set(fns)
    text = segs.get("__TEXT")
    limit = text[2] + text[1] if text else len(data)

    slots = {}
    for seg in ("__DATA_CONST", "__DATA"):
        if seg not in segs:
            continue
        vm, vs, f2 = segs[seg]
        for i in range(0, vs - 8, 8):
            v = struct.unpack_from("<Q", data, f2 + i)[0]
            if v == 0:
                continue
            for off in (v & 0xFFFFFFFFFFFF, v & 0xFFFFFFFF):
                fn = off - fo
                if fn in cand_offs:
                    slots.setdefault(fn, []).append(f2 + i)
                    break

    out = {}
    for fn, where in slots.items():
        names = []
        for slot in where[:2]:
            for i in range(slot - 0x300, slot + 0x300, 8):
                if i < 0:
                    continue
                v = struct.unpack_from("<Q", data, i)[0]
                if v == 0:
                    continue
                for off in (v & 0xFFFFFFFFFFFF, v & 0xFFFFFFFF):
                    s = cstr(data, off, limit)
                    if s and s not in names:
                        names.append(s)
        out[fn] = {"slots": [hex(x) for x in where], "names": names[:6]}

    ents = set()
    if text:
        start, size, f2 = text[2], text[1], text[2]
        vm, vs, f2 = text
        for m in re.finditer(rb"com\.apple\.[a-zA-Z0-9_.]{3,40}", data[f2:f2 + vs]):
            s = m.group(0).decode()
            if any(k in s for k in (".allow", "iokit", "private", ".entitlement")):
                ents.add(s)
    return {"slots": out, "ents": sorted(ents)[:8]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--cands", default="out/checks2.json")
    ap.add_argument("--json")
    a = ap.parse_args()

    rows = json.load(open(a.cands))
    by_kext = {}
    for r in rows:
        by_kext.setdefault(r["kext"], set()).add(r["off_a"])

    data = open(a.kc, "rb").read()
    ents = {n: f for f, _s, n in kdiff.slices(data)}

    results = []
    for kext, cands in by_kext.items():
        fo = ents.get(kext)
        if fo is None:
            continue
        facts = kext_facts(data, fo, cands)
        if not facts:
            continue
        gated = bool(facts["ents"])
        for fn, info in facts["slots"].items():
            results.append({
                "kext": kext, "fn": fn,
                "slots": info["slots"], "names": info["names"],
                "gated": gated, "ents": facts["ents"][:3],
            })

    results.sort(key=lambda r: (r["gated"], -len(r["names"])))
    print(f"candidates in {len(by_kext)} kexts; {len(results)} sit in a data table\n")
    print(f"{'gate':5} {'kext':38} {'fn':>10}  table context")
    for r in results[:30]:
        names = ", ".join(r["names"][:3]) or "-"
        print(f"{'YES' if r['gated'] else 'no':5} {r['kext'][:38]:38} {r['fn']:>#10x}  {names[:60]}")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(results, fh, indent=1)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
