"""Inventory IOExternalMethodDispatch-style tables across the whole kernelcache.

Entry layout (24 bytes): {u64 action; u32 scalarIn; u32 structIn; u32 scalarOut; u32 structOut}
Pointers use the kernelcache encodings decoded in vtable.py. An entry is accepted
when the pointer lands on a function start and the four counts are small.

Usage:
  python3 dispatchall.py KC [--json OUT]
"""
import argparse
import json
import struct

import kdiff
import vtable


def decode(v):
    if v == 0:
        return None
    if (v >> 48) == 0x0010:
        return v & 0xFFFFFFFFFFFF
    if (v >> 32) & 0xFFFF in (0x8011, 0x8010, 0x8012):
        return v & 0xFFFFFFFF
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--json")
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    ents = kdiff.slices(data)
    rows = []
    for fo, _size, name in ents:
        try:
            segs = vtable.segments(data, fo)
        except Exception:
            continue
        try:
            _to, _vm, fns = kdiff.macho_info(data, fo)
        except Exception:
            continue
        fset = set(fns)
        for seg in ("__DATA_CONST", "__DATA"):
            if seg not in segs:
                continue
            vm, vs, f2 = segs[seg]
            for i in range(0, vs - 24, 8):
                v, s1, st1, s2, st2 = struct.unpack_from("<QIIII", data, f2 + i)
                off = decode(v)
                if off is None:
                    continue
                fn = off - fo
                if fn not in fset:
                    continue
                if not (s1 < 0x10000 and st1 < 0x100000 and s2 < 0x10000 and st2 < 0x100000):
                    continue
                if s1 == st1 == s2 == st2 == 0:
                    continue
                rows.append({"kext": name, "seg": seg, "at": i, "fn": fn,
                             "scalar_in": s1, "struct_in": st1,
                             "scalar_out": s2, "struct_out": st2})

    print(f"dispatch-like entries: {len(rows)}")
    by = {}
    for r in rows:
        by.setdefault(r["kext"], []).append(r)
    top = sorted(by.items(), key=lambda kv: -len(kv[1]))[:15]
    for kext, rs in top:
        print(f"  {kext[:46]:46} {len(rs):4} entries, e.g. fn {rs[0]['fn']:#x} "
              f"in={rs[0]['scalar_in']}/{rs[0]['struct_in']} out={rs[0]['scalar_out']}/{rs[0]['struct_out']}")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rows, fh, indent=1)
        print(f"json -> {a.json}")


if __name__ == "__main__":
    main()
