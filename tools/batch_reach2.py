"""Reachability v2: walk up from each candidate and test ancestors for table slots.

v1 tested the candidate itself, which produced coincidence hits. Real dispatch
entries hold *ancestors* (the ANE case: candidate -> wrapper -> state-machine
table). A slot counts only if its pointer is tagged AND has nearby tagged
entries that also land on function starts.

Usage: python3 batch_reach2.py KC --cands out/checks2.json [--json OUT] [--depth 3]
"""
import argparse
import json
import struct
from collections import deque

import kdiff
import vtable


def tagged(v):
    if (v >> 48) == 0x0010:
        return v & 0xFFFFFFFFFFFF
    if (v >> 48) in (0x8011, 0x8010, 0x8012, 0x8013):
        return v & 0xFFFFFFFF
    return None


def table_index(data, fo, segs, fset):
    idx = {}
    for seg in ("__DATA_CONST", "__DATA"):
        if seg not in segs:
            continue
        vm, vs, f2 = segs[seg]
        for i in range(0, vs - 8, 8):
            v = struct.unpack_from("<Q", data, f2 + i)[0]
            off = tagged(v)
            if off is None:
                continue
            fn = off - fo
            if fn not in fset:
                continue
            nb = 0
            for k in range(1, 5):
                if i + 8 * k >= vs:
                    break
                o2 = tagged(struct.unpack_from("<Q", data, f2 + i + 8 * k)[0])
                if o2 is not None and (o2 - fo) in fset:
                    nb += 1
            if nb >= 2:
                idx[fn] = (f2 + i, nb)
    return idx


def build_edges(data):
    edges = {}
    for i in range(0, len(data) - 4, 4):
        w = struct.unpack_from("<I", data, i)[0]
        op = w & 0xFC000000
        if op == 0x94000000 or op == 0x14000000:
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            edges.setdefault(i + (imm << 2), []).append(i)
    return edges


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--cands", default="out/checks2.json")
    ap.add_argument("--json")
    ap.add_argument("--depth", type=int, default=3)
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    rows = json.load(open(a.cands))
    edges = build_edges(data)
    enc = {n: f for f, _s, n in kdiff.slices(data)}

    out = []
    for r in rows:
        kext, fn = r["kext"], r["off_a"]
        fo = enc.get(kext)
        if fo is None:
            continue
        try:
            segs = vtable.segments(data, fo)
        except Exception:
            continue
        _to, _vm, fns = kdiff.macho_info(data, fo)
        fset = set(fns)
        idx = table_index(data, fo, segs, fset)
        if not idx:
            continue
        start = fo + fn
        seen = {start}
        q = deque([(start, 0)])
        hit = None
        while q and hit is None:
            node, d = q.popleft()
            if d > a.depth:
                continue
            fnv = node - fo
            if fnv in idx and fnv != fn:
                hit = (fnv, idx[fnv], d)
                break
            for caller in edges.get(node, []):
                if caller in seen:
                    continue
                seen.add(caller)
                # snap to containing function
                import bisect
                j = bisect.bisect_right(fns, caller - fo) - 1
                if j < 0:
                    continue
                fs = fns[j]
                q.append((fo + fs, d + 1))
        if hit:
            out.append({"kext": kext, "cand": fn, "ancestor": hit[0],
                        "slot": hex(hit[1][0]), "depth": hit[2]})

    print(f"candidates: {len(rows)}   with a table ancestor: {len(out)}\n")
    for o in out[:25]:
        print(f"  {o['kext'][:36]:36} cand {o['cand']:>#9x} -> ancestor {o['ancestor']:>#9x} "
              f"(depth {o['depth']}, slot {o['slot']})")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=1)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
