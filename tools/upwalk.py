"""Walk up a call graph and score each ancestor by data references.

A function referenced from a data table (dispatch/vtable) is a reachability
anchor; one with only code callers is an internal helper. This prints a tree
annotated with both counts so the search stops at the first table-referenced
ancestor.

Usage:
  python3 upwalk.py KC --kext NAME --off 0x... [--depth 4]
"""
import argparse
import struct
import sys
from collections import deque

import kdiff
import vtable


def build_edges(data):
    edges = {}
    for i in range(0, len(data) - 4, 4):
        w = struct.unpack_from("<I", data, i)[0]
        op = w & 0xFC000000
        if op != 0x94000000 and op != 0xFF000000:
            continue
        if op == 0xFF000000 and (w & 0xFC000000) != 0x14000000:
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        edges.setdefault(i + (imm << 2), []).append(i)
    return edges


def data_ref_index(data):
    """Map target file offset -> number of encoded pointers to it."""
    counts = {}
    for i in range(0, len(data) - 8, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        off = None
        if (v >> 48) == 0x0010:
            off = v & 0xFFFFFFFFFFFF
        elif (v >> 32) & 0xFFFF in (0x8011, 0x8010, 0x8012):
            off = v & 0xFFFFFFFF
        if off is not None:
            counts[off] = counts.get(off, 0) + 1
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--kext", required=True)
    ap.add_argument("--off", required=True)
    ap.add_argument("--depth", type=int, default=4)
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    ents = kdiff.slices(data)
    fo = [f for f, _s, n in ents if n == a.kext][0]
    _to, _vm, fns = kdiff.macho_info(data, fo)
    fsorted = sorted(fns)

    def fstart(fileoff):
        fn = fileoff - fo
        import bisect
        j = bisect.bisect_right(fsorted, fn) - 1
        return fsorted[j] + fo if j >= 0 else None

    edges = build_edges(data)
    drefs = data_ref_index(data)

    start = fo + int(a.off, 16)
    seen = {start}
    q = deque([(start, 0, True)])
    print(f"{'depth':>5} {'fn':>18} {'code':>5} {'data':>5}  note")
    while q:
        node, depth, is_root = q.popleft()
        dn = drefs.get(node, 0)
        note = "start" if is_root else ("<== table-referenced" if dn else "")
        print(f"{depth:5} {node - fo:#18x} {len(edges.get(node, [])):5} {dn:5}  {note}")
        if depth >= a.depth:
            continue
        for caller in edges.get(node, []):
            fs = fstart(caller)
            if fs is None or fs in seen:
                continue
            seen.add(fs)
            q.append((fs, depth + 1, False))


if __name__ == "__main__":
    main()
