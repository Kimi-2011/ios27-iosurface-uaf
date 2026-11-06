"""Build a BL/B call graph over a kernelcache and walk up from a function.

One pass collects every direct branch target; walking up is then O(1) per level.
Cross-kext calls are included because all kexts share one address space.

Usage:
  python3 callgraph.py KC --kext NAME --off 0x... [--depth 3]
"""
import argparse
import struct
from collections import deque

import kdiff
import vtable


def build(data):
    edges = {}
    for i in range(0, len(data) - 4, 4):
        w = struct.unpack_from("<I", data, i)[0]
        op = w & 0xFC000000
        if op != 0x94000000 and op != 0x14000000:
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        tgt = i + (imm << 2)
        edges.setdefault(tgt, []).append((i, "bl" if op == 0x94000000 else "b"))
    return edges


def segmap(data, ents):
    out = []
    for fo, _size, name in ents:
        try:
            s = vtable.segments(data, fo)
        except Exception:
            continue
        for seg in ("__TEXT_EXEC", "__TEXT"):
            if seg in s:
                vm, vs, f2 = s[seg]
                out.append((f2, f2 + vs, name, fo))
    return out


def owner(m, off):
    for a, b, name, fo in m:
        if a <= off < b:
            return name, off - fo
    return "?", off


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--kext", required=True)
    ap.add_argument("--off", required=True)
    ap.add_argument("--depth", type=int, default=3)
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    ents = kdiff.slices(data)
    m = segmap(data, ents)
    edges = build(data)

    fo = [f for f, _s, n in ents if n == a.kext][0]
    start = fo + int(a.off, 16)
    print(f"build graph: {len(edges)} branch targets\n")

    seen = {start}
    frontier = deque([(start, 0)])
    while frontier:
        node, depth = frontier.popleft()
        name, fn = owner(m, node)
        print(f"{'  ' * depth}{name} +{fn:#x}" + ("  <== start" if depth == 0 else ""))
        if depth >= a.depth:
            continue
        for caller, kind in edges.get(node, []):
            if caller in seen:
                continue
            seen.add(caller)
            cname, cfn = owner(m, caller)
            print(f"{'  ' * (depth + 1)}{kind} from {cname} +{cfn:#x}")
            frontier.append((caller, depth + 1))


if __name__ == "__main__":
    main()
