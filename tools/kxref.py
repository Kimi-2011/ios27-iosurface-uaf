#!/usr/bin/env python3
"""String xref for kernelcache kexts: adrp/add (and ldr-literal) -> string VA -> function."""
import bisect
import re
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0] + "/tools")
from kaudit import Kext, load_dis, funcs  # noqa: E402


def build(macho, dis):
    k = Kext(macho)
    ins, order = load_dis(dis)
    starts = funcs(ins, order)
    strings = k.strings()
    pending = {}
    hits = {}
    for va in order:
        s = ins[va]
        m = re.match(r"adrp\s+(x\d+), (0x[0-9a-f]+)", s)
        if m:
            pending[(function_of(starts, va), m.group(1))] = (va, int(m.group(2), 16))
            continue
        m = re.match(r"(?:add|ldr|ldrb)\s+(x\d+), (x\d+), #(0x[0-9a-f]+|\d+)", s)
        if m:
            key = (function_of(starts, va), m.group(2))
            if key in pending:
                base, page = pending.pop(key)
                tgt = page + int(m.group(3), 0)
                if tgt in strings:
                    hits.setdefault(tgt, []).append(va)
    return k, ins, order, starts, strings, hits


def function_of(starts, va):
    i = bisect.bisect_right(starts, va) - 1
    return starts[i] if i >= 0 else 0


if __name__ == "__main__":
    macho, dis, pat = sys.argv[1], sys.argv[2], sys.argv[3]
    k, ins, order, starts, strings, hits = build(macho, dis)
    rx = re.compile(pat)
    for tgt in sorted(hits):
        if rx.search(strings[tgt]):
            fs = sorted({function_of(starts, v) for v in hits[tgt]})
            print(f"{strings[tgt][:100]!r}")
            print(f"    str={tgt:#x}  funcs={[hex(f) for f in fs]}")
