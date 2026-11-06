"""Attach nearby C strings to a function (poor man's symbolization).

Release kernelcaches are stripped, but log/format strings survive in
__TEXT,__cstring. For a function, collect adrp/add pairs that form a VA, map
that VA through the kext's segments, and print the C string at that address.

Usage:
  python3 strxref.py KC --kext NAME --off 0x... [--limit 12]
"""
import argparse
import re
import struct

import kdiff
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
PRINTABLE = re.compile(rb"^[ -~]{3,120}$")


def segs(data, fo):
    ncmds = struct.unpack_from("<I", data, fo + 16)[0]
    off = fo + 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off + 8: off + 24].rstrip(b"\x00").decode("ascii", "replace")
            vm, vs, f2 = struct.unpack_from("<QQQ", data, off + 24)
            out.append((name, vm, vs, f2))
        off += cmdsize
    return out


def va_to_file(segments, va):
    for _n, vm, vs, f2 in segments:
        if vm <= va < vm + vs:
            return f2 + (va - vm)
    return None


def cstr(data, off):
    if off is None or off >= len(data):
        return None
    end = data.find(b"\x00", off, off + 160)
    if end < 0:
        return None
    raw = data[off:end]
    if not PRINTABLE.match(raw):
        return None
    return raw.decode("ascii", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--kext", required=True)
    ap.add_argument("--off", required=True)
    ap.add_argument("--limit", type=int, default=12)
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    fo, _sz, _name = [x for x in kdiff.slices(data) if x[2] == a.kext][0]
    _to, _vm, fns = kdiff.macho_info(data, fo)
    target = int(a.off, 16)
    nxt = next((f for f in fns if f > target), target + 0x1000)
    seg = segs(data, fo)

    adrp = {}
    found = []
    for ins in md.disasm(data[fo + target: fo + nxt], 0):
        if ins.mnemonic == "adrp" and len(ins.operands) == 2:
            reg = ins.reg_name(ins.operands[0].reg)
            adrp[reg] = ins.operands[1].imm
        elif ins.mnemonic == "add" and len(ins.operands) == 3:
            d, s, imm = ins.operands
            if s.type == 1 and d.type == 1:
                base = adrp.get(ins.reg_name(s.reg))
                if base is not None and imm.type == 2:
                    va = base + imm.imm
                    st = cstr(data, va_to_file(seg, va))
                    if st:
                        found.append((ins.address, st))
        elif ins.mnemonic in ("ret", "retaa", "retab"):
            break

    print(f"{a.kext} off={a.off}  (function {target:#x}..{nxt:#x})")
    seen = set()
    for addr, s in found:
        if s in seen:
            continue
        seen.add(s)
        print(f"  +{addr:#06x}  {s}")
        if len(seen) >= a.limit:
            break
    if not seen:
        print("  (no C-string references in this function)")


if __name__ == "__main__":
    main()
