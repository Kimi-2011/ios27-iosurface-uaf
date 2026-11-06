"""Extract one kext from a kernelcache fileset into a standalone Mach-O.

Kernelcache segments are interleaved (all __TEXT together, all __TEXT_EXEC
together, ...), so a byte slice is not a loadable image. This rebuilds the kext:
header + load commands, then each segment's file bytes, rewriting every
file-offset field (segment fileoff, LC_FUNCTION_STARTS, LC_SYMTAB) to the new
layout. vmaddr/vmsize are untouched, so pointers keep their relative meaning.

Usage: python3 kext_extract.py KC --kext NAME --out kext.macho
"""
import argparse
import struct

import kdiff

SEG = 0x19
FSTART = 0x26
SYMTAB = 0x2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--kext", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    fo, _s, _n = [x for x in kdiff.slices(data) if x[2] == a.kext][0]
    ncmds, sizeofcmds = struct.unpack_from("<II", data, fo + 16)
    cmds = bytearray(data[fo + 32: fo + 32 + sizeofcmds])
    out = bytearray(data[fo:fo + 32]) + cmds      # header + commands, patched in place

    segs = []
    off = 0
    while off < sizeofcmds:
        cmd, cmdsize = struct.unpack_from("<II", cmds, off)
        if cmd == SEG:
            name = bytes(cmds[off + 8: off + 24]).rstrip(b"\x00").decode("ascii", "replace")
            vm, vs, f2, fsz = struct.unpack_from("<QQQQ", cmds, off + 24)
            segs.append({"name": name, "cmd": off, "vm": vm, "vs": vs, "old": f2, "fsz": fsz})
        off += cmdsize

    bodies = []
    for s in segs:
        if s["fsz"] == 0:
            s["new"] = 0
            continue
        s["new"] = len(out)
        out += data[s["old"]: s["old"] + s["fsz"]]
        while len(out) % 8:
            out.append(0)
        struct.pack_into("<Q", out, 32 + s["cmd"] + 40, s["new"])   # fileoff field
        bodies.append(s)

    def remap(old):
        for s in bodies:
            if s["old"] <= old < s["old"] + s["fsz"]:
                return s["new"] + (old - s["old"])
        return None

    off = 0
    while off < sizeofcmds:
        cmd, cmdsize = struct.unpack_from("<II", cmds, off)
        base = 32 + off
        if cmd == FSTART:
            (old,) = struct.unpack_from("<I", out, base + 8)
            nv = remap(old)
            if nv is not None:
                struct.pack_into("<I", out, base + 8, nv)
        elif cmd == SYMTAB:
            symoff, _n, stroff, _s2 = struct.unpack_from("<IIII", out, base + 8)
            for field, old in ((base + 8, symoff), (base + 16, stroff)):
                nv = remap(old)
                if nv is not None:
                    struct.pack_into("<I", out, field, nv)
        off += cmdsize

    struct.pack_into("<I", out, 12, 11)   # MH_KEXT_BUNDLE, not MH_FILESET
    with open(a.out, "wb") as fh:
        fh.write(out)
    print(f"{a.kext}: {len(bodies)} segments -> {a.out} ({len(out):,} bytes)")
    for s in bodies:
        print(f"  {s['name']:12} vm={s['vm']:#x} old={s['old']:#x} new={s['new']:#x} size={s['fsz']:#x}")


if __name__ == "__main__":
    main()
