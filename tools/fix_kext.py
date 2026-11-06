#!/usr/bin/env python3
"""Rebuild a kext_extract.py output into a clean Mach-O that objdump can read.

kext_extract.py relocates segments but leaves section.offset pointing into the
original (shared) kernelcache, and keeps the bogus shared __LINKEDIT. Both make
llvm-objdump refuse the file.  This rewrites:
  * section.offset = seg.fileoff + (sect.addr - seg.vmaddr)
  * drops __LINKEDIT (its contents live in the shared kextcache)
  * sets S_ATTR_PURE_INSTRUCTIONS on every __TEXT_EXEC section
usage: fix_kext.py IN OUT
"""
import struct
import sys

SECT_SIZE = 80
LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF
CPU_ARM64E = 0x0100000C


def main(src, dst):
    d = open(src, "rb").read()
    if struct.unpack_from("<I", d, 0)[0] != MH_MAGIC_64:
        sys.exit("not Mach-O 64")
    ncmds = struct.unpack_from("<I", d, 16)[0]

    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == LC_SEGMENT_64:
            name = d[off + 8: off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24)
            nsects = struct.unpack_from("<I", d, off + 64)[0]
            if name != "__LINKEDIT":
                filesize = min(filesize, len(d) - fileoff)
                secs = []
                for i in range(nsects):
                    so = off + 72 + i * SECT_SIZE
                    sname = d[so: so + 16].rstrip(b"\0").decode()
                    addr, size = struct.unpack_from("<QQ", d, so + 32)
                    new_off = fileoff + (addr - vmaddr)
                    # zerofill (__bss/__common) sections may legitimately extend
                    # past the segment's file size -- clamp so objdump accepts it
                    avail = filesize - (addr - vmaddr)
                    if avail < size:
                        size = max(0, avail)
                    secs.append((sname, addr, size, new_off))
                segs.append((name, vmaddr, vmsize, fileoff, filesize, secs))
        off += cmdsize

    lcs = bytearray()
    for name, vmaddr, vmsize, fileoff, filesize, secs in segs:
        cmdsize = 72 + SECT_SIZE * len(secs)
        b = bytearray(cmdsize)
        struct.pack_into("<II", b, 0, LC_SEGMENT_64, cmdsize)
        b[8:24] = name.encode().ljust(16, b"\0")
        struct.pack_into("<QQQQ", b, 24, vmaddr, vmsize, fileoff, filesize)
        struct.pack_into("<iiII", b, 56, 7, 5, len(secs), 0)
        for i, (sname, addr, size, new_off) in enumerate(secs):
            so = 72 + i * SECT_SIZE
            b[so: so + 16] = sname.encode().ljust(16, b"\0")
            b[so + 16: so + 32] = name.encode().ljust(16, b"\0")
            struct.pack_into("<QQ", b, so + 32, addr, size)
            usable = 0 <= new_off <= len(d) and new_off + size <= len(d)
            struct.pack_into("<I", b, so + 48, new_off if usable else 0)
            pure = 0x80000400 if (name == "__TEXT_EXEC" or name == "__TEXT_BOOT_EXEC") else 0
            struct.pack_into("<I", b, so + 64, pure)
        lcs += b

    hdr = bytearray(32)
    struct.pack_into("<IiiIIIII", hdr, 0, MH_MAGIC_64, CPU_ARM64E, 0, 0xB,
                     len(segs), len(lcs), 0x00200085, 0)
    out = bytearray(hdr) + lcs
    for name, vmaddr, vmsize, fileoff, filesize, secs in segs:
        need = fileoff + filesize
        if len(out) < need:
            out += b"\0" * (need - len(out))
        out[fileoff: fileoff + filesize] = d[fileoff: fileoff + filesize]
    open(dst, "wb").write(out)
    print(f"{dst}: {len(out)} bytes, {len(segs)} segments")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
