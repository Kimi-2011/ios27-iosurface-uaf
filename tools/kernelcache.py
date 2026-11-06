"""Kernelcache fileset parser.

iOS kernelcache is a Mach-O *fileset*: one outer Mach-O whose LC_FILESET_ENTRY
commands point at embedded kext Mach-Os. Release builds have no LC_SYMTAB, so
diffing is done on function starts + disassembly, not symbol names.

Usage:
  python3 kernelcache.py KERNELCACHE_DECOMPRESSED [--list] [--json OUT]
"""
import argparse
import json
import struct

LC_FILESET_ENTRY = 0x80000035
MH_MAGIC_64 = 0xFEEDFACF


def parse(path):
    with open(path, "rb") as fh:
        data = fh.read()
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MH_MAGIC_64:
        raise SystemExit(f"not Mach-O 64: {magic:#x}")
    cputype, cpusub, filetype, ncmds, sizeofcmds, _flags = struct.unpack_from("<IIIIII", data, 4)
    off = 32
    entries = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_FILESET_ENTRY and cmdsize >= 32:
            vmaddr, fileoff = struct.unpack_from("<QQ", data, off + 8)
            id_off = struct.unpack_from("<I", data, off + 24)[0]
            name = data[off + id_off: off + cmdsize].split(b"\x00")[0].decode("ascii", "replace")
            entries.append({"id": name, "fileoff": fileoff, "vmaddr": vmaddr, "cmdsize": cmdsize})
        off += cmdsize
    return {"cputype": cputype, "filetype": filetype, "ncmds": ncmds,
            "size": len(data), "entries": entries}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kernelcache")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()

    info = parse(a.kernelcache)
    print(f"size={info['size']:,} cputype={info['cputype']:#x} filetype={info['filetype']} "
          f"ncmds={info['ncmds']} kexts={len(info['entries'])}")

    if a.list:
        for e in info["entries"][:60]:
            print(f"  {e['fileoff']:>10}  {e['id']}")
        if len(info["entries"]) > 60:
            print(f"  ... {len(info['entries']) - 60} more")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(info, fh, indent=1)
        print(f"json -> {a.json}")


if __name__ == "__main__":
    main()
