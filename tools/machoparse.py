"""Minimal Mach-O / fat-binary parser (stdlib only).

Extracts only what L0 recon needs:
  - arch, filetype, flags
  - LC_ENCRYPTION_INFO_64 -> whether the slice is cryptid
  - LC_CODE_SIGNATURE -> embedded entitlements XML
"""
import struct

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19

CSSLOT_ENTITLEMENTS = 5
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171

def cpu_name(cputype, cpusub):
    if cputype == 0x0100000C:
        return "arm64e" if (cpusub & 0x00FFFFFF) == 2 else "arm64"
    return {7: "i386", 0x01000007: "x86_64"}.get(cputype, hex(cputype))

FILETYPE = {1: "object", 2: "execute", 6: "dylib", 8: "bundle", 11: "kext"}


def _parse_superblob(data):
    if len(data) < 12:
        return None
    magic, length, count = struct.unpack(">III", data[:12])
    if magic != CSMAGIC_EMBEDDED_SIGNATURE or count > 64:
        return None
    out = []
    for i in range(count):
        off = 12 + i * 8
        if off + 8 > len(data):
            break
        blob_type, blob_off = struct.unpack(">II", data[off:off + 8])
        if blob_type != CSSLOT_ENTITLEMENTS or blob_off + 8 > len(data):
            continue
        bmagic, blen = struct.unpack(">II", data[blob_off:blob_off + 8])
        if bmagic != CSMAGIC_EMBEDDED_ENTITLEMENTS:
            continue
        raw = data[blob_off + 8: blob_off + blen]
        out.append(raw.decode("utf-8", "replace"))
    return out or None


def parse_slice(data, base=0):
    """Parse one thin Mach-O starting at base. Returns dict or None."""
    if len(data) < base + 32:
        return None
    magic = struct.unpack_from("<I", data, base)[0]
    if magic not in (MH_MAGIC_64, MH_MAGIC):
        return None
    is64 = magic == MH_MAGIC_64
    if is64:
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from("<IIIIII", data, base + 4)
        off = base + 32
    else:
        cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from("<IIIIII", data, base + 4)
        off = base + 28

    encrypted, cryptid, cs_off, cs_size = False, 0, None, None
    segments = []
    for _ in range(min(ncmds, 4096)):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8:
            break
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and off + 20 <= len(data):
            _cryptoff, _cryptsize, cid = struct.unpack_from("<III", data, off + 8)
            cryptid = cid
            encrypted = cid != 0
        elif cmd == LC_CODE_SIGNATURE and off + 16 <= len(data):
            cs_off, cs_size = struct.unpack_from("<II", data, off + 8)
        elif cmd == LC_SEGMENT_64 and off + 24 <= len(data):
            segname = data[off + 8: off + 24].rstrip(b"\x00").decode("ascii", "replace")
            vmsize = struct.unpack_from("<Q", data, off + 32)[0] if off + 40 <= len(data) else 0
            segments.append({"name": segname, "vmsize": vmsize})
        off += cmdsize

    ents = None
    if cs_off is not None and cs_size and base + cs_off + cs_size <= len(data):
        ents = _parse_superblob(data[base + cs_off: base + cs_off + cs_size])

    return {
        "cpu": cpu_name(cputype, cpusub),
        "filetype": FILETYPE.get(filetype, str(filetype)),
        "encrypted": encrypted,
        "cryptid": cryptid,
        "entitlements": ents,
        "segments": segments,
    }


def parse_file(path):
    with open(path, "rb") as fh:
        data = fh.read(64 * 1024 * 1024)
    if len(data) < 8:
        return {"error": "too small"}
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack_from(">I", data, 4)[0]
        slices = []
        for i in range(min(nfat, 8)):
            o = 8 + i * 20
            if o + 20 > len(data):
                break
            cputype, _sub, offset, size, _align = struct.unpack_from(">IIIII", data, o)
            info = parse_slice(data, offset) or {}
            info.setdefault("cpu", cpu_name(cputype, _sub))
            info["slice_offset"] = offset
            info["slice_size"] = size
            slices.append(info)
        return {"fat": True, "slices": slices}
    info = parse_slice(data, 0)
    return info or {"error": "not mach-o"}


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(parse_file(sys.argv[1]), indent=2, ensure_ascii=False))
