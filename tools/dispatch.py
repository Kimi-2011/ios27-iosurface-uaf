"""Hunt for IOExternalMethodDispatch-style tables that reference a function.

A dispatch entry is 24 bytes:
    u64 action(void*, IOExternalMethodArguments*);
    u32 scalarInputCount;
    u32 structInputSize;
    u32 scalarOutputCount;
    u32 structOutputSize;

Pointers are VAs, so we convert the target's kext offset to a VA, search the
whole kernelcache for that 8-byte value, and print the surrounding entry.

Usage:
  python3 dispatch.py KC --kext NAME --off 0x...
"""
import argparse
import struct

import kdiff

SEG_CMD = 0x19


def segments(data, fo):
    ncmds = struct.unpack_from("<I", data, fo + 16)[0]
    off = fo + 32
    out = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == SEG_CMD:
            name = data[off + 8: off + 24].rstrip(b"\x00").decode("ascii", "replace")
            vm, vs, f2 = struct.unpack_from("<QQQ", data, off + 24)
            out.append((name, vm, vs, f2))
        off += cmdsize
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--kext", required=True)
    ap.add_argument("--off", required=True)
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    fo, _s, _n = [x for x in kdiff.slices(data) if x[2] == a.kext][0]
    _to, _vm, fns = kdiff.macho_info(data, fo)
    segs = segments(data, fo)
    texec = next((s for s in segs if s[0] == "__TEXT_EXEC"), None)
    if not texec:
        raise SystemExit("no __TEXT_EXEC")
    _tn, vm_exec, _vs, _f2 = texec
    fn0 = fns[0]
    off = int(a.off, 16)
    va = vm_exec + (off - fn0)
    print(f"{a.kext} off={off:#x} -> VA {va:#x}")

    # arm64e stores authenticated pointers: the canonical address survives in
    # the low 48 bits, the PAC/diversity bits sit above. Match on 48 bits.
    lo = va & 0xFFFFFFFFFFFF
    hits = []
    for i in range(0, len(data) - 8, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        if (v & 0xFFFFFFFFFFFF) == lo:
            hits.append(i)
    print(f"references to this pointer (48-bit masked): {len(hits)}")

    for i in hits[:8]:
        where = None
        for name, vm, vs, f2 in segs:
            if f2 <= i < f2 + vs:
                where = name
                break
        entry = data[i:i + 24]
        if len(entry) < 24:
            continue
        ptr, s1, st1, s2, st2 = struct.unpack("<QIIII", entry)
        plausible = all(0 <= v < 0x10000 for v in (s1, st1, s2, st2))
        print(f"  ref@{i:#x} in {where or 'other'} | +8: {s1},{st1},{s2},{st2}"
              f"{'  <- looks like a dispatch entry' if plausible else ''}")


if __name__ == "__main__":
    main()
