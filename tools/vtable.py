"""Reconstruct vtable-like pointer arrays and map them back to function offsets.

Without symbols, C++ virtual dispatch is the main blind spot: a method is only
reachable through a table of code pointers in __DATA_CONST. This scans that
segment for 8-byte values that land inside the kext's __TEXT_EXEC range, groups
consecutive hits into candidate vtables, and reports which one references a
given function offset.

Usage:
  python3 vtable.py KC --kext NAME [--off 0x...] [--min-len 4]
"""
import argparse
import struct

import kdiff


def segments(data, fo):
    ncmds = struct.unpack_from("<I", data, fo + 16)[0]
    off = fo + 32
    out = {}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off + 8: off + 24].rstrip(b"\x00").decode("ascii", "replace")
            vm, vs, f2 = struct.unpack_from("<QQQ", data, off + 24)
            out[name] = (vm, vs, f2)
        off += cmdsize
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kc")
    ap.add_argument("--kext", required=True)
    ap.add_argument("--off")
    ap.add_argument("--min-len", type=int, default=4)
    a = ap.parse_args()

    data = open(a.kc, "rb").read()
    fo, _s, _n = [x for x in kdiff.slices(data) if x[2] == a.kext][0]
    _to, _vm, fns = kdiff.macho_info(data, fo)
    segs = segments(data, fo)
    vm_exec, vs_exec, _f2 = segs["__TEXT_EXEC"]
    fn0 = fns[0]
    fn_set = set(fns)

    file_lo = fo
    file_hi = fo + len(data)

    def decode(v):
        """kernelcache pointer forms:
             0x0010_0000_0000_0000 | file_offset(48)
             0x8011_xxxx_xxxxxxxx  | file_offset(32)   (PAC-signed)
        """
        if v == 0:
            return None
        if (v >> 48) == 0x0010:
            return v & 0xFFFFFFFFFFFF
        if (v >> 48) in (0x8011, 0x8010, 0x8012, 0x8013):
            return v & 0xFFFFFFFF
        return None

    def off_to_fn(off):
        if off is None or not (file_lo <= off < file_hi):
            return None
        fn = off - fo
        return fn if fn in fn_set else None

    target = int(a.off, 16) if a.off else None
    tables = []
    for segname in ("__DATA_CONST", "__DATA"):
        if segname not in segs:
            continue
        vm, vs, f2 = segs[segname]
        run = []
        off = f2
        end = f2 + vs - 8
        while off <= end:
            v = struct.unpack_from("<Q", data, off)[0]
            fn = off_to_fn(decode(v))
            if fn is not None and fn in fn_set:
                run.append((off, fn))
            else:
                if len(run) >= a.min_len:
                    tables.append((segname, run))
                run = []
            off += 8
        if len(run) >= a.min_len:
            tables.append((segname, run))

    print(f"{a.kext}: {len(tables)} candidate tables (>= {a.min_len} code pointers)")
    for segname, run in tables:
        hit = [r for r in run if target is not None and r[1] == target]
        label = f"  <-- contains {a.off}" if hit else ""
        print(f"  {segname} @{run[0][0]:#x} len={len(run)} first_fn={run[0][1]:#x}{label}")
        if hit and len(run) <= 40:
            for i, (o, fn) in enumerate(run):
                mark = " *" if fn == target else "  "
                print(f"    [{i:2}]{mark} {fn:#x}")
        if len(tables) > 12 and not hit:
            continue


if __name__ == "__main__":
    main()
