#!/usr/bin/env python3
"""verify_symbols.py <reference-macho> <dumped .symbols.txt>
Cross-checks a symbol table dumped out of a live process against the nlist
entries of the same image extracted from the dyld shared cache.  Compares the
full (name -> n_value) mapping in both directions.
"""
import sys, struct

def ref_syms(path):
    d = open(path,'rb').read()
    ncmds = struct.unpack('<I', d[16:20])[0]; off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack('<II', d[off:off+8])
        if cmd == 0x2:
            symoff, nsyms, stroff, strsize = struct.unpack('<IIII', d[off+8:off+24]); break
        off += size
    else:
        raise SystemExit('no LC_SYMTAB')
    out = {}
    for k in range(nsyms):
        o = symoff + k*16
        strx, typ, sect, desc, val = struct.unpack('<IBBHQ', d[o:o+16])
        if strx >= strsize: continue
        e = d.index(b'\0', stroff+strx)
        out[d[stroff+strx:e].decode('utf-8','replace')] = val
    return out

def dump_syms(path):
    out = {}
    for line in open(path):
        p = line.split(None, 3)
        if len(p) < 4: continue
        out[p[3].strip()] = int(p[0], 16)
    return out

def main():
    r = ref_syms(sys.argv[1]); m = dump_syms(sys.argv[2])
    common = set(r) & set(m)
    diff = [n for n in common if r[n] != m[n]]
    only_r = len(set(r)-set(m)); only_m = len(set(m)-set(r))
    ok = not diff and only_r == 0 and only_m == 0
    print(f'  ref={len(r)} dump={len(m)} common={len(common)} '
          f'addr_mismatch={len(diff)} only_ref={only_r} only_dump={only_m} '
          f'-> {"VERIFIED" if ok else "MISMATCH"}')
    for n in diff[:5]: print(f'    ! {n} ref={r[n]:#x} dump={m[n]:#x}')
    sys.exit(0 if ok else 1)

main()
