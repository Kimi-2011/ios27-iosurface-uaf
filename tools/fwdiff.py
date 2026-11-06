#!/usr/bin/env python3
"""用户态 Mach-O 框架函数级差分（形状匹配 + 符号化）。"""
import sys, struct, collections, bisect, os
from capstone import *

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def load_macho(path):
    d = open(path,'rb').read()
    magic = struct.unpack_from('<I', d, 0)[0]
    if magic in (0xcafebabe, 0xbebafeca):          # fat
        nfat = struct.unpack_from('>I', d, 4)[0]
        best=None
        for i in range(nfat):
            cpu, sub, off, size, align = struct.unpack_from('>iiIII', d, 8+i*20)
            if cpu == 0x0100000c: best = off      # arm64
        if best is None: raise SystemExit("no arm64 slice")
        d = d[best:]
        magic = struct.unpack_from('<I', d, 0)[0]
    if magic != 0xfeedfacf: raise SystemExit(f"not 64-bit mach-o: {magic:#x}")
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32; segs = []; fnstarts = None; symtab = None
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, off)
        if cmd == 0x19:                            # LC_SEGMENT_64
            name = d[off+8:off+24].rstrip(b'\0').decode()
            va, vs, fo, fs = struct.unpack_from('<QQQQ', d, off+24)
            segs.append((name, va, vs, fo, fs))
        elif cmd == 0x26:                          # LC_FUNCTION_STARTS
            fnstarts = struct.unpack_from('<II', d, off+8)
        elif cmd == 0x2:                           # LC_SYMTAB
            symtab = struct.unpack_from('<IIII', d, off+8)
        off += sz
    return d, segs, fnstarts, symtab

def uleb(buf, i):
    r=0; s=0
    while True:
        b=buf[i]; i+=1; r |= (b & 0x7f) << s
        if not (b & 0x80): break
        s += 7
    return r, i

def func_starts(d, segs, fnstarts):
    if not fnstarts: return []
    dataoff, size = fnstarts
    base = None
    for n,va,vs,fo,fs in segs:
        if n == '__TEXT': base = va
    if base is None: base = segs[0][1]
    out=[]; i=dataoff; end=dataoff+size
    cur = base
    while i < end:
        v,i = uleb(d, i)
        if v == 0: break
        cur += v
        out.append(cur)
    return out

def symbols(d, symtab):
    if not symtab: return {}
    symoff, nsyms, stroff, strsize = symtab
    out={}
    for i in range(nsyms):
        strx, ntype, sect, desc, value = struct.unpack_from('<IBBHQ', d, symoff+i*16)
        if (ntype & 0x0e) != 0x0e: continue        # 只要 N_SECT
        s = d[stroff+strx: d.index(b'\0', stroff+strx)].decode(errors='replace')
        if s: out.setdefault(value, s)
    return out

def va2off(segs, va):
    for n,sv,vs,fo,fs in segs:
        if sv <= va < sv+vs and (va-sv) < fs: return fo+(va-sv)
    return None

def shape_at(d, segs, va, endva, maxi=600):
    o = va2off(segs, va)
    if o is None: return None
    e = va2off(segs, endva) or (o+0x4000)
    t=[]
    for ins in md.disasm(d[o:min(e,o+0x8000)], va):
        t.append(ins.mnemonic)
        if ins.mnemonic in ('ret','retaa') or len(t)>maxi: break
    return tuple(t) if len(t)>=6 else None

def analyze(path):
    d, segs, fnstarts, symtab = load_macho(path)
    starts = func_starts(d, segs, fnstarts)
    syms = symbols(d, symtab)
    shapes = {}
    for i,va in enumerate(starts):
        end = starts[i+1] if i+1 < len(starts) else va+0x4000
        s = shape_at(d, segs, va, end)
        if s: shapes.setdefault(s, []).append(va)
    return dict(path=path, d=d, segs=segs, starts=starts, syms=syms, shapes=shapes)

def main(pa, pb):
    A=analyze(pa); B=analyze(pb)
    print(f"A: {pa}  函数 {len(A['starts'])}")
    print(f"B: {pb}  函数 {len(B['starts'])}")
    uniqA={s:v[0] for s,v in A['shapes'].items() if len(v)==1}
    uniqB={s:v[0] for s,v in B['shapes'].items() if len(v)==1}
    common=set(uniqA) & set(uniqB)
    print(f"形状唯一且两版都有: {len(common)}")
    onlyA=[s for s in uniqA if s not in uniqB]
    onlyB=[s for s in uniqB if s not in uniqA]
    print(f"仅在 A（27.0.1）出现的形状: {len(onlyA)}")
    print(f"仅在 B（27.2）出现的形状: {len(onlyB)}")
    # 用符号给“仅在某版出现”的函数命名
    def nm(D, va): return D['syms'].get(va) or f"sub_{va:x}"
    print("\n仅在 A 出现（B 中被修改或删除）的前 20 个：")
    for s in onlyA[:20]:
        va=uniqA[s]; print(f"  {nm(A,va):40} {len(s):4d} insn")
    print("\n仅在 B 出现（A 中被修改或新增）的前 20 个：")
    for s in onlyB[:20]:
        va=uniqB[s]; print(f"  {nm(B,va):40} {len(s):4d} insn")

if __name__=='__main__':
    main(sys.argv[1], sys.argv[2])
