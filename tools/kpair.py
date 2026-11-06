#!/usr/bin/env python3
"""按 kext 内函数序号配对两个 kernelcache。参数是**相对 text_vmaddr 的函数偏移**。
用法: kpair.py A B 0x402f0ec [反汇编]
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kdiff as K
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def build(path):
    data = open(path, 'rb').read()
    sl = list(K.slices(data)) or [(0, len(data), 'com.apple.kernel')]
    out = {}
    for (foff, size, name) in sl:
        if name == '<single>':
            name = 'com.apple.kernel'
        to, tv, fns = K.macho_info(data, foff)
        if tv is None or not fns:
            continue
        out[name] = dict(data=data, text_off=to, vmaddr=tv, offs=fns,
                         segs=segs_of(data, foff))
    return out

def segs_of(data, base):
    ncmds = struct.unpack_from('<I', data, base+16)[0]
    off = base + 32
    segs = []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', data, off)
        if cmd == 0x19 and off + 72 <= len(data):
            va, vs, fo, fs = struct.unpack_from('<QQQQ', data, off+24)
            segs.append((va, vs, fo, fs))
        off += sz
    return segs

def va2off(s, va):
    for (sva, svs, sfo, sfs) in s['segs']:
        if sva <= va < sva + svs:
            delta = va - sva
            if delta < sfs:
                return sfo + delta
    return None

def dis(s, idx, n=160):
    off = s['offs'][idx]
    va = s['vmaddr'] + off
    start = va2off(s, va)
    if start is None:
        return ['<无法映射 %#x>' % va]
    nxt = s['offs'][idx+1] if idx+1 < len(s['offs']) else off + 0x800
    end = va2off(s, s['vmaddr'] + nxt) or (start + 0x2000)
    return [f"{i.mnemonic} {i.op_str}" for i in md.disasm(s['data'][start:min(end,start+0x4000)], va)][:n]

if __name__ == '__main__':
    A = build(sys.argv[1]); B = build(sys.argv[2])
    tgt = int(sys.argv[3], 16)
    do_dis = len(sys.argv) > 4
    for name, sa in A.items():
        if tgt in sa['offs']:
            idx = sa['offs'].index(tgt)
            print(f"kext={name} index={idx}/{len(sa['offs'])}")
            if name not in B:
                print('27.2 无同名 kext'); sys.exit(1)
            sb = B[name]
            if idx >= len(sb['offs']):
                print('27.2 序号越界'); sys.exit(1)
            print(f"27.0.1 offset={tgt:#x}   27.2 offset={sb['offs'][idx]:#x}")
            if do_dis:
                a = dis(sa, idx); b = dis(sb, idx)
                print(f"\n--- 27.0.1 ({len(a)} 条) ---")
                for l in a: print("  ", l)
                print(f"\n--- 27.2 ({len(b)} 条) ---")
                for l in b: print("  ", l)
            break
    else:
        print('未找到该函数偏移')
