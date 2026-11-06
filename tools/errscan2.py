"""扫描 movz wN,#imm + movk wN,#0xe000 (lsl #16) 组合，按 kext 对比两版。
纯字节编码匹配，不反汇编 —— 301 个 kext 秒级完成。

用法: python3 tools/errscan2.py [--lo 0x2d8] [--hi 0x2e8]
"""
import os, sys, struct, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg

MOVZ_M   = 0x7F800000
MOVZ_V   = 0x52800000
MOVK16_M = 0x7FE00000
MOVK16_V = 0x72A00000


def scan_index(K, lo, hi):
    """返回 {kext: set((imm16, hex_va))}"""
    out = {}
    for name in K.kexts:
        hits = set()
        for vm, vs, fo, fsz, sn in K.kexts[name]:
            blob = K.d[fo:fo + fsz]
            n = len(blob) // 4
            for i in range(n):
                w = struct.unpack_from('<I', blob, i * 4)[0]
                if (w & MOVZ_M) != MOVZ_V:
                    continue
                imm = (w >> 5) & 0xFFFF
                if not (lo <= imm <= hi):
                    continue
                rd = w & 31
                for j in range(i + 1, min(i + 7, n)):
                    w2 = struct.unpack_from('<I', blob, j * 4)[0]
                    if (w2 & MOVK16_M) == MOVK16_V and (w2 & 31) == rd \
                       and ((w2 >> 5) & 0xFFFF) == 0xE000:
                        hits.add((imm, vm + i * 4))
                        break
        if hits:
            out[name] = hits
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--lo', default='0x2d8')
    ap.add_argument('--hi', default='0x2e8')
    a = ap.parse_args(argv[1:])
    lo, hi = int(a.lo, 0), int(a.hi, 0)
    K1 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.0.1.full'))
    K2 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.2.ga.full'))
    s1 = scan_index(K1, lo, hi)
    s2 = scan_index(K2, lo, hi)
    print(f'范围 0x{lo:x}..0x{hi:x}')
    print(f'27.0.1 命中 {sum(len(v) for v in s1.values())} 处 / {len(s1)} 个 kext')
    print(f'27.2   命中 {sum(len(v) for v in s2.values())} 处 / {len(s2)} 个 kext')
    print()
    print('== 27.2 有、27.0.1 没有的（按错误码聚合）==')
    total = 0
    per_code = {}
    for name in sorted(s2):
        for imm, va in s2[name]:
            total += 1
            per_code.setdefault(imm, []).append((name, va))
    for imm in sorted(per_code):
        lst = per_code[imm]
        print(f'  0xE0000{imm:03X}  {len(lst)} 处  ({len({n for n,_ in lst})} 个 kext)')
    print()
    print('== 明细（只列 27.0.1 完全没出现过的 kext+代码组合）==')
    for imm in sorted(per_code):
        lst = per_code[imm]
        new = set()
        for name, va in lst:
            if name not in s1:
                new.add(name)
        if new:
            print(f'  0xE0000{imm:03X}: {sorted(new)}')


if __name__ == '__main__':
    main(sys.argv)
