"""解 kernelcache 的 LC_DYLD_CHAINED_FIXUPS：imports 表 + 指针链。

输出符号级引用图：导入符号名 -> 哪些数据槽绑定它。
"""
import os, sys, struct, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg

LC_CHAINED = 0x80000034


def find_lc(d, cmd_want):
    ncmds = struct.unpack_from('<I', d, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, off)
        if cmd == cmd_want:
            return off, sz
        off += sz
    return None, 0


def page_starts(d, seg):
    """seg = dyld_chained_starts_in_segment 起始偏移；返回该 seg 的 page_start 数组"""
    size, psize, pfmt, segoff, maxvalid, ncount = struct.unpack_from('<IHHQIH', d, seg)
    out = []
    for i in range(ncount):
        v = struct.unpack_from('<H', d, seg + 22 + i * 2)[0]
        out.append(v)
    return psize, pfmt, segoff, out, ncount


def decode(path):
    K = kseg.Index(path)
    d = K.d
    lc, lsz = find_lc(d, LC_CHAINED)
    if lc is None:
        return None, 'no LC_DYLD_CHAINED_FIXUPS'
    dataoff, datasize = struct.unpack_from('<II', d, lc + 8)
    base = lc  # dataoff 相对于 linkedit? 通常是文件偏移
    start = dataoff
    ver, starts_off, imports_off, symbols_off, imp_cnt, imp_fmt, sym_fmt = struct.unpack_from('<7I', d, start)
    S = start
    imports = []
    for i in range(imp_cnt):
        if imp_fmt in (1, 2):
            v = struct.unpack_from('<I', d, S + imports_off + i * 4)[0]
            lib = v & 0xFF
            weak = (v >> 8) & 1
            name_off = (v >> 9) & 0x7FFFFF
            addend = 0
            if imp_fmt == 2:
                addend = struct.unpack_from('<i', d, S + imports_off + (i + imp_cnt) * 4)[0]
        else:
            v = struct.unpack_from('<Q', d, S + imports_off + i * 8)[0]
            lib = v & 0xFFFF
            weak = (v >> 16) & 1
            name_off = (v >> 17) & 0xFFFFFF
            addend = struct.unpack_from('<q', d, S + imports_off + (i + 1) * 8 + i * 8)[0] if False else 0
        p = S + symbols_off + name_off
        e = d.index(b'\0', p)
        imports.append((d[p:e].decode('utf-8', 'replace'), lib, weak, addend))
    # starts
    seg_count = struct.unpack_from('<I', d, S + starts_off)[0]
    seg_info = struct.unpack_from(f'<{seg_count}I', d, S + starts_off + 4)
    binds = collections.defaultdict(list)   # name -> [(va, kext)]
    rebases = []
    for i, so in enumerate(seg_info):
        if so == 0:
            continue
        segbase = S + starts_off + so
        psize, pfmt, segoff, pages, ncnt = page_starts(d, segbase)
        for pi, pv in enumerate(pages):
            if pv == 0xFFFF:
                continue
            addr = segoff + pi * psize
            off = pv if pv >= 0xF000 else pv * 4
            while True:
                fo = segoff + pi * psize + off
                if fo + 8 > len(d):
                    break
                w = struct.unpack_from('<Q', d, fo)[0]
                nxt = (w >> 51) & 0xFFF
                if w >> 63:
                    ordinal = w & 0xFFFFFF
                    va = K.off2va(fo) if hasattr(K, 'off2va') else None
                    if ordinal < len(imports):
                        binds[imports[ordinal][0]].append((fo, va, i))
                else:
                    rebases.append(fo)
                if nxt == 0:
                    break
                off += nxt * 4 if pv < 0xF000 else nxt
    return {'imports': imports, 'binds': binds, 'rebases': len(rebases),
            'start': start, 'imp_cnt': imp_cnt, 'imp_fmt': imp_fmt}, None


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'out', 'kc.27.0.1.full')
    r, err = decode(path)
    if err:
        print('ERR', err); sys.exit(1)
    print(f"imports {r['imp_cnt']} 条（格式 {r['imp_fmt']}），rebase 槽 {r['rebases']} 个，绑定符号 {len(r['binds'])} 个")
    for name in ('_IOLog', '_IOSurfaceRoot', '_panic'):
        print(f"  正例 {name}: {len(r['binds'].get(name, []))} 个绑定槽")
    top = sorted(r['binds'].items(), key=lambda x: -len(x[1]))[:12]
    print('绑定最多的符号:')
    for n, v in top:
        print(f"  {n:44} {len(v):5} 槽")
