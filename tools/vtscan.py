"""正确解码的 chained-fixups 槽索引 + vtable 反推。

只收录 starts 表登记的**真实**槽（不是撒网扫 __DATA_CONST 每个 8 字节字）。
target = bits 0..29，cacheLevel = bits 30..31。
"""
import os, sys, struct, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, chainfix as C

BASE = 0xfffffe0007004000


class Slots:
    def __init__(self, path):
        self.K = kseg.Index(path)
        self.d = self.K.d
        lc, _ = C.find_lc(self.d, 0x80000034)
        S = struct.unpack_from('<I', self.d, lc + 8)[0]
        so = struct.unpack_from('<I', self.d, S + 4)[0]
        segc = struct.unpack_from('<I', self.d, S + so)[0]
        infos = struct.unpack_from(f'<{segc}I', self.d, S + so + 4)
        self.bytab = {}        # target_va -> [fileoff]
        self.slot = {}         # fileoff -> target_va
        d = self.d
        for i, sio in enumerate(infos):
            if not sio:
                continue
            b = S + so + sio
            size, psize, pfmt, segoff, mv, ncnt = struct.unpack_from('<IHHQIH', d, b)
            for pi in range(ncnt):
                pv = struct.unpack_from('<H', d, b + 22 + pi * 2)[0]
                if pv == 0xFFFF:
                    continue
                off = pv if pv >= 0xF000 else pv * 4
                while True:
                    fo = segoff + pi * psize + off
                    if fo + 8 > len(d):
                        break
                    w = struct.unpack_from('<Q', d, fo)[0]
                    nxt = (w >> 51) & 0x7FF
                    tgt = w & 0x3FFFFFFF
                    if tgt:
                        self.bytab.setdefault(BASE + tgt, []).append(fo)
                        self.slot[fo] = BASE + tgt
                    else:
                        self.slot[fo] = 0
                    if nxt == 0:
                        break
                    off += nxt * 8 if pv >= 0xF000 else nxt * 4
        self.rng = []
        for n, segs in self.K.kexts.items():
            for vm, vs, fo, fsz, sn in segs:
                self.rng.append((fo, fo + fsz, n, sn))

    def who(self, fo):
        for a, b, n, sn in self.rng:
            if a <= fo < b:
                return n, sn
        return '?', '?'

    def hits(self, va):
        return self.bytab.get(va, [])

    def neighbors(self, fo, k=6):
        """同页内相邻槽（真实槽），用来判断 vtable 归属"""
        out = []
        for delta in range(-k, k + 1):
            off = fo + delta * 8
            if off in self.slot:
                out.append((delta, off, self.slot[off], self.who(off)))
        return out


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'out', 'kc.27.2.ga.full')
    S = Slots(path)
    print(f'{os.path.basename(path)}: 真实槽 {len(S.slot)} 个，非空 target {len(S.bytab)} 个不重复')
    targets = [int(x, 16) for x in sys.argv[2:]]
    for va in targets:
        hs = S.hits(va)
        print(f'\n0x{va:x}: {len(hs)} 个槽')
        for fo in hs[:6]:
            n, sn = S.who(fo)
            print(f'   slot 0x{fo:x}  {n} {sn}')
