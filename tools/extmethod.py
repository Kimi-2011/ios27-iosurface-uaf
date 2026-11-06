"""IOExternalMethod 表枚举（步长 0x30，函数指针在 +0x08）。

为什么需要它：tools/census.py 只识别 IOExternalMethodDispatch
（步长 0x18，函数指针在 +0x00）。iOS 27 的 kext 大量使用另一种记录形态
IOExternalMethod：
    +0x00  IOService*  object
    +0x08  fn          (bti c 函数入口)
    +0x10  count0/count1
    +0x18  count2/count3
    +0x20  count4/count5
    +0x28  count6/count7
census 对这种表完全看不见（例：AppleMobileDispH18P-DCP 记 0，实际 230 项）。

用法：
    python3 tools/extmethod.py <kernelcache> [kext子串] [--json out.json]
"""
import sys, struct, json
sys.path.insert(0, __file__.rsplit('/', 2)[0] + '/tools')
import kseg

BTI_C = 0xD503245F


def scan(K):
    def first4(va):
        b = K.read(va, 4)
        return struct.unpack('<I', b)[0] if b else None
    rows = []
    for name, segs in K.kexts.items():
        tr = [(vm, vm + fsz) for vm, vs, f2, fsz, sn in segs if sn == '__TEXT_EXEC']
        if not tr:
            continue
        for vm, vs, f2, fsz, sn in segs:
            if 'DATA' not in sn.upper():
                continue
            n = fsz // 8
            ok = [False] * n
            for i in range(n):
                if (i + 6) * 8 + 8 > fsz:
                    break
                q = struct.unpack_from('<Q', K.d, f2 + i * 8 + 8)[0]
                tgt = kseg.KB_BASE + (q & 0xFFFFFFFF)
                if any(a <= tgt < b for a, b in tr) and first4(tgt) == BTI_C:
                    ok[i] = True
            i = 0
            while i < n:
                if ok[i] and (i - 6 < 0 or not ok[i - 6]):
                    L = 0
                    while i + 6 * L < n and ok[i + 6 * L]:
                        L += 1
                    if L >= 3:
                        rows.append((name, sn, vm + i * 8, L))
                    i += 6 * max(L, 1)
                else:
                    i += 1
    return rows


def dump(K, name, base, n):
    out = []
    for e in range(n):
        va = base + e * 0x30
        b = K.read(va, 0x30)
        if not b:
            break
        q = struct.unpack('<QQQQQQ', b)
        fn = kseg.KB_BASE + (q[1] & 0xFFFFFFFF)
        out.append({
            'idx': e, 'rec': va, 'fn': fn,
            'c': (q[2] & 0xFFFFFFFF, q[2] >> 32,
                  q[3] & 0xFFFFFFFF, q[3] >> 32,
                  q[4] & 0xFFFFFFFF, q[4] >> 32,
                  q[5] & 0xFFFFFFFF, q[5] >> 32),
        })
    return out


if __name__ == '__main__':
    path = sys.argv[1]
    pat = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else None
    K = kseg.Index(path)
    rows = scan(K)
    if pat:
        rows = [r for r in rows if pat in r[0]]
    print(f"表 {len(rows)}")
    from collections import Counter
    tot = Counter()
    for nn, _, _, L in rows:
        tot[nn] += L
    for k, v in tot.most_common(30):
        print(f"  {v:>5} 项  {k}")
    if '--json' in sys.argv:
        json.dump([{'kext': a, 'seg': b, 'base': hex(c), 'n': d} for a, b, c, d in rows],
                  open(sys.argv[sys.argv.index('--json') + 1], 'w'))
