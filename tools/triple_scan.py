"""全库三件套形态扫描（含平移归一）。

三件套 = 同一函数内同时具备：
  1) 0xE00002D8 错误码构造（movz wN,#0x2d8 + movk wN,#0xe000,lsl#16）
  2) 写内核结构体字段（strb wM,[xS,#off]，off < 0x4000）
  3) 读门（ldrb wM,[xS,#off2] 后 3 条内有条件跳）

避平移：先算每个 kext 的「主导偏移 delta」，把 offset 减去 delta 再比较。
已知正例 = iokit_IOSurface 的 +0xf1 三件套，必须命中。
"""
import os, sys, re, struct, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, kdiff_all as kd

MD = kd.MD
COND = {'b.eq','b.ne','b.lo','b.hi','b.ls','b.hs','b.mi','b.pl','b.vs','b.vc',
        'cbz','cbnz','tbz','tbnz'}


def sigs(view):
    """返回 {函数VA: set(签名)}，签名 = (strb偏移, ldrb偏移)"""
    out = {}
    for va, sz in view.functions():
        code = view.read(va, sz)
        if not code:
            continue
        try:
            ins = list(MD.disasm(code, va))
        except Exception:
            continue
        # 不要求 0x2d8：那个已被证否。只要「同偏移上既有写标记又有读门」
        strb, ldrb = set(), set()
        for i, x in enumerate(ins):
            m = re.match(r'w\d+, \[x\d+, #0x([0-9a-f]+)\]$', x.op_str)
            if not m:
                continue
            off = int(m.group(1), 16)
            if off >= 0x4000:
                continue
            if x.mnemonic == 'strb':
                strb.add(off)
            elif x.mnemonic == 'ldrb':
                if any(y.mnemonic in COND for y in ins[i+1:i+4]):
                    ldrb.add(off)
        both = strb & ldrb            # 同一偏移上：写标记 + 读门
        if both:
            out[va] = {(o, o) for o in both}
    return out


def dominant_delta(k1, k2, name):
    r = kd.diff_kext(k1, k2, name)
    if not r:
        return 0
    c = collections.Counter()
    for p in r['pairs']:
        rem = [t for t in p['rem'] if re.search(r'\[x\d+, #0x[0-9a-f]+\]', t)]
        add = [t for t in p['add'] if re.search(r'\[x\d+, #0x[0-9a-f]+\]', t)]
        if len(rem) != len(add):
            continue
        for a, b in zip(rem, add):
            ra, rb = re.match(r'(\w+)\s+x\d+,', a), re.match(r'(\w+)\s+x\d+,', b)
            if not (ra and rb) or ra.group(1) != rb.group(1):
                continue
            try:
                oa = int(re.search(r'#0x([0-9a-f]+)\]', a).group(1), 16)
                ob = int(re.search(r'#0x([0-9a-f]+)\]', b).group(1), 16)
            except AttributeError:
                continue
            if oa != ob:
                c[ob - oa] += 1
    return c.most_common(1)[0][0] if c else 0


def main():
    K1 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.0.1.full'))
    K2 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.2.ga.full'))
    names = sorted(set(K1.kexts) | set(K2.kexts))
    print(f'扫描 {len(names)} 个 kext 的三件套形态')
    rows = []
    for n in names:
        try:
            v1 = kd.KextView(K1, n)
            v2 = kd.KextView(K2, n)
        except Exception:
            continue
        s1, s2 = sigs(v1), sigs(v2)
        if not s1 and not s2:
            continue
        d = dominant_delta(K1, K2, n)
        def norm(s):
            return {(a - d, b - d) for a, b in s}
        n1 = collections.Counter()
        for s in s1.values():
            n1.update(norm(s))
        n2 = collections.Counter()
        for s in s2.values():
            n2.update(norm(s))
        gained = sum(max(0, n2[k] - n1.get(k, 0)) for k in n2)
        rows.append((n, len(s1), len(s2), d, gained))
    rows.sort(key=lambda r: -r[4])
    print(f'\n{"kext":52} {"27.0.1函数":>10} {"27.2函数":>9} {"主delta":>8} {"净增签名":>8}')
    for n, a, b, d, g in rows[:25]:
        print(f'{n:52} {a:10} {b:9} {d:+8} {g:8}')


if __name__ == '__main__':
    main()
