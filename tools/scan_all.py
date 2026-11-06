#!/usr/bin/env python3
"""全量用户态差分扫描：按符号名 join 两版，找「新增边界检查 / 变长」的函数。
输出 JSONL，可断点续跑。进度按百分比打印。"""
import os, sys, json, time, multiprocessing as mp

A_ROOT = '/tmp/dsc/ios2701'
B_ROOT = '/tmp/dsc/ios272'
OUT    = 'out/scan_all.jsonl'
CHK = ('cmp ', 'cmn ', 'tst ', 'subs ', 'ands ', 'ccmp', 'cbz ', 'cbnz', 'tbz ', 'tbnz', 'b.hs', 'b.lo', 'b.hi')

def feats(path):
    """返回 {符号名: (指令数, 检查数)}"""
    import fwdiff as F
    try:
        D = F.analyze(path)
    except Exception:
        return None
    starts = D['starts']; syms = D['syms']; d = D['d']; segs = D['segs']
    out = {}
    n = len(starts)
    for i, va in enumerate(starts):
        nm = syms.get(va)
        if not nm:
            continue
        end = starts[i+1] if i+1 < n else va + 0x800
        if end - va > 0xC000:            # 跳过超大函数
            continue
        s = F.shape_at(d, segs, va, end)
        if not s:
            continue
        c = 0
        for m in s:
            for t in CHK:
                if t.startswith('b.'):
                    if m == t: c += 1; break
                elif m.startswith(t.strip()):
                    c += 1; break
        out[nm] = (len(s), c)
    return out

def work(rel):
    a = os.path.join(A_ROOT, rel); b = os.path.join(B_ROOT, rel)
    if not (os.path.exists(a) and os.path.exists(b)):
        return (rel, None)
    fa = feats(a); fb = feats(b)
    if not fa or not fb:
        return (rel, None)
    hits = []
    for nm, (na, ca) in fa.items():
        if na < 8 or na > 3000:
            continue
        t = fb.get(nm)
        if not t:
            continue
        nb, cb = t
        dins = nb - na; dchk = cb - ca
        if dins > 0 and dchk > 0:
            hits.append((dchk, dins, nm, na, nb))
    return (rel, hits)

def main():
    files = []
    for root, _, fs in os.walk(A_ROOT):
        for f in fs:
            p = os.path.join(root, f)
            rel = os.path.relpath(p, A_ROOT)
            if os.path.exists(os.path.join(B_ROOT, rel)):
                files.append(rel)
    files.sort()
    total = len(files)
    print(f"待扫 {total} 个 dylib", flush=True)
    done = 0; t0 = time.time()
    with open(OUT, 'w') as out, mp.Pool(8) as pool:
        for rel, hits in pool.imap_unordered(work, files, chunksize=4):
            done += 1
            if hits:
                for dchk, dins, nm, na, nb in hits:
                    out.write(json.dumps({'f': rel, 'sym': nm, 'dchk': dchk,
                                          'dins': dins, 'na': na, 'nb': nb}) + '\n')
                out.flush()
            if done % 50 == 0 or done == total:
                el = time.time() - t0
                eta = el / done * (total - done) if done else 0
                print(f"进度 {done}/{total} = {done*100.0/total:.1f}%  "
                      f"已用 {el/60:.1f}min  预计剩余 {eta/60:.1f}min", flush=True)
    print("完成", flush=True)

if __name__ == '__main__':
    main()
