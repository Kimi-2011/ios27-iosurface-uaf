"""按归一化内容哈希判定「新函数」。
先给 27.0.1 建 (size, token-hash) 索引，再查 27.2 的每个函数是否存在于旧版。
"""
import os, sys, hashlib, argparse, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, kdiff_all as kd


def index(view):
    idx = collections.defaultdict(list)
    for va, sz in view.functions():
        t = kd.toks(view, va, sz)
        if not t:
            continue
        h = hashlib.sha1('\n'.join(t).encode()).hexdigest()
        idx[(sz, h)].append(va)
    return idx


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--kext', required=True)
    a = ap.parse_args(argv[1:])
    K1 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.0.1.full'))
    K2 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.2.ga.full'))
    v1 = kd.KextView(K1, a.kext); v2 = kd.KextView(K2, a.kext)
    i1 = index(v1)
    print(f'{a.kext}: 27.0.1 索引 {len(i1)} 组 / {sum(len(v) for v in i1.values())} 个函数')
    f2 = dict(v2.functions())
    new = []
    for va, sz in v2.functions():
        t = kd.toks(v2, va, sz)
        if not t:
            continue
        h = hashlib.sha1('\n'.join(t).encode()).hexdigest()
        if (sz, h) not in i1:
            new.append((va, sz))
    print(f'27.2 共 {len(f2)} 个函数，其中 {len(new)} 个在 27.0.1 里找不到同内容函数')
    for va, sz in new[:60]:
        print(f'  0x{va:x}  {sz:6} B')


if __name__ == '__main__':
    main(sys.argv)
