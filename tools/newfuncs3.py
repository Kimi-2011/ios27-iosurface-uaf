"""用序列对齐（difflib.SequenceMatcher）找真正的新函数。
函数序列大体保序；用 (size, 归一化哈希) 作为序列元素，插入段即新函数。
"""
import os, sys, hashlib, argparse, difflib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, kdiff_all as kd


def seq(view):
    out = []
    for va, sz in view.functions():
        t = kd.toks(view, va, sz)
        h = hashlib.sha1('\n'.join(t).encode()).hexdigest()[:16] if t else 'x'
        out.append((f'{sz}:{h}', va, sz))
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--kext', required=True)
    a = ap.parse_args(argv[1:])
    K1 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.0.1.full'))
    K2 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.2.ga.full'))
    s1 = seq(kd.KextView(K1, a.kext))
    s2 = seq(kd.KextView(K2, a.kext))
    print(f'{a.kext}: {len(s1)} -> {len(s2)}')
    sm = difflib.SequenceMatcher(None, [x[0] for x in s1], [x[0] for x in s2], autojunk=False)
    new, gone = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ('insert', 'replace'):
            for j in range(j1, j2):
                new.append(s2[j])
        if tag in ('delete', 'replace'):
            for i in range(i1, i2):
                gone.append(s1[i])
    print(f'插入（新函数）{len(new)} 个；删除 {len(gone)} 个')
    for sig, va, sz in new[:40]:
        print(f'  新 0x{va:x}  {sz:6} B')
    for sig, va, sz in gone[:10]:
        print(f'  删 0x{va:x}  {sz:6} B')


if __name__ == '__main__':
    main(sys.argv)
