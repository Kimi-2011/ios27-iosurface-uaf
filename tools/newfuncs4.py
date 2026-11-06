"""粗键序列对齐：键 = (体积桶, 前 6 条指令助记符序列)。
body 变一条指令不影响键，所以只有真新函数才会成为插入段。
"""
import os, sys, argparse, difflib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, kdiff_all as kd
MD = kd.MD


def keyof(view, va, sz):
    code = view.read(va, sz)
    if not code:
        return f'{sz//32}:?'
    try:
        ins = list(MD.disasm(code, va))
    except Exception:
        return f'{sz//32}:?'
    if not ins:
        return f'{sz//32}:e'
    head = ','.join(x.mnemonic for x in ins[:6])
    # 桶宽 32 字节，容忍小改
    return f'{sz//32}:{head}'


def seq(view):
    return [(keyof(view, va, sz), va, sz) for va, sz in view.functions()]


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--kext', required=True)
    a = ap.parse_args(argv[1:])
    K1 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.0.1.full'))
    K2 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.2.ga.full'))
    s1 = seq(kd.KextView(K1, a.kext)); s2 = seq(kd.KextView(K2, a.kext))
    print(f'{a.kext}: {len(s1)} -> {len(s2)}')
    sm = difflib.SequenceMatcher(None, [x[0] for x in s1], [x[0] for x in s2], autojunk=False)
    new, gone = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ('insert', 'replace'):
            new += s2[j1:j2]
        if tag in ('delete', 'replace'):
            gone += s1[i1:i2]
    print(f'插入 {len(new)} 个；删除 {len(gone)} 个')
    v2 = kd.KextView(K2, a.kext)
    for k, va, sz in new:
        code = v2.read(va, min(sz, 400)) or b''
        toks = [x.mnemonic for x in MD.disasm(code, va)][:14] if code else []
        tag = ''
        if any(t in ('udf', 'brk') for t in toks): tag = ' [断言]'
        joined = ' '.join(toks)
        print(f'  0x{va:x} {sz:5}B  {" ".join(toks[:8])}{tag}')


if __name__ == '__main__':
    main(sys.argv)
