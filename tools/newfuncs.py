"""列出 27.2 相对 27.0.1 的「新函数」。

不能按地址差集 —— 整镜像平移，地址全变。
正确做法：先按内容配对（diff_kext），配对不上的 27.2 函数才是新函数。

用法:
  python3 tools/newfuncs.py --kext com.apple.kernel
  python3 tools/newfuncs.py --list out/changed-kexts.txt
"""
import os, sys, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, kdiff_all as kd

MD = kd.MD


def shape(view, va, sz):
    """粗分类：返回标签列表"""
    code = view.read(va, sz)
    if not code:
        return ['读不到']
    try:
        ins = list(MD.disasm(code, va))
    except Exception:
        return ['反汇编失败']
    tags = []
    txt = [f'{x.mnemonic} {x.op_str}' for x in ins]
    joined = '\n'.join(txt)
    if any(x.mnemonic in ('udf', 'brk') for x in ins):
        tags.append('断言(udf/brk)')
    if any(x.mnemonic == 'movk' and '#0xe000' in x.op_str for x in ins):
        tags.append('构造 IOReturn')
    if any(x.mnemonic == 'ldrb' and '#' in x.op_str for x in ins):
        tags.append('字节读')
    if any(x.mnemonic == 'strb' for x in ins):
        tags.append('字节写')
    if any(x.mnemonic in ('casa', 'casal', 'cas', 'ldaxr', 'stlxr') for x in ins):
        tags.append('原子/CAS')
    if len(ins) <= 6 and any(x.mnemonic in ('ret', 'retab') for x in ins):
        tags.append('极短/转发')
    if all(x.mnemonic in ('mov', 'movk', 'movz', 'nop', 'ret', 'retab', 'bti', 'pacibsp',
                          'autibsp', 'adrp', 'add', 'ldr') for x in ins):
        tags.append('纯常量/转发')
    return tags


def run(K1, K2, name, verbose=True):
    r = kd.diff_kext(K1, K2, name)
    if not r:
        print(f'{name}: 无法差分')
        return []
    v2 = kd.KextView(K2, name)
    f2 = dict(v2.functions())
    paired = {p['va2'] for p in r['pairs']}
    new = sorted(set(f2) - paired)
    if verbose:
        print(f'\n=== {name}: 27.2 函数 {len(f2)}，配对上 {len(paired)}，未配对（新）{len(new)} ===')
    out = []
    for va in new:
        sz = f2[va]
        tg = shape(v2, va, sz)
        out.append((va, sz, tg))
        if verbose and sz >= 16:
            print(f'  0x{va:x}  {sz:6} B  {"/".join(tg) if tg else "—"}')
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--kext')
    ap.add_argument('--list')
    a = ap.parse_args(argv[1:])
    K1 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.0.1.full'))
    K2 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.2.ga.full'))
    names = [a.kext] if a.kext else [l.split()[1] for l in open(a.list) if l.strip() and not l.startswith('列') and l.split()[1] != '27.0.1']
    allnew = {}
    for n in names:
        allnew[n] = run(K1, K2, n, verbose=bool(a.kext))
    tot = sum(len(v) for v in allnew.values())
    print(f'\n合计新函数 {tot} 个，覆盖 {sum(1 for v in allnew.values() if v)} 个 kext')


if __name__ == '__main__':
    main(sys.argv)
