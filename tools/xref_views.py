
"""函数交叉引用（在 kernelcache 切片上工作）—— 逐函数反汇编，不用线性扫。

三种引用：
  callers(view, target)    `bl` 直接调用者（含调用点地址）
  addr_taken(view)         `adrp+add` 取地址表 {目标VA: [指令地址]}
  data_ptrs(view, target)  `__DATA*` 里低 48 位等于 target 的 8 字节槽（含 PAC 掩码）

用法：
    python3 tools/xref_views.py --kext com.apple.security.sandbox --va 0xfffffe000a8eee60 --field 0xc
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg
import kdiff_all as kd

MD = kd.MD


def _each_insn(view):
    for va, sz in view.functions():
        code = view.read(va, sz)
        if not code:
            continue
        try:
            for x in MD.disasm(code, va):
                yield va, x
        except Exception:
            continue


def callers(view, target):
    out = []
    for fn, x in _each_insn(view):
        if x.mnemonic == 'bl' and x.op_str.startswith('#'):
            try:
                t = int(x.op_str[1:], 0)
            except ValueError:
                continue
            if t == target:
                out.append((fn, x.address))
    return out


def addr_taken(view):
    out = {}
    for va, sz in view.functions():
        code = view.read(va, sz)
        if not code:
            continue
        try:
            ins = list(MD.disasm(code, va))
        except Exception:
            continue
        page = {}
        for x in ins:
            if x.mnemonic == 'adrp':
                try:
                    r, i = x.op_str.split(', ')
                except ValueError:
                    continue
                page[r.strip()] = int(i.strip()[1:], 0)
            elif x.mnemonic == 'add':
                p = [q.strip() for q in x.op_str.split(',')]
                if len(p) == 3 and p[1] in page and p[2].startswith('#'):
                    t = page[p[1]] + int(p[2][1:], 0)
                    out.setdefault(t, []).append(x.address)
    return out


def data_ptrs(view, target):
    hits = []
    lo48 = target & 0x0000FFFFFFFFFFFF
    pat = lo48.to_bytes(8, 'little')
    for vm, vs, fo, fsz, sn, mp, ip in view.segs:
        if ip & 0x4:
            continue
        blob = view.d[fo:fo + fsz]
        i = blob.find(pat)
        while i != -1:
            if i % 8 == 0:
                hits.append((sn, vm + i, int.from_bytes(blob[i:i + 8], 'little')))
            i = blob.find(pat, i + 1)
    return hits


def field_bytes(view, off):
    out = []
    for fn, x in _each_insn(view):
        if x.mnemonic in ('ldrb', 'ldrsb', 'strb', 'ldurb', 'sturb', 'ldar', 'stlr'):
            if ('#0x%x]' % off) in x.op_str or ('#%d]' % off) in x.op_str:
                out.append((fn, x.address, x.mnemonic, x.op_str))
    return out


def backtrace_x1(view, fn, call_at, depth=18):
    """在调用点往回扫，判断 x1 从哪来。返回 (描述, 指令列表)。"""
    sz = dict(view.functions())[fn]
    code = view.read(fn, sz)
    ins = [x for x in MD.disasm(code, fn) if x.address <= call_at]
    seq = ins[-depth:]
    for x in reversed(seq):
        ops = x.op_str
        if x.mnemonic in ('mov', 'orr') and ops.startswith('x1, '):
            return (f'mov: {x.mnemonic} {ops}', seq)
        if x.mnemonic == 'ldr' and ops.startswith('x1, '):
            return (f'load: ldr {ops}', seq)
        if x.mnemonic == 'add' and ops.startswith('x1, '):
            return (f'add: {ops}', seq)
        if x.mnemonic == 'ldp' and 'x1' in ops:
            return (f'ldp: {ops}', seq)
        if x.mnemonic == 'adrp' and 'x1' in ops:
            return (f'adrp: {ops}（x1 直接被装页基址，异常）', seq)
    return ('未在 18 条内改写 x1 ⇒ 沿用进入函数时的 x1', seq)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--kext', required=True)
    ap.add_argument('--va', required=True)
    ap.add_argument('--ver', default='2701', choices=['2701', '272'])
    ap.add_argument('--field')
    ap.add_argument('--backtrace', action='store_true')
    a = ap.parse_args(argv[1:])
    kc = 'kc.27.0.1.full' if a.ver == '2701' else 'kc.27.2.ga.full'
    K = kseg.Index(os.path.join(ROOT, 'out', kc))
    v = kd.KextView(K, a.kext)
    tgt = int(a.va, 0)
    print(f'[{a.ver}] {a.kext} 目标 0x{tgt:x}')
    c = callers(v, tgt)
    print(f'  bl 调用者: {len(c)}')
    for fn, at in c:
        print(f'     调用点 0x{at:x}  在函数 0x{fn:x}')
        if a.backtrace:
            desc, seq = backtrace_x1(v, fn, at)
            print(f'       x1 来源: {desc}')
            for x in seq[-8:]:
                print(f'         0x{x.address:x} {x.mnemonic} {x.op_str}')
    at2 = addr_taken(v)
    print(f'  adrp+add 取地址: {len(at2.get(tgt, []))}')
    for x in at2.get(tgt, [])[:10]:
        print(f'     0x{x:x}')
    dp = data_ptrs(v, tgt)
    print(f'  数据段指针槽: {len(dp)}')
    for seg, va, val in dp[:10]:
        print(f'     {seg} 0x{va:x} = 0x{val:x}')
    if a.field:
        fb = field_bytes(v, int(a.field, 0))
        print(f'  字节访问 [xN,#{a.field}]: {len(fb)} 处，涉及 {len({f for f,_,_,_ in fb})} 个函数')
        for fn, at, m, o in fb[:14]:
            print(f'     0x{at:x}  {m} {o}   在 0x{fn:x}')


if __name__ == '__main__':
    main(sys.argv)
