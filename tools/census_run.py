#!/usr/bin/env python3
"""全 cache 派发表普查 + 每个 selector 的入参画像 + 风险排序。"""
import json
import sys
from bisect import bisect_right
from collections import defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts, data_path, code_path

ARGS_FIELDS = {0x10: 'asyncWakeTarget', 0x18: 'scalarInputPacked', 0x20: 'scalarInput64',
               0x28: 'scalarInputCount', 0x30: 'structureInput', 0x38: 'structureInputSize',
               0x58: 'structureOutput', 0x60: 'size@0x60', 0x68: 'structureOutputDescriptor',
               0x70: 'size@0x70', 0x78: 'structureVariableOutputData'}
LEN_LIKE = {'structureInputSize', 'scalarInputPacked', 'scalarInput64',
            'size@0x60', 'size@0x70', 'scalarInputCount'}

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF


def _scan(c, bundle, va, fend, maxins=128):
    te = c.kseg(bundle, '__TEXT_EXEC')
    vm, vs, fo, sz = te
    off = fo + (va - vm)
    end = fo + (min(va + maxins * 4, fend) - vm)
    insns = list(md.disasm(c.d[off:end], va))
    args_regs = {'x2'}          # IOExternalMethodAction 的第 3 参
    taint = {}                  # reg -> field name（用户可控）
    bounded = set()             # 字段名（同寄存器被 imm 比较过）
    reads = set()
    hits = []
    tail = None
    USER_FIELDS = set(LEN_LIKE) | {'structureInput'}

    CREG = set()

    def tset(r, nm):
        taint[r] = nm

    for ins in insns:
        ops = ins.operands
        m = ins.mnemonic
        # 谁在指着 args
        if m in ('mov', 'add') and ops and ops[0].type == ARM64_OP_REG:
            for o in ops[1:]:
                if o.type == ARM64_OP_REG and ins.reg_name(o.reg) in args_regs:
                    args_regs.add(ins.reg_name(ops[0].reg))
        # 寄存器移动：传播污点
        if m in ('mov', 'movz', 'movk') and ops and ops[0].type == ARM64_OP_REG and \
                any(o.type == ARM64_OP_IMM for o in ops[1:]):
            CREG.add(ins.reg_name(ops[0].reg))
        if m == 'mov' and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
            src = ins.reg_name(ops[1].reg)
            if src in taint:
                tset(ins.reg_name(ops[0].reg), taint[src])
            continue
        if m.startswith('ldr') and len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
            mem = ops[1].mem
            base = ins.reg_name(mem.base)
            dst = ins.reg_name(ops[0].reg) if ops[0].type == ARM64_OP_REG else None
            if base in args_regs and mem.disp in ARGS_FIELDS:
                nm = ARGS_FIELDS[mem.disp]
                reads.add(nm)
                if dst and nm in USER_FIELDS:
                    tset(dst, nm)
            elif base in taint and dst:
                # 通过 structureInput 指针解引用得到的字段 —— 同样是用户可控
                tset(dst, taint[base] + '(field)')
            if mem.index and ins.reg_name(mem.index) in taint and \
                    ins.reg_name(mem.index) not in CREG:
                nm = taint[ins.reg_name(mem.index)]
                hits.append(('idx', nm, -1, nm in bounded))
        if m in ('cmp', 'cmn', 'subs', 'ands', 'tst', 'ccmp', 'ccmn'):
            if ops and ops[0].type == ARM64_OP_REG:
                r0 = ins.reg_name(ops[0].reg)
                if r0 in taint and any(o.type == ARM64_OP_IMM for o in ops[1:]):
                    bounded.add(taint[r0])
        if m in ('lsl', 'mul', 'umull', 'smull', 'madd', 'msub', 'umaddl', 'smaddl'):
            srcs = [ins.reg_name(o.reg) for o in ops[1:] if o.type == ARM64_OP_REG]
            names = [taint[r] for r in srcs if r in taint]
            if names and ops[0].type == ARM64_OP_REG:
                tset(ins.reg_name(ops[0].reg), names[0])
                hits.append(('arith', names[0], -1, names[0] in bounded))
        if m == 'add' and len(ops) >= 3 and ops[0].type == ARM64_OP_REG:
            srcs = [ins.reg_name(o.reg) for o in ops[1:] if o.type == ARM64_OP_REG]
            names = [taint[r] for r in srcs if r in taint]
            scaled = any(o.type == ARM64_OP_REG and getattr(o, 'shift', None)
                          and o.shift.type for o in ops[1:])
            if names:
                tset(ins.reg_name(ops[0].reg), names[0])
                if scaled and not all(ins.reg_name(o.reg) in CREG
                                      for o in ops[1:] if o.type == ARM64_OP_REG):
                    hits.append(('idx', names[0], -1, names[0] in bounded))
        if m in ('bl', 'blr', 'blraa', 'blrab') and ops:
            for oi, o in enumerate(ops):
                if o.type == ARM64_OP_REG and oi >= 1:
                    r = ins.reg_name(o.reg)
                    if r in taint:
                        hits.append(('callarg', taint[r], oi, taint[r] in bounded))
        if m.startswith('str') and len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
            mem = ops[1].mem
            if mem.index and ins.reg_name(mem.index) in taint and \
                    ins.reg_name(mem.index) not in CREG:
                nm = taint[ins.reg_name(mem.index)]
                hits.append(('idx', nm, -1, nm in bounded))
        if m == 'b' and ops and ops[0].type == ARM64_OP_IMM:
            tgt = ops[0].imm & M
            if tgt >= 0xFFFFFE0000000000:
                tail = tgt
    return dict(reads=sorted(reads), hits=hits, tail=tail)


def profile(c, bundle, va, starts):
    fend = _fend(starts, va, c)
    allreads, allhits, tails, seen = set(), [], [], set()
    cur = va
    for _ in range(3):
        if cur in seen:
            break
        seen.add(cur)
        r = _scan(c, bundle, cur, _fend(starts, cur, c))
        allreads |= set(r['reads'])
        allhits += r['hits']
        if r['tail']:
            tails.append(r['tail'])
            if _owner(starts, r['tail']) == r['tail']:   # 只跟到本 kext 的函数起点
                cur = r['tail']
                continue
        break
    return dict(reads=sorted(allreads), hits=allhits, tail=(tails[-1] if tails else None))


def _fend(starts, va, c):
    i = bisect_right(starts, va)
    return starts[i] if i < len(starts) else va + 0x4000


def _owner(starts, va):
    i = bisect_right(starts, va) - 1
    return starts[i] if i >= 0 else 0


def nm_base(row):
    return set()


def risk(row):
    s = 0
    base = nm_base(row)
    for tag, nm, argno, bd in row['_hits']:
        b = nm.split('(field)')[0]
        if bd or b not in LEN_LIKE | {'structureInput'}:
            continue
        if tag == 'idx':
            s += 5
            base.add('idx:%s' % nm)
        elif tag == 'callarg' and argno >= 2:
            s += 5
            base.add('len:x%d<-%s' % (argno, nm))
        elif tag == 'arith':
            s += 1
            base.add('arith:%s' % nm)
    if row['variable']:
        s += 1
        base.add('variable-size')
    if 'structureInputSize' in row['reads']:
        s += 1
        base.add('reads:structureInputSize')
    return s, sorted(base)


def main():
    path = sys.argv[1]
    outp = sys.argv[2] if len(sys.argv) > 2 else 'out/census.json'
    c = Cache(path)
    rows, kext_rows = [], []
    nof, bad = [], []
    for fo, bundle in c.entries:
        starts, ok, note = func_starts(c, bundle)
        if starts is None:
            nof.append((bundle, note))
            kext_rows.append(dict(kext=bundle, funcs=0, tables=0, sels=0, dual=False, conf='无', note=note))
            continue
        if not ok:
            bad.append((bundle, note))
        tables = data_path(c, bundle, starts)
        tb = {t['base'] for t in tables}
        chits = code_path(c, bundle, tb) if tb else {}
        sels = 0
        for t in tables:
            t['dual'] = t['base'] in chits
            t['refs'] = sorted({_owner(starts, p) for p in chits.get(t['base'], [])})
            profs = [profile(c, bundle, fn, starts) for fn in t['fns']]
            nread = sum(1 for p in profs if p['reads'])
            if t['dual']:
                t['conf'] = 'A'
            elif nread * 2 >= len(t['fns']):
                t['conf'] = 'B'
            else:
                t['conf'] = 'C'
            sels += len(t['fns'])
            for k, (fn, fld) in enumerate(zip(t['fns'], t['fields'])):
                pr = profs[k]
                row = dict(kext=bundle, selector=k, table='0x%x' % t['base'], stride=t['stride'],
                           handler='0x%x' % fn, scalarIn=fld[0], structIn=fld[1],
                           scalarOut=fld[2], structOut=fld[3],
                           variable=(fld[1] == 0xFFFFFFFF or fld[3] == 0xFFFFFFFF),
                           reads=pr['reads'],
                           tail=('0x%x' % pr['tail']) if pr['tail'] else None,
                           dual=t['dual'], conf=t['conf'],
                           refs=['0x%x' % r for r in t['refs']])
                row['_hits'] = [list(h) for h in pr['hits']]
                sc, why = risk(row)
                row['risk'] = sc
                row['why'] = why
                rows.append(row)
        kext_rows.append(dict(kext=bundle, funcs=len(starts), tables=len(tables), sels=sels,
                              dual=bool(tables) and all(t['dual'] for t in tables),
                              conf=''.join(sorted({t['conf'] for t in tables})) if tables else '无',
                              note=note))
    for r in rows:
        r.pop('_hits', None)
    json.dump(dict(rows=rows, kexts=kext_rows, no_fstarts=nof, selfcheck_fail=bad),
              open(outp, 'w'), indent=1)
    print('kexts=%d tables=%d selectors=%d' % (len(kext_rows), sum(k['tables'] for k in kext_rows), len(rows)))
    print('无 LC_FUNCTION_STARTS=%d 自证失败=%d' % (len(nof), len(bad)))


if __name__ == '__main__':
    main()
