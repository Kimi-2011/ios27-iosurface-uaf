#!/usr/bin/env python3
"""桩表驱动的跨基本块数据流：形态 2（释放后使用）/ 形态 3（解锁后使用）。

三处必须做对的事：
1. `bl` 的目标先经 out/stubs.json 解析（kext 调内核函数走桩）。
2. 身份用「别名 id」而不是寄存器名：`mov x19,x0` 之后释放 x0 等于释放 x19。
3. 调用破坏 caller-saved，但 callee-saved 的别名身份保留。
"""
import json
import sys
from bisect import bisect_left
from collections import Counter

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
M = 0xFFFFFFFFFFFFFFFF
VREL = 0x28
LOCK = {0xfffffe000abd3390}
UNLOCK = {0xfffffe000abd3f78}
RCINC = {0xfffffe000b266a30, 0xfffffe000b264d74}
RCDEC = {0xfffffe000b264d84}
FREE = set()
CSAVED = {f'x{i}' for i in range(19)}
COND = ('b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge', 'b.hi', 'b.hs', 'b.lo', 'b.ls',
        'b.mi', 'b.pl', 'b.vs', 'b.vc', 'b.al', 'cbz', 'cbnz', 'tbz', 'tbnz')
DEREFM = ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldrsh', 'str', 'strb', 'strh',
          'ldp', 'stp', 'ldur', 'stur', 'cas', 'casa', 'casl', 'casal',
          'ldadd', 'ldaxr', 'stlxr', 'ldxr', 'stxr')
STATS = Counter()


def blocks_of(il):
    if not il:
        return {}
    addrs = {ins.address for ins in il}
    lead = {il[0].address}
    for i, ins in enumerate(il):
        m = ins.mnemonic
        if m in COND or m in ('b', 'ret', 'retab', 'br'):
            if i + 1 < len(il):
                lead.add(il[i + 1].address)
            if ins.operands and ins.operands[0].type == ARM64_OP_IMM:
                t = ins.operands[0].imm & M
                if t in addrs:
                    lead.add(t)
    lead = sorted(lead)
    bl = {}
    for i, st in enumerate(lead):
        end = lead[i + 1] if i + 1 < len(lead) else None
        bl[st] = [x for x in il if x.address >= st and (end is None or x.address < end)]
    return bl


def succ_of(body):
    if not body:
        return []
    last = body[-1]
    m = last.mnemonic
    imm = (last.operands[0].imm & M) if last.operands and last.operands[0].type == ARM64_OP_IMM else None
    if m in ('ret', 'retab', 'br'):
        return []
    if m == 'b':
        return [imm] if imm else []
    if m in COND:
        return ([imm] if imm else []) + ['fall']
    return ['fall']


def analyze(c, kext, va, starts, stubmap):
    i = bisect_left(starts, va)
    if i >= len(starts) or starts[i] != va:
        return []
    vm, vs, fo, sz = c.kseg(kext, '__TEXT_EXEC')
    end = starts[i + 1] if i + 1 < len(starts) else vm + sz
    off = fo + (va - vm)
    il = list(md.disasm(c.d[off:min(fo + (end - vm), off + 700 * 4)], va))
    bl = blocks_of(il)
    if not bl:
        return []
    order = sorted(bl)
    nid = [0]

    def nxt():
        nid[0] += 1
        return 'v%d' % nid[0]

    # in[块] = (freed_ids, stale{id:unlock})
    state = {st: ({}, {}, {}, set()) for st in order}
    finds = []
    for _ in range(4):
        ch = False
        for st in order:
            freed, stale = dict(state[st][0]), dict(state[st][1])
            canon, objlike = dict(state[st][2]), set(state[st][3])
            authed, x17src = {}, None
            pend = None
            for kk, ins in enumerate(bl[st]):
                m, ops = ins.mnemonic, ins.operands

                def RN(x):
                    if isinstance(x, int):
                        return ins.reg_name(x)
                    if getattr(x, 'type', None) == ARM64_OP_REG:
                        return ins.reg_name(x.reg)
                    return None

                d0 = RN(ops[0]) if ops else None
                mem = ops[1].mem if len(ops) >= 2 and ops[1].type == ARM64_OP_MEM else None
                b0 = RN(mem.base) if mem is not None else None
                s1 = RN(ops[1]) if len(ops) >= 2 else None
                cid = lambda r: canon.get(r, r)
                # 「取 vtable 后续释放」不是使用：ldr xD,[R] 之后 4 条内 autda xD
                vload = False
                if m == 'ldr' and mem is not None and mem.disp == 0 and d0:
                    for nx in bl[st][kk + 1:kk + 5]:
                        if nx.mnemonic == 'autda' and nx.operands and nx.operands[0].type == ARM64_OP_REG \
                                and ins.reg_name(nx.operands[0].reg) == d0:
                            vload = True
                            break
                if m in DEREFM and b0 and not vload:
                    c = cid(b0)
                    STATS['deref'] += 1
                    if c in stale or c in freed:
                        STATS['identity_hit'] += 1
                    if c in freed and ins.address > freed[c]:
                        finds.append(('S2-use', kext, va, ins.address,
                                      '%s 释放后仍访问 [%s,#0x%x]' % (b0, b0, mem.disp)))
                        STATS['S2'] += 1
                        freed.pop(c, None)
                    elif c in stale and ins.address > stale[c]:
                        finds.append(('S3-use', kext, va, ins.address,
                                      '%s 在解锁 0x%x 后仍被访问 [%s,#0x%x]' % (
                                          b0, stale[c], b0, mem.disp)))
                        STATS['S3'] += 1
                        stale.pop(c, None)
                        STATS['s3_hit'] += 1
                if m == 'mov' and d0 and s1:
                    if d0 == 'x17':
                        x17src = s1
                    canon[d0] = cid(s1)
                elif d0 and m not in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn', 'str', 'strb',
                                      'strh', 'stp', 'stur', 'stlxr', 'stxr', 'autda', 'autib') \
                        and m not in COND:
                    if not d0.startswith('w'):
                        canon[d0] = nxt()
                        freed.pop(d0, None)
                        stale.pop(canon[d0], None)
                if m == 'autda' and d0:
                    authed[d0] = x17src
                if m == 'ldr' and mem is not None and mem.disp == VREL and b0:
                    src = authed.get(b0)
                    if src:
                        pend = src
                if m == 'ldr' and mem is not None and d0 and b0:
                    objlike.add(cid(d0))
                if m in ('bl', 'blr', 'blraa', 'blrab') and d0:
                    pass
                if m == 'bl' and ops and ops[0].type == ARM64_OP_IMM:
                    raw = ops[0].imm & M
                    tgt = stubmap.get(raw, raw)
                    STATS['bl'] += 1
                    if tgt in LOCK:
                        STATS['lock'] += 1
                    if tgt in UNLOCK:
                        STATS['unlock'] += 1
                        STATS['stale_seeded'] += len(objlike)
                        for c2 in list(objlike):
                            stale.setdefault(c2, ins.address)
                            STATS['stale_new'] += 1
                    if tgt in RCINC:
                        STATS['rcinc'] += 1
                    if tgt in RCDEC or tgt in FREE:
                        STATS['rcdec'] += 1
                        freed[cid('x0')] = ins.address
                        freed[cid('x0')] = ins.address
                if m in ('blraa', 'blrab', 'braa', 'bra'):
                    if pend:
                        STATS['vrel'] += 1
                        freed[cid(pend)] = ins.address
                        freed[cid(pend)] = ins.address
                        pend = None
                if m in ('bl', 'blr', 'blraa', 'blrab'):
                    canon['x0'] = nxt()
                    objlike.add(canon['x0'])
                    for r in CSAVED:
                        canon.pop(r, None)
            nxtst = order[order.index(st) + 1] if order.index(st) + 1 < len(order) else None
            for s2 in succ_of(bl[st]):
                if s2 == 'fall':
                    s2 = nxtst
                if isinstance(s2, int) and s2 in state:
                    a, b, cc, oo = state[s2]
                    nf = dict(a)
                    nf.update(freed)
                    ns = dict(b)
                    ns.update({k: v for k, v in stale.items() if k not in b})
                    nc = dict(cc)
                    for k2, v2 in canon.items():
                        nc.setdefault(k2, v2)
                    no = oo | objlike
                    if nf != a or ns != b or nc != cc or no != oo:
                        state[s2] = (nf, ns, nc, no)
                        ch = True
        if not ch:
            break
    return finds


def main():
    c = Cache('out/kc.27.0.1.full')
    stubs = json.load(open('out/stubs.json'))
    sres = {b: {int(k, 16): int(v, 16) for k, v in m.items() if v} for b, m in stubs.items()}
    rows = json.load(open('out/census.json'))['rows']
    so, seen = {}, {(r['kext'], r['handler']) for r in rows}
    todo = sorted(seen)
    for _ in range(5):
        nxtl = []
        for kext, hs in todo:
            if kext not in so:
                so[kext], _, _ = func_starts(c, kext)
            s = so[kext]
            v = int(hs, 16)
            if not s or v not in set(s):
                continue
            vm, vs, fo, sz = c.kseg(kext, '__TEXT_EXEC')
            i = bisect_left(s, v)
            e = s[i + 1] if i + 1 < len(s) else vm + sz
            o = fo + (v - vm)
            for ins in md.disasm(c.d[o:fo + (e - vm)], v):
                if ins.mnemonic == 'b' and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
                    t = ins.operands[0].imm & M
                    if t in s and (kext, '0x%x' % t) not in seen:
                        seen.add((kext, '0x%x' % t))
                        nxtl.append((kext, '0x%x' % t))
        todo = nxtl
        if not todo:
            break
    res = []
    for kext, hs in sorted(seen):
        s = so.get(kext)
        if not s:
            continue
        for f in analyze(c, kext, int(hs, 16), s, sres.get(kext, {})):
            res.append(dict(tag=f[0], kext=f[1], fn='0x%x' % f[2], at='0x%x' % f[3], desc=f[4]))
    print('扫了', len(seen), '个函数')
    print('覆盖计数:', dict(STATS))
    print('候选:', dict(Counter(r['tag'] for r in res)))
    json.dump(res, open('out/stubflow_candidates.json', 'w'), indent=1)


if __name__ == '__main__':
    main()
