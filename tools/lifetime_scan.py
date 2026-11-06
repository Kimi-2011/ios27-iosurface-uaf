#!/usr/bin/env python3
"""三种生命周期形态的机械扫描（形态 1/2/3）。只出候选，不下结论。

虚释放判据（从 com.apple.iokit.IOHIDFamily 0xfffffe000a1052cc 现场读出）：
    mov  x17, R            ; R = 对象
    autda x16, x17         ; x16 = 认证后的 vtable
    ldr  x8, [x16, #0x28]! ; #0x28 = OSObject::release 槽
    blraa x8, x16
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
MAXI = 500
VREL = 0x28
DEREF = ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldrsh', 'str', 'strb', 'strh',
         'ldp', 'stp', 'ldur', 'stur', 'cas', 'casal', 'casl', 'ldadd', 'ldaxr', 'stlxr')


def scan_fn(c, bundle, va, starts):
    vm, vs, fo, sz = c.kseg(bundle, '__TEXT_EXEC')
    i = bisect_left(starts, va)
    if i >= len(starts) or starts[i] != va:
        return []
    end = starts[i + 1] if i + 1 < len(starts) else vm + sz
    off = fo + (va - vm)
    il = list(md.disasm(c.d[off:min(fo + (end - vm), off + MAXI * 4)], va))
    out = []
    selfr = {'x0'}
    obj = {'x0': 'arg'}
    ivar = {}
    authed = {}
    rel = {}
    released_off = set()
    s3 = {}
    pend = None
    x17src = None
    for ins in il:
        m, ops = ins.mnemonic, ins.operands

        def RN(x):
            if isinstance(x, int):
                return ins.reg_name(x)
            if getattr(x, 'type', None) == ARM64_OP_REG:
                return ins.reg_name(x.reg)
            return None

        if m in ('ret', 'retab'):
            break
        if m == 'b' and ops and ops[0].type == ARM64_OP_IMM:
            break
        d0 = RN(ops[0]) if ops else None
        mem = ops[1].mem if len(ops) >= 2 and ops[1].type == ARM64_OP_MEM else None
        b0 = RN(mem.base) if mem is not None else None
        # 目标寄存器被「非 mov」写入 → 它不再持有 self / 对象身份
        if d0 and m not in ('mov', 'orr') and not m.startswith('st'):
            if m not in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn'):
                selfr.discard(d0) if d0 == 'x0' else None
                obj.pop(d0, None) if d0 in obj and m in ('adrp', 'add', 'ldr', 'bl', 'blr') else None
                ivar.pop(d0, None) if m in ('adrp', 'add', 'ldr', 'bl', 'blr') else None
        # 把 ivar 先清零再释放 —— 清空即意味该偏移已重置
        if m in ('str', 'stur') and mem is not None and b0 in selfr and \
                ops[0].type == ARM64_OP_REG and ins.reg_name(ops[0].reg) == 'xzr':
            released_off.add(mem.disp)
        # --- 形态 2/3 的使用判定（放在任何写回之前） ---
        if m in DEREF and b0:
            if b0 in rel and b0 not in ('sp', 'x29'):
                out.append(('S2-use', va, ins.address,
                            '%s 在 0x%x 释放后仍访问 [%s,#0x%x]' % (b0, rel[b0], b0, mem.disp)))
                del rel[b0]
            elif b0 in s3 and s3[b0][1] > 0:
                out.append(('S3-use', va, ins.address,
                            '%s(%s) 在解锁 0x%x 后经 %d 次调用被访问' % (
                                b0, obj.get(b0, '?'), s3[b0][0], s3[b0][1])))
                del s3[b0]
        # --- 寄存器移动 ---
        if m in ('mov', 'orr') and len(ops) == 2 and d0 and RN(ops[1]):
            src, d = RN(ops[1]), d0
            if d == 'x17':
                x17src = src
            if src in selfr:
                selfr.add(d)
            if src in obj:
                obj[d] = obj[src]
            if src in ivar:
                ivar[d] = ivar[src]
            if d in rel and d != src:
                del rel[d]
            if d in s3 and d != src:
                del s3[d]
        if m == 'autda' and len(ops) == 2 and d0:
            authed[d0] = x17src
            rel.pop(d0, None)
            s3.pop(d0, None)
        if m == 'ldr' and mem is not None and mem.disp == VREL and b0:
            src = authed.get(b0)
            if src:
                pend = src
        # --- 释放点 ---
        if m == 'bl' and ops and ops[0].type == ARM64_OP_IMM and (ops[0].imm & M) in RCDEC:
            iv = ivar.get('x0')
            if iv:
                released_off.add(iv[1])
            rel['x0'] = ins.address
            out.append(('S2-release', va, ins.address, '直接释放 x0(%s)' % obj.get('x0', '?')))
        if m in ('blraa', 'blrab', 'braa', 'bra') and pend:
            rel[pend] = ins.address
            iv = ivar.get(pend)
            if iv:
                released_off.add(iv[1])
            out.append(('S2-release', va, ins.address, '虚释放 %s(%s)' % (pend, obj.get(pend, '?'))))
            pend = None
        # --- 形态 1：新对象存进 self 且该偏移没先释放旧值 ---
        if m in ('str', 'stur') and mem is not None and d0 and not mem.index:
            if b0 in selfr and d0 in obj:
                desc = obj[d0]
                if desc.startswith('call@') and mem.disp not in released_off:
                    out.append(('S1-store', va, ins.address,
                                '%s -> self[0x%x]（未见先释放旧值）' % (desc, mem.disp)))
        if m == 'ldr' and mem is not None and d0 and b0 in selfr:
            obj[d0] = 'ivar[0x%x]' % mem.disp
            ivar[d0] = (b0, mem.disp)
        # --- 解锁点 ---
        if (m == 'msr' and 'daifclr' in ins.op_str) or \
                (m in ('bl', 'blr') and ops and ops[0].type == ARM64_OP_IMM
                 and (ops[0].imm & M) in UNLOCK):
            for r, dsc in obj.items():
                if r != 'x0' and (dsc.startswith('ivar[') or dsc.startswith('call@')):
                    s3[r] = (ins.address, 0)
        # --- 调用：x0 变成新值；s3 计数器 +1 ---
        if m in ('bl', 'blr', 'blraa', 'blrab'):
            for r in list(s3):
                s3[r] = (s3[r][0], s3[r][1] + 1)
            obj['x0'] = 'call@0x%x' % ins.address
            ivar.pop('x0', None)
            rel.pop('x0', None)
            s3.pop('x0', None)
    return out


UNLOCK = set()
RCDEC = {0xfffffe000b264d84}
RCDEC = {0xfffffe000b264d84}


def main():
    try:
        b = json.load(open('/tmp/api_buckets.json'))
        for tag, rows in b.items():
            if tag.startswith('daif') or tag.startswith('mutex'):
                for r in rows:
                    UNLOCK.add(int(r['va'], 16))
    except Exception:
        pass
    c = Cache('out/kc.27.0.1.full')
    rows = json.load(open('out/census.json'))['rows']
    starts_of = {}
    seen = {(r['kext'], r['handler']) for r in rows}
    todo = sorted(seen)
    for _ in range(5):
        nxt = []
        for kext, hs in todo:
            if kext not in starts_of:
                starts_of[kext], _, _ = func_starts(c, kext)
            s = starts_of[kext]
            va = int(hs, 16)
            if not s or va not in set(s):
                continue
            vm, vs, fo, sz = c.kseg(kext, '__TEXT_EXEC')
            i = bisect_left(s, va)
            end = s[i + 1] if i + 1 < len(s) else vm + sz
            o = fo + (va - vm)
            for ins in md.disasm(c.d[o:fo + (end - vm)], va):
                if ins.mnemonic == 'b' and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
                    t = ins.operands[0].imm & M
                    if t in s and (kext, '0x%x' % t) not in seen:
                        seen.add((kext, '0x%x' % t))
                        nxt.append((kext, '0x%x' % t))
        todo = nxt
        if not todo:
            break
    res = []
    for kext, hs in sorted(seen):
        s = starts_of.get(kext)
        if s is None:
            s, _, _ = func_starts(c, kext)
            starts_of[kext] = s
        if not s:
            continue
        for tag, fn, at, desc in scan_fn(c, kext, int(hs, 16), s):
            res.append(dict(tag=tag, kext=kext, fn='0x%x' % fn, at='0x%x' % at, desc=desc))
    print('扫了', len(seen), '个函数')
    print('候选:', dict(Counter(r['tag'] for r in res)))
    json.dump(res, open('out/lifetime_candidates.json', 'w'), indent=1)


if __name__ == '__main__':
    main()
