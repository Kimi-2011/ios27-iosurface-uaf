#!/usr/bin/env python3
"""产出 out/stubs-named.json：桩目标 → 语义（前 200），每条带证据。"""
import json
import sys
from collections import Counter

sys.path.insert(0, __file__.rsplit('/', 1)[0])
import stubname as S

KNOWN = {
 0xfffffe000b266a30: ('引用计数自增 @[obj+0x24]', 'mov w8,#1; add x9,x0,#0x24; ldadd w8,w9,[x9]'),
 0xfffffe000b264d74: ('引用计数 +1 @[obj+0]', 'mov w8,#1; ldadd w8,w0,[x0]; ret'),
 0xfffffe000b264d84: ('引用计数 −1 @[obj+0]', 'mov w8,#-1; ldadd w8,w0,[x0]; ret'),
 0xfffffe000abd3390: ('lck_mtx 加锁快路径', 'casa 0→cpuid on [x0+8]，cpuid 取自 tpidr_el1+0x4f8，失败走慢路径'),
 0xfffffe000abd3f78: ('lck_mtx 解锁快路径', 'casl cpuid→0 on [x0+8]，不匹配走慢路径'),
 0xfffffe000b43f0d0: ('memmove', 'sub x3,x0,x1; cmp x3,x2; b.lo → 重叠检测'),
 0xfffffe000b43f280: ('memset/bzero', 'eor x1,x1,x1; stp x1,x1,[x0]… 的 0 填充'),
 0xfffffe000b2fead0: ('状态字置 1 @[obj+8]', 'mov w8,#1; str w8,[x0,#8]'),
 0xfffffe000b2feb28: ('状态字置 −1 @[obj+0]', 'mov x8,#-1; str x8,[x0]; ret'),
 0xfffffe000b423ef0: ('带格式串的断言/日志打印', 'adrp/add 取 __TEXT 串后调用打印'),
 0xfffffe000b2d4d28: ('全局取指后尾跳 0xabd31ac', 'ldr x0,[global]; b 0xabd31ac'),
 0xfffffe000b265500: ('对象构造 / vtable 安装', 'pacda x16,x17; str x16,[x0]'),
 0xfffffe000b2660a0: ('对象构造 / vtable 安装（变体）', '同族，随后 ldr x9,[x0,#8]; ldr x21,[x9,#8]'),
 0xfffffe000b268c20: ('长度/容量断言', 'ldr w8,[x0,#0x2c]; cmp x2,x8; b.ls 否则打印串'),
 0xfffffe000b268bbc: ('长度/容量断言（变体）', '同族，cmp x1,x8 + mov w2,#0x1004'),
}


def main():
    c = S.Cache('out/kc.27.0.1.full')
    idx = S.Index(c)
    stubs = json.load(open('out/stubs.json'))
    users = Counter()
    for b, m in stubs.items():
        for t in set(m.values()):
            if t:
                users[int(t, 16)] += 1
    out = []
    for va, nk in users.most_common(200):
        il, b, exact = idx.body(va, 0x200)
        rec = dict(va='0x%x' % va, kexts=nk, inkext=b, exact=exact,
                   head=[f'{i.mnemonic} {i.op_str}' for i in (il or [])[:8]])
        # 单指令包装：`b T` → 借 T 的名字
        if il and len(il) <= 2 and il[0].mnemonic == 'b' and il[0].operands \
                and il[0].operands[0].type == 2:
            t = il[0].operands[0].imm & 0xFFFFFFFFFFFFFFFF
            tgt = KNOWN.get(t, (None, None))[0]
            rec['name'] = '包装 → 0x%x%s' % (t, ('（' + tgt + '）') if tgt else '')
            rec['evidence'] = '单指令尾跳'
            rec['conf'] = '自动'
            out.append(rec)
            continue
        if va in KNOWN:
            rec['name'], rec['evidence'], rec['conf'] = KNOWN[va][0], KNOWN[va][1], '手读'
        else:
            f = S.feats(il) if il else {}
            tags = [k for k in ('brk', 'ldadd', 'ldxr', 'stxr', 'cas', 'daif', 'sev', 'wfe',
                                'dmb', 'tailb', 'inc1', 'dec1') if f.get(k)]
            rec['name'] = '未识别'
            rec['evidence'] = ('特征: ' + ','.join(tags)) if tags else ''
            rec['conf'] = '未识别'
        out.append(rec)
    json.dump(out, open('out/stubs-named.json', 'w'), indent=1, ensure_ascii=False)
    n = sum(1 for r in out if r['conf'] == '手读')
    print('前 200 里手读命名:', n, ' 未识别:', 200 - n)


if __name__ == '__main__':
    main()
