"""跨 301 kext 的函数级差分 —— 直接在 kernelcache 里切片，不落 600 个中间文件。

核心：`KextView` 伪装成 `fdiff.MachO` 的接口（`d` / `base` / `segs` / `funstart`），
但 `d` 指向整个 kernelcache，所有偏移都是**绝对 fileoff**。

相比 `tools/fdiff.py` 新增四条拒假阳性规则（父指定）：
  规则 1  任一侧函数体 <=16 字节 -> 先跟 `bti c ; b <x>` 桩到实体，再配对
  规则 2  两侧体积悬殊 >3 倍 -> 拒绝配对（AVD 8B vs 56B 就是这么错的）
  规则 3  只差 `mov wN,#imm` 小立即数 -> 常量漂移，不计入结果
  规则 5  同一 kext 内某字段偏移 delta 恒定为常数且出现 >=3 次 -> 布局平移；
          但**若该函数同时有新增指令 (+N/-0)，仍然报**（新增本身就是信号）

用法：
    python3 tools/kdiff_all.py --kext com.apple.security.sandbox
    python3 tools/kdiff_all.py --all --outdir out/patches
"""
import os
import re
import sys
import json
import time
import bisect
import difflib
import struct
import importlib.util
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg

_spec = importlib.util.spec_from_file_location('fdiff', os.path.join(ROOT, 'tools', 'fdiff.py'))
fd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fd)
MD = fd._MD

LC_FUNCTION_STARTS = 0x26
LC_SOURCE_VERSION = 0x2a

CHECK = ('cmp', 'cmn', 'tst', 'ccmp')
BRANCH = ('cbz', 'cbnz', 'tbz', 'tbnz')
BYTELOAD = ('ldrb', 'ldrsb', 'ldar', 'ldarb')
BYTESTORE = ('strb', 'sturb', 'stlr', 'stlrb')
ATOMIC = ('casa', 'casal', 'casl', 'casb', 'casab', 'caslb', 'ldaxr', 'stlxr',
          'ldxr', 'stxr', 'ldadd', 'ldclr', 'ldset', 'ldeor', 'swpal')
OFFRE = re.compile(r'\[([wx]\d+),\s*#(0x[0-9a-f]+|\d+)\]')   # 排除 sp：[sp,#x] 是栈不是结构体
IMMSMALL = re.compile(r'#0x([0-9a-f]{1,4})\b')


class KextView:
    """把一个 fileset entry 当成独立 Mach-O 用；d 是整份 kernelcache。"""

    def __init__(self, K, name):
        self.K = K
        self.name = name
        self.d = K.d
        segs = K.kexts[name]                      # (vm, vs, fo, fsz, segname)
        self.segs = []
        for vm, vs, fo, fsz, sn in segs:
            prot = 0x5 if sn == '__TEXT_EXEC' else 0x1
            self.segs.append((vm, vs, fo, fsz, sn, prot, prot))
        base = [s[0] for s in self.segs if s[4] == '__TEXT']
        self.base = base[0] if base else min(s[0] for s in self.segs)
        self.funstart = None
        self.srcver = None
        fo = next((f for f, n in K.entries if n == name), None)
        if fo is not None:
            self._parse_lc(fo)

    def _parse_lc(self, fo):
        d = self.d
        try:
            ncmds = struct.unpack_from('<I', d, fo + 16)[0]
        except struct.error:
            return
        off = fo + 32
        for _ in range(ncmds):
            try:
                cmd, csz = struct.unpack_from('<II', d, off)
            except struct.error:
                return
            if csz == 0 or csz > 0x1000 or off + csz > len(d):
                return
            if cmd == LC_FUNCTION_STARTS:
                doff, dsize = struct.unpack_from('<II', d, off + 8)
                self.funstart = (doff, dsize)
            elif cmd == LC_SOURCE_VERSION:
                self.srcver = struct.unpack_from('<Q', d, off + 8)[0]
            off += csz

    # --- 与 fdiff.MachO 同接口 ---
    def va2off(self, va, n=0):
        for vm, vs, fo, fsz, sn, mp, ip in self.segs:
            if vm <= va < vm + fsz:
                return fo + (va - vm)
        return None

    def read(self, va, n):
        o = self.va2off(va)
        if o is None:
            return None
        return self.d[o:o + n]

    def exec_ranges(self):
        out = [(vm, vm + fsz) for vm, vs, fo, fsz, sn, mp, ip in self.segs if ip & 0x4 and fsz]
        return out or [(self.base, self.base + 0x1000)]

    def functions(self):
        return fd.MachO.functions(self)


def toks(view, va, size):
    """`fd._norm_insns` 返回 (mnemonic, ops) 元组；这里统一成 "mn ops" 字符串。"""
    if size <= 0:
        return []
    try:
        raw = fd._norm_insns(view, va, size) or []
    except Exception:
        return []
    out = []
    for t in raw:
        if isinstance(t, tuple):
            out.append((t[0] + ' ' + (t[1] if len(t) > 1 else '')).strip())
        else:
            out.append(str(t))
    return out


def follow_thunk(view, va, limit=4):
    """跟随 `bti c ; b <x>` 链，返回 (实体va, 是否桩)。"""
    cur = va
    stubbed = False
    for _ in range(limit):
        code = view.read(cur, 8)
        if not code or len(code) < 8:
            break
        try:
            ins = list(MD.disasm(code, cur))
        except Exception:
            break
        if len(ins) == 2 and ins[0].mnemonic == 'bti' and ins[1].mnemonic in ('b',):
            try:
                cur = int(ins[1].op_str[1:], 0)
            except ValueError:
                break
            stubbed = True
        else:
            break
    return cur, stubbed


def insdiff(a, b):
    sm = difflib.SequenceMatcher(None, a, b)
    add, rem = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ('insert', 'replace'):
            add += b[j1:j2]
        if tag in ('delete', 'replace'):
            rem += a[i1:i2]
    return add, rem


def only_const_drift(add, rem):
    """规则 3：只差 mov/movz/movk 的小立即数。"""
    if not add or len(add) != len(rem):
        return False
    for x, y in zip(add, rem):
        if not x.startswith(('mov', 'movz', 'movk')):
            return False
        if not IMMSMALL.findall(x) or not IMMSMALL.findall(y):
            return False
        if IMMSMALL.sub('#N', x) != IMMSMALL.sub('#N', y):
            return False
    return True


def layout_delta(add, rem):
    """规则 5 用：增删成对、只差 [reg,#off] 且 delta 恒定 -> 返回 delta。"""
    if not add or len(add) != len(rem):
        return None
    deltas = Counter()
    for x, y in zip(add, rem):
        if x.split(' ')[0] != y.split(' ')[0]:
            return None
        mx, my = OFFRE.search(x), OFFRE.search(y)
        if not mx or not my or mx.group(1) != my.group(1):
            return None
        if OFFRE.sub('[R,#O]', x) != OFFRE.sub('[R,#O]', y):
            return None
        deltas[int(mx.group(2), 0) - int(my.group(2), 0)] += 1
    return list(deltas)[0] if len(deltas) == 1 else None


def relocation_only(add, rem):
    """规则 6：条数相同、助记符相同、差异只在「结构体偏移 / tbz 位号」-> 位置迁移，不是新检查。

    sandbox 里 `ldrb [x20,#1] + tbz #7` -> `ldrb [x20,#2] + tbz #0` 就是这种：
    指令一条没加，只是同一个位域搬了字节。
    """
    if not add or len(add) != len(rem):
        return False
    for x, y in zip(add, rem):
        if x.split(' ')[0] != y.split(' ')[0]:
            return False
        a = re.sub(r'\[([wx]\d+|sp),\s*#(0x[0-9a-f]+|\d+)\]', '[R,#O]', x)
        b = re.sub(r'\[([wx]\d+|sp),\s*#(0x[0-9a-f]+|\d+)\]', '[R,#O]', y)
        a = re.sub(r'^(tbz|tbnz) (w\d+|x\d+),\s*#\d+', r'\1 \2,#BIT', a)
        b = re.sub(r'^(tbz|tbnz) (w\d+|x\d+),\s*#\d+', r'\1 \2,#BIT', b)
        # 允许 tbz<->tbnz 互换（位极性反转 = 状态语义反转，仍是同一字段）
        a = a.replace('tbnz ', 'tbz ')
        b = b.replace('tbnz ', 'tbz ')
        if a != b:
            return False
    return True


def fields_of(lines):
    out = set()
    for ln in lines:
        for m in OFFRE.finditer(ln):
            v = int(m.group(2), 0)
            if 0 < v <= 0x8000:
                out.add(v)
    return out


def classify(add, rem, old_tokens=()):
    """返回 (强信号列表, 弱信号列表)。判据照 +0xf1 实测。"""
    strong, weak = [], []
    txt = ' '.join(add)
    ops = [x.split(' ')[0] for x in add]

    # 新增错误返回：构造 IOReturn。★ 必须确认 27.0.1 侧本来没有这个错误码构造，
    # 否则只是 ldp 融合/寄存器重排（kernel 3 条就是这么误报的）。
    old_has_err = any('#0xe000' in t and t.startswith('movk') for t in old_tokens)
    if ('movk' in txt and '#0xe000' in txt and not old_has_err
            and any(o in CHECK or o in BRANCH for o in ops)):
        strong.append('新增错误返回（读字段+比较+跳错误码）')
    # 新增字节读门
    def fresh_off(x):
        m = OFFRE.search(x)
        if not m:
            return None
        off = m.group(2)
        pat = '#' + off + ']'
        if any(pat in t and ('ldrb' in t or 'strb' in t or 'ldrsb' in t) for t in old_tokens):
            return None
        return off
    bnew = [(x, fresh_off(x)) for x in add if x.split(' ')[0] in BYTELOAD]
    bnew = [(x, o) for x, o in bnew if o]
    if bnew and any(o in BRANCH for o in ops):
        strong.append('新增字节读门（ldrb + 条件跳）@+%s' % bnew[0][1])
    # 新增字节写标记
    bst = [(x, fresh_off(x)) for x in add if x.split(' ')[0] in BYTESTORE]
    bst = [(x, o) for x, o in bst if o]
    if bst and any(x.startswith(('mov w', 'movz w')) for x in add):
        strong.append('新增字节写标记（mov #1 + strb）@+%s' % bst[0][1])
    # 整数溢出
    if any(x.startswith(('adds', 'umulh', 'smulh', 'umull')) for x in add) and \
            any(o in ('b.hs', 'b.cs', 'b.vs') for o in ops):
        strong.append('新增整数溢出检查（adds/umulh + b.hs）')
    # 无条件读-改-写清位：ldr + and #imm + str 同一偏移
    rwm = False
    for i, t in enumerate(add):
        if t.startswith('and ') and '#0xffffffff' in t:
            if any(x.startswith('ldr ') for x in add[max(0, i-2):i]) and \
               any(x.startswith('str ') for x in add[i+1:i+3]):
                rwm = True
    if rwm:
        strong.append('新增无条件字段清位（ldr+and+str 读改写）')
    # CAS / refcount
    if any(o in ATOMIC for o in ops):
        strong.append('新增原子/CAS（refcount 形态）')
    # 断言收紧
    if any(o in ('udf', 'brk') for o in ops):
        strong.append('新增断言（udf/brk）')
    # lock/unlock 启发式：新增 >=2 次 bl 到同一目标
    bls = [x for x in add if x.startswith('bl ')]
    lockish = len(bls) >= 2 and len(set(bls)) < len(bls)

    if lockish and not strong:
        weak.append('可能 lock/unlock（启发式）')
    if not strong:
        if all(o in ('ldr', 'ldur', 'ldp', 'str', 'stp', 'mov', 'add', 'orr') for o in ops) and len(add) <= 3:
            weak.append('纯访问器内联')
        elif any(o in ('stp', 'str') for o in ops) and 'xzr' in txt:
            weak.append('纯清零')
        elif any(x.startswith(('adrp', 'add x0')) for x in add) and 'bl ' in txt:
            weak.append('纯日志/字符串')
        else:
            weak.append('其它')
    return strong, weak


def diff_kext(k1, k2, name, verbose=False):
    v1 = KextView(k1, name)
    v2 = KextView(k2, name)
    f1 = v1.functions()
    f2 = v2.functions()
    if not f1 or not f2:
        return None
    # 预先算 token + 哈希
    t1 = {}
    for va, sz in f1:
        t1[va] = toks(v1, va, sz)
    t2 = {}
    for va, sz in f2:
        t2[va] = toks(v2, va, sz)
    h1 = defaultdict(list)
    for va in t1:
        h1[hash(tuple(t1[va]))].append(va)
    h2 = defaultdict(list)
    for va in t2:
        h2[hash(tuple(t2[va]))].append(va)
    h2keys = set(h2)
    # 先剔除完全相同的
    only1 = [va for va in t1 if hash(tuple(t1[va])) not in h2keys]
    h1keys = set(h1)
    only2 = [va for va in t2 if hash(tuple(t2[va])) not in h1keys]
    s1 = {va: sz for va, sz in f1}
    s2 = {va: sz for va, sz in f2}
    # 规则 1：小函数先跟桩
    def resolve(view, va, sz):
        if sz <= 16:
            body, st = follow_thunk(view, va)
            if st and body in (s1 if view is v1 else s2):
                return body, True
        return va, False

    prob1 = []
    for va in only1:
        b, st = resolve(v1, va, s1[va])
        prob1.append((va, b, st))
    prob2 = []
    for va in only2:
        b, st = resolve(v2, va, s2[va])
        prob2.append((va, b, st))
    # 二级哈希：按实体 token 再匹配一次
    body1 = defaultdict(list)
    for va, b, st in prob1:
        tk = t1.get(b) or toks(v1, b, s1.get(b, 0))
        body1[hash(tuple(tk))].append((va, b, st))
    body2 = defaultdict(list)
    for va, b, st in prob2:
        tk = t2.get(b) or toks(v2, b, s2.get(b, 0))
        body2[hash(tuple(tk))].append((va, b, st))
    still1 = [(va, b, st) for h, lst in body1.items() if h not in body2 for va, b, st in lst]
    still2 = [(va, b, st) for h, lst in body2.items() if h not in body1 for va, b, st in lst]

    # 模糊配对
    pairs = []
    used2 = set()
    cand2 = sorted(still2, key=lambda x: x[1])
    b2s = [x[1] for x in cand2]
    for va, b, st in still1:
        tk1 = t1.get(b) or toks(v1, b, s1.get(b, 0))
        if not tk1:
            continue
        szb = s1.get(b, 0)
        lo = bisect.bisect_left(b2s, b - 0x80000)
        hi = bisect.bisect_right(b2s, b + 0x80000)
        best, bestr = None, 0.0
        for i in range(lo, hi):
            v2va, b2, st2 = cand2[i]
            if v2va in used2:
                continue
            sz2 = s2.get(b2, 0)
            if not sz2 or not szb:
                continue
            if max(szb, sz2) > 3 * max(1, min(szb, sz2)):      # 规则 2
                continue
            tk2 = t2.get(b2) or toks(v2, b2, sz2)
            r = difflib.SequenceMatcher(None, tk1, tk2).ratio()
            if r > bestr:
                best, bestr = (v2va, b2, st2), r
        if best and bestr >= 0.55:
            used2.add(best[0])
            pairs.append(dict(kext=name, va1=va, va2=best[0], body1=b, body2=best[1],
                              stub1=st, stub2=best[2], sim=round(bestr, 2),
                              size1=s1.get(va, 0), size2=s2.get(best[0], 0)))

    # 逐对算 diff
    for p in pairs:
        tk1 = t1.get(p['body1']) or toks(v1, p['body1'], s1.get(p['body1'], 0))
        tk2 = t2.get(p['body2']) or toks(v2, p['body2'], s2.get(p['body2'], 0))
        add, rem = insdiff(tk1, tk2)
        p['add'], p['rem'] = add, rem
        p['const_drift'] = only_const_drift(add, rem)
        p['reloc'] = relocation_only(add, rem)
        p['layout_delta'] = layout_delta(add, rem)
        p['newfields'] = sorted(fields_of(add) - fields_of(rem))
        p['strong'], p['weak'] = classify(add, rem, tk1)
        if len(add) + len(rem) > 40:
            p['big'] = True
        else:
            p['big'] = False
    return dict(kext=name, n1=len(f1), n2=len(f2), pairs=pairs,
                srcver1=v1.srcver, srcver2=v2.srcver,
                code1=sum(sz for _, sz in f1), code2=sum(sz for _, sz in f2))


def report(res, out):
    """写单个 kext 的报告。"""
    name = res['kext']
    pairs = res['pairs']
    # 规则 5：恒定 delta 出现 >=3 次 -> 布局平移
    dcnt = Counter()
    for p in pairs:
        if p['layout_delta'] is not None:
            dcnt[p['layout_delta']] += 1
    layout_shift = {d for d, c in dcnt.items() if c >= 3}
    for p in pairs:
        p['is_layout'] = (p['layout_delta'] in layout_shift) and not p['add'] or (
            p['layout_delta'] in layout_shift and len(p['add']) == len(p['rem']))
        if p['const_drift']:
            p['kind'] = '常量漂移'
        elif p['reloc']:
            p['kind'] = '位置迁移'
        elif p['add'] and not p['rem']:
            p['kind'] = '真插入'
        elif p['layout_delta'] in layout_shift:
            p['kind'] = '布局平移'
        else:
            p['kind'] = '混合'
    strong = [p for p in pairs if p['strong'] and not p.get('big')
              and p['kind'] not in ('常量漂移', '位置迁移')]
    weak = [p for p in pairs if not p['strong'] and p['kind'] in ('真插入', '混合')]
    reloc = [p for p in pairs if p['kind'] == '位置迁移']

    with open(out, 'w') as f:
        w = f.write
        w(f'# `{name}` 27.0.1 ↔ 27.2 差分\n\n')
        w(f'- 函数数：{res["n1"]} → {res["n2"]}\n')
        w(f'- 代码字节：{res["code1"]} → {res["code2"]}（{res["code2"]-res["code1"]:+d}）\n')
        w(f'- LC_SOURCE_VERSION：{res["srcver1"]} → {res["srcver2"]}\n')
        w(f'- 配对上的改动函数：**{len(pairs)}**；强信号 **{len(strong)}**、'
          f'位置迁移 {len(reloc)}、弱信号 {len(weak)}\n')
        w(f'- 布局平移 delta（>=3 次，规则 5）：{sorted(layout_shift) or "无"}\n\n')

        w('## 强信号\n\n')
        if not strong:
            w('（无）\n\n')
        for p in strong:
            w(f"### `0x{p['va1']:x}` → `0x{p['va2']:x}`  [{'/'.join(p['strong'])}]\n\n")
            w(f"- 27.0.1 函数体 **{p['size1']} B**，27.2 函数体 **{p['size2']} B**"
              f"（比 {p['size2']/max(1,p['size1']):.2f}×）\n")
            w(f"- 是否桩：27.0.1 {'**是**（已跟到实体 `0x%x`）' % p['body1'] if p['stub1'] else '否'}"
              f" / 27.2 {'**是**（已跟到实体 `0x%x`）' % p['body2'] if p['stub2'] else '否'}\n")
            w(f"- 涉及字段：{', '.join('`+0x%x`' % v for v in p['newfields'][:8]) or '无'}\n")
            w(f"- 类型判定：{'读门' if any('读门' in s for s in p['strong']) else ''}"
              f"{'/写标记' if any('写标记' in s for s in p['strong']) else ''}"
              f"{'/错误返回' if any('错误' in s for s in p['strong']) else ''}\n")
            w(f"- diff +{len(p['add'])}/−{len(p['rem'])}，相似度 {p['sim']}\n\n")
            w('```diff\n')
            for x in p['rem'][:20]:
                w(f'- {x}\n')
            for x in p['add'][:20]:
                w(f'+ {x}\n')
            w('```\n\n')

        w('## 弱信号（一行一条）\n\n')
        w('| 27.0.1 | 27.2 | 大小 | 增删 | 形态 |\n|---|---|---|---|---|\n')
        for p in weak[:120]:
            w(f"| `0x{p['va1']:x}` | `0x{p['va2']:x}` | {p['size1']}→{p['size2']} B | "
              f"+{len(p['add'])}/−{len(p['rem'])} | {'/'.join(p['weak'])} |\n")
        if len(weak) > 120:
            w(f"\n（另有 {len(weak)-120} 条略）\n")
    return len(strong), len(weak)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--kext')
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--list', default='out/changed-kexts.txt')
    ap.add_argument('--outdir', default='out/patches')
    a = ap.parse_args(argv[1:])

    k1 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.0.1.full'))
    k2 = kseg.Index(os.path.join(ROOT, 'out', 'kc.27.2.ga.full'))
    os.makedirs(os.path.join(ROOT, a.outdir), exist_ok=True)

    names = []
    if a.kext:
        names = [a.kext]
    elif a.all:
        with open(os.path.join(ROOT, a.list)) as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                names.append(ln.split()[-1])

    summary = []
    for n in names:
        t0 = time.time()
        if n not in k1.kexts or n not in k2.kexts:
            print(f'  跳过 {n}（不在两侧）')
            continue
        try:
            res = diff_kext(k1, k2, n)
        except Exception as e:
            print(f'  {n}: 失败 {e}')
            continue
        if not res:
            print(f'  {n}: 无函数')
            continue
        safe = n.replace('.', '_')
        out = os.path.join(ROOT, a.outdir, safe + '.md')
        ns, nw = report(res, out)
        dt = time.time() - t0
        summary.append((n, res['n1'], res['n2'], len(res['pairs']), ns, nw, dt,
                        res['code2'] - res['code1']))
        print(f'  {n:52} 函数 {res["n1"]:6}->{res["n2"]:6}  改动 {len(res["pairs"]):5}  '
              f'强 {ns:4}  弱 {nw:5}  {dt:6.1f}s')
    if len(summary) > 1:
        sp = os.path.join(ROOT, a.outdir, '_SUMMARY.md')
        with open(sp, 'w') as f:
            f.write('# 全量差分摘要\n\n| kext | 函数 | 改动 | 强信号 | 弱信号 | 秒 | 代码字节差 |\n|---|---|---|---|---|---|---|\n')
            for n, a1, a2, np_, ns, nw, dt, db in sorted(summary, key=lambda x: -x[4]):
                f.write(f'| `{n}` | {a1}→{a2} | {np_} | **{ns}** | {nw} | {dt:.0f} | {db:+d} |\n')
        print(f'\n摘要 -> {sp}')


if __name__ == '__main__':
    main(sys.argv)
