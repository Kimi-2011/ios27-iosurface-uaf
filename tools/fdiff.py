"""函数级差分：27.0.1 ↔ 27.2 的 kext Mach-O。

为什么不用现成工具：
- 提取出的 kext **没有符号表**（nsyms=0），只能靠 LC_FUNCTION_STARTS 划函数边界。
- `tools/kext_extract.py` 没重写 section_64.offset（见 tools/kseg.py 头注释），
  所以任何按 section 取表的代码都会读到垃圾 ⇒ 这里 VA↔off 只走 **segment**。

用法：
    python3 tools/fdiff.py iokit_IOSurface
    python3 tools/fdiff.py --all            # 全部 12 个 kext
    python3 tools/fdiff.py --all --json out/PATCH-HUNT.raw.json

判定「改动」的两层过滤：
  1. 原始字节完全相同 → 未变（跳过）。
  2. **归一化指令流**相同 → 只是地址位移/寄存器分配变化（`adrp` 目标、`bl` 目标、
     `b` 目标都按「函数内相对指令条数」归一化），不算改动。
     这一层是关键：光靠字节比对会把每个函数都判成「变了」。
"""
import struct
import sys
import os
import json
import hashlib
import difflib

try:
    import capstone
    _MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    _MD.detail = False
except Exception:                                    # pragma: no cover
    _MD = None

LC_SEGMENT_64 = 0x19        # 注意：0x19 是 LC_SEGMENT_64，不是 32 位的 LC_SEGMENT(0x1)
LC_SYMTAB = 0x2
LC_FUNCTION_STARTS = 0x26

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


class MachO:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        d = self.d
        if struct.unpack_from('<I', d, 0)[0] != 0xfeedfacf:
            raise ValueError(f'{path}: 不是 64 位 Mach-O')
        ncmds = struct.unpack_from('<I', d, 16)[0]
        off = 32
        self.segs = []            # (vmaddr, vmsize, fileoff, filesize, name, maxprot, initprot)
        self.funstart = None
        for _ in range(ncmds):
            cmd, csz = struct.unpack_from('<II', d, off)
            if cmd == LC_SEGMENT_64 and csz >= 72:
                name = d[off + 8:off + 24].rstrip(b'\0').decode('ascii', 'replace')
                vm, vs, fo, fsz = struct.unpack_from('<QQQQ', d, off + 24)
                maxprot, initprot = struct.unpack_from('<ii', d, off + 56)
                self.segs.append((vm, vs, fo, fsz, name, maxprot, initprot))
            elif cmd == LC_FUNCTION_STARTS:
                self.funstart = struct.unpack_from('<II', d, off + 8)   # (dataoff, datasize)
            off += csz
        if not self.segs:
            raise ValueError(f'{path}: 没有段')
        # 基址 = 最低 vmaddr 的段（通常是 __TEXT）
        self.base = min(s[0] for s in self.segs)

    def va2off(self, va, n=0):
        for vm, vs, fo, fsz, name, _mp, _ip in self.segs:
            if vm <= va < vm + max(vs, fsz):
                o = fo + (va - vm)
                if n and o + n > len(self.d):
                    return None
                return o
        return None

    def read(self, va, n):
        o = self.va2off(va)
        if o is None or o + n > len(self.d):
            return None
        return self.d[o:o + n]

    def exec_ranges(self):
        """可执行段区间 [(lo, hi)]。代码在 __TEXT_EXEC，不在 __TEXT（__TEXT 只有 header/字符串）。"""
        out = []
        for vm, vs, fo, fsz, name, maxprot, initprot in self.segs:
            if initprot & 0x4 and fsz:                 # VM_PROT_EXECUTE
                out.append((vm, vm + fsz))
        return out or [(self.base, self.base + len(self.d))]

    def functions(self):
        """返回 [(va, size)]，按地址升序。函数边界来自 LC_FUNCTION_STARTS（ULEB128 增量）。"""
        if self.funstart is None:
            return []
        doff, dsize = self.funstart
        blob = self.d[doff:doff + dsize]
        out = []
        cur = self.base
        i = 0
        while i < len(blob):
            v, shift = 0, 0
            while True:
                b = blob[i]
                i += 1
                v |= (b & 0x7f) << shift
                shift += 7
                if not (b & 0x80):
                    break
                if i >= len(blob):
                    break
            if v == 0:
                break
            cur += v
            out.append(cur)
        # 每个函数起点必须落在某个可执行段内；size 取「下一个起点」与「所在段末」的较小者
        ranges = self.exec_ranges()
        res = []
        for k, va in enumerate(out):
            seg = next((r for r in ranges if r[0] <= va < r[1]), None)
            if seg is None:
                continue
            nxt = out[k + 1] if k + 1 < len(out) else seg[1]
            size = max(0, min(nxt, seg[1]) - va)
            if size:
                res.append((va, size))
        return res


def _split_ops(s):
    """按逗号切操作数，但不切方括号/花括号里的（`[x2,#0x880]` 是一个操作数）。"""
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch in '[{':
            depth += 1
        elif ch in ']}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def _norm_insns(machofile, va, size):
    """把函数归一化成 token 列表：寄存器保留，PC 相对目标按函数内偏移归一化。

    归一化掉的东西（= 不算改动的变化）：
      - adrp/add 的绝对目标（不同 slide/段偏移）
      - bl / b / b.cond 的绝对目标（函数搬家）
      - 立即数里的地址形态（>0x10000 的立即数一律写成 <IMM>）
    保留的东西（= 真正的语义）：
      - mnemonic、寄存器、小立即数（0..0xffff）——`cmp w9,#0x1ff` 必须看得见
      - 访问偏移 `[x20,#0xf1]` 这类结构体字段偏移
    """
    code = machofile.read(va, size)
    if code is None:
        return [('<noread>',)]
    if _MD is None:
        return [('<hex>', hashlib.sha1(code).hexdigest())]
    toks = []
    addr2idx = {}
    insns = list(_MD.disasm(code, va))
    for idx, ins in enumerate(insns):
        addr2idx[ins.address] = idx
    # 「上一句是 adrp 给这个寄存器装了页基址」-> 下一句用它的 #imm 是页内偏移，必须一起抹掉
    adrp_pending = None
    for idx, ins in enumerate(insns):
        m = ins.mnemonic
        ops = ins.op_str
        prev_adrp = adrp_pending
        adrp_pending = None
        if m.startswith('b') or m in ('cbz', 'cbnz', 'tbz', 'tbnz', 'adr', 'adrp'):
            parts = []
            _ops_list = _split_ops(ops)
            for _oi, p in enumerate(_ops_list):
                p = p.strip()
                # cbz/cbnz/tbz/tbnz 只有**最后一个**操作数是跳转目标，前面的是位号
                _is_target = (m not in ('cbz', 'cbnz', 'tbz', 'tbnz')) or _oi == len(_ops_list) - 1
                if p.startswith('#') and _is_target:
                    try:
                        v = int(p[1:], 0)
                    except ValueError:
                        parts.append('#<X>')
                        continue
                    if m == 'adrp':
                        parts.append('#<X>')          # adrp 是页地址，永远归一化
                    else:
                        rel = addr2idx.get(v)
                        parts.append(f'#{rel - idx:d}' if rel is not None else '#<X>')
                else:
                    parts.append(p)
            ops = ','.join(parts)
            if m == 'adrp':
                first = ins.op_str.split(',')[0].strip()
                adrp_pending = first
        else:
            def _small(p, _pa=prev_adrp):
                p = p.strip()
                # 纯立即数：adrp 之后的 #imm 是页内偏移（随目标搬家而变）=> 归一化
                if p.startswith('#'):
                    try:
                        v = int(p[1:].replace('lsl', '').strip(), 0)
                    except ValueError:
                        return p
                    if _pa:
                        return '#<PAGEOFF>'
                    return p if abs(v) <= 0xffff else '#<IMM>'
                # 内存操作数 [Xb, #imm]：基址寄存器刚被 adrp 装过 => 偏移也是页内的
                if p.startswith('[') and '#' in p:
                    inner = p[1:].rstrip(']!')
                    bits = [x.strip() for x in inner.split(',')]
                    if bits and bits[0] == _pa and len(bits) >= 2 and bits[1].startswith('#'):
                        rest = ','.join(bits[1:])
                        return '[' + bits[0] + ', #<PAGEOFF>' + (', ' + ','.join(bits[2:]) if len(bits) > 2 else '') + ']'
                return p
            ops = ','.join(_small(p) for p in _split_ops(ops))
        toks.append((m, ops))
    return toks


def load(kext):
    a = MachO(os.path.join(ROOT, 'out', 'v2701', kext + '.macho'))
    b = MachO(os.path.join(ROOT, 'out', 'v272', kext + '.macho'))
    return a, b


def analyze(kext, min_size=8, similarity=0.55):
    a, b = load(kext)
    fa, fb = a.functions(), b.functions()
    A = {}
    for va, sz in fa:
        if sz < min_size:
            continue
        toks = _norm_insns(a, va, sz)
        A[va] = (sz, toks, hashlib.sha1(repr(toks).encode()).hexdigest())
    B = {}
    for va, sz in fb:
        if sz < min_size:
            continue
        toks = _norm_insns(b, va, sz)
        B[va] = (sz, toks, hashlib.sha1(repr(toks).encode()).hexdigest())
    ha = {}
    for va, (sz, toks, h) in A.items():
        ha.setdefault(h, []).append(va)
    changed = []
    used_a = set()
    for vab, (szb, toksb, hb) in sorted(B.items()):
        cand = ha.get(hb)
        if cand:
            used_a.add(cand[0])
            continue
        # 未命中：找最相似的 27.0.1 函数
        best, bestr = None, 0.0
        sa = [t[0] + ' ' + t[1] for t in toksb]
        for vaa, (sza, toksa, _ha) in A.items():
            if vaa in used_a:
                continue
            if abs(sza - szb) > max(64, 3 * min(sza, szb) // 2):
                continue
            r = difflib.SequenceMatcher(None, [t[0] + ' ' + t[1] for t in toksa], sa).ratio()
            if r > bestr:
                best, bestr = vaa, r
        changed.append({
            'kext': kext,
            'va_2701': best,
            'va_272': vab,
            'size_2701': A[best][0] if best else None,
            'size_272': szb,
            'similarity': round(bestr, 3),
            'tokens_2701': [t[0] + ' ' + t[1] for t in A[best][1]] if best else [],
            'tokens_272': sa,
        })
        if best:
            used_a.add(best)
    return {'kext': kext, 'n_2701': len(fa), 'n_272': len(fb),
            'n_changed': len(changed), 'changed': changed}


# ---------- 检查识别 ----------

CHECK_MNEMONICS = ('cbz', 'cbnz', 'tbz', 'tbnz', 'cmn', 'cmp', 'tst', 'ccmp')


def classify(tokens_2701, tokens_272):
    """找 27.2 新增的「检查型」指令序列，并给出字段偏移。"""
    old = set(tokens_2701)
    added = [t for t in tokens_272 if t not in old]
    # 只看新增里带比较/分支/加载字节的
    hits = []
    for t in added:
        m, ops = t.split(' ', 1) if ' ' in t else (t, '')
        if m in CHECK_MNEMONICS or m in ('ldrb', 'ldrsb', 'strb', 'ldar', 'stlr', 'bl'):
            hits.append(t)
    # 结构体字段偏移：#0xNN 且 NN 不太大
    fields = []
    for t in added:
        import re
        for mo in re.finditer(r'#0x([0-9a-f]{1,3})\b', t):
            v = int(mo.group(1), 16)
            if 0 < v <= 0x400:
                fields.append(hex(v))
    return {'n_added': len(added), 'check_insns': hits[:24],
            'fields': sorted(set(fields), key=lambda x: int(x, 16))[:8],
            'n_removed': len([t for t in tokens_2701 if t not in set(tokens_272)])}


def main(argv):
    allk = '--all' in argv
    out_json = None
    if '--json' in argv:
        out_json = argv[argv.index('--json') + 1]
    names = []
    if allk:
        names = sorted(f[:-6] for f in os.listdir(os.path.join(ROOT, 'out', 'v2701'))
                       if f.endswith('.macho'))
    else:
        names = [x for x in argv[1:] if not x.startswith('--') and not x.endswith('.json')]
    results = []
    for k in names:
        try:
            r = analyze(k)
        except Exception as e:
            print(f'!! {k}: {e}', file=sys.stderr)
            continue
        for c in r['changed']:
            c['verdict'] = classify(c['tokens_2701'], c['tokens_272'])
        results.append(r)
        print(f'{k:44} 函数 {r["n_2701"]:5d}/{r["n_272"]:5d}  归一化后仍不同 {r["n_changed"]:4d}')
    if out_json:
        json.dump(results, open(out_json, 'w'), ensure_ascii=False)
        print('JSON ->', out_json)
    return results


if __name__ == '__main__':
    main(sys.argv)
