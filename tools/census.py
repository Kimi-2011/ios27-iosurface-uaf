#!/usr/bin/env python3
"""全 cache 派发表普查。

两条独立发现路径，必须互证：
  A 数据路：解码 __DATA_CONST 的 chained-fixup 指针 → 成固定步长连续落在函数起点
  B 代码路：扫 __TEXT_EXEC 的 adrp+add → 表基址，并记录所在函数

用法: python3 census.py out/kc.27.0.1.full [--json out/census.json] [-v]
"""
import json
import struct
import sys
from bisect import bisect_right

LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
LC_FUNCTION_STARTS = 0x26

KB = 0xFFFFFE0007004000


# ---------------------------------------------------------------- mach-o
class Cache:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        ncmds = struct.unpack_from('<I', d, 16)[0]
        off = 32
        self.segs = []
        self.entries = []
        for _ in range(ncmds):
            cmd, cs = struct.unpack_from('<II', d, off)
            if cmd == LC_SEGMENT_64:
                nm = d[off + 8:off + 24].rstrip(b'\0').decode('ascii', 'replace')
                vm, vs, fo, fs = struct.unpack_from('<QQQQ', d, off + 24)
                self.segs.append((nm, vm, vs, fo, fs))
            elif cmd == LC_FILESET_ENTRY:
                fo = struct.unpack_from('<Q', d, off + 16)[0]
                idoff = struct.unpack_from('<I', d, off + 24)[0]
                b = off + idoff
                self.entries.append((fo, d[b:d.index(b'\0', b)].decode('ascii', 'replace')))
            off += cs
        self.kext = dict((n, fo) for fo, n in self.entries)
        self.lc = {}          # bundle -> dict(segs=[(nm,vm,vs,fo,fs)], fstarts=(off,size))
        for fo, name in self.entries:
            self.lc[name] = self._loadcmds(fo)

    def _loadcmds(self, fo):
        d = self.d
        ncmds = struct.unpack_from('<I', d, fo + 16)[0]
        off = fo + 32
        segs = []
        fs = None
        for _ in range(ncmds):
            cmd, cs = struct.unpack_from('<II', d, off)
            if cmd == LC_SEGMENT_64:
                nm = d[off + 8:off + 24].rstrip(b'\0').decode('ascii', 'replace')
                vm, vs, f2, sz = struct.unpack_from('<QQQQ', d, off + 24)
                segs.append((nm, vm, vs, f2, sz))
            elif cmd == LC_FUNCTION_STARTS:
                fs = (struct.unpack_from('<I', d, off + 8)[0],
                      struct.unpack_from('<I', d, off + 12)[0])
            off += cs
        return dict(segs=segs, fstarts=fs)

    def kseg(self, bundle, name):
        for nm, vm, vs, fo, sz in self.lc[bundle]['segs']:
            if nm == name:
                return vm, vs, fo, sz
        return None


# ---------------------------------------------------------------- decode
def decode_ptr(w):
    """chained-fixup word -> kernel VA (or None)."""
    if w == 0:
        return None
    bind = (w >> 62) & 1
    if bind:
        return None
    auth = (w >> 63) & 1
    t = (w & 0xFFFFFFFF) if auth else (w & 0xFFFFFFFFF)
    if t == 0:
        return None
    return KB + t


def func_starts(c, bundle):
    """LC_FUNCTION_STARTS, base = kext __TEXT vmaddr. Returns (list, ok, note)."""
    info = c.lc[bundle]
    text = c.kseg(bundle, '__TEXT')
    te = c.kseg(bundle, '__TEXT_EXEC')
    if info['fstarts'] is None:
        return None, False, 'no LC_FUNCTION_STARTS'
    if text is None or te is None:
        return None, False, 'no __TEXT/__TEXT_EXEC'
    doff, dsize = info['fstarts']
    blob = c.d[doff:doff + dsize]
    base = text[0]
    cur = 0
    out = []
    i = 0
    while i < len(blob):
        v = 0
        sh = 0
        while True:
            if i >= len(blob):
                return out, False, 'uleb overrun'
            b = blob[i]
            i += 1
            v |= (b & 0x7f) << sh
            sh += 7
            if not b & 0x80:
                break
        if v == 0:
            break
        cur += v
        out.append(base + cur)
    if not out:
        return out, False, 'empty'
    if out[0] != te[0]:
        return out, False, 'selfcheck: first=%#x != __TEXT_EXEC %#x' % (out[0], te[0])
    return out, True, 'ok'


# ---------------------------------------------------------------- path A
def data_path(c, bundle, starts, max_stride_trials=(0x18, 0x28)):
    """Return list of tables: dict(base, stride, fns[], fields[][])"""
    te = c.kseg(bundle, '__TEXT_EXEC')
    if te is None:
        return []
    lo, hi = te[0], te[0] + te[3]
    sset = set(starts)
    tables = []
    for segname in ('__DATA_CONST', '__DATA'):
        sg = c.kseg(bundle, segname)
        if sg is None:
            continue
        vm, vs, fo, sz = sg
        n = sz // 8
        # decode every word once
        vals = []
        for i in range(n):
            w = struct.unpack_from('<Q', c.d, fo + i * 8)[0]
            vals.append((w, decode_ptr(w)))
        used = set()
        for stride in max_stride_trials:
            step = stride // 8
            for i in range(n):
                pv = vals[i][1]
                if pv is None or not (lo <= pv < hi) or pv not in sset:
                    continue
                if i in used:
                    continue
                if not _gap_clean(vals, i, stride // 8, lo, hi, sset):
                    continue
                # extend
                fns = [pv]
                fields = [_fields(c, fo + i * 8, stride)]
                if fields[0] is None:
                    continue
                k = 1
                while True:
                    j = i + k * step
                    if j >= n:
                        break
                    p2 = vals[j][1]
                    if p2 is None or not (lo <= p2 < hi) or p2 not in sset:
                        break
                    fld = _fields(c, fo + j * 8, stride)
                    if fld is None:
                        break
                    if not _gap_clean(vals, j, stride // 8, lo, hi, sset):
                        break
                    fns.append(p2)
                    fields.append(fld)
                    k += 1
                flat = [v for f in fields if f for v in f]
                if len(fns) >= 2 and any(flat):
                    for j in range(i, i + len(fns) * step, step):
                        used.add(j)
                    tables.append(dict(seg=segname, base=vm + i * 8, stride=stride,
                                       fns=fns, fields=fields,
                                       strong=len(fns) >= 3))
    # 去重：同一 base 只留最长/最强
    best = {}
    for t in tables:
        k = (t['base'], t['stride'])
        if k not in best or len(t['fns']) > len(best[k]['fns']):
            best[k] = t
    return list(best.values())


def _gap_clean(vals, i, step, lo, hi, sset):
    """步长之间的填充字不能是本 kext 的函数指针（否则这是 vtable 不是派发表）。"""
    n = len(vals)
    for k in range(1, step):
        j = i + k
        if j >= n:
            return False
        p = vals[j][1]
        if p is not None and lo <= p < hi and p in sset:
            return False
    return True


def _fields(c, off, stride):
    """4 个 u32 健全性检查；坏则 None。"""
    a = struct.unpack_from('<4I', c.d, off + 8)
    for v in a:
        if v != 0xFFFFFFFF and v > 0x10000:
            return None
    return list(a)


# ---------------------------------------------------------------- path B
def code_path(c, bundle, targets):
    """扫 adrp+add，返回 {target_va: [函数起点...]}"""
    te = c.kseg(bundle, '__TEXT_EXEC')
    if te is None or not targets:
        return {}
    vm, vs, fo, sz = te
    blob = c.d[fo:fo + sz]
    hits = {}
    tset = targets
    n = len(blob) - 16
    pend = {}   # reg -> (page, pc)
    for i in range(0, n, 4):
        insn = struct.unpack_from('<I', blob, i)[0]
        if (insn & 0x9F000000) == 0x90000000:            # ADRP
            rd = insn & 0x1F
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            pc = vm + i
            pg = (pc & ~0xFFF) + (imm << 12)
            pend[rd] = (pg, pc)
            if pg in tset:
                hits.setdefault(pg, []).append(pc)
        elif (insn & 0xFF800000) == 0x91000000 and pend:  # ADD (imm), 64-bit
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            if rn in pend:
                page, apc = pend[rn]
                imm12 = (insn >> 10) & 0xFFF
                shift = (insn >> 22) & 3
                if shift == 1:
                    imm12 <<= 12
                elif shift != 0:
                    continue
                tgt = page + imm12
                if tgt in tset:
                    hits.setdefault(tgt, []).append(apc)
                if rd != rn:
                    pend.pop(rn, None)
    return hits
