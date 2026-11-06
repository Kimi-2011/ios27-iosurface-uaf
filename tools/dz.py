"""dz.py — 线性/重同步反汇编 + 调用者扫描（IOSurface 竞态线专用）

设计要点（对应 TOOLING-PITFALLS 的坑）：
- md.disasm 遇到坏 4 字节会停 -> 默认 resync 模式，逐 4 字节前进
- 数据段必须从 out/kc.*.full 读（kext 镜像 __DATA_CONST 全零）；本工具只走 kseg
- 调用者扫描同时收 `bl`/`b`（尾调）两种，判据纪律第 6 条

用法：
  python3 tools/dz.py fn 0xfffffe000a3460f0 0x400
  python3 tools/dz.py callers 0xfffffe000a346364 --kext com.apple.iokit.IOSurface
  python3 tools/dz.py xref 0xfffffe000837f650
"""
import sys, struct, bisect
sys.path.insert(0, '<PROJECT>/tools')
import kseg
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ROOT = '<PROJECT>'
CACHE = {
    '27.0.1': f'{ROOT}/out/kc.27.0.1.full',
    '27.2': f'{ROOT}/out/kc.27.2.ga.full',
}
_K = {}


def K(ver='27.0.1'):
    if ver not in _K:
        _K[ver] = kseg.Index(CACHE[ver])
    return _K[ver]


def _cs():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return md


def func_starts(ver='27.0.1'):
    """返回 {kext: [va,...]} （LC_FUNCTION_STARTS）"""
    k = K(ver)
    d = k.d
    out = {}
    for name, segs in k.kexts.items():
        # 找该 fileset entry 的 LC_FUNCTION_STARTS
        pass
    # 直接扫顶层所有 LC_FUNCTION_STARTS? 需要 per-entry。改用 kfunc 已有实现
    return out


def dis(va, n=0x200, ver='27.0.1', resync=True):
    """反汇编 va 起 n 字节。返回 [(addr, size, mnemonic, op_str)]"""
    k = K(ver)
    b = k.read(va, n)
    if b is None:
        return []
    md = _cs()
    out = []
    off = 0
    while off < len(b):
        got = False
        for i in md.disasm(b[off:off + 4], va + off):
            out.append((i.address, i.size, i.mnemonic, i.op_str))
            got = True
        off += 4
        if not resync and not got:
            break
    return out


def show(va, n=0x200, ver='27.0.1'):
    for a, s, m, o in dis(va, n, ver):
        print(f'0x{a:x}:  {m:8s} {o}')


def imm_target(m, o):
    """从 bl/b/adr 的 op_str 取目标"""
    if not o.startswith('#'):
        return None
    try:
        return int(o[1:].split(',')[0], 0)
    except Exception:
        return None


def callers(target, ver='27.0.1', kexts=None, also_b=True):
    """全 cache 扫描 bl/b 目标 == target 的位置。kexts=None 全扫。"""
    k = K(ver)
    md = _cs()
    hits = []
    for name, segs in k.kexts.items():
        if kexts and name not in kexts:
            continue
        for vm, vs, fo, fsz, sn in segs:
            if not sn.startswith('__TEXT'):
                continue
            b = k.d[fo:fo + min(vs, fsz)]
            base = vm
            for off in range(0, len(b) - 3, 4):
                w = struct.unpack_from('<I', b, off)[0]
                op = w & 0xFC000000
                # bl: 0x94000000 ; b: 0x14000000
                if op != 0x94000000 and (not also_b or op != 0x14000000):
                    continue
                imm = w & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                tgt = base + off + imm * 4
                if tgt == target:
                    hits.append((base + off, name, sn, 'bl' if op == 0x94000000 else 'b'))
    return hits


def datarefs(addr, ver='27.0.1', kexts=None):
    """找 __DATA* 段里等于 addr 的 8 字节（原始 or chained fixup）"""
    k = K(ver)
    hits = []
    tgt_lo = addr & 0xFFFFFFFF
    for name, segs in k.kexts.items():
        if kexts and name not in kexts:
            continue
        for vm, vs, fo, fsz, sn in segs:
            if not sn.startswith('__DATA'):
                continue
            b = k.d[fo:fo + min(vs, fsz)]
            base = vm
            for off in range(0, len(b) - 7, 8):
                q = struct.unpack_from('<Q', b, off)[0]
                if q == addr or (q & 0xFFFFFFFF) == tgt_lo:
                    hits.append((base + off, name, sn, q))
    return hits


def adrp_add_refs(addr, ver='27.0.1', kexts=None, page_span=0x1000):
    """扫 adrp+add 组合（只为拿到数据地址的粗定位）"""
    k = K(ver)
    hits = []
    for name, segs in k.kexts.items():
        if kexts and name not in kexts:
            continue
        for vm, vs, fo, fsz, sn in segs:
            if not sn.startswith('__TEXT'):
                continue
            b = k.d[fo:fo + min(vs, fsz)]
            base = vm
            last = None
            for off in range(0, len(b) - 3, 4):
                w = struct.unpack_from('<I', b, off)[0]
                if (w & 0x9F000000) == 0x90000000:      # adrp
                    immhi = (w >> 5) & 0x7FFFF
                    immlo = (w >> 29) & 3
                    imm = (immhi << 2) | immlo
                    if imm & 0x100000:
                        imm -= 0x200000
                    rd = w & 0x1F
                    last = (rd, (base + off) & ~0xFFF, imm << 12)
                elif (w & 0xFF800000) == 0x91000000 and last:   # add imm
                    rd = w & 0x1F
                    rn = (w >> 5) & 0x1F
                    imm12 = (w >> 10) & 0xFFF
                    sh = (w >> 22) & 1
                    if rn == last[0]:
                        val = last[1] + last[2] + (imm12 << (12 if sh else 0))
                        if val == addr:
                            hits.append((base + off, name, sn))
                    last = None
    return hits


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'fn':
        va = int(sys.argv[2], 16)
        n = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x200
        ver = sys.argv[4] if len(sys.argv) > 4 else '27.0.1'
        show(va, n, ver)
    elif cmd == 'callers':
        t = int(sys.argv[2], 16)
        ver = '27.0.1'
        kexts = None
        for a in sys.argv[3:]:
            if a.startswith('--kext'):
                continue
            if a.startswith('com.apple') or a.startswith('iokit_'):
                kexts = [a]
        for h in callers(t, ver, kexts):
            print(f'0x{h[0]:x}  {h[1]} {h[2]} {h[3]}')
    elif cmd == 'xref':
        t = int(sys.argv[2], 16)
        for h in datarefs(t):
            print(f'DATA 0x{h[0]:x} {h[1]} {h[2]} q=0x{h[3]:x}')
        for h in adrp_add_refs(t):
            print(f'CODE 0x{h[0]:x} {h[1]} {h[2]}')
