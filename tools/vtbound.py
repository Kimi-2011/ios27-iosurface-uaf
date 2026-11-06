"""按类构造点枚举 vtable 边界。
特征：mov w3,#<size> + bl <metactl> ; 名字来自 x1 的 cstring，vtable 来自随后写入 [x0] 的 adrp+add。
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, kdiff_all as kd

def main(path, kext):
    K = kseg.Index(path)
    v = kd.KextView(K, kext)
    segs = {sn: (vm, vs, fo, fsz) for vm, vs, fo, fsz, sn in K.kexts[kext]}
    def seg(vm_or_fo, byva=True):
        for sn, (vm, vs, fo, fsz) in segs.items():
            if byva and vm <= vm_or_fo < vm + max(vs, fsz):
                return sn
            if not byva and fo <= vm_or_fo < fo + fsz:
                return sn
        return None
    def cstr(va):
        sn = seg(va)
        if not sn:
            return None
        vm, vs, fo, fsz = segs[sn]
        f = fo + (va - vm)
        if not (0 <= f < len(K.d)):
            return None
        e = K.d.find(b'\0', f)
        s = K.d[f:min(e, f + 64)]
        return s.decode('ascii', 'replace') if s and all(32 <= c < 127 for c in s) else None
    DC0, DC1 = segs['__DATA_CONST'][0], segs['__DATA_CONST'][0] + segs['__DATA_CONST'][3]
    out = []
    for va, sz in v.functions():
        code = v.read(va, sz)
        if not code:
            continue
        ins = list(kd.MD.disasm(code, va))
        for i, x in enumerate(ins):
            if x.mnemonic != 'bl':
                continue
            try:
                t = int(x.op_str.split('#')[-1], 0)
            except Exception:
                continue
            # 元类构造：前 12 条内应有 mov w3,#size 与 adrp+add 的 cstring
            name = None
            size = None
            for y in ins[max(0, i - 14):i]:
                if y.mnemonic == 'mov' and y.op_str.startswith('w3, #0x'):
                    size = y.op_str.split('#')[1]
                if y.mnemonic == 'adrp':
                    try:
                        p = int(y.op_str.split('#')[1].split(',')[0], 0)
                    except Exception:
                        continue
                    for z in ins[ins.index(y) + 1:ins.index(y) + 3]:
                        if z.mnemonic == 'add' and '#0x' in z.op_str:
                            try:
                                loc = p + int(z.op_str.split('#')[1].split(',')[0], 0)
                            except Exception:
                                continue
                            s = cstr(loc)
                            if s and s[0].isupper():
                                name = s
                            break
            if name and size:
                # 往后找写入 [x0] 的 __DATA_CONST 地址 = vtable
                vt = None
                for y in ins[i:i + 26]:
                    if y.mnemonic == 'adrp':
                        try:
                            p = int(y.op_str.split('#')[1].split(',')[0], 0)
                        except Exception:
                            continue
                        for z in ins[ins.index(y) + 1:ins.index(y) + 3]:
                            if z.mnemonic == 'add' and '#0x' in z.op_str:
                                try:
                                    loc = p + int(z.op_str.split('#')[1].split(',')[0], 0)
                                except Exception:
                                    continue
                                if DC0 <= loc < DC1:
                                    vt = loc
                                break
                    if y.mnemonic == 'str' and y.op_str.endswith('[x0]') and vt:
                        break
                out.append((va, name, size, vt, t))
    return out

if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'out', 'kc.27.2.ga.full')
    kext = sys.argv[2] if len(sys.argv) > 2 else 'com.apple.iokit.IOSurface'
    rows = main(path, kext)
    print(f'{kext}: 类构造点 {len(rows)} 个')
    for va, nm, size, vt, t in rows:
        print(f'  fn 0x{va-0xfffffe0000000000:x}  {nm:34} size={size}  vt={hex(vt-0xfffffe0000000000) if vt else "-"}  ctor=0x{t-0xfffffe0000000000:x}')
