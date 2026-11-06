"""统一口径的 ZTV 枚举：vptr = ZTV基址 + 0x10，边界一律用 vptr。"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import kseg, kdiff_all as kd
ZTV_HDR = 0x10


def run(path, kext):
    K = kseg.Index(path)
    v = kd.KextView(K, kext)
    segs = {sn: (vm, vs, fo, fsz) for vm, vs, fo, fsz, sn in K.kexts[kext]}
    DC0, DC1 = segs['__DATA_CONST'][0], segs['__DATA_CONST'][0] + segs['__DATA_CONST'][3]
    txt = segs['__TEXT']
    def cstr(va):
        if not (txt[0] <= va < txt[0] + txt[3]):
            return None
        f = txt[2] + (va - txt[0])
        e = K.d.find(b'\0', f)
        s = K.d[f:min(e, f + 64)]
        return s.decode('ascii', 'replace') if s and all(32 <= c < 127 for c in s) else None
    rows = []
    for va, sz in v.functions():
        code = v.read(va, sz)
        if not code:
            continue
        ins = list(kd.MD.disasm(code, va))
        name = None; size = None
        for i, x in enumerate(ins):
            if x.mnemonic == 'mov' and x.op_str.startswith('w3, #0x'):
                size = x.op_str.split('#')[1]
            if x.mnemonic == 'adrp':
                try: p = int(x.op_str.split('#')[1].split(',')[0], 0)
                except Exception: continue
                for y in ins[i + 1:i + 3]:
                    if y.mnemonic == 'add' and '#0x' in y.op_str:
                        try: loc = p + int(y.op_str.split('#')[1].split(',')[0], 0)
                        except Exception: continue
                        s = cstr(loc)
                        if s and s[0].isupper() and len(s) > 5:
                            name = s
                        break
            # 找 ZTV: adrp+add -> X, 紧跟 add X,X,#0x10, 后面有 pacda
            if x.mnemonic == 'adrp':
                try: p = int(x.op_str.split('#')[1].split(',')[0], 0)
                except Exception: continue
                for j, y in enumerate(ins[i + 1:i + 3]):
                    if y.mnemonic == 'add' and '#0x' in y.op_str:
                        try: base = p + int(y.op_str.split('#')[1].split(',')[0], 0)
                        except Exception: continue
                        if not (DC0 <= base < DC1):
                            break
                        k = i + 1 + j
                        vptr = None
                        if k + 1 < len(ins) and ins[k + 1].mnemonic == 'add' and '#0x10' in ins[k + 1].op_str:
                            vptr = base + ZTV_HDR
                        else:
                            vptr = base
                        haspac = any(z.mnemonic == 'pacda' for z in ins[k + 1:k + 6])
                        if haspac:
                            rows.append((base, vptr, va, name, size))
                        break
                continue
    return K, segs, rows


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'out', 'kc.27.2.ga.full')
    kext = sys.argv[2] if len(sys.argv) > 2 else 'com.apple.iokit.IOSurface'
    K, segs, rows = run(path, kext)
    u = {}
    for base, vptr, va, nm, size in rows:
        u.setdefault(vptr, set()).add((base, nm, size))
    print(f'{kext}: ZTV 基址 {len(u)} 个（口径：vptr = base+0x10）')
    for vptr in sorted(u):
        for base, nm, size in sorted(u[vptr]):
            print(f'  base=0x{base-0xfffffe0000000000:x}  vptr=0x{vptr-0xfffffe0000000000:x}  {str(nm):34} size={size}')
