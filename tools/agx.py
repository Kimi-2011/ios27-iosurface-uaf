"""AGX Mach-O 分析内核: VA 映射 / 函数边界 / 反汇编 / 表解码。

方法纪律:
  - 函数边界: LC_FUNCTION_STARTS, ULEB128 增量累加, 基址 = __TEXT vmaddr。
    自证: 首项 == __TEXT_EXEC vmaddr。
  - 指针解码: va = 0xFFFFFE0007004000 + (word & 0xFFFFFFFF)。绝不 v>>63 过滤。
  - 只读 out/ 以外不改。
"""
import struct
import capstone

PTR_BASE = 0xFFFFFE0007004000

SEGMENT_CMD = 0x19
FSTARTS_CMD = 0x26


class MachO:
    def __init__(self, path):
        self.path = path
        self.d = open(path, "rb").read()
        d = self.d
        self.cputype, self.cpusub, = struct.unpack_from("<II", d, 4)
        ncmds, sizeofcmds = struct.unpack_from("<II", d, 16)
        self.segs = []          # {name, vm, vs, foff, fsz}
        self.sects = []         # {seg, name, addr, size, off, flags}
        fstarts = None
        off = 32
        for _ in range(ncmds):
            cmd, cs = struct.unpack_from("<II", d, off)
            if cmd == SEGMENT_CMD:
                name = d[off + 8:off + 24].rstrip(b"\0").decode()
                vm, vs, foff, fsz = struct.unpack_from("<QQQQ", d, off + 24)
                self.segs.append(dict(name=name, vm=vm, vs=vs, foff=foff, fsz=fsz))
                nsects = struct.unpack_from("<I", d, off + 64)[0]
                so = off + 72
                for _i in range(nsects):
                    sn = d[so:so + 16].rstrip(b"\0").decode()
                    addr, size = struct.unpack_from("<QQ", d, so + 32)
                    soff = struct.unpack_from("<I", d, so + 48)[0]
                    sflags = struct.unpack_from("<I", d, so + 64)[0]
                    self.sects.append(dict(seg=name, name=sn, addr=addr,
                                           size=size, off=soff, flags=sflags))
                    so += 80
            elif cmd == FSTARTS_CMD:
                fo, sz = struct.unpack_from("<II", d, off + 8)
                fstarts = (fo, sz)
            off += cs
        self.text_vm = self.segs[0]["vm"]
        self._fstarts = fstarts
        self.funcs = []
        if fstarts:
            self._load_fstarts(*fstarts)

    # ---------- 边界与映射 ----------
    def _load_fstarts(self, fo, sz):
        d = self.d
        blob = d[fo:fo + sz]
        acc = self.text_vm
        out = []
        i = 0
        while i < len(blob):
            val = 0
            shift = 0
            while True:
                b = blob[i]
                i += 1
                val |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            if val == 0:
                break
            acc += val
            out.append(acc)
        self.funcs = out

    def selfcheck(self):
        """首项必须 == __TEXT_EXEC vmaddr。"""
        exec_vm = [s for s in self.segs if s["name"] == "__TEXT_EXEC"][0]["vm"]
        return (self.funcs[0] == exec_vm if self.funcs else False), exec_vm

    def sect_of(self, va):
        for s in self.sects:
            if s["addr"] <= va < s["addr"] + s["size"]:
                return s
        for s in self.segs:
            if s["vm"] <= va < s["vm"] + s["vs"]:
                return s
        return None

    # 注意: kext_extract.py 只重写了 segment 的 fileoff, 未重写 section_64.offset,
    # 后者仍指向原始 kernelcache 偏移(全部超出文件长度)。因此映射只能走段级。
    def va2off(self, va):
        for s in self.segs:
            if s["foff"] and s["vm"] <= va < s["vm"] + s["fsz"]:
                o = s["foff"] + (va - s["vm"])
                return o if 0 <= o < len(self.d) else None
        return None

    def off2va(self, off):
        for s in self.segs:
            if s["foff"] and s["foff"] <= off < s["foff"] + s["fsz"]:
                return s["vm"] + (off - s["foff"])
        return None

    def read(self, va, n):
        o = self.va2off(va)
        if o is None or o + n > len(self.d):
            return None
        return self.d[o:o + n]

    def u32(self, va):
        b = self.read(va, 4)
        return struct.unpack("<I", b)[0] if b else None

    def u64(self, va):
        b = self.read(va, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def decode_ptr(self, word):
        """统一 auth 指针解码。"""
        return (PTR_BASE + (word & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF

    def ptr(self, va):
        w = self.u64(va)
        return None if w is None else self.decode_ptr(w)

    # ---------- 函数边界 ----------
    def func_at(self, va):
        """返回包含 va 的函数起始 VA (精确: 函数列表里 <= va 的最大值)。"""
        import bisect
        i = bisect.bisect_right(self.funcs, va) - 1
        return self.funcs[i] if i >= 0 else None

    def func_size(self, va):
        import bisect
        i = bisect.bisect_right(self.funcs, va) - 1
        if i < 0:
            return None
        if i + 1 < len(self.funcs):
            return self.funcs[i + 1] - self.funcs[i]
        return None

    def func_bounds(self, va):
        s = self.func_at(va)
        if s is None:
            return None, None
        return s, self.func_size(s)


# ---------- 反汇编 ----------
def disas(m, va, nbytes=None, count=0):
    if nbytes is None:
        nbytes = 4 * (count or 1)
    b = m.read(va, nbytes)
    if b is None:
        return []
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    return [(i.address, i.mnemonic, i.op_str) for i in md.disasm(b, va)]


def disas_func(m, va):
    s, sz = m.func_bounds(va)
    if s is None or sz is None:
        return []
    return disas(m, s, nbytes=sz)


# ---------- 编码常量 ----------
def enc_ldrsw_index(insn_word):
    """ldrsw Xt,[Xn,Xm,lsl #2] -> True"""
    return (insn_word & 0xFFE0EC00) == 0xB8A06800


def enc_adr(w):
    return (w & 0x9F000000) == 0x10000000


def enc_adrp(w):
    return (w & 0x9F000000) == 0x90000000


def enc_add_imm(w):
    return (w & 0x7F800000) == 0x11000000


def enc_cmp_w1_imm(w):
    """cmp w1, #imm  ==  subs wzr, w1, #imm  (64-bit sf=0, op=1, S=1, shift=0, Rn=1, Rd=31)"""
    return (w & 0xFFC0001F) == 0x7100001F


# ---------- 全函数扫描 ----------
def sweep(m, md=None):
    """按 LC_FUNCTION_STARTS 逐函数反汇编, 遇不可解码跳 4 字节。

    返回 {addr: (mnemonic, op_str)}; 只收成功解码的地址。
    """
    if md is None:
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    out = {}
    funcs = m.funcs
    for idx, fva in enumerate(funcs):
        end = funcs[idx + 1] if idx + 1 < len(funcs) else fva + 0x400
        b = m.read(fva, end - fva)
        if b is None:
            continue
        off = 0
        while off < len(b):
            ok = False
            for ins in md.disasm(b[off:off + 4], fva + off):
                out[ins.address] = (ins.mnemonic, ins.op_str)
                ok = True
            off += 4 if ok else 4
    return out


def adrp_add_xrefs(m, targets, insns=None):
    """在已扫指令表上做 adrp+add 组合, 返回命中 [(addr, target, text)]。"""
    import re
    if insns is None:
        insns = sweep(m)
    reg = {}
    hits = []
    addrs = sorted(insns)
    for a in addrs:
        mn, ops = insns[a]
        if mn == "adrp":
            mm = re.match(r"(x\d+|w\d+), #(0x[0-9a-f]+)", ops)
            if mm:
                reg[mm.group(1)] = int(mm.group(2), 16)
        elif mn == "add":
            mm = re.match(r"(x\d+|w\d+), (x\d+|w\d+), #(0x[0-9a-f]+|\d+)", ops)
            if mm:
                base = reg.get(mm.group(2))
                if base is not None:
                    v = base + int(mm.group(3), 0)
                    reg[mm.group(1)] = v
                    if v in targets:
                        hits.append((a, v, f"{mn} {ops}"))
        elif mn in ("ldr", "str", "ldur", "stur", "ldrb", "strb", "mov", "orr", "bl", "blr", "br", "ret"):
            # 目标寄存器被覆盖或基本块结束, 保守清空
            if mn in ("bl", "blr", "br", "ret", "b"):
                reg.clear()
            else:
                mm = re.match(r"(x\d+|w\d+)", ops)
                if mm:
                    reg.pop(mm.group(1), None)
    return hits


def const_xrefs(m, values, insns=None):
    """找字面量池里等于 values 的 8 字节字 (含未签名化高 32 位为 0 的情形)。"""
    hits = []
    d = m.d
    for seg in m.segs:
        if not seg["foff"] or seg["name"] not in ("__DATA_CONST", "__DATA", "__TEXT"):
            continue
        lo, hi = seg["foff"], seg["foff"] + seg["fsz"]
        for va_t, val in values.items():
            for lo32 in ((val & 0xFFFFFFFF), (val - PTR_BASE) & 0xFFFFFFFF):
                pat = lo32.to_bytes(4, "little") + b"\0\0\0\0"
                st = lo
                while True:
                    i = d.find(pat, st, hi)
                    if i < 0:
                        break
                    hits.append((m.off2va(i), va_t))
                    st = i + 4
    return hits
