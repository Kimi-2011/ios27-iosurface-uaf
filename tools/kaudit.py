#!/usr/bin/env python3
"""Generic kernelcache-kext analysis helper (27.x, fully-linked slices).

Pointer encoding used by the 27.x kernelcache fileset slices:
    bits[0:36]   rebase-encoded offset, in *kernelcache file-offset* space
    bits[51:62]  chain 'next' (stride = 4 bytes)  -- 0 for plain data tables
    bit[63]      bind flag (1 = symbolic bind, unresolved at rest)
Resolve with:  va = seg.vmaddr + (target - seg.fileoff_cache)

usage:
    python3 tools/kaudit.py <macho> ptr  <file_offset>      # decode pointer
    python3 tools/kaudit.py <macho> va   <addr>             # va -> file offset
    python3 tools/kaudit.py <macho> str  <regex>            # strings matching
    python3 tools/kaudit.py <macho> xref <regex>            # xrefs to strings
    python3 tools/kaudit.py <macho> dispatch                # IOExternalMethodDispatch scan
"""
import bisect
import re
import struct
import sys

LC_SEGMENT_64 = 0x19
SECT = 80
# every kext slice in this kernelcache is placed at VA = fileoff + KB; verified
# against all four extracted kexts (iosurface / iogpu / agx / udif).
KB = 0xFFFFFE0007004000


class Kext:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        self.path = path
        ncmds = struct.unpack_from("<I", self.d, 16)[0]
        off = 32
        self.segs = []      # (name, vmaddr, vmsize, fileoff, filesize)
        self.sects = []     # (seg, name, addr, size, fileoff)
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.d, off)
            if cmd == LC_SEGMENT_64:
                name = self.d[off + 8: off + 24].rstrip(b"\0").decode()
                vm, vs, fo, fs = struct.unpack_from("<QQQQ", self.d, off + 24)
                nsects = struct.unpack_from("<I", self.d, off + 64)[0]
                self.segs.append((name, vm, vs, fo, fs))
                for i in range(nsects):
                    so = off + 72 + i * SECT
                    sn = self.d[so: so + 16].rstrip(b"\0").decode()
                    a, s = struct.unpack_from("<QQ", self.d, so + 32)
                    fo2 = struct.unpack_from("<I", self.d, so + 48)[0]
                    self.sects.append((name, sn, a, s, fo2))
            off += cmdsize

    # ---- address helpers -------------------------------------------------
    def seg_of_va(self, va):
        for s in self.segs:
            if s[1] <= va < s[1] + s[2]:
                return s
        return None

    def va_to_off(self, va):
        for name, vm, vs, fo, fs in self.segs:
            if vm <= va < vm + vs:
                # sections are authoritative for the file image
                for seg, sn, a, sz, f2 in self.sects:
                    if seg == name and a <= va < a + sz:
                        return f2 + (va - a)
        return None

    def off_to_va(self, fo):
        for seg, sn, a, sz, f2 in self.sects:
            if f2 <= fo < f2 + sz:
                return a + (fo - f2)
        return None

    def decode_ptr(self, fo):
        """Return (va, kind) for a pointer slot at file offset fo."""
        v = struct.unpack_from("<Q", self.d, fo)[0]
        if v == 0:
            return None, "null"
        if (v >> 63) & 1:
            return None, f"bind(ord={v & 0xFFFFFF})"
        t = v & 0xFFFFFFFFF
        va = KB + t
        if self.seg_of_va(va):
            return va, "rebase"
        return None, f"raw({v:#018x})"

    # ---- strings ---------------------------------------------------------
    def strings(self):
        out = {}
        pat = re.compile(rb"[\x20-\x7e]{5,300}")
        for seg, sn, a, sz, fo in self.sects:
            if seg in ("__TEXT_EXEC", "__TEXT_BOOT_EXEC"):
                continue
            blob = self.d[fo: fo + sz]
            for m in pat.finditer(blob):
                s = m.start()
                if s and blob[s - 1] != 0:
                    continue
                out[a + s] = m.group().decode("ascii")
        return out


def load_dis(path):
    """Parse llvm-objdump output into {va: text} plus an ordered list."""
    ins = {}
    order = []
    rx = re.compile(r"^([0-9a-f]{16}):\s+(.*)$")
    for line in open(path):
        m = rx.match(line)
        if m:
            va = int(m.group(1), 16)
            ins[va] = m.group(2).strip()
            order.append(va)
    order.sort()
    return ins, order


def funcs(ins, order):
    """Infer function starts: pacibsp/bti c preceded by ret/b/nop."""
    starts = []
    for i, va in enumerate(order):
        s = ins[va]
        if s in ("pacibsp", "bti\tc", "bti c", "paciasp"):
            prev = ins[order[i - 1]] if i else "ret"
            if prev.startswith("ret") or prev.startswith("b\t") or prev.startswith("b ") or prev == "nop":
                starts.append(va)
    return starts


def jump_tables(k, ins, order):
    """Decode arm64 PC-relative switch tables: cmp;csneg/csel;adrp;add;ldrsw;adr;add;br."""
    import struct
    hits = []
    pos = {v: i for i, v in enumerate(order)}
    for va in order:
        if not re.match(r"br\s+x\d+", ins[va]):
            continue
        i = pos[va]
        win = [ins[order[j]] for j in range(max(0, i - 8), i)]
        if not any("ldrsw" in w for w in win) or not any(w.startswith("adr\t") for w in win):
            continue
        adr_va = None
        for j in range(max(0, i - 8), i):
            if ins[order[j]].startswith("adr\t"):
                adr_va = order[j]
                break
        page = off = None
        for j in range(max(0, i - 8), i):
            s = ins[order[j]]
            m = re.match(r"adrp\s+x\d+, (0x[0-9a-f]+)", s)
            if m:
                page = int(m.group(1), 16)
            m = re.match(r"add\s+x\d+, x\d+, #(0x[0-9a-f]+|\d+)", s)
            if m and page is not None:
                off = int(m.group(1), 0)
        if page is None or off is None or adr_va is None:
            continue
        tbl = page + off
        bound = None
        for s in win:
            m = re.match(r"cmp\s+x\d+, #(0x[0-9a-f]+|\d+)", s)
            if m:
                bound = int(m.group(1), 0)
        fo = k.va_to_off(tbl)
        ents = []
        if fo is not None and bound is not None:
            for n in range(bound + 1):
                rel = struct.unpack_from("<i", k.d, fo + n * 4)[0]
                ents.append(adr_va + rel)
        hits.append(dict(br=va, table=tbl, adr=adr_va, bound=bound, targets=ents))
    return hits


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    k = Kext(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == "ptr":
        fo = int(sys.argv[3].replace("+","+0x") if False else sys.argv[3], 0)
        va, kind = k.decode_ptr(fo)
        print(f"{fo:#x}: {kind} -> {va and hex(va)}")
    elif cmd == "va":
        va = int(sys.argv[3], 0)
        print(f"{va:#x} -> file {k.va_to_off(va) and hex(k.va_to_off(va))}")
    elif cmd == "str":
        rx = re.compile(sys.argv[3])
        for va, s in sorted(k.strings().items()):
            if rx.search(s):
                print(f"{va:#018x}  {s}")
    elif cmd == "tables":
        from kaudit import load_dis
        ins, order = load_dis(sys.argv[3])
        for t in jump_tables(k, ins, order):
            print(f"br {t['br']:#x} table={t['table']:#x} adr={t['adr']:#x} bound={t['bound'] and hex(t['bound'])} n={len(t['targets'])}")
    elif cmd == "seg":
        for s in k.segs:
            print(f"{s[0]:16s} vm={s[1]:#x} size={s[2]:#x} fo={s[3]:#x} fs={s[4]:#x}")
        for s in k.sects:
            print(f"   {s[0]:14s} {s[1]:18s} addr={s[2]:#x} size={s[3]:#x} fo={s[4]:#x}")
    else:
        sys.exit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
