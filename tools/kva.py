"""Decode chained-fixup-encoded pointers in a release kernelcache fileset.

The individual kext Mach-O entries carry NO LC_DYLD_CHAINED_FIXUPS; the whole
collection has one at the outer header.  Every relocated pointer in
__DATA_CONST / __DATA / __PRELINK_INFO is stored as

    word = 0x0010000000000000 | target            (target < 2**36)

and the runtime address is

    va = KC_TEXT_VMADDR + target                  (KC_TEXT_VMADDR = outer __TEXT vmaddr)

Verified: decoded targets land exactly on `bti c; pacibsp` prologues.

Usage:
  from kva import KC
  kc = KC("out/kc.27.0.1.full")
  kc.dis(0xfffffe0009006634, 10)      -> list of "addr  mnemonic  operands"
  kc.words(seg, off, n)               -> decoded 64-bit words with pointer targets
  kc.strings(seg)                     -> {va: str}
"""
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
PTR_TAG = 0x0010000000000000


class KC:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.d = fh.read()
        d = self.d
        ncmds = struct.unpack_from("<I", d, 16)[0]
        off = 32
        self.segs = []       # (name, vm, vsize, fo, fsize)
        entries = []         # (fileoff, name)
        for _ in range(ncmds):
            cmd, cs = struct.unpack_from("<II", d, off)
            if cmd == LC_SEGMENT_64:
                nm = d[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
                vm, vs, fo, fs = struct.unpack_from("<QQQQ", d, off + 24)
                self.segs.append((nm, vm, vs, fo, fs))
            elif cmd == LC_FILESET_ENTRY:
                fileoff = struct.unpack_from("<Q", d, off + 16)[0]
                idoff = struct.unpack_from("<I", d, off + 24)[0]
                base = off + idoff
                end = d.index(b"\0", base)
                entries.append((fileoff, d[base:end].decode("ascii", "replace")))
            off += cs
        self.base = self.segs[0][1]                     # outer __TEXT vmaddr
        self.kext = {n: fo for fo, n in entries}
        self._md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self._md.detail = False
        self._kseg = {}

    # ---------- address translation ----------
    def v2f(self, va):
        for nm, vm, vs, fo, fs in self.segs:
            if vm <= va < vm + fs:
                return fo + (va - vm)
        return None

    def in_map(self, va):
        return self.v2f(va) is not None

    # ---------- decoding ----------
    @staticmethod
    def dec(word):
        """Return the kernel VA a chained-fixup word points at, or None."""
        if word >> 36 != PTR_TAG >> 36:
            return None
        return None  # filled per-instance (needs base)

    def ptr(self, word):
        if word >> 36 != PTR_TAG >> 36:
            return None
        return self.base + (word & 0xFFFFFFFFF)

    def words(self, fo, n, va0=0):
        out = []
        for i in range(n):
            w = struct.unpack_from("<Q", self.d, fo + i * 8)[0]
            out.append((va0 + i * 8, w, self.ptr(w)))
        return out

    # ---------- kext ----------
    def ksegs(self, bundle):
        """Segment table of one fileset entry: list of (name, vm, vsize, fo, fsize)."""
        if bundle in self._kseg:
            return self._kseg[bundle]
        fo = self.kext[bundle]
        d = self.d
        ncmds = struct.unpack_from("<I", d, fo + 16)[0]
        off = fo + 32
        segs = []
        for _ in range(ncmds):
            cmd, cs = struct.unpack_from("<II", d, off)
            if cmd == LC_SEGMENT_64:
                nm = d[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
                vm, vs, f2, fs = struct.unpack_from("<QQQQ", d, off + 24)
                segs.append((nm, vm, vs, f2, fs))
            off += cs
        self._kseg[bundle] = segs
        return segs

    def kseg(self, bundle, name):
        for nm, vm, vs, fo, fs in self.ksegs(bundle):
            if nm == name:
                return vm, vs, fo, fs
        raise KeyError(name)

    # ---------- disassembly ----------
    def dis(self, va, n=16):
        f = self.v2f(va)
        if f is None:
            return ["%#x  <unmapped>" % va]
        out = []
        for ins in self._md.disasm(self.d[f:f + n * 4], va):
            out.append("%#x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
        return out

    def insns(self, va, n):
        f = self.v2f(va)
        return list(self._md.disasm(self.d[f:f + n * 4], va))

    def cstr(self, va):
        f = self.v2f(va)
        if f is None:
            return None
        e = self.d.index(b"\0", f)
        return self.d[f:e].decode("utf-8", "replace")

    def strings(self, bundle):
        """{va: string} for printable NUL-terminated runs inside the kext's file segments."""
        out = {}
        for nm, vm, vs, fo, fs in self.ksegs(bundle):
            if nm == "__LINKEDIT":
                continue
            blob = self.d[fo:fo + fs]
            i = 0
            while i < len(blob):
                if 0x20 <= blob[i] < 0x7f:
                    j = i
                    while j < len(blob) and 0x20 <= blob[j] < 0x7f:
                        j += 1
                    if j - i >= 4 and j < len(blob) and blob[j] == 0:
                        out[vm + i] = blob[i:j].decode("ascii")
                    i = j + 1
                else:
                    i += 1
        return out
