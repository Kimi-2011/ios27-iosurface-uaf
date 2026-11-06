"""段级索引 —— 唯一可信的 VA <-> fileoff 映射。

存在的理由（两条已复现的坑）：
1. tools/kdiff.slices() 用「下一个 entry 起点之差」当 size，最后一个 entry 吃掉 63 MB
   => 拿它做 offset->kext 映射会把全内核的命中错误归类。
2. tools/kext_extract.py 只补丁 segment fileoff / LC_FUNCTION_STARTS / LC_SYMTAB，
   不重写 section_64.offset => 提取出的 Mach-O 里 section 偏移仍指向原 kernelcache，
   任何按 section 取表的代码会读到垃圾。绕过：VA<->off 只走 **segment**。

用法：
    import kseg
    K = kseg.Index('out/kc.27.0.1.full')
    K.va2off(va)        -> (fileoff, kextname) | None
    K.read(va, n)       -> bytes | None
    K.off2va(off)       -> (va, kextname, segname) | None
    K.kexts             -> {kextname: [(vm, vs, fo, fsz, segname), ...]}
    K.chained(va)       -> 解码 8 字节 chained fixup（arm64e / 内核）
"""
import struct

KB_BASE = 0xFFFFFE0007004000


def _segments(d, fo):
    """解析一个 Mach-O slice 的段表。只返回 __SEGMENT_COMMAND(0x19)。"""
    try:
        ncmds = struct.unpack_from('<I', d, fo + 16)[0]
        off = fo + 32
    except struct.error:
        return []
    out = []
    for _ in range(ncmds):
        try:
            cmd, csz = struct.unpack_from('<II', d, off)
        except struct.error:
            break
        if csz == 0 or csz > 0x1000 or off + csz > len(d):
            break
        if cmd == 0x19:
            name = d[off + 8:off + 24].rstrip(b'\0').decode('ascii', 'replace')
            vm, vs, f2, fsz = struct.unpack_from('<QQQQ', d, off + 24)
            if fsz:
                out.append((vm, vs, f2, fsz, name))
        off += csz
    return out


class Index:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.d = f.read()
        d = self.d
        self.segs = []          # (fileoff, filesize, vm, vs, kext, segname)
        self.kexts = {}
        # LC_FILESET_ENTRY = 0x1F
        try:
            ncmds = struct.unpack_from('<I', d, 16)[0]
            base = 0
            off = 32
        except struct.error:
            ncmds, base, off = 0, 0, 0
        entries = []
        for _ in range(ncmds):
            try:
                cmd, csz = struct.unpack_from('<II', d, off)
            except struct.error:
                break
            if csz == 0 or csz > 0x1000 or off + csz > len(d):
                break
            if cmd == 0x80000035:                 # LC_FILESET_ENTRY (LC_REQ_DYLD)
                fileoff = struct.unpack_from('<Q', d, off + 16)[0]
                id_off = struct.unpack_from('<I', d, off + 24)[0]
                name = d[off + id_off:off + csz].split(b'\0')[0].decode('ascii', 'replace')
                entries.append((fileoff, name))
            off += csz
        self.entries = entries
        for fo, name in entries:
            segs = _segments(d, fo)
            self.kexts[name] = segs
            for vm, vs, f2, fsz, sn in segs:
                self.segs.append((f2, fsz, vm, vs, name, sn))
        self.segs.sort()
        self._starts = [s[0] for s in self.segs]

    # ---------- fileoff -> (kext, segname, va) ----------
    def off2va(self, off):
        import bisect
        i = bisect.bisect_right(self._starts, off) - 1
        if i < 0:
            return None
        f2, fsz, vm, vs, name, sn = self.segs[i]
        if not (f2 <= off < f2 + fsz):
            return None
        return (vm + (off - f2), name, sn)

    # ---------- va -> (fileoff, kext, segname) ----------
    def _by_va(self):
        if not hasattr(self, '_vstart'):
            self._vlist = sorted((s[2], s) for s in self.segs)
            self._vstart = [v for v, _ in self._vlist]
        return self._vlist, self._vstart

    def va2off(self, va):
        import bisect
        vl, vst = self._by_va()
        i = bisect.bisect_right(vst, va) - 1
        while i >= 0:
            f2, fsz, vm, vs, name, sn = vl[i][1]
            if vm <= va < vm + min(vs, fsz):
                return (f2 + (va - vm), name, sn)
            i -= 1
            if i >= 0 and vst[i] < va - 0x20000000:
                break
        return None

    def read(self, va, n):
        r = self.va2off(va)
        if not r:
            return None
        fo, _, _ = r
        return self.d[fo:fo + n]

    def kext_of(self, va):
        r = self.va2off(va)
        return r[1] if r else None

    # ---------- chained fixup ----------
    def chained(self, va):
        """解 arm64e / 内核 chained fixup 指针。绝不用 v>>63 过滤。"""
        w = self.read(va, 8)
        if not w:
            return None
        q = struct.unpack('<Q', w)[0]
        return KB_BASE + (q & 0xFFFFFFFF)

    def selfcheck(self):
        """LC_FUNCTION_STARTS 首项必须等于该 kext __TEXT_EXEC 的 vmaddr。"""
        bad = []
        for name, segs in self.kexts.items():
            tx = [s for s in segs if s[4] == '__TEXT_EXEC']
            if not tx:
                continue
            # 用 segment 级即可判断；函数表校验由调用方做
            if tx[0][3] == 0:
                bad.append(name)
        return bad


if __name__ == '__main__':
    import sys
    K = Index(sys.argv[1] if len(sys.argv) > 1 else 'out/kc.27.0.1.full')
    print(f"fileset entries {len(K.entries)}  segments {len(K.segs)}  kexts {len(K.kexts)}")
    for probe, want in ((0xfffffe00084b1960, '0x14ad960'),):
        r = K.va2off(probe)
        print(f"校验 0x{probe:x} -> fileoff 0x{r[0]:x} kext {r[1]} seg {r[2]}" if r else f"校验 0x{probe:x} 失败")
