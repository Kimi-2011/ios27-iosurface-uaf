"""Function-level kernelcache diff (arm64, fileset-aware).

Release kernelcaches are stripped, so we do not diff symbols. We:
  1. split the fileset into kexts (LC_FILESET_ENTRY)
  2. read LC_FUNCTION_STARTS to get function boundaries
  3. disassemble each function with capstone and hash a *normalized* form
     (mnemonic + operand shape; addresses collapsed to <A>)
  4. report per-kext: changed / added / removed function counts

Usage:
  python3 kdiff.py A.kcache B.kcache [--top 15] [--kext NAME] [--json OUT]
"""
import argparse
import hashlib
import json
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

LC_FILESET_ENTRY = 0x80000035
LC_FUNCTION_STARTS = 0x26
LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False


def uleb128(buf, i):
    val = shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, i


def load(path):
    with open(path, "rb") as fh:
        return fh.read()


def slices(data, base=0):
    """Yield (fileoff, size, name) for each fileset entry."""
    magic = struct.unpack_from("<I", data, base)[0]
    if magic != MH_MAGIC_64:
        raise SystemExit(f"{base:#x}: not Mach-O 64")
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    off = base + 32
    ents = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_FILESET_ENTRY:
            fileoff = struct.unpack_from("<Q", data, off + 16)[0]
            id_off = struct.unpack_from("<I", data, off + 24)[0]
            name = data[off + id_off: off + cmdsize].split(b"\x00")[0].decode("ascii", "replace")
            ents.append((fileoff, name))
        off += cmdsize
    ents.sort()
    out = []
    for i, (fo, name) in enumerate(ents):
        end = ents[i + 1][0] if i + 1 < len(ents) else len(data)
        out.append((fo, end - fo, name))
    return out


def macho_info(data, base):
    """Return (text_off, text_vmaddr, function_offsets[])."""
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    off = base + 32
    text_off = text_vmaddr = None
    fn_data = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64 and off + 72 <= len(data):
            segname = data[off + 8: off + 24].rstrip(b"\x00").decode("ascii", "replace")
            vmaddr, _vmsize, fileoff = struct.unpack_from("<QQQ", data, off + 24)
            if segname == "__TEXT":
                text_off, text_vmaddr = fileoff, vmaddr
        elif cmd == LC_FUNCTION_STARTS and off + 16 <= len(data):
            fn_data = struct.unpack_from("<II", data, off + 8)
        off += cmdsize

    fns = []
    if fn_data and fn_data[0] and fn_data[1]:
        # dataoff is absolute within the outer fileset file
        blob = data[fn_data[0]: fn_data[0] + fn_data[1]]
        i = 0
        cur = 0
        while i < len(blob):
            delta, i = uleb128(blob, i)
            if delta == 0:
                break
            cur += delta
            fns.append(cur)
    return text_off, text_vmaddr, fns


ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")

NUM_RE = re.compile(r"#?-?0x[0-9a-fA-F]+|#?-?\d+")

def _norm(opstr):
    # shape mode: drop every immediate. Layout changes split addresses into
    # movz/movk chunks, so keeping small constants re-introduces noise.
    return NUM_RE.sub("<I>", opstr)

def func_hash(code):
    if not code:
        return "empty"
    h = hashlib.sha1()
    for ins in md.disasm(code, 0):
        h.update(ins.mnemonic.encode())
        h.update(b" ")
        h.update(_norm(ins.op_str).encode())
        h.update(b";")
    return h.hexdigest()[:16]


def fingerprint(path, only=None):
    data = load(path)
    out = {}
    for fo, size, name in slices(data):
        if only and only not in name:
            continue
        try:
            text_off, _vm, fns = macho_info(data, fo)
        except Exception:
            continue
        if not fns or text_off is None:
            out[name] = {"functions": 0, "hashes": [], "size": size}
            continue
        hashes = []
        base = fo          # function-start deltas are offsets from the kext image base
        for i, fn in enumerate(fns):
            start = base + fn
            end = fo + fns[i + 1] if i + 1 < len(fns) else min(len(data), fo + size)
            if end <= start or end - start > 0x8000:
                continue
            hashes.append(func_hash(data[start:end]))
        out[name] = {"functions": len(hashes), "hashes": hashes, "size": size}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--kext")
    ap.add_argument("--json")
    a = ap.parse_args()

    A, B = fingerprint(a.a, a.kext), fingerprint(a.b, a.kext)
    only_a = set(A) - set(B)
    only_b = set(B) - set(A)
    rows = []
    for name in set(A) & set(B):
        ha, hb = A[name]["hashes"], B[name]["hashes"]
        sa, sb = set(ha), set(hb)
        changed = len([x for x in ha if x not in sb])
        new = len([x for x in hb if x not in sa])
        rows.append({"kext": name, "changed": changed, "new": new,
                     "functions": len(ha), "size_delta": B[name]["size"] - A[name]["size"]})
    rows.sort(key=lambda r: -(r["changed"] + r["new"]))

    print(f"kexts A={len(A)} B={len(B)}  onlyA={len(only_a)} onlyB={len(only_b)}\n")
    print(f"{'chg':>5} {'new':>5} {'funcs':>6} {'dSize':>9}  kext")
    for r in rows[: a.top]:
        print(f"{r['changed']:5} {r['new']:5} {r['functions']:6} {r['size_delta']:9}  {r['kext']}")
    if only_b:
        print("\nnew kexts: " + ", ".join(sorted(only_b)[:8]))
    if only_a:
        print("removed kexts: " + ", ".join(sorted(only_a)[:8]))

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rows, fh, indent=1)
        print(f"\njson -> {a.json}")


if __name__ == "__main__":
    main()
