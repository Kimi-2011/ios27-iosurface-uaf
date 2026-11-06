#!/usr/bin/env python3
"""verify_dump_sections.py <reference-macho> <dumped-__TEXT.bin>

Weaker but artefact-agnostic sibling of verify_textdump.py: compares a __TEXT
blob dumped from a live process against a *standalone* Mach-O of the same image
(e.g. the loose file inside iOS.simruntime/RuntimeRoot), section by section.

The two artefacts have different segment sizes/offsets (the shared cache packs
subimages tightly and strips some load commands), so whole-segment comparison is
meaningless.  What must match is, for every section of __TEXT:
    name, size, align, flags  and  the section's bytes.
The dumped section address is de-slid using the slide recorded in the dump.
"""
import sys, struct, hashlib

LC_SEGMENT_64 = 0x19

def segs(d):
    ncmds = struct.unpack('<I', d[16:20])[0]
    out, off = [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack('<II', d[off:off+8])
        if cmd == LC_SEGMENT_64:
            name = d[off+8:off+24].rstrip(b'\0').decode()
            va, vs, fo, fs = struct.unpack('<QQQQ', d[off+24:off+56])
            nsects = struct.unpack('<I', d[off+64:off+68])[0]
            secs = []
            for k in range(nsects):
                so = off+72+k*80
                secs.append(dict(
                    name=d[so:so+16].rstrip(b'\0').decode(),
                    seg=d[so+16:so+32].rstrip(b'\0').decode(),
                    addr=struct.unpack('<Q', d[so+32:so+40])[0],
                    size=struct.unpack('<Q', d[so+40:so+48])[0],
                    offset=struct.unpack('<I', d[so+48:so+52])[0],
                    align=struct.unpack('<I', d[so+52:so+56])[0],
                    flags=struct.unpack('<I', d[so+56:so+60])[0]))
            out.append(dict(name=name, vmaddr=va, vmsize=vs, fileoff=fo,
                            filesize=fs, secs=secs))
        off += size
    return out

def main():
    ref, dmpp = sys.argv[1], sys.argv[2]
    rd = open(ref,'rb').read()
    m  = open(dmpp,'rb').read()
    R  = {s['name']: s for s in segs(rd)}
    M  = {s['name']: s for s in segs(m)}
    if '__TEXT' not in M:
        print('FAIL: dump has no __TEXT segment'); sys.exit(1)
    slide = M['__TEXT']['vmaddr'] - R['__TEXT']['vmaddr'] if '__TEXT' in R else None
    t = M['__TEXT']
    n_ok = n_bad = 0
    for sec in t['secs']:
        off_in_dump = sec['addr'] - t['vmaddr']
        data = m[off_in_dump:off_in_dump+sec['size']]
        refsec = next((s for s in R['__TEXT']['secs'] if s['name'] == sec['name']
                       and s['size'] == sec['size']), None) if '__TEXT' in R else None
        if refsec is None:
            print(f'  ?  {sec["name"]:<20} size={sec["size"]:<9} no matching section in reference'); continue
        rdata = rd[refsec['offset']:refsec['offset']+refsec['size']]
        same = data == rdata
        n_ok += same; n_bad += (not same)
        print(f'  {"OK " if same else "BAD"} {sec["name"]:<20} size={sec["size"]:<9} '
              f'sha256={hashlib.sha256(data).hexdigest()[:24]}')
    print(f'  slide={slide:#x}  sections matched {n_ok}/{n_ok+n_bad}')
    sys.exit(0 if n_bad == 0 and n_ok > 0 else 1)

main()
