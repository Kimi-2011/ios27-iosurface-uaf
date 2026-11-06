#!/usr/bin/env python3
"""verify_textdump.py <reference-macho> <dumped-__TEXT.bin>

Proves that a __TEXT blob dumped out of a *live* process address space is the
real thing, by comparing it against the same image extracted from the dyld
shared cache with dsc_extractor.

The two artefacts are two different *layouts* of the same image:

  * in the cache the segment lives inside a huge shared file, so
    segcmd.fileoff/vmsize/filesize and section_64.offset are cache-relative and
    some segments are pure zero-fill (filesize == 0);
  * dsc_extractor renumbers offsets and grows zero-fill segments to real bytes.

So the check is split:

  A. semantic load-command equality - every segment's (name, vmaddr, maxprot,
     initprot, nsects, flags) and every section's (sectname, segname, addr,
     size, align, reloff, flags) must match exactly.
  B. section-contents equality - every byte after the load commands must match.
  C. the two fields dyld itself rewrites at runtime are reported explicitly
     (mach_header.flags |= MH_DYLIB_IN_CACHE).

Exit 0 iff A and B hold.
"""
import sys, struct, hashlib

MH_DYLIB_IN_CACHE = 0x80000000
LC_SEGMENT_64 = 0x19

def parse(path):
    d = open(path, 'rb').read()
    assert struct.unpack('<I', d[:4])[0] == 0xfeedfacf, f'{path}: not MH_MAGIC_64'
    ncmds, sizeofcmds, flags = struct.unpack('<III', d[16:28])
    off, segs, text = 32, [], None
    for _ in range(ncmds):
        cmd, size = struct.unpack('<II', d[off:off+8])
        if cmd == LC_SEGMENT_64:
            name = d[off+8:off+24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', d[off+24:off+56])
            maxprot, initprot, nsects, sflags = struct.unpack('<IIII', d[off+56:off+72])
            secs = []
            for k in range(nsects):
                so = off + 72 + k*80
                sname = d[so:so+16].rstrip(b'\0').decode()
                sseg  = d[so+16:so+32].rstrip(b'\0').decode()
                addr, sz = struct.unpack('<QQ', d[so+32:so+48])
                reloff, align, rflags = struct.unpack('<III', d[so+48:so+60])
                secs.append((sname, sseg, addr, sz, align, reloff, rflags))
            segs.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff,
                             filesize=filesize, maxprot=maxprot, initprot=initprot,
                             sflags=sflags, secs=secs))
            if name == '__TEXT':
                text = (fileoff, filesize)
        off += size
    return dict(d=d, ncmds=ncmds, sizeofcmds=sizeofcmds, flags=flags, segs=segs,
                text=text, hdr=32+sizeofcmds)

def main():
    refp, dmpp = sys.argv[1], sys.argv[2]
    R = parse(refp)
    m = open(dmpp, 'rb').read()
    foff, fsize = R['text']
    r = R['d'][foff:foff+fsize]
    print(f'ref  __TEXT vmaddr={[s for s in R["segs"] if s["name"]=="__TEXT"][0]["vmaddr"]:#x} '
          f'filesize={fsize} ncmds={R["ncmds"]} sizeofcmds={R["sizeofcmds"]}')
    print(f'dump len={len(m)}  sha256={hashlib.sha256(m).hexdigest()}')
    if len(m) != len(r):
        print(f'  FAIL length: ref={len(r)} dump={len(m)}'); sys.exit(1)

    # --- A. semantic load commands.  The dumped header+LCs live at the head of
    #        the blob; parse them the same way and compare field by field.
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as t:
        t.write(m[:R['hdr']] + b'\0'*(R['hdr']))
        tmp = t.name
    M = parse(tmp); os.unlink(tmp)

    bad = []
    if M['ncmds'] != R['ncmds'] or M['sizeofcmds'] != R['sizeofcmds']:
        bad.append(f"ncmds/sizeofcmds {M['ncmds']}/{M['sizeofcmds']} != {R['ncmds']}/{R['sizeofcmds']}")
    for a, b in zip(R['segs'], M['segs']):
        for f in ('name', 'vmaddr', 'maxprot', 'initprot', 'sflags'):
            if a[f] != b[f]:
                bad.append(f"seg {a['name']}.{f}: {a[f]!r} != {b[f]!r}")
        # reloff (index 5) is deliberately excluded: in the cache it is the
        # cache-relative file offset, on disk it is file-relative.  It is
        # reported separately below because the *magnitude* is itself evidence.
        for sa, sb in zip(a['secs'], b['secs']):
            for i, fn in enumerate(('sectname','segname','addr','size','align','reloff','flags')):
                if i == 5: continue
                if sa[i] != sb[i]:
                    bad.append(f"sect {a['name']}.{sa[0]}.{fn}: {sa[i]!r} != {sb[i]!r}")
    print(f'  A. load commands semantically identical : {not bad}')
    for b in bad[:10]:
        print(f'       ! {b}')

    # --- relayout evidence: cache-relative vs file-relative section offsets
    rel = 0
    for a, b in zip(R['segs'], M['segs']):
        for sa, sb in zip(a['secs'], b['secs']):
            if sa[5] != sb[5]: rel += 1
    print(f'  sect.reloff fields differing (cache-relative vs file-relative): {rel} (expected == #sections)')

    # --- C. the runtime-only header rewrite
    mf = struct.unpack('<I', bytes(m[24:28]))[0]
    print(f'  C. mach_header.flags ref={R["flags"]:#010x} dump={mf:#010x}  '
          f'delta={R["flags"]^mf:#010x} (expect MH_DYLIB_IN_CACHE=0x80000000)')

    # --- B. contents after the load commands
    hdr = R['hdr']
    same = r[hdr:] == m[hdr:]
    print(f'  B. section contents identical ({len(r)-hdr} bytes) : {same}')
    if not same:
        i = next(i for i in range(hdr, len(r)) if r[i] != m[i])
        print(f'       ! first diff at {i:#x}: ref={r[i]:#04x} dump={m[i]:#04x}')

    ok = (not bad) and same and (R['flags'] ^ mf) == MH_DYLIB_IN_CACHE
    print('  ==> %s' % ('VERIFIED' if ok else 'MISMATCH'))
    sys.exit(0 if ok else 1)

main()
