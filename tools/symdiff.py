#!/usr/bin/env python3
"""symdiff.py <dirA> <dirB> [--top N]

Diffs two dscdump output directories at *function* granularity, keyed by
symbol name (so it is immune to address/slide/size drift).

For each <image>.symbols.txt it reads the (address -> name) map produced by the
on-device dump, and for each <image>.FUNCSTARTS.bin it decodes the ULEB128
function boundaries that dyld keeps in __LINKEDIT.  Joining the two gives
(name -> function byte size).  Two builds are then compared:

  added     - symbol only in B          (new/renamed code)
  removed   - symbol only in A          (deleted/renamed code)
  size-changed - same name, different machine-code length  <- patch candidates
  same-size - unchanged metric

This mirrors the kernelcache normalised-semantic diff, but for userspace.
"""
import sys, os, glob, struct, collections

def load_symbols(path):
    out = []
    for line in open(path):
        p = line.split(None, 3)
        if len(p) < 4: continue
        out.append((int(p[0], 16), p[3].strip()))
    return out

def load_funcstarts(path):
    d = open(path, 'rb').read()
    addrs, cur, i = [], 0, 0
    while i < len(d) and d[i] != 0:
        shift = val = 0
        while i < len(d) and d[i] & 0x80:
            val |= (d[i] & 0x7f) << shift; shift += 7; i += 1
        if i >= len(d): break
        val |= (d[i] & 0x7f) << shift; i += 1
        cur += val
        addrs.append(cur)
    return addrs

def text_vmaddrs(d):
    """base name -> __TEXT vmaddr, from the manifest the probe writes."""
    m = {}
    p = os.path.join(d, 'manifest.json')
    if not os.path.exists(p):
        return m
    import json
    try:
        j = json.load(open(p))
    except Exception:
        return m
    for e in j.get('images', []):
        base = os.path.basename(e.get('path', ''))
        # manifest records the *slid* address the process saw; nlist n_value and
        # the FUNCSTARTS deltas are both unslid, so take the slide back out.
        try: slide = int(e.get('slide', '0x0'), 16)
        except Exception: slide = 0
        for sg in e.get('segments', []):
            if sg.get('seg') == '__TEXT':
                try: m[base] = int(sg['vmaddr'], 16) - slide
                except Exception: pass
    return m

def func_sizes(symfile, fsfile, text_va=0):
    """name -> machine-code size.

    FUNCSTARTS stores ULEB128 deltas from __TEXT.vmaddr; adding text_va turns
    them into the same unslid coordinate space as nlist.n_value.  A symbol whose
    address is an exact function start gets the distance to the next start; data
    symbols and symbols that are not function boundaries are dropped.
    """
    syms = load_symbols(symfile)
    starts = sorted(set(text_va + x for x in load_funcstarts(fsfile)))
    if not starts:
        return {}
    pos = {a: i for i, a in enumerate(starts)}
    out = {}
    for addr, name in syms:
        i = pos.get(addr)
        if i is None or i + 1 >= len(starts):
            continue
        out[name] = starts[i+1] - starts[i]
    return out

def size_sequence(fsfile):
    """Ordered list of function sizes from FUNCSTARTS alone.

    Needed on the device route, where local symbol names come back as
    "<redacted>": only exported functions keep a name, so name-keyed diffing
    covers a few hundred of ~20k functions.  The size sequence is
    name-independent, so we align the two builds with difflib instead."""
    starts = load_funcstarts(fsfile)
    if not starts: return []
    starts = sorted(set(starts))
    return [starts[i+1]-starts[i] for i in range(len(starts)-1)]

def ordinal_diff(fa, fb):
    """Align two function-size sequences; unmatched runs are the deltas."""
    import difflib
    sm = difflib.SequenceMatcher(None, fa, fb, autojunk=False)
    same = ins = dele = repl = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal': same += (i2-i1)
        elif tag == 'insert': ins += (j2-j1)
        elif tag == 'delete': dele += (i2-i1)
        else: repl += max(i2-i1, j2-j1)
    return dict(a=len(fa), b=len(fb), same=same, inserted=ins, deleted=dele, replaced=repl)

def main():
    a, b = sys.argv[1], sys.argv[2]
    top = 15
    if '--top' in sys.argv: top = int(sys.argv[sys.argv.index('--top')+1])
    def index(d):
        m = {}
        for p in glob.glob(os.path.join(d, '*.symbols.txt')):
            stem = os.path.basename(p)[:-len('.symbols.txt')]     # e.g. ImageIO.179
            base = stem.rsplit('.', 1)[0]                          # e.g. ImageIO
            m.setdefault(base, stem)
        return m
    tva, tvb = text_vmaddrs(a), text_vmaddrs(b)
    ia, ib = index(a), index(b)
    imgs = sorted(set(ia) | set(ib))
    ordinal = '--ordinal' in sys.argv
    grand = collections.Counter()
    for img in imgs:
        fa = [os.path.join(a, ia[img] + '.symbols.txt')] if img in ia else []
        fb = [os.path.join(b, ib[img] + '.symbols.txt')] if img in ib else []
        if not fa or not fb:
            print(f'{img:<24} only in {"B" if fa else "A"}'); continue
        ga = [os.path.join(a, ia[img] + '.FUNCSTARTS.bin')] if os.path.exists(os.path.join(a, ia[img]+'.FUNCSTARTS.bin')) else []
        gb = [os.path.join(b, ib[img] + '.FUNCSTARTS.bin')] if os.path.exists(os.path.join(b, ib[img]+'.FUNCSTARTS.bin')) else []
        va = tva.get(img, 0); vb = tvb.get(img, 0)
        sa = func_sizes(fa[0], ga[0], va) if ga else {n: 0 for _, n in load_symbols(fa[0])}
        sb = func_sizes(fb[0], gb[0], vb) if gb else {n: 0 for _, n in load_symbols(fb[0])}
        if ordinal:
            qa = glob.glob(os.path.join(a, ia[img] + '.FUNCSTARTS.bin')) if img in ia else []
            qb = glob.glob(os.path.join(b, ib[img] + '.FUNCSTARTS.bin')) if img in ib else []
            if not qa or not qb:
                print(f'{img:<24} (ordinal mode needs FUNCSTARTS on both sides)'); continue
            d = ordinal_diff(size_sequence(qa[0]), size_sequence(qb[0]))
            print(f'{img:<24} A={d["a"]:>7} B={d["b"]:>7} aligned={d["same"]:>7} '
                  f'inserted={d["inserted"]:>6} deleted={d["deleted"]:>6} replaced={d["replaced"]:>6} '
                  f'({d["replaced"]/max(1,d["same"]+d["replaced"])*100:.1f}% size-changed)')
            grand['changed'] += d['replaced']; grand['common'] += d['same']
            continue
        na, nb = set(sa), set(sb)
        added, removed = nb - na, na - nb
        common = na & nb
        changed = [n for n in common if sa[n] != sb[n]]
        print(f'{img:<24} A={len(na):>7} B={len(nb):>7} common={len(common):>7} '
              f'added={len(added):>6} removed={len(removed):>6} size-changed={len(changed):>7} '
              f'({len(changed)/max(1,len(common))*100:.1f}%)')
        grand['added'] += len(added); grand['removed'] += len(removed)
        grand['changed'] += len(changed); grand['common'] += len(common)
    print(f'\nTOTAL common={grand["common"]} added={grand["added"]} '
          f'removed={grand["removed"]} size-changed={grand["changed"]}')

main()
