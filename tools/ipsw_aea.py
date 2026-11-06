#!/usr/bin/env python3
"""ipsw_aea.py - list / extract / decrypt AEA components straight out of an iOS IPSW.

An IPSW is a plain ZIP whose large members are STORED (method=0), so every
component can be addressed by a byte range and there is no need to download --
or even keep -- the whole 13 GB file.

subcommands
  list    <ipsw|url>                    members with offsets, matched to BuildManifest components
  prolog  <ipsw|url> <component>        fetch just the AEA prologue (~256 KB) and print aea id
  key     <ipsw|url> <component>        prologue -> fcs-key-url -> HPKE -> symmetric key
  extract <ipsw|url> <component> -o F   download that member only (resumable)
  unlock  <ipsw|url> <component> -o F   extract + aea decrypt -> plaintext dmg

<component> is a BuildManifest key ("OS", "Cryptex1,SystemOS", "Ap,ExclaveOS")
or a member name / prefix.
"""
import argparse, json, os, plistlib, struct, subprocess, sys, urllib.request, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

def http_range(url, start, length):
    req = urllib.request.Request(url, headers={'Range': f'bytes={start}-{start+length-1}'})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()

def head_size(url):
    req = urllib.request.Request(url, method='HEAD')
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers['Content-Length'])

def is_url(x):
    return x.startswith('http://') or x.startswith('https://')

def read_at(src, off, length):
    if is_url(src):
        return http_range(src, off, length)
    with open(src, 'rb') as f:
        f.seek(off)
        return f.read(length)

def size_of(src):
    return head_size(src) if is_url(src) else os.path.getsize(src)

def zip_members(src):
    total = size_of(src)
    tailn = min(1048576, total)
    tail = read_at(src, total - tailn, tailn)
    base = total - tailn
    j = tail.rfind(b'PK\x06\x07')          # ZIP64 EOCD locator
    if j < 0:
        i = tail.rfind(b'PK\x05\x06')
        _, _, _, _, nrec, cdsize, cdoff, _ = struct.unpack('<IHHHHIIH', tail[i:i+22])
    else:
        _, _, e64off, _ = struct.unpack('<IIQI', tail[j:j+20])
        k = e64off - base
        if k < 0:
            raise SystemExit('zip64 EOCD outside the tail window; increase tailn')
        _, _, _, _, _, _, _, nrec, cdsize, cdoff = struct.unpack('<IQHHIIQQQQ', tail[k:k+56])
    if not (base <= cdoff < total):
        cd = read_at(src, cdoff, cdsize)
    else:
        cd = tail[cdoff-base:cdoff-base+cdsize]
    recs, k = [], 0
    while k < len(cd)-4 and cd[k:k+4] == b'PK\x01\x02':
        (_, _, _, _, meth, _, _, crc, csz, usz, nlen, elen, clen, _, _, _, off) = \
            struct.unpack('<IHHHHHHIIIHHHHHII', cd[k:k+46])
        name = cd[k+46:k+46+nlen].decode('utf-8', 'replace')
        extra = cd[k+46+nlen:k+46+nlen+elen]
        p = 0
        while p+4 <= len(extra):
            hid, hsz = struct.unpack('<HH', extra[p:p+4]); body = extra[p+4:p+4+hsz]
            if hid == 1:
                q = 0
                if usz == 0xFFFFFFFF: usz = struct.unpack('<Q', body[q:q+8])[0]; q += 8
                if csz == 0xFFFFFFFF: csz = struct.unpack('<Q', body[q:q+8])[0]; q += 8
                if off == 0xFFFFFFFF: off = struct.unpack('<Q', body[q:q+8])[0]; q += 8
            p += 4+hsz
        recs.append(dict(name=name, lfh=off, csize=csz, usize=usz, method=meth))
        k += 46+nlen+elen+clen
    return recs, total

def data_off(src, r):
    """Resolve the true payload offset from the local file header (lazy: one
    small range request per member, only for the members we actually touch)."""
    if 'data' in r: return r['data']
    h = read_at(src, r['lfh'], 30)
    _, _, _, _, _, _, _, _, _, nlen, elen = struct.unpack('<IHHHHHIIIHH', h)
    r['data'] = r['lfh'] + 30 + nlen + elen
    return r['data']

def manifest(src, recs):
    m = next((r for r in recs if r['name'] == 'BuildManifest.plist'), None)
    if not m: return {}
    raw = read_at(src, data_off(src, m), m['csize'])
    if m['method'] == 8: raw = zlib.decompress(raw, -15)
    d = plistlib.loads(raw)
    out = {}
    for key, v in d['BuildIdentities'][0]['Manifest'].items():
        p = (v.get('Info') or {}).get('Path')
        if p: out[key] = p
    return out, d.get('ProductBuildVersion'), d.get('ProductVersion')

def resolve(recs, compmap, comp):
    for k, p in compmap.items():
        if k == comp: path = os.path.basename(p)
        elif p == comp or p.endswith('/'+comp): path = os.path.basename(p)
        else: continue
        for r in recs:
            if r['name'] == path: return r, k
    for r in recs:
        if r['name'] == comp or r['name'].startswith(comp): return r, comp
    raise SystemExit(f'component not found: {comp}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['list', 'prolog', 'key', 'extract', 'unlock'])
    ap.add_argument('src')
    ap.add_argument('component', nargs='?')
    ap.add_argument('-o', '--out')
    ap.add_argument('--threads', type=int, default=20)
    ap.add_argument('--chunk-mb', type=int, default=32)
    a = ap.parse_args()

    recs, total = zip_members(a.src)
    compmap, build, ver = manifest(a.src, recs)
    if a.cmd == 'list':
        print(f'{a.src}\n  size {total}  build {build}  version {ver}')
        for r in recs:
            for k, p in compmap.items():
                if os.path.basename(p) == r['name']:
                    print(f"  {k:<24} {r['name']:<28} lfh={r['lfh']:>14} size={r['csize']:>13} method={r['method']}")
        return
    r, key = resolve(recs, compmap, a.component)
    data_off(a.src, r)
    print(f"component {key} -> {r['name']} data_off={r['data']} size={r['csize']}", file=sys.stderr)
    if a.cmd == 'prolog':
        open((a.out or r['name'] + '.head'), 'wb').write(read_at(a.src, r['data'], 262144))
        subprocess.run(['aea', 'id', '-i', a.out or r['name']+'.head', '-v'])
        return
    if a.cmd == 'key':
        p = r['name'] + '.head.aea'
        open(p, 'wb').write(read_at(a.src, r['data'], 262144))
        subprocess.run([sys.executable, os.path.join(HERE, 'aea_unlock.py'), p, '--key-only'])
        return
    out = a.out or r['name']
    if a.cmd == 'extract':
        subprocess.run([sys.executable, os.path.join(HERE, 'pget.py'), a.src, out,
                        '--offset', str(r['data']), '--length', str(r['csize']),
                        '--threads', str(a.threads), '--chunk-mb', str(a.chunk_mb)])
        return
    if a.cmd == 'unlock':
        if not os.path.exists(out):
            subprocess.run([sys.executable, os.path.join(HERE, 'pget.py'), a.src, out,
                            '--offset', str(r['data']), '--length', str(r['csize']),
                            '--threads', str(a.threads), '--chunk-mb', str(a.chunk_mb)], check=True)
        subprocess.run([sys.executable, os.path.join(HERE, 'aea_unlock.py'), out,
                        '-o', (a.out or out) + '.dmg'], check=True)

main()
