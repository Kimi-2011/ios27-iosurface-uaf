#!/usr/bin/env python3
"""aea_unlock.py - decrypt an Apple AEA (`.dmg.aea` / `*.aea`) container offline.

Apple's AEA containers ship their own key-provenance metadata in the archive
prologue.  For the "symmetric" profile used on iOS system volumes that means:

  com.apple.wkms.fcs-response : {"enc-request": <65B P-256 point>, "wrapped-key": <48B>}
  com.apple.wkms.fcs-key-url  : https://wkms-public.apple.com/fcs-keys/<id>
      where <id> == base64url(sha256(uncompressed P-256 public key))

The URL is an unauthenticated public lookup that returns the PEM of the P-256
private key it is addressed by.  The wrapped key is opened with HPKE
(RFC 9180, P256_SHA256_AES_GCM_256, empty info) using that private key as the
recipient key and `enc-request` as the encapsulated key.  The 32-byte result is
the symmetric AES key AEA itself wants (`aea decrypt -key-value hex:<key>`).

usage:
  aea_unlock.py <file.aea> [-o out.dmg] [--key-only] [--force]
  aea_unlock.py --identify <file.aea>

Everything happens offline except one GET to the CDN for the private key.
"""
import argparse, base64, json, os, re, subprocess, sys, hashlib, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
HPKE = os.path.join(HERE, 'aea', 'hpke_open')

def aea_id(path):
    r = subprocess.run(['aea', 'id', '-i', path, '-v'], capture_output=True, text=True)
    txt = r.stdout + r.stderr
    prof = re.search(r'profile:\s*(\S+)', txt)
    return (prof.group(1) if prof else None), txt

def prologue(path, n=65536):
    with open(path, 'rb') as f:
        return f.read(n)

def find_fcs(blob):
    m = re.search(rb'\{"enc-request":\s*"[^"]+",\s*"wrapped-key":\s*"[^"]+"\}', blob)
    if not m:
        m = re.search(rb'\{"wrapped-key":\s*"[^"]+",\s*"enc-request":\s*"[^"]+"\}', blob)
    return json.loads(m.group(0).decode()) if m else None

def find_key_url(blob):
    m = re.search(rb'https://wkms-public\.apple\.com/fcs-keys/[A-Za-z0-9_\-+/]+=*', blob)
    return m.group(0).decode() if m else None

def fetch_pem(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'aea_unlock/1.0'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

def unwrap(pem_path, enc_b64, wrapped_b64):
    r = subprocess.run([HPKE, pem_path, enc_b64, wrapped_b64], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise SystemExit(f'HPKE unwrap failed: {r.stderr.strip()[:200]}')
    return r.stdout.strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file')
    ap.add_argument('-o', '--out')
    ap.add_argument('--key-only', action='store_true')
    ap.add_argument('--identify', action='store_true')
    ap.add_argument('--force', action='store_true')
    a = ap.parse_args()

    prof, idtxt = aea_id(a.file)
    if a.identify:
        print(idtxt); return
    blob = prologue(a.file)
    fcs = find_fcs(blob); url = find_key_url(blob)
    if not fcs or not url:
        print(f'profile={prof}\nno WKMS fcs metadata in prologue -> cannot auto-unlock', file=sys.stderr)
        sys.exit(3)
    print(f'profile      : {prof}')
    print(f'fcs-key-url  : {url}')
    pem = fetch_pem(url)
    pem_path = a.file + '.fcs-key.pem'
    if os.path.exists(pem_path) and not a.force:
        pass
    open(pem_path, 'wb').write(pem)
    # sanity: the URL id must equal base64url(sha256(pubkey of the returned PEM)
    d = subprocess.run(['openssl', 'pkey', '-in', pem_path, '-pubout', '-outform', 'DER'],
                       capture_output=True).stdout
    pub = d[-65:]
    want = base64.urlsafe_b64encode(hashlib.sha256(pub).digest()).decode()
    got = url.rsplit('/', 1)[-1]
    print(f'key id check : {"OK" if want == got else "MISMATCH"} ({got})')
    key = unwrap(pem_path, fcs['enc-request'], fcs['wrapped-key'])
    print(f'symmetric key: {key}')
    if a.key_only:
        print(key); return
    out = a.out or re.sub(r'\.aea$', '', a.file)
    print(f'decrypting -> {out}')
    r = subprocess.run(['aea', 'decrypt', '-i', a.file, '-o', out,
                        '-key-value', f'hex:{key}'])
    if r.returncode != 0:
        sys.exit(r.returncode)
    print(subprocess.run(['file', out], capture_output=True, text=True).stdout.strip())
    print('done')

main()
