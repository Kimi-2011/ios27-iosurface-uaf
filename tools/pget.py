#!/usr/bin/env python3
"""pget.py - parallel segmented HTTP range downloader (no deps).
usage:
  pget.py URL OUTPATH [--threads 32] [--chunk-mb 64]     # download / resume
  pget.py URL OUTPATH --verify-samples 12                # verify a finished file

Resumable: keeps OUTPATH.part + OUTPATH.state (json of completed chunk idx)
and OUTPATH.coverage (human-readable list of completed byte ranges).

SAFETY: the .part file is created at full logical length (sparse) so that
chunks can be written out of order.  That means **the file size is NOT a
completion signal** - an in-flight or abandoned .part reads as zeros past the
download frontier.  Always consult OUTPATH.state / OUTPATH.coverage, or run
--verify-samples, before using the file.  Never hand a .part to a parser."""
import sys, os, json, threading, time, urllib.request, argparse

def head_size(url):
    req = urllib.request.Request(url, method='HEAD')
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers['Content-Length']), r.headers.get('Accept-Ranges','')

def fetch(url, start, length):
    req = urllib.request.Request(url, headers={'Range': f'bytes={start+OFFSET}-{start+OFFSET+length-1}'})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()

def verify(url, path, nsamples):
    """Post-download check: compare random windows against the origin.
    This is what a consumer must run before trusting the file."""
    import random
    sz = os.path.getsize(path)
    random.seed()
    bad = 0
    for k in range(nsamples):
        off = random.randrange(0, max(1, sz - 65536))
        n = min(65536, sz - off)
        with open(path, 'rb') as f:
            f.seek(off); local = f.read(n)
        remote = fetch(url, off, n, getattr(a, 'url_off', 0) if False else 0)
        ok = local == remote
        if not ok: bad += 1
        print(f"  window {off:>14} ({n} B): {'OK' if ok else 'MISMATCH'}", flush=True)
    print(f"verify: {nsamples-bad}/{nsamples} windows match")
    sys.exit(0 if bad == 0 else 2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('url'); ap.add_argument('out')
    ap.add_argument('--threads', type=int, default=32)
    ap.add_argument('--chunk-mb', type=int, default=64)
    ap.add_argument('--offset', type=int, default=0,
                    help='start byte in the remote resource (range extraction)')
    ap.add_argument('--length', type=int, default=0,
                    help='number of bytes to fetch (0 = to end of resource)')
    ap.add_argument('--verify-samples', type=int, default=0,
                    help='re-fetch this many random 64 KiB windows and byte-compare, then exit')
    a = ap.parse_args()
    if a.verify_samples:
        return verify(a.url, a.out, a.verify_samples)
    total, ar = head_size(a.url)
    print(f"total={total} accept-ranges={ar}", flush=True)
    if a.offset or a.length:
        a.url_off = a.offset
        total = (a.length if a.length else total - a.offset)
        print(f"range mode: remote offset {a.offset}, length {total}", flush=True)
    else:
        a.url_off = 0
    part = a.out + '.part'
    statef = a.out + '.state'
    csz = a.chunk_mb*1024*1024
    n = (total + csz - 1)//csz
    done = set()
    meta = {}
    if os.path.exists(statef):
        raw = json.load(open(statef))
        if isinstance(raw, dict):              # {"chunk": n, "done": [...]}
            meta, done = raw, set(raw.get('done', []))
            if meta.get('chunk') and meta['chunk'] != csz:
                raise SystemExit(f"chunk-size mismatch: state was written with "
                                 f"{meta['chunk']} B chunks, you asked for {csz} B. "
                                 f"Resume with --chunk-mb {meta['chunk']//(1024*1024)} "
                                 f"or delete {statef} and {part} to start over.")
        else:
            done = set(raw)
    if not os.path.exists(part):
        with open(part,'wb') as f:
            f.truncate(total)
    lock = threading.Lock()
    got = [0]
    def save():
        with lock:
            tmp = statef+'.tmp'
            json.dump({'chunk': csz, 'total': total, 'done': sorted(done)}, open(tmp,'w'))
            os.replace(tmp, statef)
    q = [i for i in range(n) if i not in done]
    print(f"chunks={n} remaining={len(q)}", flush=True)
    t0=time.time()
    def worker(wid):
        while True:
            with lock:
                if not q: return
                i = q.pop(0)
            s = i*csz; e = min(total-1, s+csz-1)
            if e < s: 
                with lock: done.add(i)
                continue
            for attempt in range(6):
                try:
                    req = urllib.request.Request(a.url, headers={'Range': f'bytes={s+a.url_off}-{e+a.url_off}'})
                    with urllib.request.urlopen(req, timeout=120) as r:
                        with open(part,'r+b') as f:
                            f.seek(s)
                            left = e-s+1
                            while left>0:
                                b = r.read(min(1<<20, left))
                                if not b: raise IOError('short read')
                                f.write(b); left -= len(b)
                                with lock: got[0]+=len(b)
                    with lock:
                        done.add(i)
                    save()
                    break
                except Exception as ex:
                    if attempt==5:
                        print(f"[w{wid}] chunk {i} FAILED {ex}", flush=True)
                        with lock: q.append(i)
                        return
                    time.sleep(1+attempt)
    ths=[threading.Thread(target=worker,args=(k,),daemon=True) for k in range(a.threads)]
    for t in ths: t.start()
    last=0
    while any(t.is_alive() for t in ths):
        time.sleep(5)
        with lock:
            g=got[0]; d=len(done)
        el=time.time()-t0
        rate=(g-last)/5 if el>5 else 0
        last=g
        pct = (sum(min(csz, total-i*csz) for i in done))/total*100
        print(f"  {pct:5.1f}%  {g/1e9:6.2f} GB  {rate/1e6:6.2f} MB/s  eta={((total*(pct/100)-sum(min(csz,total-i*csz) for i in done))/max(rate,1))/60:6.1f} min", flush=True)
    for t in ths: t.join()
    with lock:
        ok = len(done)==n
    with open(a.out + '.coverage','w') as f:
        f.write(f"total_bytes {total}\nchunk_bytes {csz}\nchunks_done {len(done)}/{n}\n")
        for i in sorted(done):
            f.write(f"  {i*csz} {min(total-1,(i+1)*csz-1)}\n")
    if ok:
        with open(part,'r+b') as f:
            f.flush(); os.fsync(f.fileno())
        os.replace(part, a.out)
        try: os.remove(statef)
        except OSError: pass
        print("COMPLETE", a.out, os.path.getsize(a.out), flush=True)
    else:
        print(f"INCOMPLETE done={len(done)}/{n}", flush=True); sys.exit(2)

if __name__=='__main__':
    main()
