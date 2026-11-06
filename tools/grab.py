#!/usr/bin/env python3
"""grab.py <url> <start> <size> <out> [threads] — 带断点续传的分段下载。"""
import sys, os, threading, urllib.request, time, json

def worker(url, base, seg_off, seg_len, path, log):
    done=os.path.getsize(path) if os.path.exists(path) else 0
    while done < seg_len:
        a=base+seg_off+done; b=base+seg_off+seg_len-1
        req=urllib.request.Request(url, headers={'Range':f'bytes={a}-{b}','User-Agent':'curl/8'})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                code=r.getcode()
                if code not in (200,206): raise RuntimeError(f'HTTP {code}')
                with open(path,'ab') as f:
                    while True:
                        chunk=r.read(1<<20)
                        if not chunk: break
                        f.write(chunk); done+=len(chunk)
        except Exception as e:
            log.append(str(e)[:60]); time.sleep(2)

def main():
    url,start,size,out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    n=int(sys.argv[5]) if len(sys.argv)>5 else 32
    d=out+'.segs'; os.makedirs(d, exist_ok=True)
    seg=(size+n-1)//n
    logs=[]; ths=[]
    for i in range(n):
        off=i*seg; ln=min(seg, size-off)
        t=threading.Thread(target=worker, args=(url,start,off,ln,os.path.join(d,f'{i:04d}'),logs), daemon=True)
        t.start(); ths.append(t)
    t0=time.time()
    while any(t.is_alive() for t in ths):
        time.sleep(15)
        got=sum(os.path.getsize(os.path.join(d,f)) for f in os.listdir(d) if not f.endswith('.x'))
        el=time.time()-t0
        print(f"{got/1024**2:8.0f}MB / {size/1024**2:8.0f}MB  {got*100//size:3d}%  {got/1024**2/el:5.1f}MB/s", flush=True)
        if got>=size: break
    # 合并
    with open(out,'wb') as o:
        for i in range(n):
            p=os.path.join(d,f'{i:04d}')
            if os.path.exists(p):
                with open(p,'rb') as f: o.write(f.read())
    g=os.path.getsize(out)
    print(f"DONE {out} {g}/{size} {'OK' if g==size else 'BAD'}", flush=True)

main()
