#!/usr/bin/env python3
"""只按 Range 抓取 IPSW(zip) 中指定成员，避免下载整个 12GB。"""
import sys, struct, urllib.request, os

def http(url, rng=None, timeout=120):
    h={'User-Agent':'curl/8'}
    if rng: h['Range']=f'bytes={rng[0]}-{rng[1]}'
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout).read()

def total_size(url):
    h={'User-Agent':'curl/8','Range':'bytes=0-0'}
    r=urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=60)
    cr=r.headers.get('Content-Range','')
    if '/' in cr: return int(cr.split('/')[-1])
    return int(r.headers['Content-Length'])

def parse_cd(url):
    total=total_size(url)
    tail=http(url,(max(0,total-262144), total-1))
    base=total-len(tail)
    ents=[]; i=0
    while True:
        i=tail.find(b'PK\x01\x02', i)
        if i<0: break
        (sig,vm,vn,flag,meth,mt,md,crc,csz,usz,nlen,elen,clen,disk,iattr,eattr,lho)= \
            struct.unpack_from('<IHHHHHHIIIHHHHHII',tail,i)
        name=tail[i+46:i+46+nlen].decode('utf-8','replace')
        extra=tail[i+46+nlen:i+46+nlen+elen]
        # zip64 扩展字段
        j=0; real_usize, real_csize, real_lho = usz, csz, lho
        while j+4 <= len(extra):
            hid, hsz = struct.unpack_from('<HH', extra, j)
            if hid == 1:
                p=j+4
                if usz==0xFFFFFFFF: real_usize=struct.unpack_from('<Q',extra,p)[0]; p+=8
                if csz==0xFFFFFFFF: real_csize=struct.unpack_from('<Q',extra,p)[0]; p+=8
                if lho==0xFFFFFFFF: real_lho=struct.unpack_from('<Q',extra,p)[0]; p+=8
            j += 4+hsz
        ents.append(dict(name=name, method=meth, csize=real_csize, usize=real_usize, lho=real_lho))
        i += 46+nlen+elen+clen
    return total, ents

def fetch_member(url, e, out):
    # 读本地头拿数据起点
    lh=http(url,(e['lho'], e['lho']+29+512))
    if lh[:4]!=b'PK\x03\x04': raise SystemExit(f"本地头异常 {e['name']}")
    nlen, elen = struct.unpack_from('<HH', lh, 26)
    start=e['lho']+30+nlen+elen
    end=start+e['csize']-1
    print(f"  下载 {e['name']}  {e['usize']/1024**3:.2f}GB  区间 {start}-{end}  method={e['method']}")
    req=urllib.request.Request(url, headers={'Range':f'bytes={start}-{end}','User-Agent':'curl/8'})
    with urllib.request.urlopen(req, timeout=300) as r, open(out,'wb') as f:
        while True:
            chunk=r.read(1<<20)
            if not chunk: break
            f.write(chunk)
    got=os.path.getsize(out)
    print(f"  完成 {got/1024**3:.2f}GB (期望 {e['csize']/1024**3:.2f}GB) {'OK' if got==e['csize'] else '不匹配!'}")

if __name__=='__main__':
    url=sys.argv[1]; pats=sys.argv[2].split(','); outdir=sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    total, ents = parse_cd(url)
    print(f"IPSW 总大小 {total/1024**3:.2f}GB，成员 {len(ents)} 个")
    for p in pats:
        for e in ents:
            if e['name']==p or (p in e['name'] and e['name'].count('/')==0):
                fetch_member(url, e, os.path.join(outdir, e['name']))
