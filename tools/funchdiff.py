#!/usr/bin/env python3
"""funchdiff.py <A-macho> <B-macho> [--slice arm64e|arm64] [--show N]

Exact, name-keyed, function-level diff of two Mach-O files.

Unlike a mnemonic-"shape" diff this compares the *bytes* of every function, so it
catches operand-level changes (constants, branch targets, added checks) as well
as size changes.

FUNCTION BOUNDARIES come from LC_FUNCTION_STARTS (survives stripped symbols),
NAMES from LC_SYMTAB; when symbols are absent we fall back to ordinal alignment
(difflib over the size sequence).

Output: per-function verdict (identical / changed N bytes / size delta / added /
removed) sorted by interest.
"""
import sys, struct, hashlib, subprocess, difflib, argparse

MH_EXECUTE=2
def slices(d):
    magic=struct.unpack_from('<I',d,0)[0]
    if magic in (0xcafebabe,0xbebafeca):
        n=struct.unpack_from('>I',d,4)[0]; out={}
        for i in range(n):
            cpu,sub,off,size,align=struct.unpack_from('>iiIII',d,8+i*20)
            if cpu != 0x0100000c: continue
            arch = 'arm64e' if (sub & 0xff) == 2 else 'arm64'
            out.setdefault(arch, (off, size))
        return out,True
    return {'thin':(0,len(d))},False

def parse(d):
    assert struct.unpack_from('<I',d,0)[0]==0xfeedfacf, 'not MH_MAGIC_64'
    ncmds=struct.unpack_from('<I',d,16)[0]
    off=32; segs={}; fnst=None; sym=None
    for _ in range(ncmds):
        cmd,sz=struct.unpack_from('<II',d,off)
        if cmd==0x19:
            nm=d[off+8:off+24].rstrip(b'\0').decode()
            va,vs,fo,fs=struct.unpack_from('<QQQQ',d,off+24)
            segs[nm]=dict(va=va,vmsize=vs,fileoff=fo,filesize=fs)
        elif cmd==0x26: fnst=struct.unpack_from('<II',d,off+8)
        elif cmd==0x2:  sym=struct.unpack_from('<IIII',d,off+8)
        off+=sz
    return segs,fnst,sym

def va2off(segs,va):
    for nm,s in segs.items():
        if s['filesize'] and s['va']<=va<s['va']+s['filesize']:
            return s['fileoff']+(va-s['va'])
    return None

def funcstarts(d,segs,fnst,text_va):
    """Decode LC_FUNCTION_STARTS; the ULEB128 deltas are relative to
    __TEXT.vmaddr, so the returned addresses are absolute vmaddrs."""
    if not fnst: return []
    doff,dsize=fnst              # dataoff is a plain file offset in a real Mach-O
    blob=d[doff:doff+dsize]
    addrs=[];cur=0;i=0
    while i<len(blob) and blob[i]:
        shift=0;val=0
        while i<len(blob) and blob[i]&0x80:
            val|=(blob[i]&0x7f)<<shift; shift+=7; i+=1
        if i>=len(blob): break
        val|=(blob[i]&0x7f)<<shift; i+=1
        cur+=val; addrs.append(text_va+cur)
    return addrs

def symbols(d,sym):
    if not sym: return {}
    symoff,nsyms,stroff,strsize=sym
    out={}
    for k in range(nsyms):
        o=symoff+k*16
        strx,typ,sect,desc,val=struct.unpack_from('<IBBHQ',d,o)
        if not strx or strx>=strsize: continue
        if typ & 0xe0: continue      # skip debug/stab
        e=d.index(b'\0',stroff+strx)
        out.setdefault(val, d[stroff+strx:e].decode('utf-8','replace'))
    return out

def funcs(path, want_slice=None):
    raw=open(path,'rb').read()
    sl,isfat=slices(raw)
    if isfat:
        arch = want_slice if want_slice in sl else ('arm64e' if 'arm64e' in sl else sorted(sl)[0])
        off,size=sl[arch]; d=raw[off:off+size]
    else:
        arch='thin'; d=raw
    segs,fnst,sym=parse(d)
    text_va=segs.get('__TEXT',{}).get('va',0)
    starts=sorted(set(funcstarts(d,segs,fnst,text_va)))
    syms=symbols(d,sym)
    text=segs.get('__TEXT',{})
    res=[]
    for i,a in enumerate(starts):
        b=starts[i+1] if i+1<len(starts) else min(a+4096, text.get('vmsize',a+4096))
        o=va2off(segs,a)
        if o is None: continue
        body=d[o:o+(b-a)]
        res.append(dict(addr=a,size=b-a,name=syms.get(a),sha=hashlib.sha256(body).hexdigest(),body=body))
    return arch,res

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('a'); ap.add_argument('b')
    ap.add_argument('--slice',default=None); ap.add_argument('--show',type=int,default=25)
    ap.add_argument('--bytes',action='store_true', help='show byte offsets that differ')
    a=ap.parse_args()
    archA,fa=funcs(a.a,a.slice); archB,fb=funcs(a.b,a.slice)
    print(f'A {a.a}\n  slice={archA} functions={len(fa)} named={sum(1 for f in fa if f["name"])}')
    print(f'B {a.b}\n  slice={archB} functions={len(fb)} named={sum(1 for f in fb if f["name"])}')
    na={f['name']:f for f in fa if f['name']}
    nb={f['name']:f for f in fb if f['name']}
    if len(na) < max(8, len(fa)//4):
        # production binaries are symbol-stripped: fall back to ordinal pairing
        # (function starts are emitted in address order, so index i <-> index i
        #  is correct whenever the function counts match)
        print('\n[no usable symbols -> ordinal pairing]')
        if len(fa) != len(fb):
            print(f'  function count differs ({len(fa)} vs {len(fb)}); '
                  f'pairing the common prefix and reporting the tail separately')
        n=min(len(fa),len(fb)); changed_i=[]
        for i in range(n):
            if fa[i]['sha']!=fb[i]['sha']: changed_i.append(i)
        print(f'  paired={n} identical={n-len(changed_i)} changed={len(changed_i)}')
        for i in changed_i[:a.show]:
            A,Bf=fa[i],fb[i]
            la,lb=A['body'],Bf['body']; k=0
            while k<min(len(la),len(lb)) and la[k]==lb[k]: k+=1
            print(f'    fn#{i:<4} A@{A["addr"]:#x} {A["size"]:>5}B -> B@{Bf["addr"]:#x} {Bf["size"]:>5}B'
                  f' ({Bf["size"]-A["size"]:+d})  first-diff-byte={k}')
            if a.bytes and k < min(len(la),len(lb)):
                print(f'        A: {la[max(0,k-8):k+16].hex()}')
                print(f'        B: {lb[max(0,k-8):k+16].hex()}')
        if len(fa)!=len(fb):
            print(f'  extra tail A:{len(fa)-n} B:{len(fb)-n} functions')
        return
    same=[n for n in na if n in nb and na[n]['sha']==nb[n]['sha']]
    changed=[n for n in na if n in nb and na[n]['sha']!=nb[n]['sha']]
    added=sorted(set(nb)-set(na)); removed=sorted(set(na)-set(nb))
    print(f'\nidentical={len(same)} changed={len(changed)} added={len(added)} removed={len(removed)}')
    if added: print('ADDED:');   [print('  +',n) for n in added[:a.show]]
    if removed: print('REMOVED:'); [print('  -',n) for n in removed[:a.show]]
    if changed:
        print('\nCHANGED (sorted by |Δsize| then name):')
        for n in sorted(changed, key=lambda x:(-abs(nb[x]['size']-na[x]['size']),x))[:a.show]:
            A,Bf=na[n],nb[x] if False else (na[n],nb[n])
            dsz=Bf['size']-A['size']
            # how many leading bytes are common
            la,lb=A['body'],Bf['body']; k=0
            while k<min(len(la),len(lb)) and la[k]==lb[k]: k+=1
            print(f'  {n:<60} {A["size"]:>6} -> {Bf["size"]:>6} ({dsz:+d})  first-diff-byte={k}')
            if a.bytes:
                print(f'      A[0x{k:x}:]: {la[k:k+16].hex()}')
                print(f'      B[0x{k:x}:]: {lb[k:k+16].hex()}')

main()
