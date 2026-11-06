#!/usr/bin/env python3
"""跨版本函数差分：按解析后的调用目标配对，检测新增的 lock/unlock/retain/release。
用法: cdiff.py <kext短名> [--verbose]
"""
import struct,sys,json,collections
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
KB=0xFFFFFE0007004000
# 已手读确认的桩目标语义（A 方向交付）
SEM={0xabd3390:'lock',0xabd3f78:'unlock',0xb266a30:'retain',0xb264d84:'release'}

def parse(p):
    d=open(p,'rb').read()
    n=struct.unpack_from('<I',d,16)[0]; off=32; segs={}; fs=None
    for _ in range(n):
        cmd,sz=struct.unpack_from('<II',d,off)
        if cmd==0x19:
            nm=d[off+8:off+24].rstrip(b'\0').decode(); segs[nm]=struct.unpack_from('<QQQQ',d,off+24)
        if cmd==0x26: fs=struct.unpack_from('<II',d,off+8)
        off+=sz
    blob=d[fs[0]:fs[0]+fs[1]]; a=[];cur=0;i=0
    while i<len(blob):
        v=0;sh=0
        while True:
            b=blob[i];i+=1;v|=(b&0x7f)<<sh;sh+=7
            if not b&0x80:break
        if v==0:break
        cur+=v;a.append(segs['__TEXT'][0]+cur)
    return d,segs,a

def rd(d,segs,va,n):
    for vm,sz,fo,_ in segs.values():
        if vm<=va<vm+sz: return d[fo+(va-vm):fo+(va-vm)+n]
    return None

def resolve(d,segs,ta):
    """bl 目标 -> 真实语义目标。命中桩则解引用槽；否则返回 ta 本身。"""
    b=rd(d,segs,ta,16)
    if not b or len(b)<16: return ta
    ins=list(md.disasm(b,ta))
    if len(ins)>=4 and ins[0].mnemonic=='adrp' and ins[1].mnemonic=='add' \
       and ins[2].mnemonic=='ldr' and ins[3].mnemonic in('braa','bra'):
        try:
            slot=int(ins[1].op_str.split('#')[1],16)+ (int(ins[0].op_str.split('#')[1],16)&~0xfff)
        except Exception: return ta
        w=rd(d,segs,slot,8)
        if w: return KB+(struct.unpack('<Q',w)[0]&0xFFFFFFFF)
    return ta

def analyze(path):
    d,segs,A=parse(path)
    vm,sz,fo,_=segs['__TEXT_EXEC']
    F={}
    for k,a0 in enumerate(A):
        st=fo+(a0-vm)
        en=A[k+1] if k+1<len(A) else vm+sz
        if st<0 or st>=len(d): continue
        ins=list(md.disasm(d[st:st+(en-a0)],a0))
        if not ins: continue
        tg=[]
        for i in ins:
            if i.mnemonic in ('bl','b') and i.op_str.startswith('#'):
                try: ta=int(i.op_str[1:],16)
                except Exception: continue
                tg.append(resolve(d,segs,ta) if i.mnemonic=='bl' else ta)
        cnt=collections.Counter(SEM.get(t,'?') for t in tg)
        F[a0]={'n':len(ins),'calls':tuple(sorted(tg)),
               'sem':(cnt['lock'],cnt['unlock'],cnt['retain'],cnt['release'])}
    return F

def main():
    name=sys.argv[1]; verb='--verbose' in sys.argv
    A=analyze(f'out/v2701/{name}.macho'); B=analyze(f'out/v272/{name}.macho')
    # 按调用目标多重集配对
    idx=collections.defaultdict(list)
    for a,v in B.items(): idx[v['calls']].append(a)
    pairs=[];unA=[]
    for a,v in A.items():
        c=idx.get(v['calls'])
        if c: pairs.append((a,c.pop(0)))
        else: unA.append(a)
    print(f"### {name}")
    print(f"函数 27.0.1={len(A)}  27.2={len(B)}  按调用目标配对={len(pairs)}  未配对27.0.1={len(unA)}")
    tot=collections.Counter()
    for a,b in pairs:
        sa,sb=A[a]['sem'],B[b]['sem']
        if sa!=sb:
            for i,k in enumerate(['lock','unlock','retain','release']):
                if sb[i]>sa[i]: tot[k]+=sb[i]-sa[i]
            print(f"  变 {hex(a)}→{hex(b)}  长{A[a]['n']}→{B[b]['n']}  "
                  f"lock {sa[0]}→{sb[0]}  unlock {sa[1]}→{sb[1]}  "
                  f"retain {sa[2]}→{sb[2]}  release {sa[3]}→{sb[3]}")
            if verb:
                da=collections.Counter(A[a]['calls']); db=collections.Counter(B[b]['calls'])
                add=db-da
                print(f"      新增调用: {[(hex(t),n,SEM.get(t,'?')) for t,n in add.items()][:8]}")
    print(f"合计新增: {dict(tot) if tot else '无'}")
    print()

if __name__=='__main__': main()
