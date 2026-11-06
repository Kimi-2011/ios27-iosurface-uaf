import sys,struct,difflib,hashlib
from capstone import *
BTI=b'\x5f\x24\x03\xd5'; PACI=b'\x7f\x23\x03\xd5'
TERM={b'\xc0\x03\x5f\xd6', b'\xff\x0f\x5f\xd6', b'\x1f\x20\x03\xd5', b'\x00\x00\x00\x00'}
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
COND={'cbz','cbnz','tbz','tbnz','csel','csinc','csinv','csneg'}
def isc(m): return m in COND or m.startswith('b.') or m=='cbz' or m=='cbnz'
def seg(p,nm):
    d=open(p,'rb').read(); n=struct.unpack_from('<I',d,16)[0]; off=32
    for _ in range(n):
        cmd,sz=struct.unpack_from('<II',d,off)
        if cmd==0x19:
            s=d[off+8:off+24].rstrip(b'\0').decode()
            vm,vs,fo,fs=struct.unpack_from('<QQQQ',d,off+24)
            if s==nm: return d,vm,fo,fs
        off+=sz
def funcs(p):
    d,vm,fo,fs=seg(p,'__TEXT_EXEC'); body=d[fo:fo+fs]; L=len(body)
    starts=[]
    for i in range(0,L-3,4):
        w=body[i:i+4]
        if w not in (BTI,PACI): continue
        if i==0: starts.append(i); continue
        if body[i-4:i] in TERM: starts.append(i); continue
        # 前一指令是否为无条件跳转/终止
        prev=list(md.disasm(body[i-4:i],0))
        if prev and (prev[0].mnemonic in ('ret','retab','b','br','braa','blraa') or prev[0].mnemonic.startswith('b.')) is False and prev[0].mnemonic in ('ret','retab','b'): starts.append(i); continue
        if prev and prev[0].mnemonic.startswith('b.') is False and prev[0].mnemonic in ('ret','retab','b','br'): starts.append(i); continue
    starts=sorted(set(starts))
    out=[]
    for k,st in enumerate(starts):
        end=starts[k+1] if k+1<len(starts) else L
        ins=[(i.mnemonic,i.op_str) for i in md.disasm(body[st:end],0)]
        toks=[m+' '+' '.join('#I' if x.strip().startswith('#') else ('A' if x.strip().startswith('0x') else x.strip()) for x in o.split(',') if x.strip()) for m,o in ins]
        out.append((vm+st,len(ins),hashlib.sha1('\n'.join(toks).encode()).hexdigest()[:12],sum(1 for m,o in ins if isc(m))))
    return out
A=funcs(sys.argv[1]); B=funcs(sys.argv[2])
sm=difflib.SequenceMatcher(None,[f[2] for f in A],[f[2] for f in B],autojunk=False)
rows=[]
for tag,i1,i2,j1,j2 in sm.get_opcodes():
    if tag=='equal': continue
    for k in range(max(i2-i1,j2-j1)):
        a=A[i1+k] if i1+k<i2 else None; b=B[j1+k] if j1+k<j2 else None
        if a and b: rows.append((b[3]-a[3], b[1]-a[1], a[0], b[0], a[3], b[3]))
rows.sort(reverse=True)
print(f"函数数 A={len(A)} B={len(B)} | 改动对 {len(rows)}")
print(f"dChk>0: {sum(1 for r in rows if r[0]>0)} | =0: {sum(1 for r in rows if r[0]==0)} | <0: {sum(1 for r in rows if r[0]<0)} | 净 {sum(r[0] for r in rows)}")
for d,ds,va,vb,ca,cb in rows[:12]:
    print(f"{d:>5}{ds:>6}  0x{va:x} 0x{vb:x}  {ca}→{cb}")
