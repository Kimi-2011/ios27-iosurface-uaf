import struct, sys, collections, bisect
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
def macho_segs(path):
    d=open(path,'rb').read()
    magic=struct.unpack_from('<I',d,0)[0]
    assert magic==0xfeedfacf, hex(magic)
    ncmds=struct.unpack_from('<I',d,16)[0]
    off=32; segs=[]
    for _ in range(ncmds):
        cmd,sz=struct.unpack_from('<II',d,off)
        if cmd==0x19:
            name=d[off+8:off+24].rstrip(b'\0').decode()
            va,vs,fo,fs=struct.unpack_from('<QQQQ',d,off+24)
            segs.append((name,va,vs,fo,fs))
        off+=sz
    return d,segs
def va2off(segs,va):
    for n,sv,ss,fo,fs in segs:
        if sv<=va<sv+ss and (va-sv)<fs: return fo+(va-sv)
    return None
def shape(d,segs,va,endv):
    o=va2off(segs,va)
    if o is None: return None
    e=va2off(segs,endv) or (o+0x4000)
    t=[]
    for i in md.disasm(d[o:min(e,o+0x8000)],va):
        t.append(i.mnemonic)
        if i.mnemonic in ('ret','retaa') or len(t)>400: break
    return tuple(t)
