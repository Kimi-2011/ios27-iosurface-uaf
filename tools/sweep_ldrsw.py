import struct,sys,json
import numpy as np
from capstone import *
KC='out/kc.27.0.1.full'
d=open(KC,'rb').read()
ncmds=struct.unpack_from('<I',d,16)[0]; off=32; ents=[]
for _ in range(ncmds):
    cmd,sz=struct.unpack_from('<II',d,off)
    if cmd==0x80000035:
        vm,fo=struct.unpack_from('<QQ',d,off+8)
        so=struct.unpack_from('<I',d,off+24)[0]
        eid=d[off+so:off+so+128].split(b'\0')[0].decode(errors='replace')
        ents.append((eid,vm,fo))
    off+=sz
def segs_at(fo):
    m=struct.unpack_from('<I',d,fo)[0]
    if m!=0xfeedfacf: return []
    n=struct.unpack_from('<I',d,fo+16)[0]; o=fo+32; out=[]
    for _ in range(n):
        c,s=struct.unpack_from('<II',d,o)
        if c==0x19:
            nm=d[o+8:o+24].split(b'\0')[0].decode()
            vm,vs,f2,fs=struct.unpack_from('<QQQQ',d,o+24)
            out.append((nm,vm,vs,f2,fs))
        o+=s
    return out
MASK=0xFFE0EC00; VAL=0xB8A06800
hits=[]
for eid,vm0,fo in ents:
    for nm,vm,vs,f2,fs in segs_at(fo):
        if nm not in ('__TEXT_EXEC','__TEXT','__TEXT_BOOT_EXEC'): continue
        buf=np.frombuffer(d,dtype=np.uint32,count=fs//4,offset=f2)
        idx=np.nonzero((buf & MASK)==VAL)[0]
        for i in idx: hits.append((eid,nm,vm+int(i)*4,f2+int(i)*4))
print('kexts',len(ents),'raw ldrsw-reg-hits',len(hits))
json.dump([(a,b,hex(c),e) for a,b,c,e in hits],open('/tmp/ldrsw_hits.json','w'))
