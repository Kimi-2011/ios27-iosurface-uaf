import struct,json,re
from capstone import *
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
d=open('out/kc.27.0.1.full','rb').read()
hits=json.load(open('/tmp/ldrsw_hits.json'))
def dis(foff,va,n=40):
    return list(md.disasm(d[foff:foff+n*4],va))
rows=[]
for eid,seg,vas,foff in hits:
    va=int(vas,16)
    win=None;k=None
    for back in (8,16,4,24,32):
        w=dis(foff-back*4,va-back*4,back+36)
        for i,x in enumerate(w):
            if x.address==va: win=w;k=i;break
        if k is not None: break
    if k is None: continue
    op=win[k].op_str            # "x16, [x17, x16, lsl #2]"
    m=re.match(r'(\w+), \[(\w+), (\w+), lsl #2\]',op)
    if not m: continue
    rt,base,idx=m.groups()
    # forward: adr + add + br/braa within 6
    ok=False; rel_adr=None; brk=None
    for j in range(k+1,min(k+7,len(win))):
        if win[j].mnemonic=='adr' and rel_adr is None:
            try: rel_adr=int(win[j].op_str.split('#')[-1],16)
            except: pass
        if win[j].mnemonic in ('br','braa'):
            brk=j; ok=True; break
    if not ok: continue
    # backward: bound
    bound=None; bva=None
    for j in range(k-1,max(0,k-14),-1):
        if win[j].mnemonic=='cmp' and '#' in win[j].op_str:
            try:
                v=int(win[j].op_str.split('#')[-1],16)
                bound=v; bva=win[j].address; break
            except: pass
    # table base: find adrp+add defining `base` before k
    tb=None
    for j in range(k-1,max(0,k-12),-1):
        if win[j].mnemonic=='adrp' and win[j].op_str.startswith(base+','):
            try: page=int(win[j].op_str.split('#')[-1],16)
            except: continue
            for jj in range(j+1,min(j+4,k+1)):
                if win[jj].mnemonic=='add' and win[jj].op_str.startswith(base+',') and 'lsl' not in win[jj].op_str:
                    parts=win[jj].op_str.split(',')
                    if len(parts)==3:
                        try: tb=page+int(parts[2].lstrip(' #'),16)
                        except: tb=page
                    break
            if tb is None: tb=page
            break
    rows.append({'kext':eid,'va':va,'base':tb,'bound':bound,'cmp_va':bva,'adr':rel_adr,
                 'br':win[brk].mnemonic,'seg':seg})
print('classified int32-relative dispatch points:',len(rows))
json.dump([{**r,'va':hex(r['va']),'base':hex(r['base']) if r['base'] else None,
            'cmp_va':hex(r['cmp_va']) if r['cmp_va'] else None,
            'adr':hex(r['adr']) if r['adr'] else None} for r in rows],open('/tmp/dispatch_pts.json','w'))
import collections
c=collections.Counter(r['kext'] for r in rows)
print('kexts involved:',len(c))
for k,v in c.most_common(15): print(f'  {v:3d}  {k}')
