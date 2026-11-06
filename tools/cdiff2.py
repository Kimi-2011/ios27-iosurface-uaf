#!/usr/bin/env python3
"""结构形状差分：将每条语句归一化为 (关键字/运算符/常量) 的形状串。"""
import re, sys, collections

def blocks(path):
    out=[]; cur=None; buf=[]
    for line in open(path, errors='replace'):
        if line.startswith('// ====='):
            if cur is not None: out.append((cur, buf))
            cur=line.strip(); buf=[]
        elif cur is not None: buf.append(line.rstrip('\n'))
    if cur is not None: out.append((cur, buf))
    return out

KW = re.compile(r'\b(if|else|while|for|do|switch|case|default|return|goto|break|continue)\b')

def shape(stmt):
    s=stmt.strip()
    if not s or s.startswith('/*') or s.startswith('*') or s in ('{','}','};','else {'): 
        return None
    # 去掉类型/声明：没有 = ( ) 且不含关键字 → 纯声明，丢弃
    if not re.search(r'[=()\[\]]', s) and not KW.search(s):
        return None
    s=re.sub(r'"[^"]*"','S',s)                     # 字符串
    s=re.sub(r"\b0x[0-9a-f]+\b",'N',s)             # 十六进制常量
    s=re.sub(r'\b\d+\b','N',s)                     # 十进制常量
    s=re.sub(r'->','.',s)
    s=re.sub(r'\((?:X\s*\*+\s*)+X?\)','',s)   # 去掉 (X*) / (X**) 之类的强制类型转换
    s=re.sub(r'\*','',s)                        # 指针星号本身无意义
    # 标识符 → 占位符（保留关键字）
    def rid(m):
        w=m.group(0)
        return w if KW.fullmatch(w) else 'X'
    s=re.sub(r'\b[A-Za-z_]\w*\b', rid, s)
    s=re.sub(r'\((?:X\*+)\)','',s)
    s=re.sub(r'\*','',s)
    s=re.sub(r'\s+','',s)
    return s

def shapes(buf):
    out=[]
    for ln in buf:
        sh=shape(ln)
        if sh: out.append(sh)
    return out

def main(pa,pb,top=20):
    A=blocks(pa); B=blocks(pb); n=min(len(A),len(B))
    res=[]
    for i in range(n):
        sa=shapes(A[i][1]); sb=shapes(B[i][1])
        ca,cb=collections.Counter(sa),collections.Counter(sb)
        add=list((cb-ca).elements()); rem=list((ca-cb).elements())
        # 形状数量差异过大 → 判定为反编译失败，单独标记
        bad = (len(sa)+len(sb))>0 and min(len(sa),len(sb))/max(len(sa),len(sb)) < 0.6
        res.append((-1 if bad else len(add)+len(rem), i, add, rem, len(sa), len(sb)))
    same=sum(1 for r in res if r[0]==0)
    bad=sum(1 for r in res if r[0]==-1)
    print(f"配对 {n} 个 | 形状完全相同 {same} | 真实差异 {n-same-bad} | 反编译失配 {bad}")
    res.sort(reverse=True)
    print(f"\n{'差异':>4} {'块序':>4}  新增形状 → 删除形状")
    for d,i,add,rem,la,lb in res[:top]:
        if d==0: break
        print(f"{d:4d} {i:4d}  +{add[0][:60] if add else ''}")
        if rem: print(f"          -{rem[0][:60]}")
    return res

if __name__=='__main__':
    main(sys.argv[1], sys.argv[2])
