#!/usr/bin/env python3
"""给 27.0.1 普查结果加 27.2 列：kext/函数数/派发表/每个 selector 的 4 个 check 字段是否一致。

不做字节比较：函数体里的 adrp/bl/b 是位置相关编码，布局一移位字节就变，
字节相同/不同都不能证明代码逻辑相同或不同。
"""
import json
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from census import Cache, func_starts, data_path


def main():
    src, newpath, outp = sys.argv[1], sys.argv[2], sys.argv[3]
    j = json.load(open(src))
    c2 = Cache(newpath)
    names2 = {n for _, n in c2.entries}
    kstat = {}
    tables2 = {}
    for bundle in {r['kext'] for r in j['rows']}:
        if bundle not in names2:
            kstat[bundle] = dict(present=False)
            continue
        s, ok, note = func_starts(c2, bundle)
        if not s:
            kstat[bundle] = dict(present=True, funcs=0, note=note)
            continue
        t = data_path(c2, bundle, s)
        tables2[bundle] = t
        kstat[bundle] = dict(present=True, funcs=len(s), tables=len(t),
                             sels=sum(len(x['fns']) for x in t),
                             strides=sorted({x['stride'] for x in t}),
                             selfcheck=ok)
    # 表级匹配：同 stride、同 fields 序列
    match = {}
    for bundle, ts in tables2.items():
        for t in ts:
            key = (bundle, t['stride'], tuple(tuple(f) for f in t['fields']))
            match.setdefault(key, []).append(t)
    for r in j['rows']:
        st = kstat.get(r['kext'], {})
        r['v272_kext'] = st.get('present')
        r['v272_table'] = None
        r['v272_fields_same'] = None
        if not st.get('present'):
            continue
        key = (r['kext'], r['stride'], None)
        hit = None
        for k, v in match.items():
            if k[0] != r['kext'] or k[1] != r['stride']:
                continue
            t = v[0]
            if r['selector'] < len(t['fields']) and tuple(t['fields'][r['selector']]) == (
                    r['scalarIn'], r['structIn'], r['scalarOut'], r['structOut']):
                hit = t
                break
        if hit:
            r['v272_table'] = '0x%x' % hit['base']
            r['v272_fields_same'] = True
        else:
            # kext 里有没有同 stride 的表
            same = [t for t in tables2.get(r['kext'], []) if t['stride'] == r['stride']]
            if same:
                r['v272_table'] = '0x%x' % same[0]['base']
                r['v272_fields_same'] = False
            else:
                r['v272_fields_same'] = False
    for k in j['kexts']:
        st = kstat.get(k['kext'], {})
        k['v272_present'] = st.get('present')
        k['v272_funcs'] = st.get('funcs')
        k['v272_sels'] = st.get('sels')
        k['v272_selfcheck'] = st.get('selfcheck')
    j['v272_kexts'] = kstat
    json.dump(j, open(outp, 'w'), indent=1)
    ok = sum(1 for r in j['rows'] if r['v272_fields_same'])
    print('rows=%d check字段一致=%d 不一致=%d  kext缺失=%d' % (
        len(j['rows']), ok,
        sum(1 for r in j['rows'] if r['v272_fields_same'] is False),
        sum(1 for r in j['rows'] if r['v272_kext'] is False)))


if __name__ == '__main__':
    main()
