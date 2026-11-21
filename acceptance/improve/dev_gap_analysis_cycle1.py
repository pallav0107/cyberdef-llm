# Descriptive gap analysis on the DEV split only (cycle-1 dev; never VSP-T).
import json, difflib, statistics as st
from collections import defaultdict
_j = json.load(open('results/vsp_dev_cases.json')); C = {c['id']: c for c in (_j if isinstance(_j, list) else _j['cases'])}
F = {'base': 'results/vsp_r2/ci_ev_qwen3.8-27b_vspdev.json', 'K1': 'results/vsp_r2/ci_ev_vsp_pilot_k1_vspdev.json',
     'K2': 'results/vsp_r2/ci_ev_vsp_pilot_k2_vspdev.json'}
P = {m: {r['id']: r['p_vuln'] for r in json.load(open(f))['per_case']} for m, f in F.items()}
pairs = defaultdict(dict)
for i, c in C.items(): pairs[c['pair']][c['label']] = c
def strat(v, s):
    lv, ls = len(v['code']), len(s['code']); return 'A' if ls > lv else ('B' if lv > ls else 'E')
def rank(xs):
    o = sorted(range(len(xs)), key=lambda i: xs[i]); r = [0]*len(xs)
    for k, i in enumerate(o): r[i] = k
    return r
def spear(a, b):
    ra, rb = rank(a), rank(b); return st.correlation(ra, rb)
print('== within-pair accuracy (p(V) > p(S)) by stratum; A = fix longer, B = vuln longer, E = equal')
rows = []
for pid, d in pairs.items():
    v, s = d['VULNERABLE'], d['SAFE']; k = strat(v, s)
    nd = sum(1 for l in difflib.unified_diff(s['code'].splitlines(), v['code'].splitlines(), lineterm='', n=0)
             if l[:1] in '+-' and not l.startswith(('+++', '---')))
    rows.append((pid, k, v, s, nd))
for m in P:
    out = []
    for k in 'ABE':
        R = [P[m][v['id']] > P[m][s['id']] for _, kk, v, s, _ in rows if kk == k]
        out.append(f"{k}: {sum(R)/len(R):.3f} (n={len(R)})")
    tie = sum(1 for _, _, v, s, _ in rows if abs(P[m][v['id']] - P[m][s['id']]) < 1e-6)
    bal = (sum(P[m][v['id']] > P[m][s['id']] for _, k, v, s, _ in rows if k == 'A') / sum(1 for r in rows if r[1] == 'A') +
           sum(P[m][v['id']] > P[m][s['id']] for _, k, v, s, _ in rows if k == 'B') / sum(1 for r in rows if r[1] == 'B')) / 2
    print(f"{m:5s} {'  '.join(out)}  | A/B-balanced {bal:.3f} | exact ties {tie}")
print('\n== does the model just score longer code as more vulnerable? within-pair: sign(dp) vs sign(dlen)')
for m in P:
    dp = [P[m][v['id']] - P[m][s['id']] for _, k, v, s, _ in rows if k != 'E']
    dl = [len(v['code']) - len(s['code']) for _, k, v, s, _ in rows if k != 'E']
    agree = sum((a > 0) == (b > 0) for a, b in zip(dp, dl)) / len(dp)
    print(f"{m:5s} 'longer = more vulnerable' agreement {agree:.3f}; Spearman(dp, dlen) {spear(dp, dl):+.3f}; "
          f"mean |dp| {st.mean(abs(x) for x in dp):.4f}; pooled Spearman(p, len) "
          f"{spear([P[m][i] for i in C], [len(C[i]['code']) for i in C]):+.3f}")
print('\n== by size of the fix (changed lines)')
for lo, hi in ((1, 2), (3, 6), (7, 20), (21, 10**6)):
    sub = [r for r in rows if lo <= r[4] <= hi]
    if not sub: continue
    print(f"{lo}-{hi if hi < 10**6 else '+'} lines (n={len(sub)}): " + '  '.join(
        f"{m} {sum(P[m][v['id']] > P[m][s['id']] for _, _, v, s, _ in sub)/len(sub):.3f}" for m in P))
print('\n== K2 vs base, pairs flipped')
up = sum(1 for _, _, v, s, _ in rows if P['K2'][v['id']] > P['K2'][s['id']] and not P['base'][v['id']] > P['base'][s['id']])
dn = sum(1 for _, _, v, s, _ in rows if not P['K2'][v['id']] > P['K2'][s['id']] and P['base'][v['id']] > P['base'][s['id']])
print(f"fixed by K2 {up}, broken by K2 {dn}, of {len(rows)}")
print('\n== top CWEs: within-pair acc base / K2')
by = defaultdict(list)
for r in rows: by[str(r[2]['cwe'])].append(r)
for cwe, sub in sorted(by.items(), key=lambda x: -len(x[1]))[:8]:
    print(f"{cwe[:30]:30s} n={len(sub):3d} base {sum(P['base'][v['id']] > P['base'][s['id']] for _,_,v,s,_ in sub)/len(sub):.2f}"
          f"  K2 {sum(P['K2'][v['id']] > P['K2'][s['id']] for _,_,v,s,_ in sub)/len(sub):.2f}")
