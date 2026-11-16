"""Build a LENGTH-MATCHED neutral test set from VulSpot (ods01/VulSpot cpp/full @ v2026-10-12).
VulSpot gives leakage-controlled splits but does NOT control length; we pair each vulnerable function with a
safe one of near-identical chars+tokens inside the SAME split list, then run the fail-first control
(length-only AUROC must be in [0.45,0.55]). Functions whose normalised text or fix commit appears in
PrimeVul TRAIN are dropped first (so PrimeVul-trained adapters are not scored on things they trained on).
Usage: build_vulspot_eval.py SPLIT_NAME KEY OUT_PREFIX   e.g. project_holdout test / chrono test_no_linux"""
from __future__ import annotations
import json, random, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
import pandas as pd
from transformers import AutoTokenizer
from cyberdef import benchdata as b, lenmatch
from build_lenmatch_eval import len_aurocs

split, key, out = sys.argv[1:4]
MAXPAIRS, MC, SEED = 600, 4000, 0
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")
df = pd.read_parquet("data/vulspot/cpp/full/data.parquet").set_index("idx")
ids = json.load(open(f"data/vulspot/cpp/full/splits/{split}.json"))[key]
d = df.loc[ids]
d = d[~d.label_conflict.fillna(False).astype(bool)]
sp = b.spec("primevul")
bad_h, bad_c = set(), set()
for r in b._load_split(sp, "train"):
    bad_h.add(b.norm(r["func"] or "")); bad_c.add(r["commit_id"])
rows, drop = [], 0
seen = set()
for idx, r in d.iterrows():
    code = r.func_body or ""
    h = b.norm(code)
    if h in bad_h or r.commit_id in bad_c or h in seen or not code:
        drop += 1; continue
    seen.add(h)
    rows.append(dict(id=f"vs{idx}", code=code, project=r.project, y=int(bool(r.is_vulnerable))))
print(f"[vs] {split}/{key}: split rows={len(d)} kept={len(rows)} dropped(overlap/dup)={drop}", flush=True)
lenmatch.attach_len(rows, tok)
def mkraw(r, pid):
    return dict(id=r["id"], code=r["code"][:MC], code_chars=r["chars"], truncated=r["chars"] > MC,
                label="VULNERABLE" if r["y"] else "SAFE", pair=pid, project=r["project"], toks=None,
                lines=r["code"].count(chr(10)) + 1)
_v = [r for r in rows if r["y"]]; _s = [r for r in rows if not r["y"]]
random.Random(SEED + 1).shuffle(_v); random.Random(SEED + 1).shuffle(_s)
_n = min(500, len(_v))
raw = [mkraw(x, i) for i in range(_n) for x in (_v[i], _s[i])]
random.Random(SEED).shuffle(raw)
for c in raw:
    c["toks"] = c["code_chars"] // 3
rawctl = len_aurocs(raw)
print("[raw] UNMATCHED random balanced sample n=%d length-only AUROC: %s" % (len(raw), json.dumps(rawctl["chars_full_function"])), flush=True)
json.dump(dict(cases=raw, pool=dict(n_pairs=_n, note="random balanced, NOT length-matched"), split=key, seed=SEED),
          open(f"results/{out.replace('_matched','_raw')}_cases.json", "w"))
json.dump(rawctl, open(f"results/{out.replace('_matched','_raw')}_control.json", "w"), indent=1)
vul = [r for r in rows if r["y"]]; saf = [r for r in rows if not r["y"]]
random.Random(SEED).shuffle(vul)
pairs, dropped = lenmatch.match_pairs(vul[:MAXPAIRS * 2], saf, tok, 0.03, SEED)
pairs = pairs[:MAXPAIRS]
print(f"[vs] vuln={len(vul)} safe={len(saf)} pairs={len(pairs)}", flush=True)
def mk(r, pid):
    return dict(id=r["id"], code=r["code"][:MC], code_chars=r["chars"], truncated=r["chars"] > MC,
                label="VULNERABLE" if r["y"] else "SAFE", pair=pid, project=r["project"], toks=r["toks"],
                lines=r["code"].count("\n") + 1)
cases = [mk(x, i) for i, (v, s) in enumerate(pairs) for x in (v, s)]
random.Random(SEED).shuffle(cases)
ctl = len_aurocs(cases)
ok = all(0.45 <= v["auroc"] <= 0.55 for v in ctl.values())
print("[control] length-only AUROC on matched:", json.dumps(ctl), "PASS=", ok, flush=True)
json.dump(dict(n_pairs=len(pairs), n_cases=len(cases), control_matched=ctl, control_pass=ok, dropped_overlap=drop,
               projects=len({c["project"] for c in cases})), open(f"results/{out}_control.json", "w"), indent=1)
if ok:
    json.dump(dict(cases=cases, pool=dict(n_pairs=len(pairs)), split=key, seed=SEED), open(f"results/{out}_cases.json", "w"))
sys.exit(0 if ok else 1)
