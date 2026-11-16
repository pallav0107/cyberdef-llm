"""Stage H step 1 (repo .venv): choose the base cases for the length axis and the vuln/fix pairs for the semantic axis.
Writes results/reason_H_bases.json. Pre-registered in EXPERIMENT_PLAN_REASONING.md (Stage H)."""
import json, random, sys
sys.path.insert(0, "src")
import pandas as pd
from cyberdef import benchdata as b

SEED = 0
cases = json.load(open("results/lenmatched_eval_cases.json"))["cases"]
ok = [c for c in cases if c["code_chars"] <= 3000 and not c["truncated"]]
v = [c for c in ok if c["label"] == "VULNERABLE"]; s = [c for c in ok if c["label"] == "SAFE"]
rng = random.Random(SEED); rng.shuffle(v); rng.shuffle(s)
length_bases = [dict(id=c["id"], label=c["label"], code=c["code"]) for c in v[:75] + s[:75]]

df = pd.read_parquet("data/vulspot/cpp/full/data.parquet").set_index("idx")
ids = set()
for sp in ("chrono", "project_holdout"):
    ids |= set(json.load(open(f"data/vulspot/cpp/full/splits/{sp}.json"))["test_paired_high"])
sp = b.spec("primevul"); bad_h, bad_c = set(), set()
for r in b._load_split(sp, "train"):
    bad_h.add(b.norm(r["func"] or "")); bad_c.add(r["commit_id"])
pairs, seen = [], set()
for idx in sorted(ids):
    if idx not in df.index:
        continue
    r = df.loc[idx]
    if not bool(r.is_vulnerable) or r.fixed_func_idx != r.fixed_func_idx:
        continue
    fi = int(r.fixed_func_idx)
    if fi not in df.index or bool(df.loc[fi].is_vulnerable):
        continue
    f = df.loc[fi]
    cv, cf = r.func_body or "", f.func_body or ""
    if not cv or not cf or cv == cf or b.norm(cv) in bad_h or b.norm(cf) in bad_h or r.commit_id in bad_c:
        continue
    if abs(len(cv) - len(cf)) / max(len(cv), len(cf)) > 0.05 or len(cv) > 6000:
        continue
    if b.norm(cv) in seen:
        continue
    seen.add(b.norm(cv))
    pairs.append(dict(pair=int(idx), vuln_code=cv, fixed_code=cf, chars_v=len(cv), chars_f=len(cf), project=r.project))
random.Random(SEED).shuffle(pairs)
n_before = len(pairs)
pairs = pairs[:300]
json.dump(dict(length_bases=length_bases, pairs=pairs), open("results/reason_H_bases.json", "w"))
print(f"[H bases] length_bases={len(length_bases)} semantic pairs available={n_before} used={len(pairs)} "
      f"mean |dchars|/chars={sum(abs(p['chars_v']-p['chars_f'])/max(p['chars_v'],p['chars_f']) for p in pairs)/max(1,len(pairs)):.4f}")
