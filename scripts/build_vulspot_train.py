"""Arm D training set: VulSpot (cpp, clean==True, label_conflict dropped) project_holdout TRAIN split, length-matched
(chars+tokens caliper, same lenmatch code as the PrimeVul set), 500 pairs, project 'linux' pairs duplicated x2 (same recipe
as the PrimeVul length-matched run). Functions whose normalised text or fix commit is in PrimeVul val/test are removed so
the PrimeVul-based length-matched eval stays leak-free for this arm. Output: results/vulspot_lenmatch_train_items.json"""
import json, random, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
import pandas as pd
from transformers import AutoTokenizer
from cyberdef import benchdata as b, lenmatch
NP, MC, SEED = 500, 4000, 0
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")
df = pd.read_parquet("data/vulspot/cpp/full/data.parquet").set_index("idx")
ids = json.load(open("data/vulspot/cpp/full/splits/project_holdout.json"))["train"]
d = df.loc[ids]
print("[vs-train] split rows", len(d), "clean", int(d.clean.fillna(False).astype(bool).sum()), flush=True)
d = d[d.clean.fillna(False).astype(bool) & ~d.label_conflict.fillna(False).astype(bool)]
sp = b.spec("primevul"); bad_h, bad_c = set(), set()
for s in ("validation", "test"):
    for r in b._load_split(sp, s):
        bad_h.add(b.norm(r["func"] or "")); bad_c.add(r["commit_id"])
rows, seen, drop = [], set(), 0
for idx, r in d.iterrows():
    code = r.func_body or ""; h = b.norm(code)
    if not code or h in seen or h in bad_h or r.commit_id in bad_c:
        drop += 1; continue
    seen.add(h); rows.append(dict(id=f"vs{idx}", code=code, project=r.project, y=int(bool(r.is_vulnerable))))
lenmatch.attach_len(rows, tok)
vul = [r for r in rows if r["y"]]; saf = [r for r in rows if not r["y"]]
print(f"[vs-train] kept={len(rows)} dropped={drop} vuln={len(vul)} safe={len(saf)}; projects top:",
      pd.Series([r['project'] for r in vul]).value_counts().head(4).to_dict(), flush=True)
random.Random(SEED).shuffle(vul)
# VulSpot train is ~85% Linux; cap it so the kernel share matches arm A's recipe (~40% of pairs after its x2 oversample):
# 200 linux pairs + 300 non-linux pairs, no duplication.
lin = [r for r in vul if r["project"] == "linux"][:400]
oth = [r for r in vul if r["project"] != "linux"][:600]
pl, _ = lenmatch.match_pairs(lin, saf, tok, 0.03, SEED)
used = {id(s) for _, s in pl[:200]}
po, _ = lenmatch.match_pairs(oth, [x for x in saf if id(x) not in used], tok, 0.03, SEED)
pairs = pl[:200] + po[:300]
extra = []
items = []
for v, s in pairs:
    for r in (v, s):
        items.append(dict(id=r["id"], code=r["code"][:MC], code_chars=r["chars"], toks=r["toks"], project=r["project"],
                          label="VULNERABLE" if r["y"] else "SAFE"))
random.Random(SEED).shuffle(items)
json.dump(dict(items=items, pairs=len(pairs), linux_dup_pairs=len(extra)), open("results/vulspot_lenmatch_train_items.json", "w"))
print("[vs-train] items", len(items), "pairs", len(pairs), "linux dup", len(extra), flush=True)
