"""Training-set builders for #1 (vuln-vs-patch pairs), #7 (clean vs unfiltered labels) and the #1 pair eval set.
  .venv/bin/python scripts/imp_build_train.py            (CPU; nice -n 19)
Writes (all results/imp_*):
  imp_train_pairs_items.json        #1: N=1000 vuln/fix pairs, pair-adjacent order (arm and control share this file)
  imp_train_clean_lm_items.json     #7: 1000 length-matched pairs from the CLEAN pool
  imp_train_unfilt_lm_items.json    #7: 1000 length-matched pairs from the UNFILTERED pool
  imp_vs_pairs_eval_cases.json      #1 eval: project_holdout test_paired_high pairs (995)
  imp_train_build_stats.json        overlap removals, linux share, length-only AUROC of each train set
Overlap removal (normalised-text hash + commit_id) against: PrimeVul validation+test, VulSpot holdout/no-linux matched cases,
VulSpot test_paired_high (project_holdout AND chrono), CASTLE. Both functions of a pair must be <= 4000 chars (fully visible)."""
import json, random, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
import pandas as pd
from transformers import AutoTokenizer
from cyberdef import benchdata as b, lenmatch
from build_lenmatch_eval import len_aurocs

N, MC, SEED, LIN_CAP = 1000, 4000, 0, 0.30
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")
cols = ["idx", "project", "commit_id", "is_vulnerable", "func_body", "pair_status", "fixed_func_idx", "clean", "label_conflict"]
df = pd.read_parquet("data/vulspot/cpp/full/data.parquet", columns=cols).set_index("idx")
S = "data/vulspot/cpp/full/splits/"
ph = json.load(open(S + "project_holdout.json")); ch = json.load(open(S + "chrono.json"))

bad_h, bad_c, stats = set(), set(), {}


def ban(h=None, c=None, tag=""):
    n0 = len(bad_h)
    if h:
        bad_h.add(h)
    if c:
        bad_c.add(c)


sp = b.spec("primevul")
for s in ("validation", "test"):
    for r in b._load_split(sp, s):
        bad_h.add(b.norm(r["func"] or "")); bad_c.add(r["commit_id"])
stats["banned_after_primevul"] = [len(bad_h), len(bad_c)]
for name in ("vs_holdout_matched", "vs_nolinux_matched"):
    for c in json.load(open(f"results/{name}_cases.json"))["cases"]:
        bad_h.add(b.norm(c["code"]))
        bad_c.add(df.loc[int(c["id"][2:])].commit_id)
for ids in (ph["test_paired_high"], ch["test_paired_high"]):
    for i in ids:
        r = df.loc[i]
        bad_h.add(b.norm(r.func_body or "")); bad_c.add(r.commit_id)
for c in json.load(open("results/xdata_castle_cases.json"))["cases"]:
    bad_h.add(b.norm(c["code"]))
stats["banned_total"] = [len(bad_h), len(bad_c)]

train = df.loc[ph["train"]]
train = train[train.func_body.notna()]


def okrow(r):
    return b.norm(r.func_body) not in bad_h and r.commit_id not in bad_c


def item(idx, r, label, pair):
    code = r.func_body
    return dict(id=f"vs{idx}", code=code[:MC], code_chars=len(code), toks=max(1, len(tok(code, add_special_tokens=False)["input_ids"])),
                project=r.project, label=label, pair=pair)


# ---------------- #1: fix pairs ----------------
t1 = train[train.clean.fillna(False).astype(bool) & ~train.label_conflict.fillna(False).astype(bool) & (train.pair_status == "paired")]
pairs, rej = [], {"overlap": 0, "no_partner": 0, "too_long": 0, "dup": 0}
seen = set()
for idx, r in t1[t1.is_vulnerable].iterrows():
    fi = r.fixed_func_idx
    if pd.isna(fi) or int(fi) not in t1.index or t1.loc[int(fi)].is_vulnerable:
        rej["no_partner"] += 1; continue
    f = t1.loc[int(fi)]
    if not (okrow(r) and okrow(f)):
        rej["overlap"] += 1; continue
    if len(r.func_body) > MC or len(f.func_body) > MC:
        rej["too_long"] += 1; continue
    key = (b.norm(r.func_body), b.norm(f.func_body))
    if key in seen or key[0] == key[1]:
        rej["dup"] += 1; continue
    seen.add(key); pairs.append((idx, r, int(fi), f))
lin = [p for p in pairs if p[1].project == "torvalds/linux" or "linux" in p[1].project.lower() and p[1].project.lower().endswith("linux")]
oth = [p for p in pairs if p not in lin]
random.Random(SEED).shuffle(lin); random.Random(SEED).shuffle(oth)
nl = min(len(lin), int(N * LIN_CAP))
sel = lin[:nl] + oth[:N - nl]
if len(sel) < N:
    sel += lin[nl:nl + (N - len(sel))]
random.Random(SEED + 1).shuffle(sel)
items = []
for k, (vi, vr, fi, fr) in enumerate(sel):
    items += [item(vi, vr, "VULNERABLE", k), item(fi, fr, "SAFE", k)]
json.dump({"items": items, "pairs": len(sel), "note": "pair-adjacent order: items[2k], items[2k+1] are vuln, fix of pair k"}, open("results/imp_train_pairs_items.json", "w"))
la1 = len_aurocs([dict(c, truncated=False, lines=c["code"].count("\n") + 1) for c in items])
stats["pairs"] = {"candidates": len(pairs), "rejected": rej, "selected": len(sel), "linux_pairs": nl, "length_only": la1,
                  "projects": len({p[1].project for p in sel})}

# ---------------- #7: clean vs unfiltered, length-matched ----------------
def lm_items(pool, name):
    pool = pool[pool.func_body.map(lambda x: len(x) <= MC)]
    pool = pool[pool.apply(okrow, axis=1)]
    rows = {}
    for idx, r in pool.iterrows():
        h = b.norm(r.func_body)
        if h in rows:
            continue
        rows[h] = dict(id=f"vs{idx}", code=r.func_body, project=r.project, y=int(bool(r.is_vulnerable)), chars=len(r.func_body), toks=None)
    rows = list(rows.values())
    vul = [r for r in rows if r["y"]]; saf = [r for r in rows if not r["y"]]
    random.Random(SEED).shuffle(vul)
    lv = [r for r in vul if "linux" in r["project"].lower()]; ov = [r for r in vul if "linux" not in r["project"].lower()]
    pl, _ = lenmatch.match_pairs(lv[:int(N * LIN_CAP) * 3], saf, tok, 0.03, SEED)
    used = {id(s) for _, s in pl[:int(N * LIN_CAP)]}
    po, _ = lenmatch.match_pairs(ov[:N * 3], [x for x in saf if id(x) not in used], tok, 0.03, SEED)
    prs = pl[:int(N * LIN_CAP)] + po[:N - len(pl[:int(N * LIN_CAP)])]
    random.Random(SEED + 2).shuffle(prs)
    its = []
    for k, (v, s) in enumerate(prs):
        for r_, lab in ((v, "VULNERABLE"), (s, "SAFE")):
            its.append(dict(id=r_["id"], code=r_["code"][:MC], code_chars=r_["chars"], toks=r_["toks"], project=r_["project"], label=lab, pair=k))
    json.dump({"items": its, "pairs": len(prs), "note": "pair-adjacent; length-matched (chars+tokens caliper 3%)"}, open(f"results/{name}", "w"))
    return {"pool_rows": len(rows), "pool_vuln": len(vul), "pool_safe": len(saf), "pairs": len(prs),
            "length_only": len_aurocs([dict(c, truncated=False, lines=c["code"].count("\n") + 1) for c in its]),
            "label_conflict_rows_in_pool": int(pool.loc[[int(r["id"][2:]) for r in rows]].label_conflict.fillna(False).astype(bool).sum()),
            "clean_false_rows_in_pool": int((~pool.loc[[int(r["id"][2:]) for r in rows]].clean.fillna(False).astype(bool)).sum())}


stats["clean"] = lm_items(train[train.clean.fillna(False).astype(bool) & ~train.label_conflict.fillna(False).astype(bool)], "imp_train_clean_lm_items.json")
stats["unfiltered"] = lm_items(train, "imp_train_unfilt_lm_items.json")

# ---------------- #1 eval: test_paired_high pairs ----------------
te = df.loc[ph["test_paired_high"]]
cases, pid = [], 0
for idx, r in te[te.is_vulnerable].iterrows():
    fi = r.fixed_func_idx
    if pd.isna(fi) or int(fi) not in te.index:
        continue
    f = te.loc[int(fi)]
    if not (isinstance(f.func_body, str) and isinstance(r.func_body, str)):
        continue
    for i_, rr, lab in ((idx, r, "VULNERABLE"), (int(fi), f, "SAFE")):
        code = rr.func_body
        cases.append(dict(id=f"vs{i_}", code=code[:MC], code_chars=len(code), truncated=len(code) > MC, label=lab, pair=pid, project=rr.project,
                          toks=len(code) // 3, lines=code.count("\n") + 1))
    pid += 1
json.dump({"cases": cases, "pool": {"n_pairs": pid}, "split": "test_paired_high", "seed": 0}, open("results/imp_vs_pairs_eval_cases.json", "w"))
stats["pair_eval"] = {"pairs": pid, "cases": len(cases), "length_only": len_aurocs(cases)}
json.dump(stats, open("results/imp_train_build_stats.json", "w"), indent=1, default=str)
print(json.dumps({k: (v if k != "pairs" else {x: y for x, y in v.items() if x != "length_only"}) for k, v in stats.items()}, default=str)[:1800])
