"""Acceptance for the #1 / #7 training-data builds (written BEFORE the build). Run from repo root with .venv/bin/python.
 1 each items file has exactly 2*pairs items in pair-adjacent order: items[2k] VULNERABLE, items[2k+1] SAFE, same pair id; pairs == 1000
 2 #1: vuln and fix differ (normalised text); both <= 4000 chars; linux share of pairs <= 0.30 + 0.02
 3 NO overlap (normalised hash OR commit id) with: PrimeVul validation+test, VulSpot matched cases (both), test_paired_high (both splits), CASTLE
 4 #7 clean and unfiltered sets have the SAME number of pairs and both length-only AUROCs (chars, tokens) in [0.45,0.55]
 5 #7 clean set contains only clean==True & label_conflict==False rows; the unfiltered set contains at least one row that is not (reported count)
 6 results/imp_vs_pairs_eval_cases.json: len(cases)==2*pairs, no case id appears in any training file
Fail-first self-check: --selftest injects one test function into a copy of the pairs file and requires check 3 to catch it."""
import json, sys, copy
sys.path.insert(0, "src")
import pandas as pd
from cyberdef import benchdata as b

R = "results/"
selftest = "--selftest" in sys.argv
fails = []
cols = ["idx", "commit_id", "func_body", "clean", "label_conflict"]
df = pd.read_parquet("data/vulspot/cpp/full/data.parquet", columns=cols).set_index("idx")
S = "data/vulspot/cpp/full/splits/"
ph = json.load(open(S + "project_holdout.json")); ch = json.load(open(S + "chrono.json"))
bh, bc = set(), set()
for s in ("validation", "test"):
    for r in b._load_split(b.spec("primevul"), s):
        bh.add(b.norm(r["func"] or "")); bc.add(r["commit_id"])
for n in ("vs_holdout_matched", "vs_nolinux_matched"):
    for c in json.load(open(R + f"{n}_cases.json"))["cases"]:
        bh.add(b.norm(c["code"])); bc.add(df.loc[int(c["id"][2:])].commit_id)
for ids in (ph["test_paired_high"], ch["test_paired_high"]):
    for i in ids:
        r = df.loc[i]; bh.add(b.norm(r.func_body or "")); bc.add(r.commit_id)
for c in json.load(open(R + "xdata_castle_cases.json"))["cases"]:
    bh.add(b.norm(c["code"]))


def load(n):
    try:
        return json.load(open(R + n))
    except Exception as e:
        print("FAIL: cannot read", n, e); sys.exit(1)


def auroc(s, y):
    P = [a for a, b_ in zip(s, y) if b_]; N = [a for a, b_ in zip(s, y) if not b_]
    return sum(1.0 if a > b_ else 0.5 if a == b_ else 0.0 for a in P for b_ in N) / (len(P) * len(N))


def structure(name, d, want_pairs=1000):
    it = d["items"]
    if d.get("pairs") != want_pairs or len(it) != 2 * want_pairs:
        fails.append(f"{name}: pairs/items {d.get('pairs')}/{len(it)} != {want_pairs}")
    for k in range(0, len(it) - 1, 2):
        if not (it[k]["label"] == "VULNERABLE" and it[k + 1]["label"] == "SAFE" and it[k]["pair"] == it[k + 1]["pair"]):
            fails.append(f"{name}: pair adjacency broken at {k}"); break
    return it


def overlap(name, it):
    for x in it:
        r = df.loc[int(x["id"][2:])]
        if b.norm(r.func_body) in bh or r.commit_id in bc:
            fails.append(f"{name}: {x['id']} overlaps a test/banned set"); return True
    return False


pairs = load("imp_train_pairs_items.json")
it1 = structure("pairs", pairs)
if selftest:
    r = df.loc[ph["test_paired_high"][0]]
    it1 = copy.deepcopy(it1); it1[0] = dict(it1[0], id=f"vs{ph['test_paired_high'][0]}")
    if overlap("selftest", it1):
        print("SELFTEST OK: injected test-set function was caught"); sys.exit(0)
    print("SELFTEST FAIL: overlap check missed an injected test function"); sys.exit(1)
overlap("pairs", it1)
for k in range(0, len(it1), 2):
    v, f = it1[k], it1[k + 1]
    if b.norm(df.loc[int(v["id"][2:])].func_body) == b.norm(df.loc[int(f["id"][2:])].func_body):
        fails.append("pairs: vuln == fix"); break
    if v["code_chars"] > 4000 or f["code_chars"] > 4000:
        fails.append("pairs: function longer than 4000 chars"); break
lin = sum(1 for k in range(0, len(it1), 2) if "linux" in it1[k]["project"].lower()) / (len(it1) / 2)
if lin > 0.32:
    fails.append(f"pairs: linux share {lin:.3f} > 0.32")
c7, u7 = load("imp_train_clean_lm_items.json"), load("imp_train_unfilt_lm_items.json")
ic, iu = structure("clean", c7), structure("unfilt", u7)
if c7["pairs"] != u7["pairs"]:
    fails.append("clean/unfiltered pair counts differ")
for nm, it in (("clean", ic), ("unfilt", iu)):
    overlap(nm, it)
    y = [1 if x["label"] == "VULNERABLE" else 0 for x in it]
    for key in ("code_chars", "toks"):
        a = auroc([x[key] for x in it], y)
        if not 0.45 <= a <= 0.55:
            fails.append(f"{nm}: length-only {key} AUROC {a:.3f} outside [0.45,0.55]")
bad_ic = [x for x in ic if not (bool(df.loc[int(x["id"][2:])].clean) and not bool(df.loc[int(x["id"][2:])].label_conflict))]
if bad_ic:
    fails.append(f"clean set contains {len(bad_ic)} non-clean rows")
n_unclean = sum(1 for x in iu if not (bool(df.loc[int(x["id"][2:])].clean) and not bool(df.loc[int(x["id"][2:])].label_conflict)))
print("unfiltered set rows that are NOT clean:", n_unclean, "of", len(iu))
if n_unclean == 0:
    fails.append("unfiltered set has no unclean rows: the label-quality variable is not varied")
ev = load("imp_vs_pairs_eval_cases.json")
ids = {x["id"] for it in (it1, ic, iu) for x in it}
if len(ev["cases"]) != 2 * ev["pool"]["n_pairs"] or any(c["id"] in ids for c in ev["cases"]):
    fails.append("eval cases malformed or present in a training file")
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS: #1/#7 data builds verified")
