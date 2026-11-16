"""Builds the CoT training item files (arm + verdict-only twin on IDENTICAL rows) from results/imp_trace_bank.jsonl.
Plain python (+ sc_cot SYSTEM, reason_C_witness.numbered). Selection rule (EXPERIMENT_PLAN_IMPROVE.md): per function, among traces with V and P and S!=False and X!=False,
most tags, then shortest, then generator order, then sample index.
Outputs results/imp_cot_<arm>_items.json and results/imp_cot_<arm>_twin_items.json for arm in 2, 3, 5clean, 5unfilt, 6, 7 + results/imp_cot_items_stats.json
(counts, drops, feasibility). Item order is fixed here (seed 0); train with --pair-batches so arm and twin see the same batches."""
import json, random, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S
from reason_C_witness import numbered, parse_json

import os
R = os.environ.get("IMP_RESULTS", "results").rstrip("/") + "/"
QUICK = os.environ.get("IMP_BANK", "full") == "quick"
SUF, PRE = ("_quick", "imp_cotq_") if QUICK else ("", "imp_cot_")
GEN_ORDER = {"g1": 0, "g14": 1, "g2": 2, "g3": 3, "g4": 4}
pools = {}
for k, f in (("A", "imp_train_pairs_items.json"), ("B", "imp_train_clean_lm_items.json"), ("C", "imp_train_unfilt_lm_items.json"), ("J", "imp_train_juliet_items.json"), ("J2", "imp_train_juliet2_items.json"), ("J3", "imp_train_juliet3_items.json"), ("Q", "imp_train_sqli_items.json")):
    if not os.path.exists(R + f):
        continue
    for it in json.load(open(R + f))["items"]:
        pools.setdefault(it["id"], dict(it, pools=set()))["pools"].add(k)
rows = [json.loads(l) for l in open(R + f"imp_trace_bank{SUF}.jsonl")]
orig = {}
edits = {}
for r in rows:
    if r["edit"] == "orig":
        orig.setdefault(r["fn"], []).append(r)
    else:
        edits.setdefault(r["fn"], []).append(r)


def rank_key(r):
    return (-(1 + (r["S"] is True) + (r["X"] is True) + (r.get("X_strict") is True) + (r.get("K") is True) + (r.get("O") is True)), len(r["raw"]), GEN_ORDER.get(r["gen"], 9), r["sample"])


def select(fn, pool_gens=None):
    c = [r for r in orig.get(fn, []) if r["V"] and r["P"] and r["S"] is not False and r["X"] is not False and r.get("K") is not False and r.get("O") is not False and (pool_gens is None or r["gen"] in pool_gens)]
    c.sort(key=rank_key)
    return c[0] if c else None


def cot_item(it, tr, code=None, raw=None, rank=True):
    code = code or it["code"]
    d = parse_json(raw or tr["raw"])
    return dict(id=it["id"], code=code, code_chars=len(code), toks=max(1, len(code) // 3), label=it["label"], project=it.get("project"), pair=it.get("pair"),
                system=S.SYSTEM, user=numbered(code), target=json.dumps(d, ensure_ascii=False), rank=rank, gen=tr["gen"])


def twin_item(it, code=None, rank=True):
    code = code or it["code"]
    return dict(id=it["id"], code=code, code_chars=len(code), toks=max(1, len(code) // 3), label=it["label"], project=it.get("project"), pair=it.get("pair"), rank=rank)


def dump(name, cot, twin, note):
    json.dump({"items": cot, "n": len(cot), "note": note, "bank": "quick" if QUICK else "full"}, open(R + f"{PRE}{name}_items.json", "w"))
    json.dump({"items": twin, "n": len(twin), "bank": "quick" if QUICK else "full", "note": "verdict-only twin of " + name + " (same rows, same order)"}, open(R + f"{PRE}{name}_twin_items.json", "w"))
    return {"n_items": len(cot)}


stats = {}
rng = random.Random(0)
# ---------- pairs from pool A (consecutive vuln, fix in the items file) ----------
a_items = json.load(open(R + "imp_train_pairs_items.json"))["items"]
pairs = [(a_items[i], a_items[i + 1]) for i in range(0, len(a_items), 2)]
if QUICK:
    a_items = a_items[:1600]
    pairs = pairs[:800]
assert all(v['label'] == 'VULNERABLE' and f['label'] == 'SAFE' and v['pair'] == f['pair'] for v, f in pairs), 'pair order broken'
sel_A = {it["id"]: select(it["id"]) for it in a_items}
# ---------- per-category balancing (pre-registered: EXPERIMENT_PLAN_IMPROVE.md, balancing amendment) ----------
import math
from cyberdef.cwe_oracle import CWE_ORACLE
TRUE_CWE = json.load(open(R + "imp_true_cwe.json")) if os.path.exists(R + "imp_true_cwe.json") else {}
PARTNER = {}
for _k, _f in (("A", "imp_train_pairs_items.json"), ("B", "imp_train_clean_lm_items.json"), ("C", "imp_train_unfilt_lm_items.json"), ("J", "imp_train_juliet_items.json"),
               ("J2", "imp_train_juliet2_items.json"), ("J3", "imp_train_juliet3_items.json"), ("Q", "imp_train_sqli_items.json")):
    if os.path.exists(R + _f):
        _its = json.load(open(R + _f))["items"]
        for _i in range(0, len(_its) - 1, 2):
            if _its[_i]["label"] != _its[_i + 1]["label"]:
                PARTNER.setdefault(_its[_i]["id"], _its[_i + 1]["id"]); PARTNER.setdefault(_its[_i + 1]["id"], _its[_i]["id"])
MONITOR_CATS = ["memory/asan", "integer", "lsan", "tsan", "resource", "cmd_injection", "format_string", "path_traversal", "sqli"]
FLOOR_SHARE = 0.05


def gid_of(fid):
    p = PARTNER.get(fid)
    return min(fid, p) if p else fid


def category_of_group(gid):
    for fid in (gid, PARTNER.get(gid)):
        cw = [c for c in TRUE_CWE.get(fid, []) if c in CWE_ORACLE] if fid else []
        if cw:
            o = CWE_ORACLE[sorted(cw)[0]]
            return "memory/asan" if o == "asan" else o
    return "unknown"


def balance(cot, twin, seed=0):
    """Stratify by monitor category (pair-aware: whole pair groups are resampled so SAFE twins stay with their vulnerable partner), upsample categories below FLOOR_SHARE of the
    rows with replacement, shrink the largest category without replacement so the total stays (about) fixed. cot and twin are parallel lists: the twin gets the IDENTICAL row multiset."""
    r = random.Random(seed)
    if not cot:      # nothing to balance (e.g. no pair with both traces qualifying): report an empty arm instead of crashing
        return cot, twin, {"empty": True, "floor_share": FLOOR_SHARE, "floor_rows": 0, "rows_before": 0, "rows_after": 0, "category_rows_before": {}, "category_rows_after": {}, "safe_fraction_before": 0.0, "safe_fraction_after": 0.0, "largest_category_shrunk": None}
    groups = {}
    for i, x in enumerate(cot):
        groups.setdefault(gid_of(x["id"]), []).append(i)
    cats = {}
    for g in groups:
        cats.setdefault(category_of_group(g), []).append(g)
    N = len(cot)
    rows_of = lambda gs: sum(len(groups[g]) for g in gs)
    before = {c: rows_of(gs) for c, gs in cats.items()}
    keep = {c: list(gs) for c, gs in cats.items()}
    fl = math.ceil(FLOOR_SHARE * N)
    for c in MONITOR_CATS:
        if c in keep and 0 < rows_of(keep[c]) < fl:
            while rows_of(keep[c]) < fl:
                keep[c].append(r.choice(cats[c]))
    total = sum(rows_of(v) for v in keep.values())
    big = max(keep, key=lambda c: rows_of(keep[c]))
    while total > N and len(keep[big]) > 1 and rows_of(keep[big]) - len(groups[keep[big][-1]]) >= fl:
        r.shuffle(keep[big])
        g = keep[big].pop()
        total -= len(groups[g])
    order = [g for gs in keep.values() for g in gs]
    r.shuffle(order)
    new_c, new_t = [], []
    for g in order:
        for i in groups[g]:
            new_c.append(cot[i]); new_t.append(twin[i])
    if len(new_c) % 2:
        k = next((j for j in range(len(order) - 1, -1, -1) if len(groups[order[j]]) % 2 == 1), None)
        if k is not None:
            gdrop = order[k]
            rm = set(id(x) for x in [cot[i] for i in groups[gdrop]][:1])
            for j in range(len(new_c) - 1, -1, -1):
                if id(new_c[j]) in rm:
                    new_c.pop(j); new_t.pop(j); break
        else:
            new_c.pop(); new_t.pop()
    after = {}
    for x in new_c:
        c = category_of_group(gid_of(x["id"]))
        after[c] = after.get(c, 0) + 1
    safe = lambda L: round(sum(1 for x in L if x["label"] == "SAFE") / max(1, len(L)), 4)
    return new_c, new_t, {"floor_share": FLOOR_SHARE, "floor_rows": fl, "rows_before": N, "rows_after": len(new_c), "category_rows_before": dict(sorted(before.items())),
                          "category_rows_after": dict(sorted(after.items())), "safe_fraction_before": safe(cot), "safe_fraction_after": safe(new_c), "largest_category_shrunk": big}


# ---------- arm 2: pool A functions (+ Juliet) ----------
cot2, tw2, drop2 = [], [], 0
j_items = [it for it in pools.values() if it["pools"] & {"J", "J2", "J3", "Q"}]      # execution-verified pools: Juliet sanitizer, Juliet injection (J2), synthetic SQLi (Q)
for it in [pools[i["id"]] for i in a_items] + j_items:
    tr = select(it["id"])
    if not tr:
        drop2 += 1; continue
    cot2.append(cot_item(it, tr, rank=False)); tw2.append(twin_item(it, rank=False))
cot2, tw2, bal2 = balance(cot2, tw2, seed=0)
stats["arm2"] = dict(**dump("2", cot2, tw2, "pool A + Juliet/J2/SQLi functions with a qualifying trace, category-balanced (twin = identical row multiset)"), balance=bal2, dropped_no_trace=drop2,
                     by_label={l: sum(1 for x in cot2 if x["label"] == l) for l in ("VULNERABLE", "SAFE")}, from_juliet=sum(1 for x in cot2 if x["id"].startswith("juliet")))
# ---------- arm 3: pairs where vuln has V+P(+S) and fix has V+P ----------
cot3, tw3 = [], []
for v, f in pairs:
    tv, tf = select(v["id"]), select(f["id"])
    if tv and tf:
        cot3 += [cot_item(pools[v["id"]], tv), cot_item(pools[f["id"]], tf)]
        tw3 += [twin_item(pools[v["id"]]), twin_item(pools[f["id"]])]
cot3, tw3, bal3 = balance(cot3, tw3, seed=1)
stats["arm3"] = dict(**dump("3", cot3, tw3, "pool-A pairs, pair-adjacent, rank=1 (use --pair-loss 1), category-balanced"), balance=bal3, pairs=len(cot3) // 2, pairs_total=len(pairs))
# ---------- arm 6: pairs first (rank=1), then singles and length-edited copies (rank=0) ----------
cot6, tw6 = list(cot3), list(tw3)
singles, singles_tw = [], []
used = {x["id"] for x in cot3}
for x, t in zip(cot2, tw2):
    if x["id"] in used:
        continue
    singles.append(dict(x, rank=False)); singles_tw.append(dict(t, rank=False))
n_edit = 0
for x in cot2:
    tr = select(x["id"])
    base_v = tr["verdict_final"] if tr else None
    for e in edits.get(x["id"], []):
        if e["gen"] == x["gen"] and e["V"] and e["P"] and e["verdict_final"] == base_v and e.get("edited_code"):
            it = pools[x["id"]]
            singles.append(cot_item(it, e, code=e["edited_code"], raw=e["raw"], rank=False)); singles_tw.append(twin_item(it, code=e["edited_code"], rank=False))
            n_edit += 1
order = list(range(len(singles))); rng.shuffle(order)
singles = [singles[i] for i in order]; singles_tw = [singles_tw[i] for i in order]
cot6 += singles; tw6 += singles_tw
if len(cot6) % 2:
    cot6.pop(); tw6.pop()
stats["arm6"] = dict(**dump("6", cot6, tw6, "pairs (rank=1) first, then singles + length-edited copies with the same verdict"), pairs=len(cot3) // 2, edited_copies=n_edit)
# ---------- arm 5: clean (pool B) vs unfiltered (pool C), generator g1 only, same count ----------
def pool_items(k):
    its = json.load(open(R + {"B": "imp_train_clean_lm_items.json", "C": "imp_train_unfilt_lm_items.json"}[k]))["items"]
    out, tws = [], []
    for it in its:
        tr = select(it["id"], {"g1"})
        if tr:
            out.append(cot_item(pools[it["id"]], tr, rank=False)); tws.append(twin_item(pools[it["id"]], rank=False))
    return out, tws

cb, tb = pool_items("B") if not QUICK else ([], []); cc, tc = pool_items("C") if not QUICK else ([], [])
n5 = min(len(cb), len(cc)) // 2 * 2
stats["arm5"] = dict(**dump("5clean", cb[:n5], tb[:n5], "pool B (clean) first n"), **{})
stats["arm5"].update(n=n5, clean_available=len(cb), unfilt_available=len(cc))
dump("5unfilt", cc[:n5], tc[:n5], "pool C (unfiltered) first n")
# ---------- arm 7: STRICT-X Juliet traces (feasibility-gated on the STRICT count) ----------
x_traces = [r for fn, rs in orig.items() for r in rs if r.get("X_strict") is True]
x_loose = [r for fn, rs in orig.items() for r in rs if r["X"] is True and r["P"]]
c7, t7 = [], []
strict_fns = {r["fn"] for r in x_traces}
for fn in sorted(strict_fns):
    it = pools[fn]
    tr = min((r for r in x_traces if r["fn"] == fn), key=rank_key)
    c7.append(cot_item(it, tr, rank=False)); t7.append(twin_item(it, rank=False))
    good = pools.get(fn[:-1] + "S")
    gt = select(good["id"]) if good else None
    if gt:
        c7.append(cot_item(good, gt, rank=False)); t7.append(twin_item(good, rank=False))
if len(c7) % 2:
    c7.pop(); t7.pop()
stats["arm7"] = dict(**dump("7", c7, t7, "STRICT-X Juliet bad traces + V+P SAFE traces of their good twins"), x_loose_traces=len(x_loose), x_strict_traces=len(x_traces),
                     x_strict_functions=len(strict_fns), gate_min_strict_x_traces=200, feasible=len(x_traces) >= 200)
json.dump(stats, open(R + f"{PRE}items_stats.json", "w"), indent=1)
print(json.dumps(stats, indent=1))
