"""Acceptance for the CoT trace bank (written BEFORE any bank exists). Run from repo root with .venv/bin/python (uses sc_cot.validate read-only).
 1 results/imp_trace_bank.jsonl exists, every row has fn, gen, sample, edit, raw, tags V,P (bool), engine, model; generator names are open-weight models only
   (no 'claude', 'gpt-4', 'gpt-5', 'gemini', 'ablit' in model strings)
 2 V and P are RECOMPUTED from raw (parse + validate against the function text from the imp_train_* files) for every 'orig' row and must equal the stored tags
 3 no function in the bank overlaps (normalised hash or commit id) a test set: PrimeVul val/test, VulSpot matched/test_paired_high, CASTLE (the pool files are
   train-only; re-checked here independently, Juliet exempt from commit check)
 4 X is only ever True on a Juliet bad item whose exec_sanitizer is True and whose verdict_raw is VULNERABLE; S only on VULNERABLE labels
 5 results/imp_trace_bank_counts.json totals equal a recount
 6 --selftest: a broken tagger (always-pass validator) must be caught by check 2
Usage: check_bank.py [--selftest]"""
import json, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S, benchdata as b
from reason_C_witness import parse_json
import pandas as pd

import os
R = "results/"
SUF = "_quick" if os.environ.get("IMP_BANK") == "quick" else ""
fails = []
funcs = {}
for f in ("imp_train_pairs_items.json", "imp_train_clean_lm_items.json", "imp_train_unfilt_lm_items.json", "imp_train_juliet_items.json"):
    try:
        for it in json.load(open(R + f))["items"]:
            funcs[it["id"]] = it
    except FileNotFoundError:
        fails.append("missing pool file " + f)
try:
    rows = [json.loads(l) for l in open(R + f"imp_trace_bank{SUF}.jsonl")]
except Exception as e:
    print("FAIL: bank missing:", e); sys.exit(1)
if not rows:
    print("FAIL: bank empty"); sys.exit(1)
BAN = ("claude", "gpt-4", "gpt-5", "gemini", "ablit", "anthropic", "openai/gpt-4")
selftest = "--selftest" in sys.argv
TRUE = json.load(open(R + "imp_true_cwe.json")) if os.path.exists(R + "imp_true_cwe.json") else {}
for r in rows:
    for k in ("fn", "gen", "sample", "edit", "raw", "V", "P", "engine", "model"):
        if k not in r:
            fails.append(f"row missing {k}"); break
    if any(x in str(r.get("model", "")).lower() for x in BAN):
        fails.append("non-open or banned model: " + str(r.get("model")))
bad = 0
for r in rows:
    if r["edit"] != "orig" or r["fn"] not in funcs:
        continue
    d = parse_json(r["raw"])
    f = funcs[r["fn"]]
    if selftest:
        v = S.validate(d, f["code"], broken=True)
    else:
        v = S.validate(d, f["code"]) if d is not None else dict(valid=False, verdict_raw=None, verdict_final="UNCERTAIN")
    V = v["verdict_raw"] == f["label"]
    if "K" in r and not selftest:
        from cyberdef.cwe_oracle import CWE_ORACLE
        tr = [c for c in TRUE.get(r["fn"], []) if c in CWE_ORACLE]
        Kc = (v.get("cwe_id") in tr) if tr else None
        Oc = (v.get("oracle") in {CWE_ORACLE[c] for c in tr}) if tr else None
        if Kc != r["K"] or Oc != r["O"]:
            bad += 1
    P = bool(v["valid"]) and v["verdict_final"] == v["verdict_raw"]
    if V != r["V"] or P != r["P"]:
        bad += 1
if bad:
    fails.append(f"{bad} rows whose V/P tags differ from an independent recomputation")
if selftest:
    print("SELFTEST OK: broken tagger caught (%d mismatches)" % bad if bad else "SELFTEST FAIL: broken tagger not caught"); sys.exit(0 if bad else 1)
unk = [r["fn"] for r in rows if r["fn"] not in funcs]
if unk:
    fails.append(f"{len(unk)} rows for functions not in any pool file")
# overlap
cols = ["idx", "commit_id", "func_body"]
df = pd.read_parquet("data/vulspot/cpp/full/data.parquet", columns=cols).set_index("idx")
bh, bc = set(), set()
for s in ("validation", "test"):
    for r_ in b._load_split(b.spec("primevul"), s):
        bh.add(b.norm(r_["func"] or "")); bc.add(r_["commit_id"])
for n in ("vs_holdout_matched", "vs_nolinux_matched"):
    for c in json.load(open(R + f"{n}_cases.json"))["cases"]:
        bh.add(b.norm(c["code"]))
sp = json.load(open("data/vulspot/cpp/full/splits/project_holdout.json")); ch = json.load(open("data/vulspot/cpp/full/splits/chrono.json"))
for ids in (sp["test_paired_high"], ch["test_paired_high"]):
    for i in ids:
        bh.add(b.norm(df.loc[i].func_body or "")); bc.add(df.loc[i].commit_id)
for c in json.load(open(R + "xdata_castle_cases.json"))["cases"]:
    bh.add(b.norm(c["code"]))
seen = set()
for r in rows:
    if r["fn"] in seen or r["fn"] not in funcs:
        continue
    seen.add(r["fn"])
    f = funcs[r["fn"]]
    if b.norm(f["code"]) in bh:
        fails.append("bank function overlaps a test set by text: " + r["fn"]); break
    if r["fn"].startswith("vs") and df.loc[int(r["fn"][2:])].commit_id in bc:
        fails.append("bank function shares a commit with a test set: " + r["fn"]); break
for r in rows:
    f = funcs.get(r["fn"])
    if f is None:
        continue
    if r.get("X") is True and not (f.get("exec_sanitizer") and f["label"] == "VULNERABLE" and r["verdict_raw"] == "VULNERABLE"):
        fails.append("X tag on an ineligible trace " + r["fn"]); break
    if r.get("X_strict") is True and (r.get("X_strict_detail", {}).get("empty_crash") or not r["V"] or not r["P"] or not r.get("X_strict_detail", {}).get("witness_present")):
        fails.append("X_strict on an ineligible trace (empty input already crashes, or no V/P/witness) " + r["fn"]); break
    if r.get("S") is True and f["label"] != "VULNERABLE":
        fails.append("S tag on a non-vulnerable function"); break
try:
    cn = json.load(open(R + f"imp_trace_bank{SUF}_counts.json"))
    if cn["total_traces"] != sum(1 for r in rows if r["edit"] == "orig"):
        fails.append("counts total != recount")
    if cn["x_verified_traces_VP"] != sum(1 for r in rows if r["edit"] == "orig" and r.get("X") is True and r["P"]):
        fails.append("x_verified count != recount")
    if "x_strict_traces_total" in cn and cn["x_strict_traces_total"] != sum(1 for r in rows if r["edit"] == "orig" and r.get("X_strict") is True):
        fails.append("x_strict count != recount")
    if cn.get("arm7_feasible") != (cn.get("x_strict_traces_total", 0) >= 200):
        fails.append("arm7_feasible flag is not the STRICT-X gate")
except Exception as e:
    fails.append("counts file: %s" % e)
if fails:
    print("FAIL:"); [print(" -", f) for f in fails[:20]]; sys.exit(1)
print("PASS: bank verified, %d rows" % len(rows))
