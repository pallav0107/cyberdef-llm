"""Stage D: execute model witnesses on CASTLE programs in the sandbox (src/cyberdef/exec_harness.py).
Input: results/reason_D_<tag>_castle_cache.jsonl (generations from reason_C_witness.py with GEN_ONLY_CASES).
Usage: reason_D_exec.py <tag>"""
import json, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0, "scripts"); sys.path.insert(0, "src")
from length_baseline import auroc, hanley_mcneil_se
from reason_C_witness import parse_json, witness_null
from cyberdef import exec_harness as eh
tag = sys.argv[1]
cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
cache = {}
for l in Path(f"results/reason_D_{tag}_castle_cache.jsonl").read_text().splitlines():
    r = json.loads(l); cache[r["id"] + r["label"]] = r["raw"]
def one(c):
    d = parse_json(cache[c["id"] + c["label"]])
    verdict = str(d.get("verdict", "")).upper() if d else None
    parsed = verdict in ("VULNERABLE", "SAFE")
    wn = True if not parsed else witness_null(d)
    row = {"executed": False, "crash_class": None, "safe_counterpart_crashes": None,   # CASTLE has no paired safe program -> null
           "id": c["id"], "label": c["label"], "parsed": parsed, "verdict": verdict, "witness_null": wn,
           "compiled": False, "sanitizer": False, "kind": None, "timed_out": False, "confirmed": False, "code_chars": c["code_chars"]}
    if parsed and not wn:
        argv, stdin = eh.witness_to_input(d.get("witness"))
        r = eh.run_c(c["code"], argv, stdin, timeout=5)
        row.update(image=r.get("image"), executed=bool(r["compiled"]), crash_class=(r["kind"] if r["sanitizer"] else None), compiled=r["compiled"], sanitizer=r["sanitizer"], kind=r["kind"], timed_out=r["timed_out"])
        row["confirmed"] = bool(verdict == "VULNERABLE" and r["sanitizer"])
    return row
with ThreadPoolExecutor(4) as ex:
    per = list(ex.map(one, cases))
y = [1 if p["label"] == "VULNERABLE" else 0 for p in per]
n1 = sum(y); n0 = len(y) - n1
def A(score):
    a = auroc(score, y); return {"auroc": round(a, 4), "se_hm": round(hanley_mcneil_se(a, n1, n0), 4)}
res = {"stage": "D", "tag": tag, "set": "castle", "n_total": len(per), "n_vuln_cases": n1, "n_safe_cases": n0,
       "n_parsed": sum(p["parsed"] for p in per), "n_witness_null": sum(p["witness_null"] for p in per),
       "n_executed": sum(p["parsed"] and not p["witness_null"] for p in per),
       "n_compiled": sum(p["compiled"] for p in per), "n_compile_fail": sum(p["parsed"] and not p["witness_null"] and not p["compiled"] for p in per),
       "n_confirmed": sum(p["confirmed"] for p in per),
       "confirmed_among_vuln": sum(p["confirmed"] for p in per if p["label"] == "VULNERABLE"),
       "confirmed_among_safe": sum(p["confirmed"] for p in per if p["label"] == "SAFE"),
       "sanitizer_on_safe_with_witness": sum(p["sanitizer"] for p in per if p["label"] == "SAFE"),
       "s3_confirmed": A([1.0 if p["confirmed"] else 0.0 for p in per]),
       "s0_plain_verdict": A([(1 if p["verdict"] == "VULNERABLE" else 0) if p["parsed"] else .5 for p in per]),
       "length_only": A([p["code_chars"] for p in per])}
d0 = Path("results/reason_D0_castle_preflight_v2.json")
if d0.exists():
    d0j = json.load(open(d0)); m = {r["id"] + r["label"]: r for r in d0j["per_case"]}
    res["comparator_empty_input_sanitizer_no_model"] = A([1.0 if m[p["id"] + p["label"]]["sanitizer_any"] else 0.0 for p in per])
    res["comparator_d0_image"] = d0j["image"]
for t in ("flawfinder", "semgrep"):
    f = Path(f"results/reason_B_sast_{t}_castle.json")
    if f.exists():
        m = {r["id"] + r["label"]: r for r in json.load(open(f))["per_case"]}
        res[f"comparator_sast_{t}"] = A([m[p["id"] + p["label"]]["score"] for p in per])
vv = [p for p in per if p["label"] == "VULNERABLE"]; ss = [p for p in per if p["label"] == "SAFE"]
res["image"] = next((p.get("image") for p in per if p.get("image")), None)
res["witness_confirmed_rate_on_vulnerable"] = {"confirmed": sum(p["confirmed"] for p in vv), "n": len(vv), "rate": round(sum(p["confirmed"] for p in vv) / len(vv), 4)}
res["false_confirmations_on_safe"] = {"confirmed": sum(p["confirmed"] for p in ss), "n": len(ss)}
res["right_verdict_wrong_witness"] = {"n": sum(1 for p in vv if p["verdict"] == "VULNERABLE" and not p["witness_null"] and not p["confirmed"]),
                                      "of_vulnerable_verdicts_on_vulnerable": sum(1 for p in vv if p["verdict"] == "VULNERABLE")}
res["compile_failures_among_executed"] = res["n_compile_fail"]
res["unparsed"] = sum(not p["parsed"] for p in per)
res["per_case"] = per
json.dump(res, open(f"results/reason_D_{tag}_castle.json", "w"))
print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))
