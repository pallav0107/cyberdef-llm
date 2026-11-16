"""Stage D / D0 split by CWE class (post-hoc split requested by the coordinator; classes from results/imp_castle_input_channels.json).
(a) sanitizer-detectable = cwe in sanitizer_cwe_set; (b) crash-like-other = outside that set but an abort/crash/hang is plausible
(134, 401, 617, 628, 761, 770, 835, 843); (c) non-crash = everything else outside the set (22, 78, 89, 253, 327, 362, 522, 798 ...).
(b) vs (c) is MY judgement call; (a) vs outside is the file's list."""
import json, re, sys
sys.path.insert(0, "scripts")
from length_baseline import auroc, hanley_mcneil_se
ch = json.load(open("results/imp_castle_input_channels.json"))["cwe_ceiling"]
SAN = set(ch["sanitizer_cwe_set"]); CRASHLIKE = {134, 401, 617, 628, 761, 770, 835, 843}
def cls(i):
    c = int(re.match(r"CASTLE-(\d+)-", i).group(1))
    return "a_sanitizer_detectable" if c in SAN else "b_crash_like_other" if c in CRASHLIKE else "c_non_crash"
d0 = {p["id"] + p["label"]: p for p in json.load(open("results/reason_D0_castle_preflight_v2.json"))["per_case"]}
out = {"classes": {"a": "CWE in sanitizer_cwe_set", "b": sorted(CRASHLIKE), "c": "other outside the set"}, "models": {}, "floor": {}}
def stat(rows, key):
    y = [1 if r["label"] == "VULNERABLE" else 0 for r in rows]; n1 = sum(y)
    if n1 in (0, len(y)): return None
    s = [1.0 if key(r) else 0.0 for r in rows]; a = auroc(s, y)
    return {"n": len(y), "n_vuln": n1, "vuln_hit": sum(1 for r, v in zip(rows, y) if v and key(r)), "safe_hit": sum(1 for r, v in zip(rows, y) if not v and key(r)),
            "auroc": round(a, 3), "se_hm": round(hanley_mcneil_se(a, n1, len(y) - n1), 3)}
for name in ("a_sanitizer_detectable", "b_crash_like_other", "c_non_crash", "ALL"):
    rows = [dict(r, _k=r["id"] + r["label"]) for r in d0.values() if name == "ALL" or cls(r["id"]) == name]
    out["floor"][name] = stat(rows, lambda r: r["sanitizer_any"])
for t in ("base7b", "tuned7b"):
    ex = json.load(open(f"results/reason_D_{t}_castle.json"))["per_case"]
    res = {}
    for name in ("a_sanitizer_detectable", "b_crash_like_other", "c_non_crash", "ALL"):
        rows = [p for p in ex if name == "ALL" or cls(p["id"]) == name]
        r = {"model_confirmed": stat(rows, lambda p: p["confirmed"])}
        newb = sum(1 for p in rows if p["label"] == "VULNERABLE" and p["confirmed"] and not d0[p["id"] + p["label"]]["sanitizer_any"])
        both = sum(1 for p in rows if p["label"] == "VULNERABLE" and p["confirmed"] and d0[p["id"] + p["label"]]["sanitizer_any"])
        floor_only = sum(1 for p in rows if p["label"] == "VULNERABLE" and not p["confirmed"] and d0[p["id"] + p["label"]]["sanitizer_any"])
        r["vulnerable_confirmed_by_model_NOT_by_floor"] = newb; r["confirmed_by_both"] = both; r["floor_only_missed_by_model"] = floor_only
        r["union_model_or_floor"] = stat(rows, lambda p: p["confirmed"] or d0[p["id"] + p["label"]]["sanitizer_any"])
        res[name] = r
    out["models"][t] = res
json.dump(out, open("results/reason_D_byclass.json", "w"), indent=1)
for name in ("a_sanitizer_detectable", "b_crash_like_other", "c_non_crash", "ALL"):
    f = out["floor"][name]; print(name, "FLOOR", f)
    for t in ("base7b", "tuned7b"):
        r = out["models"][t][name]; print("   ", t, "model", r["model_confirmed"], "| new-vs-floor", r["vulnerable_confirmed_by_model_NOT_by_floor"], "both", r["confirmed_by_both"], "floor-only", r["floor_only_missed_by_model"], "| union", r["union_model_or_floor"] and (r["union_model_or_floor"]["vuln_hit"], r["union_model_or_floor"]["safe_hit"], r["union_model_or_floor"]["auroc"]))
