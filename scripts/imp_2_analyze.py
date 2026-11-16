"""#2 summary across arms (reads results/imp_2_fuzz_<arm>_b60.json that exist; writes results/imp_2_summary.json). Pre-registered quantities:
per arm AUROC (time score) +/- HM SE on all 198 and on programs compiled in both that arm and the empty-input floor, crash rates, secondary any-crash AUROC (not the pre-registered score),
floor AUROC (reason_D0_castle_preflight, read-only), length-only, and the attribution differences (iii)-(i), (iii)-(ii) with conservative SE_diff and the 2*SE bar.
  python3 scripts/imp_2_analyze.py"""
import json, math, os, sys
sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, hm_se, r4

R = "results/"
floor = {p["id"]: p for p in json.load(open(R + "reason_D0_castle_preflight.json"))["per_case"]}
arms = {}
for a in ("empty", "random", "random_resized", "llm", "llm_direct"):
    f = R + f"imp_2_fuzz_{a}_b60.json"
    if os.path.exists(f):
        arms[a] = json.load(open(f))
out = {"floor_source": "results/reason_D0_castle_preflight.json (gcc ASan+UBSan, empty stdin)", "arms": {}}
ids = sorted(floor)
yall = {i: 1 if next(p for p in next(iter(arms.values()))["per_case"] if p["id"] == i)["label"] == "VULNERABLE" else 0 for i in ids} if arms else {}
if arms:
    y = [yall[i] for i in ids]
    fa = auroc([float(floor[i]["sanitizer"]) for i in ids], y)
    out["floor_auroc_all198"] = r4(fa); out["floor_se"] = r4(hm_se(fa, 99, 99))
for a, d in arms.items():
    pc = {p["id"]: p for p in d["per_case"]}
    y = [yall[i] for i in ids]
    sc = [pc[i]["score"] for i in ids]
    au = auroc(sc, y); se = hm_se(au, 99, 99)
    both = [i for i in ids if pc[i]["compiled"] and floor[i]["compiled"]]
    yb = [yall[i] for i in both]
    anyc = [1.0 if (pc[i]["confirmed_crash"] or pc[i]["unconfirmed_crash"]) else 0.0 for i in ids]
    out["arms"][a] = {"n": len(ids), "auroc": r4(au), "se": r4(se), "n_compiled_in_both": len(both), "auroc_compiled_in_both": r4(auroc([pc[i]["score"] for i in both], yb)),
                      "floor_auroc_compiled_in_both": r4(auroc([float(floor[i]["sanitizer"]) for i in both], yb)),
                      "any_crash_auroc_secondary": r4(auroc(anyc, y)), "summary": d["summary"], "budget_s": d["budget_s"], "seconds": d["seconds"],
                      "afl_aborted": d["summary"].get("afl_aborted_all_seeds_timeout_or_crash"),
                      "seed_rule": {"programs_with_confirmed_seed_crash_counted_at_t0": sum(1 for i in ids if (pc[i]["seed_crash"] or {}).get("confirmed")),
                                    "of_which_afl_aborted": sum(1 for i in ids if (pc[i]["seed_crash"] or {}).get("confirmed") and pc[i]["afl_aborted"]),
                                    "afl_aborted_without_seed_crash_(seed_timeouts_counted_no_crash)": sum(1 for i in ids if pc[i]["afl_aborted"] and not pc[i]["seed_crash"])},
                      "sensitivity_without_CASTLE-674-10": (lambda ii: {"auroc": r4(auroc([pc[i]["score"] for i in ii], [yall[i] for i in ii])), "n": len(ii)})([i for i in ids if i != "CASTLE-674-10.c"])}
def diff(a, b):
    if a in out["arms"] and b in out["arms"]:
        x, y_ = out["arms"][a], out["arms"][b]
        se = math.sqrt(x["se"] ** 2 + y_["se"] ** 2)
        return {"delta": r4(x["auroc"] - y_["auroc"]), "se_diff": r4(se), "over_2se": (x["auroc"] - y_["auroc"]) > 2 * se}
out["attribution"] = {"llm_minus_empty": diff("llm", "empty"), "llm_minus_random": diff("llm", "random"), "random_minus_empty": diff("random", "empty"),
                      "llm_direct_minus_empty": diff("llm_direct", "empty")}
if "llm" in arms and "random" in arms:
    s = json.load(open(R + "imp_2_llm_seeds.json"))
    rs = sorted(b for p in arms["random"]["per_case"] for b in p["seed_bytes"])
    ls = sorted(s["seed_bytes_sorted"])
    def ks(a, b):
        i = j = 0; d = 0.0
        while i < len(a) and j < len(b):
            x = min(a[i], b[j])
            while i < len(a) and a[i] <= x: i += 1
            while j < len(b) and b[j] <= x: j += 1
            d = max(d, abs(i / len(a) - j / len(b)))
        return d
    D = ks(ls, rs); n, m = len(ls), len(rs)
    en = math.sqrt(n * m / (n + m)); p = 2 * sum((-1) ** (k - 1) * math.exp(-2 * (k * en * D) ** 2) for k in range(1, 100))
    out["seed_size_ks"] = {"D": r4(D), "p_approx": r4(min(1.0, max(0.0, p))), "llm_mean_bytes": r4(sum(ls) / len(ls)), "random_mean_bytes": r4(sum(rs) / len(rs)),
                           "random_resized_control_needed": p < 0.05}
json.dump(out, open(R + "imp_2_summary.json", "w"), indent=1)
print(json.dumps({k: v for k, v in out.items() if k != "arms"}, indent=1))
for a, v in out["arms"].items():
    print(a, {k: v[k] for k in ("auroc", "se", "auroc_compiled_in_both", "floor_auroc_compiled_in_both", "any_crash_auroc_secondary", "afl_aborted")},
          "vuln", v["summary"]["confirmed_crash_on_vulnerable"]["k"], "safe", v["summary"]["confirmed_crash_on_safe"]["k"])
