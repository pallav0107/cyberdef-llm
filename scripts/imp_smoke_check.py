"""Verdict of the 30-step GPU smoke (P16_z0_imp_smoke). Reads results/imp_smoke_{a,b,ref}.log (Trainer stdout) and out/imp_smoke_{a,b}_imp_train_log.json.
Pre-registered criteria (fixed before the run):
  F1 every logged loss and grad_norm is finite (no NaN/inf) in all three runs
  F2 imp flags-off (a) and imp --pair-loss 1 (b): mean of the last 2 logged losses < mean of the first 2 (loss decreases)
  F3 grad-norm sanity: median grad_norm of (a) within [1/3, 3] of the train_devign reference (ref); (b) within [1/5, 5] of ref
  F4 (b) logged a finite pair-loss mean (the ranking term ran)
Writes results/imp_smoke_result.json {"pass": bool, ...}. Run: python3 scripts/imp_smoke_check.py   (plain python, cwd ~/cyberdef-lm or repo root)"""
import json, math, os, re, statistics, sys

R = "results/"
LOSS = re.compile(r"""['"]loss['"]:\s*['"]?([-+0-9.eEnaif]+)""")
GN = re.compile(r"""['"]grad_norm['"]:\s*['"]?([-+0-9.eEnaif]+)""")


def parse(tag):
    try:
        t = open(R + f"imp_smoke_{tag}.log", errors="replace").read()
    except FileNotFoundError:
        return None
    ls = [float(x) for x in LOSS.findall(t) if x not in ("e", "E")]
    gs = [float(x) for x in GN.findall(t)]
    return {"loss": ls, "grad_norm": gs}


res = {"pass": False, "failures": [], "runs": {}}
runs = {t: parse(t) for t in ("a", "b", "ref")}
for t, d in runs.items():
    if d is None or len(d["loss"]) < 2 or not d["grad_norm"]:
        res["failures"].append(f"run {t}: log missing or has too few logged steps"); continue
    res["runs"][t] = {"loss": d["loss"], "grad_norm": d["grad_norm"]}
    if not all(math.isfinite(x) for x in d["loss"] + d["grad_norm"]):
        res["failures"].append(f"F1 run {t}: non-finite loss/grad_norm")
for t in ("a", "b"):
    d = runs.get(t)
    if d and len(d["loss"]) >= 4 and not (statistics.mean(d["loss"][-2:]) < statistics.mean(d["loss"][:2])):
        res["failures"].append(f"F2 run {t}: loss did not decrease {d['loss']}")
    elif d and len(d["loss"]) < 4:
        res["failures"].append(f"F2 run {t}: fewer than 4 logged losses")
ref = runs.get("ref")
if ref and ref["grad_norm"]:
    mr = statistics.median(ref["grad_norm"])
    for t, k in (("a", 3.0), ("b", 5.0)):
        d = runs.get(t)
        if d and d["grad_norm"]:
            ma = statistics.median(d["grad_norm"]); res["runs"][t]["median_gn_over_ref"] = ma / mr if mr else None
            if not mr or not (1 / k <= ma / mr <= k):
                res["failures"].append(f"F3 run {t}: median grad_norm {ma:.4g} vs ref {mr:.4g} (ratio outside [1/{k:g},{k:g}])")
else:
    res["failures"].append("F3 reference run missing")
try:
    lg = json.load(open("out/imp_smoke_b_imp_train_log.json"))
    pm = lg["stats_means"]["pair"]
    if pm is None or not math.isfinite(pm):
        res["failures"].append("F4 pair-loss mean missing/non-finite")
    res["pair_loss_mean"] = pm
except Exception as e:
    res["failures"].append(f"F4 train log unreadable: {e}")
res["pass"] = not res["failures"]
json.dump(res, open(R + "imp_smoke_result.json", "w"), indent=1)
print("SMOKE", "PASS" if res["pass"] else "FAIL", res["failures"])
sys.exit(0)
