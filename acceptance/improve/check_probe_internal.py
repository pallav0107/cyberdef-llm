"""Acceptance for Stage I (internal-probe-vs-output). Written BEFORE scripts/imp_probe_fit.py. Run from the repo root with .venv/bin/python (CPU).
  check_probe_internal.py selftest     synthetic data through src/cyberdef/imp_probe.py:
     S1 a label planted in 3 dimensions is recovered OUT-OF-FOLD (nested AUROC > 0.9)
     S2 pure-noise features give nested out-of-fold AUROC ~0.5 (|a - 0.5| < 0.10): the pipeline cannot fake a win
     S3 shuffled labels on the SAME planted features give ~0.5 (< 0.58)
     S4 LEAK MUTANT: fitting and scoring on the same cases gives > 0.8 on pure noise (so a leaking probe would 'win'), and the real pipeline stays < 0.6 on the same noise
     S5 grouped folds: no group appears in two folds
  check_probe_internal.py results FILE results/imp_probe_internal_<model>.json:
     per-layer held-out AUROCs present for pair-grouped and project-grouped CV; nested headline recomputed from per_case scores equals the stored one (1e-3); both controls present (shuffled, length-only) and
     recomputed; if the shuffled-label control mean exceeds 0.55 the file MUST carry probe_invalid=true; the output-AUROC comparison and the verdict flags are consistent with the stored numbers; n == len(per_case)."""
import json, sys

sys.path.insert(0, "src")
import numpy as np
from cyberdef import imp_probe as P
from cyberdef.imp_common import auroc, hm_se


def synth(n=600, d=64, planted=True, seed=0):
    r = np.random.RandomState(seed)
    y = np.array([i % 2 for i in range(n)])
    X = r.randn(n, d)
    if planted:
        X[:, :3] += (y[:, None] * 2 - 1) * 0.8
    groups = [i // 2 for i in range(n)]
    return X, y, groups


def selftest():
    fails = []
    X, y, g = synth(planted=True)
    a1 = auroc(list(P.oof_nested({"L1": X, "L2": X[:, ::-1].copy()}, y, g)[0]), list(y))
    if not a1 > 0.9:
        fails.append(f"S1 planted signal not recovered: {a1:.3f}")
    Xn, yn, gn = synth(planted=False, seed=3)
    a2 = auroc(list(P.oof_nested({"L1": Xn, "L2": Xn[:, ::-1].copy()}, yn, gn)[0]), list(yn))
    if abs(a2 - 0.5) > 0.10:
        fails.append(f"S2 noise gave {a2:.3f}")
    ys = np.random.RandomState(5).permutation(y)
    a3 = auroc(list(P.oof_nested({"L1": X}, ys, g)[0]), list(ys))
    if not a3 < 0.58:
        fails.append(f"S3 shuffled labels gave {a3:.3f}")
    Xw, yw, gw = synth(d=400, planted=False, seed=4)                       # wide noise: an in-sample fit can memorise it
    leak = auroc(list(P.fit_predict(Xw, yw, Xw, 10.0)), list(yw))          # MUTANT: fit and score on the same cases
    a4 = auroc(list(P.oof_nested({"L1": Xw}, yw, gw)[0]), list(yw))
    if not leak > 0.8:
        fails.append(f"S4 leak mutant did not exceed 0.8 ({leak:.3f}): the leak detector is vacuous")
    if not a4 < 0.6:
        fails.append(f"S4 real pipeline not below 0.6 on the same wide noise ({a4:.3f})")
    r6 = np.random.RandomState(9); y6 = r6.randint(0, 4, 500); X6 = r6.randn(500, 3584)       # S6 wide multiclass (the PCA path): class signal spread over 80 dims
    for c in range(4):
        X6[y6 == c, c * 20:(c + 1) * 20] += 1.0
    p6 = P.fit_predict(X6[:350], y6[:350], X6[350:], 3e-3, n_classes=4).argmax(1)
    s6 = float((p6 == y6[350:]).mean())
    if not s6 > 0.6:
        fails.append(f"S6 wide multiclass signal not recovered ({s6:.2f}); class probe cannot be trusted")
    ys6 = np.random.RandomState(1).permutation(y6[:350])
    c6 = float((P.fit_predict(X6[:350], ys6, X6[350:], 3e-3, n_classes=4).argmax(1) == y6[350:]).mean())
    if not c6 < 0.4:
        fails.append(f"S6 shuffled-label multiclass control too high ({c6:.2f})")
    f = P.group_folds(g, 5, 0)
    seen = {}
    for gi, fi in zip(g, f):
        if seen.setdefault(gi, fi) != fi:
            fails.append("S5 a group spans two folds"); break
    if fails:
        print("FAIL:"); [print(" -", x) for x in fails]; return 1
    print(f"PASS: S1={a1:.3f} S2={a2:.3f} S3={a3:.3f} S4(leak mutant)={leak:.3f} vs real {a4:.3f} S5 ok S6={s6:.2f}/shuf {c6:.2f}"); return 0


def results(path):
    d = json.load(open(path)); fails = []
    pc = d["per_case"]
    if d["n"] != len(pc):
        fails.append("n != len(per_case)")
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in pc]
    a = auroc([p["score_nested_pair_cv"] for p in pc], y)
    if abs(a - d["headline_pair_grouped"]["auroc"]) > 1e-3:
        fails.append(f"nested AUROC stored {d['headline_pair_grouped']['auroc']} recomputed {a:.4f}")
    al = auroc([p["score_length_only"] for p in pc], y)
    if abs(al - d["control_length_only"]["auroc"]) > 1e-3:
        fails.append("length-only control not reproducible from per_case")
    for key in ("per_layer_pair_grouped", "per_layer_project_grouped", "control_shuffled_labels", "control_length_only", "output_comparison", "verdict"):
        if key not in d:
            fails.append("missing " + key)
    sh = d.get("control_shuffled_labels", {}).get("mean_auroc")
    if sh is not None and sh > 0.55 and not d.get("probe_invalid"):
        fails.append("shuffled-label control above 0.55 but probe_invalid is not set")
    oc = d.get("output_comparison", {})
    if oc:
        se = (d["headline_pair_grouped"]["se_hm"] ** 2 + oc["output_se"] ** 2) ** 0.5
        if abs((d["headline_pair_grouped"]["auroc"] - oc["output_auroc"]) - oc["delta"]) > 2e-3 or abs(se - oc["se_diff"]) > 2e-3:
            fails.append("output comparison inconsistent")
    if fails:
        print("FAIL:"); [print(" -", x) for x in fails]; return 1
    print("PASS:", path, d["headline_pair_grouped"]); return 0


if __name__ == "__main__":
    sys.exit(selftest() if sys.argv[1] == "selftest" else results(sys.argv[2]))
