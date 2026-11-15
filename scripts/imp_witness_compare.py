#!/usr/bin/env python3
"""Gate for the witness train/test run: integrity first, then the PRE-REGISTERED hypotheses in acceptance/witness_bar.json.
 - integrity: each eval file's stored AUROC must equal the AUROC recomputed from its per_case (exit 1 on mismatch);
 - paired bootstrap (same programs, B resamples) of AUROC(fine-tuned) - AUROC(comparator) for: zero-shot base (H1),
   no-model deterministic witnesses from the Phase-A capture (H2, primary), fuzzer floor (H3);
   PASS iff diff > 2 * bootstrap SE.  A FAIL is a valid result and never fails the job.
Writes a JSON verdict and a markdown table (the workflow appends it to the run summary page)."""
from __future__ import annotations
import argparse, json, random, sys

sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, r4


def load_eval(p):
    d = json.load(open(p))
    pc = {c["id"]: c for c in d["per_case"]}
    s = [c["p_vuln"] for c in d["per_case"]]
    y = [1 if c["label"] == "VULNERABLE" else 0 for c in d["per_case"]]
    re = auroc(s, y)
    ok = d.get("auroc") is not None and re is not None and abs(re - d["auroc"]) <= 0.005
    return d, pc, ok, re


def boot(ids, y, a, b, B, seed):
    rng = random.Random(seed)
    n, diffs = len(ids), []
    for _ in range(B):
        idx = [rng.randrange(n) for _ in range(n)]
        yy = [y[i] for i in idx]
        if 0 < sum(yy) < n:
            diffs.append(auroc([a[i] for i in idx], yy) - auroc([b[i] for i in idx], yy))
    m = sum(diffs) / len(diffs)
    sd = (sum((x - m) ** 2 for x in diffs) / (len(diffs) - 1)) ** 0.5
    diffs.sort()
    return sd, (diffs[int(0.025 * len(diffs))], diffs[int(0.975 * len(diffs))])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--ft", required=True)
    ap.add_argument("--det", default="data/witness_train.jsonl")
    ap.add_argument("--floor", default="results/imp_2o_floor_b60.json")
    ap.add_argument("--bar", default="acceptance/witness_bar.json")
    ap.add_argument("--B", type=int, default=2000)
    ap.add_argument("--out", required=True)
    ap.add_argument("--md", required=True)
    a = ap.parse_args()

    bd, bpc, bok, bre = load_eval(a.base)
    fd, fpc, fok, fre = load_eval(a.ft)
    det = {r["id"]: r for r in (json.loads(l) for l in open(a.det) if l.strip())}
    flo = {p["id"]: p for p in json.load(open(a.floor))["per_case"]}
    ids = sorted(set(fpc) & set(bpc) & set(det) & set(flo))
    y = [1 if fpc[i]["label"] == "VULNERABLE" else 0 for i in ids]
    sc = {"fine_tuned": [fpc[i]["p_vuln"] for i in ids],
          "base_zero_shot": [bpc[i]["p_vuln"] for i in ids],
          "deterministic_no_model": [1.0 if (det[i].get("confirmed") and det[i].get("reproduced")) else 0.0 for i in ids],
          "fuzzer_floor": [1.0 if flo[i].get("confirmed") else 0.0 for i in ids]}

    def rates(s):
        n1 = sum(y)
        return {"auroc": r4(auroc(s, y)), "tpr": r4(sum(1 for i in range(len(y)) if y[i] and s[i]) / n1),
                "fpr": r4(sum(1 for i in range(len(y)) if not y[i] and s[i]) / (len(y) - n1))}

    table = {k: rates(v) for k, v in sc.items()}
    hyp = {}
    for name, comp in (("H1_finetuning_teaches_witnessing", "base_zero_shot"),
                       ("H2_primary_beats_no_model_baseline", "deterministic_no_model"),
                       ("H3_beats_fuzzer_floor", "fuzzer_floor")):
        diff = auroc(sc["fine_tuned"], y) - auroc(sc[comp], y)
        se, ci = boot(ids, y, sc["fine_tuned"], sc[comp], a.B, 0)
        hyp[name] = {"comparator": comp, "diff": r4(diff), "boot_se": r4(se), "ci95": [r4(ci[0]), r4(ci[1])],
                     "pass": bool(diff > 2 * se)}
    verdict = {"n": len(ids), "integrity": {"base": bok, "fine_tuned": fok}, "table": table, "hypotheses": hyp,
               "bar_file": a.bar, "base_file": a.base, "ft_file": a.ft,
               "claim": ("model beats execution-without-a-model (H2 PASS) -- requires experiment-auditor before any external use"
                         if hyp["H2_primary_beats_no_model_baseline"]["pass"] else
                         "no claim that the model beats the no-model execution baseline (H2 not passed)")}
    json.dump(verdict, open(a.out, "w"), indent=2)
    lines = [f"## Witness train/test — {fd.get('model')}", "",
             f"Integrity (stored AUROC == recomputed from per_case): base **{bok}**, fine-tuned **{fok}**  |  n = {len(ids)} programs", "",
             "| detector | AUROC | TPR | FPR |", "|---|---|---|---|"]
    for k, v in table.items():
        lines.append(f"| {k} | {v['auroc']} | {v['tpr']} | {v['fpr']} |")
    lines += ["", "| pre-registered hypothesis | Δ AUROC | 2×SE | 95% CI | result |", "|---|---|---|---|---|"]
    for k, v in hyp.items():
        lines.append(f"| {k} (vs {v['comparator']}) | {v['diff']} | {r4(2 * v['boot_se'])} | {v['ci95']} | {'PASS' if v['pass'] else 'not passed'} |")
    lines += ["", f"**Claim:** {verdict['claim']}"]
    open(a.md, "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if not (bok and fok):
        print("::error::integrity failed: a stored AUROC does not match its per_case")
        sys.exit(1)


if __name__ == "__main__":
    main()
