"""Arm-vs-reference comparison with the pre-registered default bar (EXPERIMENT_PLAN_IMPROVE.md): AUROC +/- Hanley-McNeil SE per file, delta with conservative
SE_diff = sqrt(SE1^2+SE2^2), length-only and SAST baselines on the SAME cases, pairwise win rate (+ binomial SE) when cases carry a pair id, pair-correct rate.
  python3 scripts/imp_compare.py --arm A.json [--ref B.json] --cases C.json [--subset S_cases.json] [--sast ff.json sg.json] [--score p_vuln|s_sc|s_mean] --out O.json
Restricting with --subset keeps only the (id,label) keys present in S (used for the re-matched pairings of #3/#4). Never drops cases otherwise; reports n and any id mismatch."""
import argparse, json, math, sys
sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, hm_se, r4


def load_scores(path, key):
    d = json.load(open(path))
    return {(p["id"], p["label"]): p[key] for p in d["per_case"]}, d


def stats(keys, score, cases, y):
    sc = [score[k] for k in keys]
    n1 = sum(y)
    a = auroc(sc, y)
    return a, hm_se(a, n1, len(y) - n1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--ref", default=None)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--subset", default=None)
    ap.add_argument("--sast", nargs="*", default=[])
    ap.add_argument("--score", default="p_vuln")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cases = {(c["id"], c["label"]): c for c in json.load(open(a.cases))["cases"]}
    keys = list(cases)
    if a.subset:
        sub = {(c["id"], c["label"]) for c in json.load(open(a.subset))["cases"]}
        keys = [k for k in keys if k in sub]
    arm, armd = load_scores(a.arm, a.score)
    missing = [k for k in keys if k not in arm]
    keys = [k for k in keys if k in arm]
    ref = None
    if a.ref:
        ref, refd = load_scores(a.ref, a.score)
        missing += [k for k in keys if k not in ref]
        keys = [k for k in keys if k in ref]
    y = [1 if k[1] == "VULNERABLE" else 0 for k in keys]
    n1 = sum(y); n0 = len(y) - n1
    out = {"arm": a.arm, "ref": a.ref, "cases": a.cases, "subset": a.subset, "score_key": a.score, "n": len(keys), "n_vuln": n1, "n_safe": n0,
           "missing_ids_not_scored": len(set(missing))}
    aa, se_a = stats(keys, arm, cases, y)
    out["arm_auroc"] = r4(aa); out["arm_se"] = r4(se_a); out["arm_z_vs_0.5"] = r4((aa - 0.5) / se_a) if se_a else None
    la = auroc([cases[k]["code_chars"] if "code_chars" in cases[k] else len(cases[k]["code"]) for k in keys], y)
    # length as the model sees it (augmented / sliced code) is what matters for #3/#4
    lm = auroc([len(cases[k]["code"]) for k in keys], y)
    out["length_only_auroc_code_chars_field"] = r4(la); out["length_only_auroc_model_input_chars"] = r4(lm)
    out["length_only_se"] = r4(hm_se(lm, n1, n0))
    base = [aa - 2 * se_a, la, lm]
    for sp in a.sast:
        s, _ = load_scores(sp, "score")
        ks = [k for k in keys if k in s]
        yy = [1 if k[1] == "VULNERABLE" else 0 for k in ks]
        if len(ks) == len(keys):
            sa = auroc([s[k] for k in ks], yy)
        else:
            sa = None
        out.setdefault("sast_auroc", {})[sp.split("/")[-1]] = r4(sa)
    if ref is not None:
        ra, se_r = stats(keys, ref, cases, y)
        out["ref_auroc"] = r4(ra); out["ref_se"] = r4(se_r)
        out["delta_arm_minus_ref"] = r4(aa - ra); out["se_diff_conservative"] = r4(math.sqrt(se_a ** 2 + se_r ** 2))
        out["delta_over_2se"] = (aa - ra) > 2 * math.sqrt(se_a ** 2 + se_r ** 2)
    # pairwise + pair-correct
    byp = {}
    for k in keys:
        byp.setdefault(cases[k].get("pair"), {})[1 if k[1] == "VULNERABLE" else 0] = arm[k]
    pr = [v for p, v in byp.items() if p is not None and 0 in v and 1 in v]
    if pr:
        w = [1.0 if v[1] > v[0] else 0.5 if v[1] == v[0] else 0.0 for v in pr]
        out["pairs"] = len(pr); out["pairwise_win_rate"] = r4(sum(w) / len(w)); out["pairwise_se_binom"] = r4(math.sqrt(0.25 / len(w)))
        out["pair_correct_rate_v_ge_.5_and_f_lt_.5"] = r4(sum(1 for v in pr if v[1] >= 0.5 and v[0] < 0.5) / len(pr)) if a.score == "p_vuln" else None
    beats_len = aa > max(la, lm) + 2 * math.sqrt(se_a ** 2 + (out["length_only_se"] or 0) ** 2)
    sast_vals = [v for v in out.get("sast_auroc", {}).values() if v is not None]
    beats_sast = all(aa > v for v in sast_vals) if sast_vals else None
    out["beats_length_only_by_2se"] = bool(beats_len); out["beats_sast"] = beats_sast
    out["above_chance_2se"] = bool(aa > 0.5 + 2 * se_a)
    out["bar_passed"] = bool(out["above_chance_2se"] and beats_len and beats_sast is not False and (ref is None or out["delta_over_2se"]))
    json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps({k: v for k, v in out.items() if k not in ("arm", "ref", "cases")}))


if __name__ == "__main__":
    main()
