"""Stage I CPU step: held-out linear probes on the dumped activations of the length-matched set (results/imp_acts_<tag>_pv.npz).
  .venv/bin/python scripts/imp_probe_fit.py --tag base7b --output-file results/imp_src_base7b_matched.json     -> results/imp_probe_internal_<tag>.json
Everything is out-of-fold (see src/cyberdef/imp_probe.py): grouped 5-fold CV, nested selection of layer and C on the training part of each outer fold only.
Primary CV groups = matched PAIR (partners stay together); robustness CV groups = PROJECT. Controls through the identical nested pipeline: shuffled labels (3 repeats) and length-only features.
Verdict (fixed beforehand): the probe WINS only if nested held-out AUROC > 0.5 + 2*SE AND > the shuffled-control mean + 2 sd AND > the length-only probe AND beats the model OUTPUT AUROC by > 2*SE_diff (conservative); a shuffled-label mean above 0.55 marks the run INVALID."""
import argparse, json, math, sys
import numpy as np
sys.path.insert(0, "src")
from cyberdef import imp_probe as P
from cyberdef.imp_common import auroc, hm_se

LAYERS = [4, 8, 12, 16, 20, 24, 28]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--output-file", required=True, help="the model's OWN logprob-scored result on the same cases (per_case p_vuln)")
    ap.add_argument("--cases-file", default="results/lenmatched_eval_cases.json")
    ap.add_argument("--shuffles", type=int, default=3)
    a = ap.parse_args()
    z = np.load(f"results/imp_acts_{a.tag}_pv.npz")
    cases = {c["id"] + "|" + c["label"]: c for c in json.load(open(a.cases_file))["cases"]}
    ids = [str(i) for i in z["ids"]]
    cs = [cases[i] for i in ids]
    y = np.array([1 if c["label"] == "VULNERABLE" else 0 for c in cs])
    pair = [f"pair{c['pair']}" for c in cs]; proj = [f"proj{c['project']}" for c in cs]
    Xs = {L: z[f"L{L}"].astype(np.float32) for L in LAYERS}
    res = {"experiment": "imp_probe_internal", "tag": a.tag, "n": len(y), "n_vuln": int(y.sum()), "layers": LAYERS, "cases_file": a.cases_file, "cv": "5-fold grouped; nested layer/C choice on the train part only",
           "Cs": [3e-4, 3e-3, 3e-2]}
    # per-layer descriptive tables (fixed C = 3e-3; NOT used for selection)
    for name, groups in (("pair_grouped", pair), ("project_grouped", proj)):
        res[f"per_layer_{name}"] = {str(L): P.summarise(P.oof_plain(Xs[L], y, groups, 3e-3), y) for L in LAYERS}
    # headline: nested, pair-grouped; robustness: nested, project-grouped
    oof_pair, ch_pair = P.oof_nested(Xs, y, pair)
    oof_proj, ch_proj = P.oof_nested(Xs, y, proj)
    res["headline_pair_grouped"] = P.summarise(oof_pair, y); res["nested_choices_pair"] = ch_pair
    res["headline_project_grouped"] = P.summarise(oof_proj, y); res["nested_choices_project"] = ch_proj
    # controls through the same nested pipeline
    shuf = []
    for s in range(a.shuffles):
        ys = np.random.RandomState(100 + s).permutation(y)
        o, _ = P.oof_nested(Xs, ys, pair)
        shuf.append(auroc(list(o), list(ys)))
    m = float(np.mean(shuf)); sd = float(np.std(shuf))
    res["control_shuffled_labels"] = {"aucs": [round(x, 4) for x in shuf], "mean_auroc": round(m, 4), "sd": round(sd, 4), "valid_if_mean_le": 0.55}
    res["probe_invalid"] = bool(m > 0.55)
    Lf = np.array([[math.log(max(1, c["code_chars"])), math.log(max(1, c.get("toks") or 1)), math.log(max(1, c.get("lines") or 1))] for c in cs], dtype=np.float32)
    o_len, _ = P.oof_nested({"len": Lf}, y, pair, Cs=(1e-2, 1.0, 100.0))
    res["control_length_only"] = P.summarise(o_len, y)
    # the model's own output on the same cases
    out = json.load(open(a.output_file))
    om = {p["id"] + "|" + p["label"]: p["p_vuln"] for p in out["per_case"]}
    sc_out = [om[i] for i in ids]
    ao = auroc(sc_out, list(y)); n1 = int(y.sum()); so = hm_se(ao, n1, len(y) - n1)
    h = res["headline_pair_grouped"]
    se_diff = math.sqrt(h["se_hm"] ** 2 + so ** 2)
    res["output_comparison"] = {"output_file": a.output_file, "output_auroc": round(ao, 4), "output_se": round(so, 4), "delta": round(h["auroc"] - ao, 4), "se_diff": round(se_diff, 4),
                                "probe_minus_output_over_2se": bool(h["auroc"] - ao > 2 * se_diff)}
    wins = (h["auroc"] > 0.5 + 2 * h["se_hm"] and h["auroc"] > m + 2 * sd and h["auroc"] > res["control_length_only"]["auroc"] and res["output_comparison"]["probe_minus_output_over_2se"] and not res["probe_invalid"])
    res["verdict"] = {"probe_wins": bool(wins), "above_chance_2se": bool(h["auroc"] > 0.5 + 2 * h["se_hm"]), "above_shuffled_control": bool(h["auroc"] > m + 2 * sd),
                      "above_length_only": bool(h["auroc"] > res["control_length_only"]["auroc"]), "beats_output_by_2se_diff": res["output_comparison"]["probe_minus_output_over_2se"],
                      "project_grouped_agrees": bool(res["headline_project_grouped"]["auroc"] > 0.5 + 2 * res["headline_project_grouped"]["se_hm"]),
                      "reading": ("hidden state encodes the label better than the output: a READOUT problem" if wins else
                                  ("probe above chance but does not beat the output / controls by the bar" if h["auroc"] > 0.5 + 2 * h["se_hm"] else "probe at chance: the model does not linearly represent the label here"))}
    res["per_case"] = [{"id": c["id"], "label": c["label"], "score_nested_pair_cv": round(float(s1), 6), "score_nested_project_cv": round(float(s2), 6), "score_length_only": round(float(s3), 6),
                        "output_p_vuln": so_} for c, s1, s2, s3, so_ in zip(cs, oof_pair, oof_proj, o_len, sc_out)]
    json.dump(res, open(f"results/imp_probe_internal_{a.tag}.json", "w"), indent=1)
    print(json.dumps({k: res[k] for k in ("headline_pair_grouped", "headline_project_grouped", "control_shuffled_labels", "control_length_only", "output_comparison", "verdict", "probe_invalid")}, indent=1))


if __name__ == "__main__":
    main()
