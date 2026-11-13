"""Mean-p_vuln ensemble of selective_eval result files scored on the SAME cases in the SAME order.
Metrics are recomputed with selective_eval's own auroc/ece/risk_coverage (same rounding), from the
rounded per_case values, so the output passes scripts/verify_results.py."""
from __future__ import annotations
import argparse, json, sys, time
from pathlib import Path

sys.path.insert(0, "scripts")
sys.path.insert(0, "src")
from selective_eval import auroc, ece, risk_coverage  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if len(a.inputs) < 2:
        raise SystemExit("need at least two inputs")
    docs = [json.loads(Path(p).read_text()) for p in a.inputs]
    pcs = [d["per_case"] for d in docs]
    n = len(pcs[0])
    for p, pc in zip(a.inputs, pcs):
        assert len(pc) == n, f"length mismatch: {p}"
    per, scores, labels, confs, correct = [], [], [], [], []
    for i in range(n):
        lab = pcs[0][i]["label"]
        for p, pc in zip(a.inputs, pcs):
            assert pc[i]["label"] == lab, f"label mismatch at {i} in {p}"
            assert pc[i]["id"] == pcs[0][i]["id"], f"id mismatch at {i} in {p}"
        pv = round(sum(float(pc[i]["p_vuln"]) for pc in pcs) / len(pcs), 6)
        pred = "VULNERABLE" if pv >= 0.5 else "SAFE"
        conf = round(max(pv, 1.0 - pv), 6)
        ok = int(pred == lab)
        per.append({"id": pcs[0][i]["id"], "label": lab, "pred": pred,
                    "p_vuln": pv, "conf": conf, "correct": ok})
        scores.append(pv)
        labels.append(1 if lab == "VULNERABLE" else 0)
        confs.append(conf)
        correct.append(ok)
    covs = [0.1, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0]
    d0 = docs[0]
    res = {
        "benchmark": d0.get("benchmark"), "dataset": d0.get("dataset"),
        "eval_split": d0.get("eval_split"),
        "method": "mean p_vuln ensemble of logprob-scored verdicts",
        "pool": d0.get("pool"), "model": d0.get("model"),
        "adapter": [d.get("adapter") for d in docs], "seed": d0.get("seed"),
        "n": n, "n_per_class": d0.get("n_per_class"),
        "max_chars": [d.get("max_chars") for d in docs],
        "accuracy": round(sum(correct) / n, 4) if n else 0.0,
        "auroc": auroc(scores, labels), "ece": ece(confs, correct),
        "risk_coverage": risk_coverage(confs, correct, covs),
        "members": list(a.inputs),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "per_case": per,
    }
    if d0.get("cases_file"):
        res["cases_file"] = d0["cases_file"]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    rc = res["risk_coverage"]
    print(f"[ensemble] members={len(docs)} acc={res['accuracy']} auroc={res['auroc']} ece={res['ece']} "
          f"acc@25%={rc['0.25']['accuracy']} acc@10%={rc['0.10']['accuracy']}")


if __name__ == "__main__":
    main()
