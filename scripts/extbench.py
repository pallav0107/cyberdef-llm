"""Evaluate baseline vs tuned on a RECOGNIZED benchmark (Devign or PrimeVul) with the SAME
harness; only the adapter varies, so the delta is attributable to the fine-tune. The dataset
registry lives in cyberdef.benchdata. Every per_case records the real model output; score is
recomputed from per_case by scripts/make_results_table.py."""
from __future__ import annotations
import argparse, json, time
from pathlib import Path
import sys
sys.path.insert(0, "src")
from cyberdef.evaluate import SYSTEM, make_user, parse_pred
from cyberdef import model_io, benchdata


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dataset", default="devign", choices=list(benchdata.BENCHES))
    ap.add_argument("--n-per-class", type=int, default=100)
    ap.add_argument("--max-chars", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--split", default="test", choices=["test", "validation", "train"])
    a = ap.parse_args()

    cases, pool = benchdata.balanced_sample(a.dataset, a.split, a.n_per_class, a.seed, a.max_chars)
    model, tok = model_io.load_hf(a.model, adapter=a.adapter)

    per, correct = [], 0
    tp = tn = fp = fn = unknown = 0
    for c in cases:
        raw = model_io.generate(model, tok, SYSTEM, make_user(c["code"]))
        pred = parse_pred(raw)
        ok = (pred == c["label"]); correct += int(ok)
        if pred == "UNKNOWN":
            unknown += 1
        if c["label"] == "VULNERABLE":
            tp += int(pred == "VULNERABLE"); fn += int(pred != "VULNERABLE")
        else:
            tn += int(pred == "SAFE"); fp += int(pred != "SAFE")
        per.append({"id": c["id"], "label": c["label"], "pred": pred, "correct": ok,
                    "truncated": c["truncated"], "code_chars": c["code_chars"],
                    "raw": raw.strip()[:200]})
    n = len(cases)
    prec = round(tp / (tp + fp), 4) if (tp + fp) else None
    rec = round(tp / (tp + fn), 4) if (tp + fn) else None
    res = {
        "benchmark": benchdata.spec(a.dataset)["hf"], "dataset": a.dataset,
        "split": a.split, "eval_split": a.split, "pool": pool,
        "note": "recognized benchmark; balanced sample; baseline-vs-tuned delta is the honest signal.",
        "model": a.model, "adapter": a.adapter, "seed": a.seed,
        "n_per_class": a.n_per_class, "max_chars": a.max_chars,
        "n": n, "score": round(correct / n, 4) if n else 0.0,
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "unknown": unknown},
        "precision_vuln": prec, "recall_vuln": rec,
        "truncated_count": sum(p["truncated"] for p in per),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "per_case": per,
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    print(f"[extbench] dataset={a.dataset} model={a.model} adapter={a.adapter} "
          f"n={n} score={res['score']} conf={res['confusion']} unknown={unknown}")


if __name__ == "__main__":
    main()
