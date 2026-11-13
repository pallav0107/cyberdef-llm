"""Selective / calibrated evaluation -- the basis of the model's ADOPTION EDGE. Works on any
registered benchmark (Devign/PrimeVul) via --dataset. Scores the two candidate verdicts by
the model's own log-probability to get a real per-case confidence, then reports accuracy,
AUROC (ranking), ECE (calibration) and a risk-coverage curve (accuracy on the top-X% most
confident cases). The edge is real only if the tuned curve beats base on an independent
benchmark -- this measures it, it does not assume it. Scores recompute from per_case."""
from __future__ import annotations
import argparse, json, math, time
from pathlib import Path
import sys
sys.path.insert(0, "src")
import torch
from cyberdef.evaluate import SYSTEM, make_user
from cyberdef.train import _ids
from cyberdef import model_io, benchdata

CAND = {"VULNERABLE": "VERDICT: VULNERABLE", "SAFE": "VERDICT: SAFE"}


@torch.no_grad()
def mean_logp(model, tok, prompt_ids, answer):
    ans_ids = tok(answer, add_special_tokens=False)["input_ids"]
    full = list(prompt_ids) + list(ans_ids)
    ids = torch.tensor([full], device=model.device)
    logits = model(ids).logits[0]
    lp = torch.log_softmax(logits.float(), dim=-1)
    tot = 0.0
    for j, tid in enumerate(ans_ids):
        pos = len(prompt_ids) + j - 1
        tot += lp[pos, tid].item()
    return tot / max(len(ans_ids), 1)


def auroc(scores, labels):
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    sum_pos = sum(ranks[i] for i in range(len(scores)) if labels[i] == 1)
    n1, n0 = len(pos), len(neg)
    return round((sum_pos - n1 * (n1 + 1) / 2.0) / (n1 * n0), 4)


def ece(confs, correct, bins=10):
    tot = len(confs)
    if not tot:
        return None
    e = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i in range(tot) if (confs[i] > lo and confs[i] <= hi) or (b == 0 and confs[i] <= hi)]
        if not idx:
            continue
        acc = sum(correct[i] for i in idx) / len(idx)
        conf = sum(confs[i] for i in idx) / len(idx)
        e += (len(idx) / tot) * abs(acc - conf)
    return round(e, 4)


def risk_coverage(confs, correct, covs):
    order = sorted(range(len(confs)), key=lambda i: -confs[i])
    out = {}
    for c in covs:
        k = max(1, int(round(c * len(order))))
        sub = order[:k]
        out[f"{c:.2f}"] = {"coverage_n": k,
                           "accuracy": round(sum(correct[i] for i in sub) / k, 4)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--dataset", default="devign", choices=list(benchdata.BENCHES))
    ap.add_argument("--split", default="test")
    ap.add_argument("--n-per-class", type=int, default=100)
    ap.add_argument("--max-chars", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cases-file", default=None,
                    help="JSON with a 'cases' list (see scripts/xdata_clean_sample.py); score exactly "
                         "those cases instead of drawing a sample")
    a = ap.parse_args()

    if a.cases_file:
        cf = json.loads(Path(a.cases_file).read_text())
        cases, pool = cf["cases"], cf.get("pool", {})
        a.split = cf.get("split", a.split)
        a.n_per_class = len(cases) // 2
        a.seed = cf.get("seed", a.seed)
    else:
        cases, pool = benchdata.balanced_sample(a.dataset, a.split, a.n_per_class, a.seed, a.max_chars)
    model, tok = model_io.load_hf(a.model, adapter=a.adapter)
    model.eval()

    per, scores, labels, confs, correct = [], [], [], [], []
    for c in cases:
        prompt_ids = _ids(model_io.chat_prompt(tok, SYSTEM, make_user(c["code"]), tensors=False))
        sv = mean_logp(model, tok, prompt_ids, CAND["VULNERABLE"])
        ss = mean_logp(model, tok, prompt_ids, CAND["SAFE"])
        p_vuln = 1.0 / (1.0 + math.exp(ss - sv))
        pred = "VULNERABLE" if p_vuln >= 0.5 else "SAFE"
        conf = max(p_vuln, 1.0 - p_vuln)
        ok = int(pred == c["label"])
        per.append({"id": c["id"], "label": c["label"], "pred": pred,
                    "p_vuln": round(p_vuln, 6), "conf": round(conf, 6), "correct": ok})
        scores.append(p_vuln); labels.append(1 if c["label"] == "VULNERABLE" else 0)
        confs.append(conf); correct.append(ok)

    n = len(per)
    covs = [0.1, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0]
    res = {
        "benchmark": benchdata.spec(a.dataset)["hf"], "dataset": a.dataset,
        "eval_split": a.split, "method": "logprob-scored verdict", "pool": pool,
        "model": a.model, "adapter": a.adapter, "seed": a.seed,
        "n": n, "n_per_class": a.n_per_class, "max_chars": a.max_chars,
        "accuracy": round(sum(correct) / n, 4) if n else 0.0,
        "auroc": auroc(scores, labels), "ece": ece(confs, correct),
        "risk_coverage": risk_coverage(confs, correct, covs),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "per_case": per,
    }
    if a.cases_file:
        res["cases_file"] = a.cases_file
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    rc = res["risk_coverage"]
    print(f"[selective] dataset={a.dataset} model={a.model} adapter={a.adapter} "
          f"acc={res['accuracy']} auroc={res['auroc']} ece={res['ece']} "
          f"acc@25%={rc['0.25']['accuracy']} acc@10%={rc['0.10']['accuracy']}")


if __name__ == "__main__":
    main()
