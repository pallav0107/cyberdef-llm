"""Length-only baseline (EXPERIMENT_PLAN_MULTILANG.md, amendment item 7 + stricter bar): AUROC of
score = number of characters of each case's code against the labels, on EXACTLY the cases a model
was scored on. Input is either a selective_eval result file (its per_case ids are checked against
the cases, in order) or a cases file. Reports two variants: chars of the code the model saw
(truncated to --max-chars) and chars of the full original function; `auroc` (the one used for
gating) is the larger of the two, i.e. the stricter baseline. Writes JSON; never modifies inputs."""
from __future__ import annotations
import argparse
import json
import math
import sys
from pathlib import Path


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
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2.0 + 1.0
        i = j + 1
    n1, n0 = len(pos), len(neg)
    return (sum(ranks[i] for i in range(len(scores)) if labels[i] == 1) - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def hanley_mcneil_se(a, n1, n0):
    q1, q2 = a / (2 - a), 2 * a * a / (1 + a)
    v = (a * (1 - a) + (n1 - 1) * (q1 - a * a) + (n0 - 1) * (q2 - a * a)) / (n1 * n0)
    return math.sqrt(max(v, 0.0))


def load_cases(d, path):
    if "cases" in d:
        return d["cases"], str(path)
    cf = d.get("cases_file")
    if cf:
        return json.loads(Path(cf).read_text())["cases"], cf
    sys.path.insert(0, "src")
    from cyberdef import benchdata
    cases, _ = benchdata.balanced_sample(d["dataset"], d["eval_split"], d["n_per_class"], d["seed"], d["max_chars"])
    return cases, f"rebuilt:{d['dataset']}/{d['eval_split']}/seed{d['seed']}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="selective_eval result JSON (with per_case) or a cases JSON")
    ap.add_argument("--cases-file", default=None, help="override the cases file for a result JSON")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    d = json.loads(Path(a.input).read_text())
    if a.cases_file:
        d = dict(d, cases_file=a.cases_file)
    cases, src = load_cases(d, a.input)
    if "per_case" in d:
        got = [p["id"] for p in d["per_case"]]
        want = [c["id"] for c in cases]
        if got != want:
            raise SystemExit(f"case mismatch: result has {len(got)} ids, cases {len(want)}; "
                             f"same set={sorted(got) == sorted(want)}; refusing to compute")
        if any(p["label"] != c["label"] for p, c in zip(d["per_case"], cases)):
            raise SystemExit("label mismatch between result and cases")
    labels = [1 if c["label"] == "VULNERABLE" else 0 for c in cases]
    seen = [len(c["code"]) for c in cases]
    full = [c.get("code_chars", len(c["code"])) for c in cases]
    a_seen, a_full = auroc(seen, labels), auroc(full, labels)
    n1, n0 = sum(labels), len(labels) - sum(labels)
    best = None if a_seen is None else max(a_seen, a_full)
    res = {"input": a.input, "cases_source": src, "n": len(cases), "n_vuln": n1, "n_safe": n0,
           "auroc": None if best is None else round(best, 4),
           "auroc_chars_seen_by_model": None if a_seen is None else round(a_seen, 4),
           "auroc_chars_full_function": None if a_full is None else round(a_full, 4),
           "se_hanley_mcneil": None if best is None else round(hanley_mcneil_se(best, n1, n0), 4),
           "note": "auroc = max of the two length variants (stricter baseline); score = character count"}
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(res, indent=2))
    print(f"[length_baseline] n={res['n']} auroc={res['auroc']} (seen={res['auroc_chars_seen_by_model']} "
          f"full={res['auroc_chars_full_function']}) se={res['se_hanley_mcneil']} src={src}")


if __name__ == "__main__":
    main()
