"""Zero-shot / adapter logprob scoring of any cases file: same prompt, loader and scorer as scripts/selective_eval.py (imported, read-only),
plus --suffix (chat-template continuation, needed for gpt-oss harmony 'final' channel) and tolerance for several models.
Output schema = selective_eval's, so scripts/verify_results.py and lenmatch_analyze.py work on it.
  python3 scripts/imp_selective.py --model M [--adapter A] --cases-file results/X_cases.json --out results/imp_...json [--suffix S]"""
import argparse, json, math, sys, time
from pathlib import Path
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
import torch
import selective_eval as se
from cyberdef.evaluate import SYSTEM, make_user
from cyberdef.train import _ids
from cyberdef import model_io


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--cases-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--suffix", default="")
    ap.add_argument("--meta", default="", help="free text recorded in the result (e.g. bank=quick)")
    ap.add_argument("--max-cases", type=int, default=0, help="debug only")
    a = ap.parse_args()
    cf = json.loads(Path(a.cases_file).read_text())
    cases = cf["cases"][:a.max_cases] if a.max_cases else cf["cases"]
    model, tok = model_io.load_hf(a.model, adapter=a.adapter)
    model.eval()
    suf = tok(a.suffix, add_special_tokens=False)["input_ids"] if a.suffix else []
    per, scores, labels, confs, correct = [], [], [], [], []
    t0 = time.time()
    for i, c in enumerate(cases):
        prompt_ids = _ids(model_io.chat_prompt(tok, SYSTEM, make_user(c["code"]), tensors=False)) + suf
        sv = se.mean_logp(model, tok, prompt_ids, se.CAND["VULNERABLE"])
        ss = se.mean_logp(model, tok, prompt_ids, se.CAND["SAFE"])
        p = 1.0 / (1.0 + math.exp(max(-50, min(50, ss - sv))))
        pred = "VULNERABLE" if p >= 0.5 else "SAFE"
        ok = int(pred == c["label"])
        per.append({"id": c["id"], "label": c["label"], "pred": pred, "p_vuln": round(p, 6), "conf": round(max(p, 1 - p), 6), "correct": ok})
        scores.append(p); labels.append(1 if c["label"] == "VULNERABLE" else 0); confs.append(max(p, 1 - p)); correct.append(ok)
        if i % 200 == 0:
            print(f"[imp_selective] {i}/{len(cases)} {time.time()-t0:.0f}s", flush=True)
    n = len(per)
    res = {"benchmark": a.cases_file, "dataset": "cases_file", "eval_split": cf.get("split"), "method": "logprob-scored verdict (imp_selective)",
           "pool": cf.get("pool", {}), "model": a.model, "adapter": a.adapter, "suffix": a.suffix, "meta": a.meta, "seed": cf.get("seed", 0), "n": n,
           "n_per_class": n // 2, "max_chars": 6000, "accuracy": round(sum(correct) / n, 4), "auroc": se.auroc(scores, labels),
           "ece": se.ece(confs, correct), "risk_coverage": se.risk_coverage(confs, correct, [0.1, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0]),
           "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "cases_file": a.cases_file, "per_case": per}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1))
    print(f"[imp_selective] model={a.model} adapter={a.adapter} cases={a.cases_file} n={n} acc={res['accuracy']} auroc={res['auroc']}")


if __name__ == "__main__":
    main()
