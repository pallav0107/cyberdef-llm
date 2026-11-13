"""Benchmark a model on a defensive-security suite. Writes a results JSON with full
per-case outputs so a run is auditable (no fabricated scores: every number here comes
from a real model generation recorded in per_case)."""
from __future__ import annotations
import argparse, json, time
from pathlib import Path
from .config import SEED
from .data import SUITES
from . import model_io

SYSTEM = ("You are a meticulous secure-code reviewer. You are given one code snippet. "
          "Decide whether it contains a security vulnerability. Answer with exactly one "
          "line 'VERDICT: VULNERABLE' or 'VERDICT: SAFE'. If vulnerable, add a second line "
          "'CWE: <name>'. Do not output anything else.")


def make_user(code: str) -> str:
    return f"```python\n{code}\n```\nIs this code vulnerable?"


def parse_pred(text: str) -> str:
    u = text.upper()
    iv, isf = u.find("VULNERABLE"), u.find("SAFE")
    if iv == -1 and isf == -1:
        return "UNKNOWN"
    if iv == -1:
        return "SAFE"
    if isf == -1:
        return "VULNERABLE"
    return "VULNERABLE" if iv < isf else "SAFE"


def run(model_id, suite, backend, adapter, limit, ollama_url):
    cases = SUITES[suite](SEED)
    if limit:
        cases = cases[:limit]
    if backend == "hf":
        model, tok = model_io.load_hf(model_id, adapter=adapter)
        gen = lambda s, u: model_io.generate(model, tok, s, u)
    else:
        gen = lambda s, u: model_io.ollama_chat(ollama_url, model_id, s, u)

    per, correct = [], 0
    for c in cases:
        raw = gen(SYSTEM, make_user(c["code"]))
        pred = parse_pred(raw)
        ok = (pred == c["label"])
        correct += int(ok)
        per.append({"id": c["id"], "family": c["family"], "label": c["label"],
                    "pred": pred, "correct": ok, "heldout": c["heldout"],
                    "raw": raw.strip()[:200]})
    n = len(cases)
    ho = [p for p in per if p["heldout"]]
    byfam: dict[str, list[int]] = {}
    for p in per:
        b = byfam.setdefault(p["family"], [0, 0])
        b[0] += int(p["correct"]); b[1] += 1
    return {
        "model": model_id, "adapter": adapter, "suite": suite, "backend": backend,
        "n": n, "score": round(correct / n, 4) if n else 0.0,
        "heldout_n": len(ho),
        "heldout_score": round(sum(p["correct"] for p in ho) / len(ho), 4) if ho else None,
        "by_family": {k: round(v[0] / v[1], 4) for k, v in byfam.items()},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "per_case": per,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--suite", default="vuln_detect")
    ap.add_argument("--backend", choices=["hf", "ollama"], default="hf")
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    res = run(a.model, a.suite, a.backend, a.adapter, a.limit or 0, a.ollama_url)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2))
    print(f"[eval] model={a.model} adapter={a.adapter} suite={a.suite} "
          f"n={res['n']} score={res['score']} heldout={res['heldout_score']}")


if __name__ == "__main__":
    main()
