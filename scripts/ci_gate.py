#!/usr/bin/env python3
"""Honest-evidence gate for a cyberdef eval result. Recomputes AUROC from per_case using the
SAME canonical metric the rest of the repo uses (cyberdef.imp_common.auroc / auroc_se), so a
result cannot claim a headline its own per_case does not support.

It does TWO separate things, and only the first can fail the job:
  1. INTEGRITY  — the stored `auroc` must equal the value recomputed from per_case (within --tol).
                  A mismatch is a real defect (a hand-edited or stale headline) -> exit 1.
  2. VERDICT    — informational: does the honest number clear the pre-registered bar
                  (AUROC > 0.5 + 2*SE AND AUROC >= --bar)? A NULL is a valid, expected result,
                  so it NEVER fails the job. Only a human + experiment-auditor may call a win.

Usage:  ci_gate.py --result results/box_ev_x.json [--bar 0.60] [--tol 0.005]
        ci_gate.py --selftest
Emits name=value lines for $GITHUB_OUTPUT (recomputed_auroc, se, stored_auroc, integrity, verdict).
"""
from __future__ import annotations
import argparse, json, os, sys

sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, auroc_se  # canonical metric, reused


def _scores_labels(per_case):
    sc, lb = [], []
    for c in per_case:
        if "p_vuln" not in c or "label" not in c:
            return None, None
        sc.append(float(c["p_vuln"]))
        lb.append(1 if c["label"] == "VULNERABLE" else 0)
    return sc, lb


def grade(result_path, bar, tol):
    d = json.load(open(result_path))
    stored = d.get("auroc")
    pc = d.get("per_case") or []
    out = {"stored_auroc": stored, "n": d.get("n"), "integrity": "unverified",
           "recomputed_auroc": None, "se": None, "verdict": "unknown"}
    sc, lb = _scores_labels(pc)
    if not pc or sc is None:
        out["note"] = "per_case absent or lacks p_vuln/label — cannot recompute"
        return out, True  # cannot verify, but do not fail the job on a schema gap
    a, se = auroc_se(sc, lb)
    out["recomputed_auroc"] = round(a, 4) if a is not None else None
    out["se"] = round(se, 4) if se is not None else None
    ok = (stored is not None and a is not None and abs(a - stored) <= tol)
    out["integrity"] = "ok" if ok else "MISMATCH"
    if a is not None and se is not None:
        signal = (a > 0.5 + 2 * se) and (a >= bar)
        out["verdict"] = ("SIGNAL (clears bar — confirm via per_case recompute + experiment-auditor "
                          "before calling a win)" if signal else "NULL (does not clear the bar)")
    return out, ok


def selftest():
    # perfect separation -> AUROC 1.0; reversed -> 0.0; interleaved -> ~0.5
    import tempfile
    def mk(scores, labels):
        pc = [{"id": str(i), "label": "VULNERABLE" if labels[i] else "SAFE", "p_vuln": scores[i]}
              for i in range(len(scores))]
        a, _ = auroc_se(scores, [1 if l else 0 for l in labels])
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"auroc": round(a, 4), "n": len(pc), "per_case": pc}, f); f.close()
        return f.name
    # integrity passes when stored matches per_case
    p = mk([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0])
    o, ok = grade(p, 0.60, 0.005)
    assert ok and o["integrity"] == "ok" and o["recomputed_auroc"] == 1.0, o
    assert "SIGNAL" in o["verdict"], o
    # integrity FAILS when the headline is tampered to beat the bar but per_case says chance
    import json as _j
    d = _j.load(open(p)); d["per_case"] = [{"id": "0", "label": "VULNERABLE", "p_vuln": 0.5},
                                           {"id": "1", "label": "SAFE", "p_vuln": 0.5}]
    _j.dump(d, open(p, "w"))
    o2, ok2 = grade(p, 0.60, 0.005)
    assert (not ok2) and o2["integrity"] == "MISMATCH", o2  # stored 1.0 vs recomputed 0.5 -> caught
    print("[ci_gate selftest] PASS: recompute matches, and a tampered headline is caught as MISMATCH")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--result")
    ap.add_argument("--bar", type=float, default=0.60)
    ap.add_argument("--tol", type=float, default=0.005)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.result:
        ap.error("--result required (or --selftest)")
    out, ok = grade(a.result, a.bar, a.tol)
    gh = os.environ.get("GITHUB_OUTPUT")
    if gh:
        with open(gh, "a") as fh:
            for k in ("recomputed_auroc", "se", "stored_auroc", "integrity", "verdict"):
                fh.write(f"{k}={out.get(k)}\n")
    print(json.dumps(out, indent=2))
    if not ok:
        print("::error::integrity check failed — stored auroc does not match per_case recompute")
        sys.exit(1)


if __name__ == "__main__":
    main()
