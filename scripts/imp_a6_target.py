#!/usr/bin/env python3
"""Attempt-6 owner target (CURRENT_PLAN.md section 4): the pooled AUROC of every seed >= 0.70 on all 776 VSP-T rows.

  .venv/bin/python scripts/imp_a6_target.py --manifest M.json [--out D.json]
  .venv/bin/python scripts/imp_a6_target.py --selftest

Exit 0 = target MET, 3 = NOT MET, 2 = refusal (message on stderr; never a traceback). D.json = {"decision": ...}.
Manifest: {"cases": path of the VSP-T cases file, "seeds": {"0": S, "1": S, "2": S}} with
S = {"result": registered per_case result file, "verdicts": {"own_base": path, "pinned_27b_base": path}} (imp_verdict
round outputs run with --z 2.394). MET iff for every seed 0, 1, 2: the tie-averaged AUROC recomputed from per_case
p_vuln over all 776 rows, at full precision and unrounded, is >= 0.70, and both verdicts say PASS with z == 2.394, the
pinned_27b_base verdict listing an input whose sha256 starts with 96cd996c. Headline fields in a result file are ignored.
Constants are literals here; no flag, env var or file changes them. The only seed-level inputs are the three registered
result files and the six verdict files named in the manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.dont_write_bytecode = True

TARGET_AUROC = 0.70
VERDICT_Z = 2.394
N_ROWS = 776
SEEDS = ("0", "1", "2")
CASES_SHA = "543c4346ed41dd8d254f6c82346a4a592cc9e62fa7a26da5dd038bb18f2f5185"
BASE_SHA_PREFIX = "96cd996c"


class Refused(Exception):
    pass


def read_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError) as exc:
        raise Refused(f"cannot read {what} {path}: {type(exc).__name__}: {exc}")


def auroc(scores, labels):
    from cyberdef.imp_common import auroc as _auroc
    return float(_auroc(scores, labels))


def load_cases(path):
    if not isinstance(path, str) or not Path(path).is_file():
        raise Refused(f"cases file {path} does not exist")
    sha = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if sha != CASES_SHA:
        raise Refused(f"cases sha {sha[:8]} is not the pinned VSP-T cases {CASES_SHA[:8]}")
    cases = read_json(path, "cases")["cases"]
    if len(cases) != N_ROWS:
        raise Refused(f"cases n={len(cases)} is not {N_ROWS}")
    return [(c["id"], c["label"]) for c in cases]


def seed_auroc(path, keys):
    # returns the AUROC; the caller binds the file by sha256
    res = read_json(path, "result")
    pc = res.get("per_case") if isinstance(res, dict) else None
    if not isinstance(pc, list):
        raise Refused(f"{path}: per_case missing")
    if len(pc) != N_ROWS:
        raise Refused(f"{path}: n={len(pc)} is not {N_ROWS} (a subset or an extension is refused)")
    got = {}
    for r in pc:
        p = r.get("p_vuln") if isinstance(r, dict) else None
        if p is None or isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p):
            raise Refused(f"{path}: a per_case p_vuln is null or not a number")
        got[(r.get("id"), r.get("label"))] = float(p)
    if set(got) != set(keys) or len(got) != len(pc):
        raise Refused(f"{path}: per_case ids / labels differ from the cases file")
    scores = [got[k] for k in keys]
    labels = [1 if k[1] == "VULNERABLE" else 0 for k in keys]
    return auroc(scores, labels)


def verdict_ok(path, what, pinned, result_sha=None):
    v = read_json(path, what)
    if not isinstance(v, dict):
        raise Refused(f"{what}: not a JSON object")
    why = []
    if v.get("verdict") != "PASS":
        why.append(f"{what}: verdict is {v.get('verdict')!r}, not PASS")
    if v.get("z") != VERDICT_Z:
        why.append(f"{what}: z is {v.get('z')!r}, not {VERDICT_Z}")
    inputs = v.get("inputs")
    if result_sha is not None:
        shas_all = list(inputs.values()) if isinstance(inputs, dict) else []
        if result_sha not in shas_all:
            raise Refused(f"{what}: its inputs do not list the sha256 of this seed's result file")
    if pinned:
        inputs = v.get("inputs")
        shas = list(inputs.values()) if isinstance(inputs, dict) else []
        if not any(isinstance(s, str) and s.startswith(BASE_SHA_PREFIX) for s in shas):
            why.append(f"{what}: no input with sha256 {BASE_SHA_PREFIX}... (the pinned 27B base file)")
    return why


def seed_met(auc):
    return auc >= TARGET_AUROC


def run(manifest):
    if not isinstance(manifest, dict):
        raise Refused("manifest is not a JSON object")
    keys = load_cases(manifest.get("cases"))
    seeds = manifest.get("seeds")
    if not isinstance(seeds, dict):
        raise Refused("manifest has no seeds")
    detail, why, seen = {}, [], {}
    for s in SEEDS:
        ent = seeds.get(s)
        if not isinstance(ent, dict) or not ent.get("result"):
            why.append(f"seed {s}: not registered")
            continue
        auc = seed_auroc(ent["result"], keys)
        rsha = hashlib.sha256(Path(ent["result"]).read_bytes()).hexdigest()
        if rsha in seen:
            raise Refused(f"seed {s}: its result file is byte-identical to the one registered for seed {seen[rsha]}")
        seen[rsha] = s
        vs = ent.get("verdicts") if isinstance(ent.get("verdicts"), dict) else {}
        if not vs.get("own_base") or not vs.get("pinned_27b_base"):
            raise Refused(f"seed {s}: both verdict files (own_base, pinned_27b_base) are required")
        vwhy = verdict_ok(vs["own_base"], f"seed {s} own_base verdict", False, rsha) + \
            verdict_ok(vs["pinned_27b_base"], f"seed {s} pinned_27b_base verdict", True, rsha)
        detail[s] = {"auroc": auc, "auroc_ok": seed_met(auc), "verdict_problems": vwhy}
        if not seed_met(auc):
            why.append(f"seed {s}: AUROC {auc!r} < {TARGET_AUROC}")
        why.extend(vwhy)
    return {"decision": "MET" if not why else "NOT_MET", "seeds": detail, "reasons": why}


def selftest():
    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)
    check("0.70 met", seed_met(0.70) and seed_met(0.7000011))
    check("0.69999 not met", not seed_met(0.69999) and not seed_met(0.6999947))
    labels = [1, 1, 0, 0]
    check("auroc perfect", auroc([0.9, 0.8, 0.2, 0.1], labels) == 1.0)
    check("auroc tie-averaged", abs(auroc([0.5, 0.5, 0.5, 0.5], labels) - 0.5) < 1e-12)
    check("auroc 0.75", abs(auroc([0.9, 0.3, 0.5, 0.1], labels) - 0.75) < 1e-12)
    print("a6 target selftest " + ("PASS" if not bad else f"FAIL {bad}"))
    return 0 if not bad else 1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest")
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    if a.selftest:
        return selftest()
    if not a.manifest:
        print("refused: --manifest is required", file=sys.stderr)
        return 2
    try:
        dec = run(read_json(a.manifest, "manifest"))
        if a.out:
            Path(a.out).write_text(json.dumps(dec, indent=1), encoding="utf-8")
        print(f"target {dec['decision']}: " + ("; ".join(dec["reasons"]) or "all three seeds >= 0.70 with passing verdicts"))
        return 0 if dec["decision"] == "MET" else 3
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001  a refusal, never a traceback
        print(f"refused: internal error {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
