"""Acceptance checker for scripts/imp_a6_target.py (criterion C4 of cyberdef-a6-tooling).

Usage:
  .venv/bin/python acceptance/improve/check_a6_target.py [--target F] [--mutants]

THE TARGET CONTRACT (this checker is the spec; CURRENT_PLAN.md section 4, "Owner target"):
  python scripts/imp_a6_target.py --manifest M.json [--out D.json]        and        python scripts/imp_a6_target.py --selftest
  exit 0 = TARGET MET, 3 = NOT MET, 2 = refusal (message on stderr, never a traceback). D.json = {"decision": "MET"|"NOT_MET"}.
  M.json = {"cases": path of results/vsp_t_cases.json,
            "seeds": {"0": S, "1": S, "2": S}}
  S = {"result": path of the registered per_case result file,
       "verdicts": {"own_base": path, "pinned_27b_base": path}}      (imp_verdict round outputs, --z 2.394)
MET iff, for each of the seeds 0, 1 and 2: the AUROC recomputed from per_case p_vuln (tie-averaged, full precision, no
rounding) over ALL 776 rows is >= 0.70, and both verdict JSONs have "verdict": "PASS" with "z" == 2.394, and the
pinned_27b_base verdict lists an input whose sha256 starts with 96cd996c (the pinned Qwen3.8-27B base file).
Anything in a result file that is not per_case (auroc, headline fields) is ignored. Refusals (exit 2): cases file whose
sha256 is not 543c4346... (the VSP-T cases), a result with n != 776 or keys that differ from the cases, a null p_vuln, an
unreadable file, a verdict file that is missing. A missing seed or a seed with only a subset of rows is never MET (exit 2 or 3).
The checker builds SYNTHETIC per_case scores from the (id, label) pairs of the VSP-T cases file. It never opens a real VSP-T
result file. --mutants shifts the 0.70 and 2.394 literals of the target script; every mutant must be caught.
"""
from __future__ import annotations

import argparse
import ast
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import check_a6_common as C  # noqa: E402

THRESH, Z = 0.70, 2.394
K_HI = 105381   # 105381 / 150544 = 0.7000011 ; 105380 / 150544 = 0.6999947  (388 x 388 pairs)
K_LO = 105380
PIN27 = "96cd996c" + "0" * 56


class Fx:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="a6tgt_"))
        self.cases = json.load(open(C.VSPT, encoding="utf-8"))["cases"]
        self.keys = [(c["id"], c["label"]) for c in self.cases]
        self.y = C.labels01(self.cases)
        self.n1 = int(self.y.sum())
        self.n0 = len(self.y) - self.n1
        self.n = 0

    def path(self, stem):
        self.n += 1
        return self.tmp / f"{stem}_{self.n}.json"

    def scores(self, k, seed):
        """per-case p with AUROC exactly k / (n1 * n0): bisect a label shift, then swap adjacent rank neighbours."""
        total = self.n1 * self.n0
        noise = np.random.default_rng(seed).normal(0.0, 1.0, len(self.y))
        lo, hi = 0.0, 4.0
        for _ in range(40):
            mid = (lo + hi) / 2.0
            if C.auroc(noise + mid * self.y, self.y) * total < k:
                lo = mid
            else:
                hi = mid
        s = noise + hi * self.y
        for _ in range(400):
            cur = round(C.auroc(s, self.y) * total)
            if cur == k:
                break
            order = np.argsort(s, kind="mergesort")
            ys = self.y[order]
            want_up = cur < k
            for t in range(len(order) - 1):
                if (want_up and ys[t] == 1 and ys[t + 1] == 0) or (not want_up and ys[t] == 0 and ys[t + 1] == 1):
                    i, j = order[t], order[t + 1]
                    s[i], s[j] = s[j], s[i]
                    break
        assert round(C.auroc(s, self.y) * total) == k, "could not reach the exact AUROC count"
        return C.sigmoid(s / 4.0)

    def write_result(self, p, headline=None, rows=None):
        per = [{"id": k[0], "label": k[1], "p_vuln": float(p[i])} for i, k in enumerate(self.keys)]
        if rows is not None:
            per = per[:rows]
        path = self.path("res")
        d = {"method": "selective:fixture", "per_case": per}
        if headline is not None:
            d["auroc"] = headline
            d["headline"] = {"auroc": headline}
        json.dump(d, open(path, "w"))
        return str(path)

    def write_verdict(self, verdict="PASS", z=Z, pinned=False, with_pin=True, result=None):
        """result: the seed's result file; imp_verdict lists it (path -> sha256) among the verdict inputs."""
        path = self.path("verdict")
        inputs = {"/x/cases.json": "543c4346" + "0" * 56, "/x/adapter.json": "ab" * 32}
        if result is not None:
            inputs[str(Path(result).resolve())] = C.sha256(result)
        inputs["/x/base.json"] = PIN27 if (pinned and with_pin) else "cd" * 32
        d = {"mode": "round", "n": 776, "verdict": verdict, "inputs": inputs}
        if z is not None:
            d["z"] = z
        json.dump(d, open(path, "w"))
        return str(path)


def entry(fx, p, headline=None, rows=None, own="PASS", pinned="PASS", z=Z, zp=Z, with_pin=True):
    res = fx.write_result(p, headline, rows)
    return {"result": res,
            "verdicts": {"own_base": fx.write_verdict(own, z, result=res),
                         "pinned_27b_base": fx.write_verdict(pinned, zp, True, with_pin, result=res)}}


def build_manifest(fx, seeds, cases=None):
    path = fx.path("manifest")
    json.dump({"cases": str(cases or C.VSPT), "seeds": seeds}, open(path, "w"))
    return str(path)


def tests(fx):
    T = []
    P = {s: fx.scores(k, 40 + s) for s, k in ((0, 105700), (1, 106500), (2, 107300))}   # 0.7021 / 0.7074 / 0.7127
    hi, lo = fx.scores(K_HI, 77), fx.scores(K_LO, 78)

    def add(label, build, allowed):
        T.append((label, build, allowed))

    def good(seed=None, e=None):
        d = {str(s): entry(fx, P[s]) for s in (0, 1, 2)}
        if seed is not None:
            d[str(seed)] = e
        return d

    add("MET: three seeds at 0.702 / 0.707 / 0.713, all six verdicts PASS at z 2.394", lambda: build_manifest(fx, good()), {0})
    add("MET: seed 1 at 0.7000011 (105381 / 150544), the first count above 0.70",
        lambda: build_manifest(fx, good(1, entry(fx, hi))), {0})
    add("NOT MET: seed 1 at 0.6999947 (105380 / 150544)", lambda: build_manifest(fx, good(1, entry(fx, lo))), {3})
    add("NOT MET: seed 2 at 0.6999947 with a headline auroc of 0.75",
        lambda: build_manifest(fx, good(2, entry(fx, lo, headline=0.75))), {3})
    add("MET: seed 0 headline says 0.50 but per_case AUROC is 0.702",
        lambda: build_manifest(fx, good(0, entry(fx, P[0], headline=0.50))), {0})
    add("NOT MET: a rounded headline 0.70 over a per_case AUROC of 0.6999947",
        lambda: build_manifest(fx, good(0, entry(fx, lo, headline=0.70))), {3})
    return T, P, hi, lo, good, add


def more_tests(fx, P, good, add):
    def partial():
        d = good()
        del d["2"]
        return d

    def subset_dup():
        d = good()
        del d["2"]
        d["2"] = entry(fx, P[0], rows=700)
        return d

    add("not MET: seed 2 missing", lambda: build_manifest(fx, partial()), {2, 3})
    add("not MET: seed 2 replaced by a 700-row subset", lambda: build_manifest(fx, subset_dup()), {2, 3})
    add("refuse: a result covering 700 of the 776 rows (a subset)",
        lambda: build_manifest(fx, good(0, entry(fx, P[0], rows=700))), {2})
    add("NOT MET: own-base verdict is FAIL", lambda: build_manifest(fx, good(1, entry(fx, P[1], own="FAIL"))), {3})
    add("NOT MET: pinned 27B-base verdict is FAIL",
        lambda: build_manifest(fx, good(2, entry(fx, P[2], pinned="FAIL"))), {3})
    add("NOT MET: own-base verdict was run at z 2.0, not 2.394",
        lambda: build_manifest(fx, good(0, entry(fx, P[0], z=2.0))), {3})
    add("NOT MET: pinned verdict at z 2.393", lambda: build_manifest(fx, good(0, entry(fx, P[0], zp=2.393))), {3})
    add("NOT MET: the pinned-base verdict does not list the 96cd996c base file",
        lambda: build_manifest(fx, good(1, entry(fx, P[1], with_pin=False))), {3})
    add("refuse: the cases file is the dev2 cases (sha not 543c4346)",
        lambda: build_manifest(fx, good(), cases=C.DEV2), {2})

    def nullp():
        e = entry(fx, P[1])
        d = json.load(open(e["result"]))
        d["per_case"][3]["p_vuln"] = None
        json.dump(d, open(e["result"], "w"))
        e["verdicts"] = {"own_base": fx.write_verdict(result=e["result"]),
                         "pinned_27b_base": fx.write_verdict(pinned=True, result=e["result"])}   # re-bind to the edited file
        return build_manifest(fx, good(1, e))

    def noverdict():
        e = entry(fx, P[1])
        Path(e["verdicts"]["own_base"]).unlink()
        return build_manifest(fx, good(1, e))

    add("refuse: a null p_vuln", nullp, {2})
    add("refuse: a verdict file is missing", noverdict, {2})


def all_tests(fx):
    T, P, hi, lo, good, add = tests(fx)
    more_tests(fx, P, good, add)
    return T


def run_tool(tool, mf, tmp):
    out = Path(tmp) / "decision.json"
    if out.exists():
        out.unlink()
    p = subprocess.run([sys.executable, str(tool), "--manifest", mf, "--out", str(out)], cwd=ROOT, capture_output=True,
                       text=True, timeout=300)
    return p.returncode, p.stdout + p.stderr, (json.load(open(out)) if out.is_file() else None)


def evaluate(fx, tests_, tool, fail_fast=False):
    fails, lines = 0, []
    for label, build, allowed in tests_:
        code, text, dec = run_tool(tool, build(), fx.tmp)
        ok = code in allowed and "Traceback" not in text
        if ok and code == 0:
            ok = bool(dec) and dec.get("decision") == "MET"
        if ok and code == 3:
            ok = bool(dec) and dec.get("decision") == "NOT_MET"
        fails += 0 if ok else 1
        why = "" if ok else f" (want {sorted(allowed)}; {text.strip()[-140:]})"
        lines.append(("ok   " if ok else "FAIL ") + f"{label}: exit {code}" + why)
        if fail_fast and not ok:
            break
    return fails, lines


def static_checks(tool):
    p = Path(tool)
    if not p.is_file():
        return False, f"{tool} does not exist (target not built yet)"
    tree = ast.parse(p.read_text(encoding="utf-8"))
    nums = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, (int, float))}
    missing = [c for c in (THRESH, Z, 776) if not any(abs(v - c) < 1e-12 for v in nums)]
    flags = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
             and n.value.startswith("--") and len(n.value) > 2 and " " not in n.value}
    extra = sorted(flags - {"--manifest", "--out", "--selftest"})
    return not missing and not extra, f"literals missing {missing}; flags beyond manifest/out/selftest {extra}"


def run_mutants(fx, tests_, tool):
    tool = Path(tool)
    unc, out = 0, []
    for const, delta in ((THRESH, -0.001), (THRESH, 0.001), (Z, -0.001), (Z, 0.001)):
        tree = ast.parse(tool.read_text(encoding="utf-8"))
        hit = 0
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, float) and abs(n.value - const) < 1e-12:
                n.value = round(n.value + delta, 6)
                hit += 1
        if not hit:
            out.append(f"MUTANT {const}{delta:+}: not found as a float literal")
            unc += 1
            continue
        mp = tool.parent / f"_a6mut_{tool.name}"
        mp.write_text(ast.unparse(tree), encoding="utf-8")
        try:
            fails, _ = evaluate(fx, tests_, mp, fail_fast=True)
        finally:
            mp.unlink()
        unc += 0 if fails else 1
        out.append(("caught   " if fails else "UNCAUGHT ") + f"mutant {const} {delta:+}")
    return unc, out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=str(ROOT / "scripts/imp_a6_target.py"))
    ap.add_argument("--mutants", action="store_true")
    a = ap.parse_args(argv)
    ok_static, detail = static_checks(a.target)
    print(("PASS " if ok_static else "FAIL ") + "CONSTANTS_IN_CODE - " + detail, flush=True)
    if not Path(a.target).is_file():
        print("RESULT: FAIL (target script missing; no fixture can run)")
        return 1
    fx = Fx()
    try:
        ts = all_tests(fx)
        fails, lines = evaluate(fx, ts, a.target)
        for ln in lines:
            print(ln, flush=True)
        total = fails + (0 if ok_static else 1)
        if a.mutants and total == 0:
            unc, out = run_mutants(fx, ts, a.target)
            for ln in out:
                print(ln, flush=True)
            total += unc
        print(f"RESULT: {'FAIL' if total else 'PASS'} ({fails} failures{'' if ok_static else ', constants/flags'})")
        return 1 if total else 0
    finally:
        shutil.rmtree(fx.tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
