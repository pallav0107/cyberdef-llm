#!/usr/bin/env python3
"""Fail-first controls for the cyberdef backbone, as one visible CI step.

Every control is a PAIR: the real thing must PASS and a deliberately broken mutant must be CAUGHT. A control whose
mutant is not caught is measuring nothing (AGENTS.md: "a test that has never failed is unverified").

  oracle   : exec_oracle --selftest / --selftest2 in real mode -> every check True; in the 'never' and 'always'
             mutant modes -> at least one check False (the oracle cannot fake a pass).
  length   : length-only AUROC on each length-matched eval set must sit in [0.45, 0.55] (the sets' own build
             criterion); mutant = the same set with its shortest half of SAFE cases removed -> must leave the band.
  accept   : acceptance/improve check_* self-tests and their --broken mutants, per acceptance/improve/MUTATION_PROOF.md.

Exit 1 if any real control fails or any mutant goes uncaught. Writes results/ci_controls.json and a markdown table
(--md) for the GitHub run summary. Usage: ci_controls.py [--only oracle,length,accept] [--md FILE] [--timeout S]"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time

sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, r4

PY = sys.executable
MATCHED_SETS = ["results/lenmatched_eval_cases.json", "results/vs_holdout_matched_cases.json",
                "results/vs_nolinux_matched_cases.json"]
BAND = (0.45, 0.55)

# (name, argv, expect[, requires]) -- expect:
#   "pass"        exit 0
#   "caught"      non-zero exit (the check fails on the mutant)                       e.g. check_6 --broken
#   "caught_msg"  exit 0 AND prints "MUTANT CAUGHT" (these checks report a caught mutant as success; confirmed from their
#                 own output "BROKEN MUTANT CAUGHT (check fails as it must)")         e.g. check_2o / check_strictx --broken
# requires: a file that must exist for the control to be runnable here; if absent the control is BLOCKED (never PASS).
ACCEPT = [
    ("check_2o selftest", ["acceptance/improve/check_2o.py", "selftest"], "pass"),
    ("check_2o selftest --broken (mutant)", ["acceptance/improve/check_2o.py", "selftest", "--broken"], "caught_msg"),
    ("check_2 selftest", ["acceptance/improve/check_2.py", "selftest"], "pass"),
    ("check_6 grl", ["acceptance/improve/check_6.py", "grl"], "pass"),
    ("check_6 grl --broken (mutant)", ["acceptance/improve/check_6.py", "grl", "--broken"], "caught"),
    ("check_zs selftest", ["acceptance/improve/check_zs.py", "selftest"], "pass"),
    ("check_probe_internal selftest", ["acceptance/improve/check_probe_internal.py", "selftest"], "pass"),
    ("check_probe_internal results (Stage I file)",
     ["acceptance/improve/check_probe_internal.py", "results", "results/imp_probe_internal_boxbase7b.json"], "pass"),
    ("check_9a baselines", ["acceptance/improve/check_9a.py", "baselines"], "pass"),
    ("check_cotitems --selftest", ["acceptance/improve/check_cotitems.py", "--selftest"], "pass", "results/imp_trace_bank.jsonl"),
    ("check_data17 --selftest", ["acceptance/improve/check_data17.py", "--selftest"], "pass"),
    ("check_strictx", ["acceptance/improve/check_strictx.py"], "pass"),
    ("check_strictx --broken (mutant)", ["acceptance/improve/check_strictx.py", "--broken"], "caught_msg"),
]


def run(argv, timeout):
    t0 = time.time()
    try:
        p = subprocess.run([PY] + argv, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "PYTHONPATH": "src"})
        return p.returncode, (p.stdout + p.stderr)[-1500:], round(time.time() - t0, 1)
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT", round(time.time() - t0, 1)


def oracle_controls(timeout):
    rows = []
    for flag in ("--selftest", "--selftest2"):
        for mode in ("real", "never", "always"):
            argv = ["src/cyberdef/exec_oracle.py", flag] + ([] if mode == "real" else [mode])
            rc, out, secs = run(argv, timeout)
            d = None
            for line in reversed(out.strip().splitlines()):
                try:
                    d = json.loads(line)
                    break
                except Exception:
                    continue
            if not isinstance(d, dict):
                ok, detail = False, "no JSON result (rc=%s): %s" % (rc, out[-200:])
            elif mode == "real":
                bad = [k for k, v in d.items() if not v]
                ok, detail = (not bad), ("all %d checks True" % len(d) if not bad else "FAILED: " + ", ".join(bad))
            else:
                bad = [k for k, v in d.items() if not v]
                ok, detail = bool(bad), ("mutant caught by: " + ", ".join(bad[:4]) if bad else "mutant NOT caught (every check still True)")
            rows.append({"group": "oracle", "name": f"exec_oracle {flag} {mode}", "expect": "pass" if mode == "real" else "caught",
                         "ok": ok, "detail": detail, "seconds": secs})
    return rows


def length_controls():
    rows = []
    for path in MATCHED_SETS:
        if not os.path.exists(path):
            rows.append({"group": "length", "name": path, "expect": "pass", "ok": False, "detail": "file missing", "seconds": 0})
            continue
        d = json.load(open(path))
        cases = d["cases"] if isinstance(d, dict) else d
        ln = [float(c.get("code_chars") or len(c.get("code", ""))) for c in cases]
        y = [1 if c["label"] in ("VULNERABLE", 1, "1") else 0 for c in cases]
        a = auroc(ln, y)
        rows.append({"group": "length", "name": f"length-only AUROC {os.path.basename(path)} (n={len(cases)})", "expect": "pass",
                     "ok": a is not None and BAND[0] <= a <= BAND[1], "detail": f"auroc={r4(a)} band={BAND}", "seconds": 0})
        safe = sorted((i for i in range(len(cases)) if y[i] == 0), key=lambda i: ln[i])
        drop = set(safe[:len(safe) // 2])
        keep = [i for i in range(len(cases)) if i not in drop]
        am = auroc([ln[i] for i in keep], [y[i] for i in keep])
        rows.append({"group": "length", "name": f"  mutant: shortest half of SAFE removed ({os.path.basename(path)})", "expect": "caught",
                     "ok": am is not None and not (BAND[0] <= am <= BAND[1]), "detail": f"auroc={r4(am)} (must leave the band)", "seconds": 0})
    return rows


def accept_controls(timeout):
    rows = []
    for spec in ACCEPT:
        name, argv, expect = spec[:3]
        req = spec[3] if len(spec) > 3 else None
        if not os.path.exists(argv[0]):
            rows.append({"group": "accept", "name": name, "expect": expect, "ok": False, "detail": "script missing", "seconds": 0})
            continue
        if req and not os.path.exists(req):
            rows.append({"group": "accept", "name": name, "expect": expect, "ok": False, "blocked": True,
                         "detail": f"BLOCKED: needs {req} (not on this machine)", "seconds": 0})
            continue
        rc, out, secs = run(argv, timeout)
        if expect == "pass":
            ok = rc == 0
        elif expect == "caught":
            ok = rc not in (0, None)
        else:  # caught_msg
            ok = rc == 0 and "MUTANT CAUGHT" in out
        tail = out.strip().splitlines()[-1][:160] if out.strip() else ""
        rows.append({"group": "accept", "name": name, "expect": expect, "ok": ok, "detail": f"rc={rc}  {tail}", "seconds": secs})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="oracle,length,accept")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--md", default="")
    ap.add_argument("--out", default="results/ci_controls.json")
    a = ap.parse_args()
    groups = set(a.only.split(","))
    rows = []
    if "length" in groups:
        rows += length_controls()
    if "oracle" in groups:
        rows += oracle_controls(a.timeout)
    if "accept" in groups:
        rows += accept_controls(a.timeout)
    blocked = [r for r in rows if r.get("blocked")]
    failed = [r for r in rows if not r["ok"] and not r.get("blocked")]
    json.dump({"rows": rows, "failed": len(failed), "blocked": len(blocked), "n": len(rows)}, open(a.out, "w"), indent=1)
    lines = ["## Fail-first controls", "",
             f"{len(rows) - len(failed) - len(blocked)}/{len(rows)} OK, {len(failed)} FAIL, {len(blocked)} BLOCKED (missing precondition, never counted as a pass)", "",
             "| group | control | expect | result | detail | s |", "|---|---|---|---|---|---|"]
    for r in rows:
        res = "BLOCKED" if r.get("blocked") else ("OK" if r["ok"] else "**FAIL**")
        lines.append(f"| {r['group']} | {r['name']} | {r['expect']} | {res} | {r['detail'].replace('|', '/')} | {r['seconds']} |")
    md = "\n".join(lines) + "\n"
    print(md)
    for r in blocked:
        print(f"::warning::BLOCKED control: {r['name']} -- {r['detail']}")
    if a.md:
        open(a.md, "w").write(md)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
