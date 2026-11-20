#!/usr/bin/env python3
"""Dev gate: choose the pilot configuration on VSP-DEV, before VSP-T is read.

Inputs are imp_verdict `round` output JSONs, one per pilot config, each scored on results/vsp_dev_cases.json:

  .venv/bin/python scripts/imp_dev_gate.py --round K1=r1.json --round K2=r2.json [--round K3=r3.json] \
      --dev-cases results/vsp_dev_cases.json [--out decision.json]
  .venv/bin/python scripts/imp_dev_gate.py --selftest

Rule (fixed here, not a run-time knob):
  eligible  pair_veto.delta > 0 AND comparisons.base.delta > 0 (adapter beats base within pairs and overall)
  winner    the eligible config with the highest pair_veto.delta, except that K1 wins when it is eligible and within
            TIE_K1 (0.02) of the best (the simpler recipe wins a near-tie)
  none eligible -> NO-GO, exit 3
A round file whose n is not 2 * (number of dev pairs) was not scored on the dev set: refused, exit 2.
Exit codes: 0 winner chosen, 2 refused input or usage error, 3 NO-GO.
"""
from __future__ import annotations

import argparse
import json
import sys

TIE_K1 = 0.02
SIMPLE = "K1"


class Refused(Exception):
    """An input that must not be used (wrong n, missing fields, unreadable file)."""


def dev_n(cases_path):
    """Number of cases (2 per pair) in the dev cases file."""
    try:
        cases = json.load(open(cases_path, encoding="utf-8"))["cases"]
    except (OSError, ValueError, KeyError) as exc:
        raise Refused(f"cannot read dev cases {cases_path}: {type(exc).__name__}: {exc}")
    pairs = {c["pair"] for c in cases}
    if len(cases) != 2 * len(pairs):
        raise Refused(f"dev cases are not whole pairs: {len(cases)} cases, {len(pairs)} pairs")
    return len(cases)


def summarise(name, rnd, n_dev):
    """The fields the gate reads from one round output; Refused if n is not the dev n or a field is absent."""
    try:
        n = rnd["n"]
        pv, base = rnd["pair_veto"]["delta"], rnd["comparisons"]["base"]["delta"]
    except (KeyError, TypeError) as exc:
        raise Refused(f"{name}: round output lacks {exc} (needs n, pair_veto.delta, comparisons.base.delta)")
    if n != n_dev:
        raise Refused(f"{name}: n={n} is not the dev n={n_dev} (2 x {n_dev // 2} dev pairs); not scored on VSP-DEV")
    if pv is None or base is None:
        raise Refused(f"{name}: pair_veto.delta or comparisons.base.delta is null")
    return {"name": name, "n": n, "pair_veto_delta": pv, "base_delta": base,
            "eligible": pv > 0 and base > 0}


def decide(rows):
    """(decision, winner name or None, reason) from summarised rows."""
    eligible = [r for r in rows if r["eligible"]]
    if not eligible:
        return "NO-GO", None, "no config has pair_veto.delta > 0 and comparisons.base.delta > 0"
    best = max(eligible, key=lambda r: r["pair_veto_delta"])
    k1 = next((r for r in eligible if r["name"] == SIMPLE), None)
    if k1 is not None and best["pair_veto_delta"] - k1["pair_veto_delta"] <= TIE_K1:
        why = "best eligible" if k1 is best else f"within {TIE_K1} of the best ({best['name']})"
        return "GO", SIMPLE, f"{SIMPLE} is eligible and {why}"
    return "GO", best["name"], f"highest pair_veto.delta among eligible configs ({best['pair_veto_delta']:.4f})"


def run(rounds, n_dev):
    """Full gate over {name: round dict}: returns the decision dict."""
    rows = [summarise(name, rnd, n_dev) for name, rnd in rounds]
    decision, winner, reason = decide(rows)
    return {"decision": decision, "winner": winner, "reason": reason, "tie_k1": TIE_K1, "n_dev": n_dev,
            "configs": rows}


def parse_round(spec):
    name, sep, path = spec.partition("=")
    if not sep or not name or not path:
        raise Refused(f"--round wants NAME=PATH, got {spec!r}")
    try:
        return name, json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"cannot read round file {path}: {type(exc).__name__}: {exc}")


def synth(n, pv, base):
    return {"n": n, "pair_veto": {"delta": pv}, "comparisons": {"base": {"delta": base}}}


def selftest():
    n = 632
    cases = [
        ("K1 only eligible", [("K1", synth(n, 0.10, 0.05)), ("K2", synth(n, -0.01, 0.05))], "GO", "K1"),
        ("K2 clearly better", [("K1", synth(n, 0.05, 0.05)), ("K2", synth(n, 0.15, 0.05))], "GO", "K2"),
        ("K1 within 0.02 of the best", [("K1", synth(n, 0.10, 0.05)), ("K2", synth(n, 0.12, 0.05))], "GO", "K1"),
        ("K1 just outside the tie", [("K1", synth(n, 0.10, 0.05)), ("K2", synth(n, 0.121, 0.05))], "GO", "K2"),
        ("K1 ineligible, K2 wins", [("K1", synth(n, 0.10, -0.01)), ("K2", synth(n, 0.03, 0.02))], "GO", "K2"),
        ("K3 best of three", [("K1", synth(n, 0.02, 0.1)), ("K2", synth(n, 0.05, 0.1)), ("K3", synth(n, 0.2, 0.1))],
         "GO", "K3"),
        ("pair veto zero is not eligible", [("K1", synth(n, 0.0, 0.1)), ("K2", synth(n, 0.0, 0.1))], "NO-GO", None),
        ("base delta zero is not eligible", [("K1", synth(n, 0.1, 0.0))], "NO-GO", None),
        ("none eligible", [("K1", synth(n, -0.1, -0.1)), ("K2", synth(n, 0.1, -0.1))], "NO-GO", None),
    ]
    bad = 0
    for label, rounds, want, want_winner in cases:
        got = run(rounds, n)
        ok = got["decision"] == want and got["winner"] == want_winner
        bad += not ok
        print(("ok   " if ok else "FAIL ") + f"{label}: {got['decision']} {got['winner']} ({got['reason']})")
    try:
        run([("K1", synth(2 * 388, 0.1, 0.1))], n)
        print("FAIL wrong n accepted")
        bad += 1
    except Refused as exc:
        print(f"ok   wrong n refused: {exc}")
    for label, bad_round in (("missing pair_veto", {"n": n, "comparisons": {"base": {"delta": 0.1}}}),
                             ("null delta", synth(n, None, 0.1))):
        try:
            run([("K1", bad_round)], n)
            print(f"FAIL {label} accepted")
            bad += 1
        except Refused as exc:
            print(f"ok   {label} refused: {exc}")
    print("dev gate selftest " + ("PASS" if not bad else f"FAIL ({bad})"))
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--round", action="append", default=[], metavar="NAME=PATH",
                    help="imp_verdict round output for one config (repeat; K1 is the simple recipe)")
    ap.add_argument("--dev-cases", default="results/vsp_dev_cases.json")
    ap.add_argument("--out", default=None, help="write the decision JSON here")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not a.round:
        ap.error("give at least one --round NAME=PATH (or --selftest)")
    try:
        n_dev = dev_n(a.dev_cases)
        rounds = [parse_round(s) for s in a.round]
        names = [n for n, _ in rounds]
        if len(set(names)) != len(names):
            raise Refused(f"duplicate config names {names}")
        out = run(rounds, n_dev)
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    for r in out["configs"]:
        print(f"{r['name']}: pair_veto.delta={r['pair_veto_delta']:+.4f} base.delta={r['base_delta']:+.4f} "
              f"eligible={r['eligible']}")
    print(f"{out['decision']}" + (f" winner={out['winner']}" if out["winner"] else "") + f": {out['reason']}")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=1)
    return 0 if out["decision"] == "GO" else 3


if __name__ == "__main__":
    sys.exit(main())
