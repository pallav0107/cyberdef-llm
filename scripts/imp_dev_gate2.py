#!/usr/bin/env python3
"""Cycle-2 dev gate: choose the K4 pilot configuration on VSP-DEV2, before VSP-T is read.
(scripts/imp_dev_gate.py, the cycle-1 gate, stays pinned and untouched; scripts/imp_verdict.py is imported, never edited.)

  .venv/bin/python scripts/imp_dev_gate2.py --round K4a=r1.json --scores K4a=A1,A2,A3:B1,B2,B3 --train-log K4a=log1.json \
      --round K4b=r2.json --scores K4b=... --train-log K4b=log2.json [--dev2-cases results/vsp_dev2_cases.json] [--out d.json]
  .venv/bin/python scripts/imp_dev_gate2.py --selftest

Inputs per config: the imp_verdict `round --pair-veto` output scored on results/vsp_dev2_cases.json; the adapter and base
per-case score files that round used (--scores NAME=adapter files:base files, comma separated) from which the
stratum-B win counts are recomputed with imp_verdict.pair_wins (a round output does not carry them); and the train log
(out/imp_<TAG>_imp_train_log.json). The screens are read from the log BEFORE any dev2 number is looked at.

Rule (constants fixed here, never a run-time knob; CURRENT_PLAN.md Amendment 1):
  screens   1 per-domain sampler: inside linux and inside other, A and B slot counts differ by <= 1 in every epoch and no
              pair appears more than twice in an epoch
            2 last200.pair < 0.679
            3 K4b only: pair terms logged == pair-steps (the verdict_slot trap switches the pair term off silently)
            A missing or null log field is a refusal (exit 2), not a pass.
  eligible  every screen passes AND comparisons.base.delta > 0 AND pair_veto.delta >= 0.035
            AND B-stratum wins(adapter) >= B-stratum wins(base) - 2
  winner    the eligible config with the highest pair_veto.delta, except K4a wins when it is eligible and within 0.02
            of the best (a gap of exactly 0.02 is within). A config that is not eligible is never promoted.
  none eligible -> NO-GO, exit 3, nothing is scored on VSP-T.
A round whose n is not 2 x the dev2 pair count, or that was scored on the linux held-out probe set or the cycle-1 dev set,
is refused (probe and cycle-1 dev are not gate sets). Exit codes: 0 winner, 2 refused input or usage error, 3 NO-GO.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

VETO_MIN = 0.035        # pair_veto.delta threshold (about 1 SE at B 122 / A 369)
B_WINS_SLACK = 2        # B-stratum wins(adapter) >= wins(base) - 2
TIE_K4A = 0.02          # K4a wins when eligible and within this of the best
PAIR_LOSS_MAX = 0.679   # last200.pair must be strictly below
SIMPLE = "K4a"
K4B = "K4b"
CONFIG_NAMES = (SIMPLE, K4B)   # exact match only: the K4b screen is keyed on the name
PROBE_N, DEV1_N = 600, 632   # case counts of the linux held-out probe and cycle-1 dev (never gate sets)


class Refused(Exception):
    """An input that must not be used (wrong n, null fields, unreadable file, a non-gate test set)."""


def dev2_n(cases_path):
    """Number of cases (2 per pair) of the dev2 cases file; Refused if it is not dev2 or not whole pairs."""
    try:
        d = json.load(open(cases_path, encoding="utf-8"))
        cases = d["cases"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Refused(f"cannot read dev2 cases {cases_path}: {type(exc).__name__}: {exc}")
    return check_cases(d.get("split"), cases)


def check_cases(split, cases):
    pairs = {c["pair"] for c in cases}
    if split == "vsp_probe" or (cases and all(c.get("source") == "probe" for c in cases)) or \
            (cases and all(c.get("project") == "linux" for c in cases)):
        raise Refused("the cases are the linux held-out probe set: descriptive only, never a gate set")
    if split == "vsp_dev":
        raise Refused("the cases are the cycle-1 dev set: retired, never a gate set")
    if len(cases) != 2 * len(pairs):
        raise Refused(f"dev2 cases are not whole pairs: {len(cases)} cases, {len(pairs)} pairs")
    return len(cases)


def num(d, *path, what):
    """d[path...] as a float; Refused if absent or null."""
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            raise Refused(f"{what}: field {'.'.join(path)} is missing")
        cur = cur[p]
    if cur is None or isinstance(cur, bool) or not isinstance(cur, (int, float)):
        raise Refused(f"{what}: field {'.'.join(path)} is null or not a number")
    return float(cur)


def screens(name, log):
    """(passed, [failure reasons]) from a train log; Refused on a missing or null field."""
    what = f"{name} train log"
    ps = log.get("pair_sampler") if isinstance(log, dict) else None
    eps = ps.get("epochs_iterated") if isinstance(ps, dict) else None
    if not isinstance(eps, list) or not eps:
        raise Refused(f"{what}: pair_sampler.epochs_iterated is missing or empty")
    fails = []
    for e in eps:
        if not isinstance(e, dict) or not isinstance(e.get("domains"), dict) or e.get("max_pair_count") is None:
            raise Refused(f"{what}: an epoch entry lacks domains or max_pair_count")
        for dom in ("linux", "other"):
            d = e["domains"].get(dom)
            if not isinstance(d, dict) or d.get("A") is None or d.get("B") is None:
                raise Refused(f"{what}: epoch {e.get('epoch')} domain {dom} lacks A / B counts")
            if abs(d["A"] - d["B"]) > 1:
                fails.append(f"sampler: epoch {e.get('epoch')} {dom} A={d['A']} B={d['B']} differ by more than 1")
        if e["max_pair_count"] > 2:
            fails.append(f"sampler: epoch {e.get('epoch')} a pair appears {e['max_pair_count']} times (max 2)")
    pair = num(log, "last200", "pair", what=what)
    if not pair < PAIR_LOSS_MAX:
        fails.append(f"last200.pair {pair:.4f} is not below {PAIR_LOSS_MAX}")
    if name == K4B:
        terms, steps = num(log, "pair_terms", what=what), num(log, "pair_steps", what=what)
        if terms != steps:
            fails.append(f"K4b: {int(terms)} pair terms for {int(steps)} pair-steps (pair term switched off)")
    return not fails, fails


def summarise(name, rnd, log, n_dev):
    """The fields the gate reads from one config; Refused if n is not the dev2 n or a field is absent / null."""
    blob = json.dumps(rnd, sort_keys=True)
    if "vsp_probe_cases" in blob:
        raise Refused(f"{name}: the round file names the linux held-out probe set: not a gate set")
    if "vsp_dev_cases" in blob:
        raise Refused(f"{name}: the round file names the cycle-1 dev set: not a gate set")
    n = num(rnd, "n", what=name)
    if n == PROBE_N and n != n_dev:
        raise Refused(f"{name}: n={int(n)} is the linux held-out probe set size: the probe is not a gate set")
    if n == DEV1_N and n != n_dev:
        raise Refused(f"{name}: n={int(n)} is the cycle-1 dev set size: not a gate set")
    if n != n_dev:
        raise Refused(f"{name}: n={int(n)} is not the dev2 n={n_dev} (2 x {n_dev // 2} dev2 pairs); not scored on dev2")
    pv = num(rnd, "pair_veto", "delta", what=name)
    base = num(rnd, "comparisons", "base", "delta", what=name)
    bwa = num(rnd, "pair_veto", "b_wins_adapter", what=name)
    bwb = num(rnd, "pair_veto", "b_wins_base", what=name)
    ok_screens, why = screens(name, log)
    eligible = (ok_screens and base > 0 and round(pv, 9) >= VETO_MIN and bwa >= bwb - B_WINS_SLACK - 1e-9)
    reasons = list(why)
    if not base > 0:
        reasons.append(f"comparisons.base.delta {base:+.4f} is not > 0")
    if not round(pv, 9) >= VETO_MIN:
        reasons.append(f"pair_veto.delta {pv:+.4f} is below {VETO_MIN}")
    if not bwa >= bwb - B_WINS_SLACK - 1e-9:
        reasons.append(f"B wins adapter {bwa:g} < base {bwb:g} - {B_WINS_SLACK}")
    return {"name": name, "n": int(n), "pair_veto_delta": pv, "base_delta": base, "b_wins_adapter": bwa,
            "b_wins_base": bwb, "screens_ok": ok_screens, "eligible": bool(eligible), "reasons": reasons}


def decide(rows):
    """(decision, winner name or None, reason) from summarised rows."""
    eligible = sorted((r for r in rows if r["eligible"]), key=lambda r: r["name"])
    if not eligible:
        return "NO-GO", None, "no config passes every screen with base delta > 0, veto delta >= 0.035 and B wins"
    best = max(eligible, key=lambda r: (r["pair_veto_delta"], r["name"]))
    k4a = next((r for r in eligible if r["name"] == SIMPLE), None)
    if k4a is not None and round(best["pair_veto_delta"] - k4a["pair_veto_delta"], 9) <= TIE_K4A:
        why = "best eligible" if k4a is best else f"within {TIE_K4A} of the best ({best['name']})"
        return "GO", SIMPLE, f"{SIMPLE} is eligible and {why}"
    return "GO", best["name"], f"highest pair_veto.delta among eligible configs ({best['pair_veto_delta']:.4f})"


def run(configs, n_dev):
    """configs: [(name, round dict with pair_veto.b_wins_*, train log dict)] -> decision dict (input order irrelevant)."""
    names = [c[0] for c in configs]
    bad = [n for n in names if n not in CONFIG_NAMES]
    if bad:
        raise Refused(f"config names must be exactly {CONFIG_NAMES}, got {bad}")
    if len(set(names)) != len(names):
        raise Refused(f"duplicate config names {names}")
    rows = [summarise(n, r, lg, n_dev) for n, r, lg in sorted(configs, key=lambda c: c[0])]
    decision, winner, reason = decide(rows)
    return {"decision": decision, "winner": winner, "reason": reason, "veto_min": VETO_MIN,
            "b_wins_slack": B_WINS_SLACK, "tie_k4a": TIE_K4A, "n_dev": n_dev, "configs": rows}


def b_wins(cases_path, adapter_files, base_files):
    """(adapter, base) stratum-B win sums on the dev2 cases from per-case score files, via imp_verdict.pair_wins."""
    import imp_verdict as iv
    cases, keys = iv.load_cases(cases_path)
    groups = iv.pair_groups(cases, keys)
    out = []
    for files in (adapter_files, base_files):
        runs = [iv.load_result(p, keys)[1] for p in files]
        mean = [sum(r[i] for r in runs) / len(runs) for i in range(len(keys))]
        wins, _eq, _skip = iv.pair_wins(cases, keys, groups, mean)
        out.append(sum(wins["B"]))
    return out[0], out[1]


def prepare_round(name, rnd, scores_spec, cases_path, wins_fn=None):
    """The round dict with stratum-B wins recomputed from the score files. A round file that already carries any
    b_wins_* field is refused (never trusted); so is a config with no --scores."""
    if "b_wins" in json.dumps(rnd):
        raise Refused(f"{name}: the round file already contains b_wins_* fields; they are never trusted, "
                      "B wins are always recomputed from --scores")
    if not scores_spec:
        raise Refused(f"{name}: no --scores (B-stratum wins are recomputed from the per-case score files)")
    ad, _, bs = scores_spec.partition(":")
    if not ad or not bs:
        raise Refused(f"--scores for {name} wants ADAPTER_FILES:BASE_FILES")
    wa, wb = (wins_fn or b_wins)(cases_path, ad.split(","), bs.split(","))
    rnd = copy.deepcopy(rnd)
    pv = rnd.setdefault("pair_veto", {})
    if not isinstance(pv, dict):
        raise Refused(f"{name}: pair_veto is not an object")
    pv["b_wins_adapter"], pv["b_wins_base"] = wa, wb
    return rnd


def read_json(path, what):
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"cannot read {what} {path}: {type(exc).__name__}: {exc}")


def split_spec(spec, flag):
    name, sep, rest = spec.partition("=")
    if not sep or not name or not rest:
        raise Refused(f"{flag} wants NAME=VALUE, got {spec!r}")
    return name, rest


# ---------------------------------------------------------------------------------------------------- selftest

def good_log(name=SIMPLE, pair=0.55, terms=816, steps=816):
    ep = {"epoch": 0, "max_pair_count": 2,
          "domains": {"linux": {"A": 308, "B": 308, "E": 1}, "other": {"A": 88, "B": 88, "E": 21}}}
    log = {"pair_sampler": {"mode": "balanced_by_domain", "epochs_iterated": [ep, {**ep, "epoch": 1}]},
           "last200": {"pair": pair}, "pair_terms": terms, "pair_steps": steps}
    return log


def synth(n, pv, base, bwa=40.0, bwb=40.0):
    return {"n": n, "pair_veto": {"delta": pv, "b_wins_adapter": bwa, "b_wins_base": bwb},
            "comparisons": {"base": {"delta": base}}}


def cases_for(m, n):
    """(label, configs, expected decision, expected winner or Refused) for module m; each boundary has both sides."""
    S = lambda name, pv, base=0.05, bwa=40.0, bwb=40.0, **kw: (name, synth(n, pv, base, bwa, bwb), good_log(name, **kw))
    def mutate(cfg, fn):
        name, r, lg = cfg
        r, lg = copy.deepcopy(r), copy.deepcopy(lg)
        fn(r, lg)
        return (name, r, lg)
    def drop(path):
        def f(r, lg):
            cur = r
            for p in path.split(".")[:-1]:
                cur = cur[p]
            cur[path.split(".")[-1]] = None
        return f
    def delete(path):
        def f(r, lg):
            cur = r
            for p in path.split(".")[:-1]:
                cur = cur[p]
            del cur[path.split(".")[-1]]
        return f
    def log_epoch(**kw):
        def f(r, lg):
            e = lg["pair_sampler"]["epochs_iterated"][1]
            e.update({k: v for k, v in kw.items() if k != "linux"})
            if "linux" in kw:
                e["domains"]["linux"] = kw["linux"]
        return f
    R = Refused
    return [
        ("veto +0.034 is NO-GO", [S("K4a", 0.034)], "NO-GO", None),
        ("veto +0.035 is eligible", [S("K4a", 0.035)], "GO", "K4a"),
        ("veto +0.035, B wins three below base: NO-GO", [S("K4a", 0.035, bwa=37, bwb=40)], "NO-GO", None),
        ("veto +0.035, B wins two below base: eligible", [S("K4a", 0.035, bwa=38, bwb=40)], "GO", "K4a"),
        ("pooled delta exactly 0 with veto +0.10: NO-GO", [S("K4a", 0.10, base=0.0)], "NO-GO", None),
        ("negative pooled delta: NO-GO", [S("K4a", 0.10, base=-0.01)], "NO-GO", None),
        ("K4a within 0.02 of a higher K4b: K4a wins", [S("K4a", 0.10), S("K4b", 0.12)], "GO", "K4a"),
        ("K4a 0.0201 below K4b: K4b wins", [S("K4a", 0.10), S("K4b", 0.1201)], "GO", "K4b"),
        ("K4a ineligible, K4b eligible: K4b wins", [S("K4a", 0.034), S("K4b", 0.10)], "GO", "K4b"),
        ("K4b higher, K4a not eligible on B wins: K4b wins", [S("K4a", 0.10, bwa=30), S("K4b", 0.11)], "GO", "K4b"),
        ("input order does not change the winner", [S("K4b", 0.12), S("K4a", 0.10)], "GO", "K4a"),
        # screens: one passing and one failing case each; a screen failure beats a good dev2 delta
        ("screen 1 fails: a linux epoch A/B differ by 2", [mutate(S("K4a", 0.2), log_epoch(
            linux={"A": 308, "B": 310, "E": 1}))], "NO-GO", None),
        ("screen 1 passes: a linux epoch A/B differ by 1", [mutate(S("K4a", 0.2), log_epoch(
            linux={"A": 308, "B": 309, "E": 1}))], "GO", "K4a"),
        ("screen 1 fails: a pair appears three times", [mutate(S("K4a", 0.2), log_epoch(max_pair_count=3))],
         "NO-GO", None),
        ("screen 1 passes: a pair appears twice", [mutate(S("K4a", 0.2), log_epoch(max_pair_count=2))], "GO", "K4a"),
        ("screen 2 fails: last200.pair 0.679", [S("K4a", 0.2, pair=0.679)], "NO-GO", None),
        ("screen 2 passes: last200.pair 0.678", [S("K4a", 0.2, pair=0.678)], "GO", "K4a"),
        ("screen 3 fails: K4b pair terms 0 of 816 steps", [S("K4b", 0.2, terms=0, steps=816)], "NO-GO", None),
        ("screen 3 passes: K4b pair terms equal pair-steps", [S("K4b", 0.2, terms=816, steps=816)], "GO", "K4b"),
        ("screen 3 does not apply to K4a", [S("K4a", 0.2, terms=0, steps=816)], "GO", "K4a"),
        # refusals
        ("n is not 2 x the dev2 pairs", [("K4a", synth(2 * 388, 0.1, 0.1), good_log())], "REFUSE", R),
        ("a round scored on the linux held-out probe (n 600)", [("K4a", synth(600, 0.1, 0.1), good_log())], "REFUSE", R),
        ("a round scored on cycle-1 dev (n 632)", [("K4a", synth(632, 0.1, 0.1), good_log())], "REFUSE", R),
        ("null pair_veto.delta", [mutate(S("K4a", 0.1), drop("pair_veto.delta"))], "REFUSE", R),
        ("missing comparisons.base.delta", [mutate(S("K4a", 0.1), delete("comparisons.base.delta"))], "REFUSE", R),
        ("null B-win field", [mutate(S("K4a", 0.1), drop("pair_veto.b_wins_adapter"))], "REFUSE", R),
        ("missing B-win field", [mutate(S("K4a", 0.1), delete("pair_veto.b_wins_base"))], "REFUSE", R),
        ("null last200.pair in the log", [mutate(S("K4a", 0.1), lambda r, lg: lg["last200"].__setitem__("pair", None))],
         "REFUSE", R),
        ("missing sampler block in the log", [mutate(S("K4a", 0.1), lambda r, lg: lg.pop("pair_sampler"))], "REFUSE", R),
        ("null K4b pair_terms in the log", [mutate(S("K4b", 0.1), lambda r, lg: lg.__setitem__("pair_terms", None))],
         "REFUSE", R),
    ]


def run_cases(m, n_dev, verbose=False):
    """Run every case against module m; return (number of mismatches, lines)."""
    bad, lines = 0, []
    for label, configs, want, want_winner in cases_for(m, n_dev):
        try:
            got = m.run(configs, n_dev)
            ok = want != "REFUSE" and got["decision"] == want and got["winner"] == want_winner
            what = f"{got['decision']} {got['winner']}"
        except m.Refused as exc:
            ok = want == "REFUSE"
            what = f"REFUSED ({exc})"
        bad += not ok
        lines.append(("ok   " if ok else "FAIL ") + f"{label}: {what}")
    return bad, lines


def input_check(m):
    """Config names are exact; a round file carrying b_wins_* is refused; B wins always come from --scores."""
    bad = 0
    fake = lambda cp, ad, bs: (40.0, 40.0)
    plain = {"n": 1010, "pair_veto": {"delta": 0.1}, "comparisons": {"base": {"delta": 0.1}}}
    tests = []
    for nm in ("K4B", "k4b", "K1", "K4a "):
        tests.append((f"config name {nm!r} refused", lambda nm=nm: m.run([(nm, synth(1010, 0.1, 0.1), good_log(nm))], 1010)))
    tests.append(("round with b_wins_* refused", lambda: m.prepare_round(
        "K4a", synth(1010, 0.1, 0.1), "a:b", "x", fake)))
    tests.append(("round with b_wins_* outside pair_veto refused", lambda: m.prepare_round(
        "K4a", {**plain, "b_wins_base": 3}, "a:b", "x", fake)))
    tests.append(("no --scores refused", lambda: m.prepare_round("K4a", plain, None, "x", fake)))
    for label, fn in tests:
        try:
            fn()
            ok = False
        except m.Refused:
            ok = True
        bad += not ok
        print(("ok   " if ok else "FAIL ") + f"{label}")
    r = m.prepare_round("K4a", plain, "a1,a2:b1,b2", "x", fake)
    ok = r["pair_veto"]["b_wins_adapter"] == 40.0 and r["pair_veto"]["b_wins_base"] == 40.0
    bad += not ok
    print(("ok   " if ok else "FAIL ") + "B wins recomputed from --scores and injected")
    return bad


def probe_case_check(m):
    """A cases file that is the probe set, the cycle-1 dev set, or not whole pairs is refused; a dev2-like file is not."""
    lin = [{"pair": "1", "project": "linux", "source": "probe"}, {"pair": "1", "project": "linux", "source": "probe"}]
    d2 = [{"pair": "1", "project": "a"}, {"pair": "1", "project": "a"}, {"pair": "2", "project": "b"},
          {"pair": "2", "project": "b"}]
    bad = 0
    for label, split, cs, refused in (("probe cases", "vsp_probe", lin, True), ("cycle-1 dev cases", "vsp_dev", d2, True),
                                      ("half pair", "vsp_dev2", d2[:3], True), ("dev2 cases", "vsp_dev2", d2, False)):
        try:
            m.check_cases(split, cs)
            ok = not refused
        except m.Refused:
            ok = refused
        bad += not ok
        print(("ok   " if ok else "FAIL ") + f"cases file {label}: {'refused' if refused else 'accepted'} expected")
    return bad


def load_mutant(src, subs):
    """Module from a temporary copy of this file with constant lines replaced; None if a substitution found nothing."""
    import importlib.util
    text = src
    for a, b in subs:
        if a not in text:
            return None
        text = text.replace(a, b, 1)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "gate2_mutant.py"
        p.write_text(text, encoding="utf-8", newline="\n")
        spec = importlib.util.spec_from_file_location("gate2_mutant", p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["gate2_mutant"] = mod
        spec.loader.exec_module(mod)
        return mod


def selftest():
    n_dev = 1010
    me = sys.modules[__name__]
    bad, lines = run_cases(me, n_dev)
    print("\n".join(lines))
    bad += probe_case_check(me)
    bad += input_check(me)
    # determinism: the same inputs give byte-identical output twice
    cfg = [("K4a", synth(n_dev, 0.10, 0.05), good_log("K4a")), ("K4b", synth(n_dev, 0.12, 0.05), good_log("K4b"))]
    a, b = json.dumps(run(cfg, n_dev), sort_keys=True), json.dumps(run(cfg, n_dev), sort_keys=True)
    ok = a == b
    bad += not ok
    print(("ok   " if ok else "FAIL ") + "deterministic: two runs give byte-identical output")
    # the selftest can fail: each mutated constant must produce a mismatch
    src = Path(__file__).read_text(encoding="utf-8")
    for label, subs in (("veto 0.035 -> 0.03", [("VETO_MIN = 0.035 ", "VETO_MIN = 0.03 ")]),
                        ("wins - 2 -> wins - 3", [("B_WINS_SLACK = 2 ", "B_WINS_SLACK = 3 ")]),
                        ("tie 0.02 -> 0.03", [("TIE_K4A = 0.02 ", "TIE_K4A = 0.03 ")])):
        mut = load_mutant(src, subs)
        if mut is None:
            print(f"FAIL mutation {label}: the constant line was not found")
            bad += 1
            continue
        nbad, _ = run_cases(mut, n_dev)
        ok = nbad > 0
        bad += not ok
        print(("ok   " if ok else "FAIL ") + f"mutation {label}: {nbad} cases report a mismatch (must be > 0)")
    print("dev gate 2 selftest " + ("PASS" if not bad else f"FAIL ({bad})"))
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--round", action="append", default=[], metavar="NAME=PATH")
    ap.add_argument("--scores", action="append", default=[], metavar="NAME=ADAPTER_FILES:BASE_FILES")
    ap.add_argument("--train-log", action="append", default=[], metavar="NAME=PATH")
    ap.add_argument("--dev2-cases", default="results/vsp_dev2_cases.json")
    ap.add_argument("--out", default=None, help="write the decision JSON here")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not a.round:
        ap.error("give --round NAME=PATH (with --scores and --train-log per config), or --selftest")
    try:
        n_dev = dev2_n(a.dev2_cases)
        rounds = dict(split_spec(s, "--round") for s in a.round)
        scores = dict(split_spec(s, "--scores") for s in a.scores)
        logs = dict(split_spec(s, "--train-log") for s in a.train_log)
        configs = []
        for name, path in rounds.items():
            rnd = read_json(path, "round file")
            if name not in logs:
                raise Refused(f"{name}: no --train-log (the screens need it)")
            rnd = prepare_round(name, rnd, scores.get(name), a.dev2_cases)
            configs.append((name, rnd, read_json(logs[name], "train log")))
        out = run(configs, n_dev)
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    for r in out["configs"]:
        print(f"{r['name']}: pair_veto.delta={r['pair_veto_delta']:+.4f} base.delta={r['base_delta']:+.4f} "
              f"B wins {r['b_wins_adapter']:g} vs base {r['b_wins_base']:g} screens={r['screens_ok']} "
              f"eligible={r['eligible']}" + ("" if r["eligible"] else " :: " + "; ".join(r["reasons"])))
    print(out["decision"] + (f" winner={out['winner']}" if out["winner"] else "") + f": {out['reason']}")
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(out, f, indent=1, sort_keys=True)
    return 0 if out["decision"] == "GO" else 3


if __name__ == "__main__":
    sys.exit(main())
