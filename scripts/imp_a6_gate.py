#!/usr/bin/env python3
"""Attempt-6 GO rule (CURRENT_PLAN.md section 3): stage 1 on dev2, stage 2 on dev3. Constants live in this file only.

  .venv/bin/python scripts/imp_a6_gate.py --manifest M.json [--out D.json]
  .venv/bin/python scripts/imp_a6_gate.py --selftest

Exit 0 = GO, 3 = NO-GO, 2 = refusal (message on stderr; never a traceback). No other flag, env var or config file can
change a constant. Every AUROC, pair-veto and B-stratum win count is recomputed from per_case; headline fields in a
result file are ignored.

Manifest: {"dev2_cases": path, "dev3_cases": path | null,
           "candidates": [{"name": A1|A2|B1|B2|C1|C2, "dev2": {"pilot": E, "base": E}, "dev3": {"pilot": E}}],
           "reference": {"name": "K4b-27B", "dev2": {"pilot": E}, "dev3": {"pilot": E}} (optional)}
E = {"result": path, "provenance": path} plus "log": path on every dev2 pilot of a candidate (the train log).

Rule:
  S1 eligible(c): train-log screens pass (sampler A/B within 1 and max_pair_count <= 2 in every epoch, last200.pair <
      0.679, pair_terms == pair_steps == 1628, flags.mode == "4bit") AND dev2 AUROC >= 0.685 AND dev2 pair-veto >=
      0.6598 AND AUROC delta vs own base > 0 AND veto delta vs own base >= 0.035 AND B-stratum wins >= base - 2.
  Winner: highest dev2 AUROC; every eligible candidate within 0.005 of it competes on (parameter count, list order).
  Ensemble (only if no single is eligible): E = per-case mean of logit(p_vuln) of the top two dev2 AUROCs among the
      screened candidates plus the reference; eligible iff dev2 AUROC(E) >= 0.690 and pair-veto(E) >= 0.6598.
  S2 (the winner; E formed from the dev3 results for an ensemble): dev3 AUROC >= 0.665 and (dev2 + dev3) / 2 >= 0.685.
  GO = S1 and S2. A winner whose dev3 results are absent is an incomplete input (exit 2). No S1 winner is NO-GO.
Refusals: a VSP-T input anywhere, cases sha not the pinned dev2 / dev3 file, n differs from the cases, a null or missing
log or result field, provenance mismatch, a candidate outside the fixed list, no candidates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))
sys.dont_write_bytecode = True

# ---- committed constants (never run-time knobs) ----
S1_AUROC_MIN = 0.685        # stage 1: dev2 AUROC of a single candidate
VETO_FLOOR = 0.6598         # dev2 pair-veto of the 27B K4b pilot: the within-pair direction must not be bought back
ENSEMBLE_AUROC_MIN = 0.690  # stage 1 fallback: dev2 AUROC of the ensemble
S2_DEV3_MIN = 0.665         # stage 2: dev3 AUROC
S2_MEAN_MIN = 0.685         # stage 2: (dev2 + dev3) / 2
VETO_DELTA_MIN = 0.035      # gate v2: pair-veto delta vs own base
B_WINS_SLACK = 2            # gate v2: B-stratum wins >= base - 2
TIE = 0.005                 # winner tie window on dev2 AUROC
PAIR_LOSS_MAX = 0.679       # last200.pair must be strictly below (also enforced by imp_dev_gate2.screens)
PAIR_STEPS = 1628
CANDIDATES = ("A1", "A2", "B1", "B2", "C1", "C2")                     # fixed list = tie-break order
PARAMS_B = {"A1": 32, "A2": 32, "B1": 14, "B2": 7, "C1": 30, "C2": 32}
REF_NAME = "K4b-27B"
PINNED = {"dev2": "9511373d2663d088633fe8918c1f4db9caa36611947920e12d1ee20f592fa1b2",
          "dev3": "31366b4ab3e372612f6b1433daee7e9fa6a1a180cf9b0f0066ea588560974d11"}
FORBIDDEN_SHA_PREFIX = "543c4346"
FORBIDDEN_NAME = re.compile(r"vsp_?t", re.I)
EPS = 1e-15


class Refused(Exception):
    pass


# ------------------------------------------------------------------ loading
def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError) as exc:
        raise Refused(f"cannot read {what} {path}: {type(exc).__name__}: {exc}")


def no_vspt(path, what):
    if not isinstance(path, str) or not path:
        raise Refused(f"{what}: path missing")
    if FORBIDDEN_NAME.search(os.path.basename(path)):
        raise Refused(f"{what}: {os.path.basename(path)} names a VSP-T file; VSP-T is never an input of this gate")


def load_cases(path, which):
    no_vspt(path, f"{which} cases")
    if not Path(path).is_file():
        raise Refused(f"{which} cases file {path} does not exist")
    sha = sha256_file(path)
    if sha.startswith(FORBIDDEN_SHA_PREFIX):
        raise Refused(f"{which} cases are the VSP-T cases (sha {sha[:8]}); VSP-T is never an input of this gate")
    if sha != PINNED[which]:
        raise Refused(f"{which} cases sha {sha[:8]} is not the pinned {PINNED[which][:8]}")
    cases = read_json(path, f"{which} cases").get("cases")
    if not isinstance(cases, list) or not cases:
        raise Refused(f"{which} cases file has no cases")
    return cases


class Cases:
    def __init__(self, cases):
        import imp_verdict as iv
        self.iv = iv
        self.cases = cases
        self.keys = [(c["id"], c["label"]) for c in cases]
        self.groups = iv.pair_groups(cases, self.keys)
        self.y = [1 if c["label"] == "VULNERABLE" else 0 for c in cases]

    def metrics(self, scores):
        from cyberdef.imp_common import auroc
        iv = self.iv
        wins, _eq, _skip = iv.pair_wins(self.cases, self.keys, self.groups, scores)
        veto = iv.pair_balanced(wins)
        if veto is None:
            raise Refused("a length stratum has no pairs; pair-veto undefined")
        return {"auroc": float(auroc(scores, self.y)), "veto": float(veto), "bwins": float(sum(wins["B"]))}


D3_ADAPTER_PREFIX = "vsp_pilot_k4b_d3"
PILOT_ADAPTER_PREFIX = "vsp_pilot"


def load_scores(entry, cs, what, which, model, role):
    """per-case p_vuln in case order from {"result", "provenance"}; Refused on any irregularity."""
    if not isinstance(entry, dict) or not entry.get("result") or not entry.get("provenance"):
        raise Refused(f"{what}: result / provenance entry missing")
    no_vspt(entry["result"], f"{what} result")
    res = read_json(entry["result"], f"{what} result")
    prov = read_json(entry["provenance"], f"{what} provenance")
    want = prov.get("result_sha256") if isinstance(prov, dict) else None
    if not isinstance(want, str) or want != sha256_file(entry["result"]):
        raise Refused(f"{what}: provenance result_sha256 does not match the result file")
    bind_provenance(entry, prov, what, which, model, role)
    pc = res.get("per_case") if isinstance(res, dict) else None
    if not isinstance(pc, list):
        raise Refused(f"{what}: per_case missing")
    if len(pc) != len(cs.keys):
        raise Refused(f"{what}: n={len(pc)} differs from the cases n={len(cs.keys)}")
    got = {}
    for r in pc:
        p = r.get("p_vuln") if isinstance(r, dict) else None
        if p is None or isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p) \
                or not 0.0 <= p <= 1.0:
            raise Refused(f"{what}: a per_case p_vuln is null or not a probability")
        got[(r.get("id"), r.get("label"))] = float(p)
    if set(got) != set(cs.keys) or len(got) != len(pc):
        raise Refused(f"{what}: per_case ids / labels do not match the cases file")
    return [got[k] for k in cs.keys]


def bind_provenance(entry, prov, what, which, model, role):
    """The provenance must say this result was scored on THIS cases file, by THIS model and adapter."""
    if prov.get("cases_file_sha256") != PINNED[which]:
        raise Refused(f"{what}: provenance cases_file_sha256 is missing or is not the pinned {which} sha")
    if not isinstance(model, str) or not model:
        raise Refused(f"{what}: the manifest names no model for this candidate")
    inputs = prov.get("inputs")
    if not isinstance(inputs, dict) or inputs.get("model") != model:
        raise Refused(f"{what}: provenance inputs.model is not the manifest model {model}")
    want = entry.get("adapter") or ""
    got = inputs.get("adapter") or ""
    if not isinstance(want, str) or not isinstance(got, str) or want != got:
        raise Refused(f"{what}: manifest adapter {want!r} differs from provenance inputs.adapter {got!r}")
    if role == "base" and want:
        raise Refused(f"{what}: a base entry must carry no adapter")
    if role == "pilot3" and not want.startswith(D3_ADAPTER_PREFIX):
        raise Refused(f"{what}: a dev3 pilot adapter must start with {D3_ADAPTER_PREFIX}")
    if role == "pilot2" and not (want.startswith(PILOT_ADAPTER_PREFIX) and not want.startswith(D3_ADAPTER_PREFIX)):
        raise Refused(f"{what}: a dev2 pilot adapter must start with {PILOT_ADAPTER_PREFIX} and not {D3_ADAPTER_PREFIX}")


def run_id_of(path):
    prov = read_json(path, "provenance")
    rid = (prov.get("ci") or {}).get("run_id") if isinstance(prov, dict) else None
    if not rid:
        raise Refused("pilot provenance has no ci.run_id")
    return str(rid)


def check_log(name, entry):
    """(screens_ok, reasons) from a dev2 pilot train log; Refused on a missing or null field."""
    from imp_dev_gate2 import Refused as GateRefused, screens
    path = entry.get("log") if isinstance(entry, dict) else None
    if not path:
        raise Refused(f"{name}: dev2 pilot has no train log")
    log = read_json(path, f"{name} train log")
    try:
        _ok, why = screens("K4b", log)   # the K4b name switches on the pair-term screen; it applies to every candidate
    except GateRefused as exc:
        raise Refused(str(exc))
    for field in ("pair_terms", "pair_steps"):
        v = log.get(field)
        if v is None or isinstance(v, bool) or not isinstance(v, (int, float)):
            raise Refused(f"{name} train log: {field} is missing or null")
    flags = log.get("flags")
    meta = flags.get("meta") if isinstance(flags, dict) else None
    m = re.search(r"(?:^|\s)run=(\S+)", meta) if isinstance(meta, str) else None
    if not m or m.group(1) != run_id_of(entry["provenance"]):
        raise Refused(f"{name} train log: flags.meta run= does not match the pilot provenance ci.run_id")
    mode = flags.get("mode") if isinstance(flags, dict) else None
    if mode is None:
        raise Refused(f"{name} train log: flags.mode is missing or null")
    why = list(why)
    if not (log["pair_terms"] == log["pair_steps"] == PAIR_STEPS):
        why.append(f"pair_terms {log['pair_terms']} / pair_steps {log['pair_steps']} is not {PAIR_STEPS}")
    if mode != "4bit":
        why.append(f"flags.mode {mode} is not 4bit")
    return not why, why


# ------------------------------------------------------------------ the rule
def s1_eligible(m, mb, screens_ok):
    """(eligible, [reasons]) for one candidate from its dev2 pilot and base metrics."""
    why = []
    if not screens_ok:
        why.append("train-log screens failed")
    if not m["auroc"] >= S1_AUROC_MIN:
        why.append(f"dev2 AUROC {m['auroc']:.4f} < {S1_AUROC_MIN}")
    if not m["veto"] >= VETO_FLOOR:
        why.append(f"dev2 pair-veto {m['veto']:.4f} < {VETO_FLOOR}")
    if not m["auroc"] - mb["auroc"] > 0:
        why.append("AUROC delta vs own base is not > 0")
    if not m["veto"] - mb["veto"] >= VETO_DELTA_MIN:
        why.append(f"veto delta {m['veto'] - mb['veto']:+.4f} < {VETO_DELTA_MIN}")
    if not m["bwins"] >= mb["bwins"] - B_WINS_SLACK:
        why.append(f"B wins {m['bwins']:g} < base {mb['bwins']:g} - {B_WINS_SLACK}")
    return not why, why


def pick_winner(rows):
    """rows: [(name, dev2 AUROC)] of eligible candidates -> winner name (tie window, then size, then list order)."""
    best = max(a for _n, a in rows)
    near = [n for n, a in rows if best - a <= TIE]
    return min(near, key=lambda n: (PARAMS_B[n], CANDIDATES.index(n)))


def ensemble_eligible(m):
    return m["auroc"] >= ENSEMBLE_AUROC_MIN and m["veto"] >= VETO_FLOOR


def s2_pass(a2, a3):
    return a3 >= S2_DEV3_MIN and (a2 + a3) / 2.0 >= S2_MEAN_MIN


def _logit(p):
    p = min(max(p, EPS), 1.0 - EPS)
    return math.log(p / (1.0 - p))


def mean_logit(score_lists):
    n = len(score_lists)
    return [sum(_logit(p) for p in vals) / n for vals in zip(*score_lists)]


# ------------------------------------------------------------------ driver
def run(manifest):
    if not isinstance(manifest, dict):
        raise Refused("manifest is not a JSON object")
    cs2 = Cases(load_cases(manifest.get("dev2_cases"), "dev2"))
    d3path = manifest.get("dev3_cases")
    cs3 = Cases(load_cases(d3path, "dev3")) if d3path else None
    cands = manifest.get("candidates")
    if not isinstance(cands, list) or not cands:
        raise Refused("no candidates in the manifest")
    names = [c.get("name") if isinstance(c, dict) else None for c in cands]
    bad = [n for n in names if n not in CANDIDATES]
    if bad:
        raise Refused(f"candidate(s) {bad} are not on the fixed list {list(CANDIDATES)}")
    if len(set(names)) != len(names):
        raise Refused(f"duplicate candidates {names}")
    ref = manifest.get("reference")
    if ref is not None and (not isinstance(ref, dict) or ref.get("name") != REF_NAME):
        raise Refused(f"reference must be named {REF_NAME}")

    rows = {}
    for c in cands:
        n = c["name"]
        d2 = c.get("dev2") or {}
        model = c.get("model")
        p2 = load_scores(d2.get("pilot"), cs2, f"{n} dev2 pilot", "dev2", model, "pilot2")
        b2 = load_scores(d2.get("base"), cs2, f"{n} dev2 base", "dev2", model, "base")
        screens_ok, why_s = check_log(n, d2["pilot"])
        m, mb = cs2.metrics(p2), cs2.metrics(b2)
        ok, why = s1_eligible(m, mb, screens_ok)
        rows[n] = {"p2": p2, "dev2": m, "base": mb, "screens_ok": screens_ok, "eligible": ok, "why": why + why_s,
                   "entry": c}
    ref_row = None
    if ref is not None:
        rp = load_scores((ref.get("dev2") or {}).get("pilot"), cs2, f"{REF_NAME} dev2 pilot", "dev2", ref.get("model"), "pilot2")
        ref_row = {"p2": rp, "dev2": cs2.metrics(rp), "entry": ref}

    def dev3_scores(entry, who):
        d3 = (entry or {}).get("dev3")
        if cs3 is None or not isinstance(d3, dict) or not d3.get("pilot"):
            raise Refused(f"incomplete: dev3 results of {who} are absent (stage 2 must be run before the gate decides)")
        return load_scores(d3["pilot"], cs3, f"{who} dev3 pilot", "dev3", (entry or {}).get("model"), "pilot3")

    out = {"candidates": {n: {"dev2": r["dev2"], "base": r["base"], "eligible": r["eligible"], "reasons": r["why"]}
                          for n, r in rows.items()}}
    elig = [(n, r["dev2"]["auroc"]) for n, r in rows.items() if r["eligible"]]
    if elig:
        win = pick_winner(elig)
        a3 = cs3.metrics(dev3_scores(rows[win]["entry"], win))["auroc"]   # dev3_scores refuses when cs3 is None
        a2 = rows[win]["dev2"]["auroc"]
        go = s2_pass(a2, a3)
        out.update({"stage1": "single", "winner": win, "dev2_auroc": a2, "dev3_auroc": a3, "s2": go,
                    "decision": "GO" if go else "NO-GO"})
        return out
    # ensemble fallback: only when no single candidate is eligible
    pool = [(n, r["dev2"]["auroc"], r["p2"], r["entry"]) for n, r in rows.items() if r["screens_ok"]]
    if ref_row is not None:
        pool.append((REF_NAME, ref_row["dev2"]["auroc"], ref_row["p2"], ref_row["entry"]))
    pool.sort(key=lambda t: (-t[1], CANDIDATES.index(t[0]) if t[0] in CANDIDATES else len(CANDIDATES)))
    if len(pool) < 2:
        out.update({"decision": "NO-GO", "winner": None, "stage1": "none eligible; fewer than two ensemble members"})
        return out
    top = pool[:2]
    me = cs2.metrics(mean_logit([t[2] for t in top]))
    out["ensemble"] = {"members": [t[0] for t in top], "dev2": me}
    if not ensemble_eligible(me):
        out.update({"decision": "NO-GO", "winner": None, "stage1": "no single and no ensemble eligible"})
        return out
    e3 = mean_logit([dev3_scores(t[3], t[0]) for t in top])
    a3 = cs3.metrics(e3)["auroc"]
    go = s2_pass(me["auroc"], a3)
    out.update({"stage1": "ensemble", "winner": "ENSEMBLE", "members": [t[0] for t in top], "dev2_auroc": me["auroc"],
                "dev3_auroc": a3, "s2": go, "decision": "GO" if go else "NO-GO"})
    return out


def selftest():
    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)
    m = {"auroc": 0.69, "veto": 0.67, "bwins": 12.0}
    mb = {"auroc": 0.60, "veto": 0.62, "bwins": 13.0}
    check("eligible baseline", s1_eligible(m, mb, True)[0])
    check("screens fail", not s1_eligible(m, mb, False)[0])
    check("auroc below 0.685", not s1_eligible({**m, "auroc": 0.6849}, mb, True)[0])
    check("auroc at 0.685", s1_eligible({**m, "auroc": 0.685}, mb, True)[0])
    check("veto below floor", not s1_eligible({**m, "veto": 0.6597}, {**mb, "veto": 0.60}, True)[0])
    check("veto delta below 0.035", not s1_eligible(m, {**mb, "veto": 0.636}, True)[0])
    check("veto delta at 0.035", s1_eligible(m, {**mb, "veto": 0.635}, True)[0])
    check("auroc delta zero", not s1_eligible(m, {**mb, "auroc": 0.69}, True)[0])
    check("B wins base-2 ok", s1_eligible({**m, "bwins": 11.0}, mb, True)[0])
    check("B wins base-3 fails", not s1_eligible({**m, "bwins": 10.0}, mb, True)[0])
    check("tie picks smaller model", pick_winner([("A1", 0.700), ("B2", 0.696)]) == "B2")
    check("no tie picks best", pick_winner([("A1", 0.700), ("B2", 0.694)]) == "A1")
    check("equal size list order", pick_winner([("A2", 0.700), ("A1", 0.698)]) == "A1")
    check("ensemble bar", ensemble_eligible({"auroc": 0.690, "veto": 0.66})
          and not ensemble_eligible({"auroc": 0.6899, "veto": 0.66})
          and not ensemble_eligible({"auroc": 0.7, "veto": 0.659}))
    check("s2 dev3 floor", s2_pass(0.72, 0.665) and not s2_pass(0.72, 0.6649))
    check("s2 mean floor", s2_pass(0.70, 0.67) and not s2_pass(0.69, 0.6799))
    ml = mean_logit([[0.5, 0.9], [0.5, 0.9]])
    check("mean logit", abs(ml[0]) < 1e-9 and abs(ml[1] - math.log(9)) < 1e-9)
    print("a6 gate selftest " + ("PASS" if not bad else f"FAIL {bad}"))
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
            Path(a.out).write_text(json.dumps(dec, indent=1, default=str), encoding="utf-8")
        print(f"{dec['decision']}: winner {dec.get('winner')}")
        return 0 if dec["decision"] == "GO" else 3
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001  a refusal, never a traceback
        print(f"refused: internal error {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
