"""Acceptance checker for scripts/imp_a6_gate.py (criterion C3 of cyberdef-a6-tooling).

Usage:
  .venv/bin/python acceptance/improve/check_a6_gate.py [--gate F] [--dev3-cases F] [--mutants] [--only SUBSTR]

THE GATE CONTRACT (this checker is the spec; CURRENT_PLAN.md section 3 gives the rule, this fixes the interface):
  python scripts/imp_a6_gate.py --manifest M.json [--out D.json]      and      python scripts/imp_a6_gate.py --selftest
  exit 0 = GO, 3 = NO-GO, 2 = refusal (message on stderr). Nothing else; every refusal is exit 2, never a traceback.
  M.json = {"dev2_cases": path, "dev3_cases": path | null,
            "candidates": [{"name": "A1"|"A2"|"B1"|"B2"|"C1"|"C2",
                            "dev2": {"pilot": E, "base": E}, "dev3": {"pilot": E} (only once stage 2 was run)}],
            "reference": {"name": "K4b-27B", "dev2": {"pilot": E}, "dev3": {"pilot": E}} | absent}
  E = {"result": path, "provenance": path} plus "log": path on every dev2 pilot (the train log).
  result file     {"per_case": [{"id", "label", "p_vuln"}, ...], ...}; any headline field (auroc, pair_veto, ...)
                  is IGNORED: every AUROC, pair-veto and B-wins number is recomputed from per_case.
  provenance      {"result_sha256": sha256 of the result file, ...}; a mismatch is a refusal.
  train log       as scripts/imp_dev_gate2.py reads it: pair_sampler.epochs_iterated[*].{domains.{linux,other}.{A,B},
                  max_pair_count}, last200.pair, pair_terms, pair_steps, flags.mode; a missing or null field is a refusal.
  D.json          {"decision": "GO"|"NO-GO", "winner": "A1".."C2" | "ENSEMBLE", "members": [names] (ensemble only)}.
Rule under test: S1 per candidate (screens: sampler A/B within 1 and max_pair_count <= 2 in every epoch, last200.pair <
0.679, pair_terms == pair_steps == 1628, flags.mode == "4bit"; dev2 AUROC >= 0.685; dev2 pair_veto >= 0.6598; AUROC delta
vs own base > 0; veto delta >= 0.035; B-stratum wins >= base - 2). Winner = highest dev2 AUROC; candidates within 0.005 of
it -> smaller parameter count (B2 7 < B1 14 < C1 30 < A1 = A2 = C2 32), then list order A1,A2,B1,B2,C1,C2. If none is
eligible: the ensemble E = per-case mean of logit(p_vuln) of the top two dev2 AUROCs among candidates + reference, eligible
iff AUROC(E) >= 0.690 and pair_veto(E) >= 0.6598. S2 on the winner (E from the d3 results for an ensemble): dev3 AUROC >=
0.665 and (dev2 + dev3) / 2 >= 0.685. GO = S1 and S2. No S1 winner -> NO-GO (exit 3). A winner without dev3 results in the
manifest -> exit 2 (incomplete). Refusals (exit 2): a VSP-T input anywhere (cases sha 543c4346..., or a path naming vspt /
vsp_t), cases sha not the pinned dev2 (9511373d...) or the d3 file, n != cases, null / missing log or result field,
provenance mismatch, unlisted candidate name, no candidates.
--mutants: re-runs the suite against copies of the gate with each threshold literal shifted; every mutant must be caught.
Fixtures are synthetic per-case scores on the real dev2 / dev3 case files; each has its realised metrics asserted first
(a fixture that misses its window is a FIXTURE error, reported separately from a gate failure).
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

S1, VETO, ENS, S2D3, MEAN, DELTA, TIE = 0.685, 0.6598, 0.690, 0.665, 0.685, 0.035, 0.005
EDGE = 0.0007          # fixtures sit this far from a threshold on each side (the mutants shift it by >= 0.002)
TOL = 2.5e-4
NAMES = ["A1", "A2", "B1", "B2", "C1", "C2"]


class FixtureError(Exception):
    pass


def good_log(pair=0.55, terms=1628, steps=1628, mode="4bit", linux_b=308):
    ep = {"epoch": 0, "max_pair_count": 2,
          "domains": {"linux": {"A": 308, "B": linux_b, "E": 1}, "other": {"A": 88, "B": 88, "E": 21}}}
    return {"pair_sampler": {"mode": "balanced_by_domain", "epochs_iterated": [ep, {**ep, "epoch": 1}]},
            "last200": {"pair": pair}, "pair_terms": terms, "pair_steps": steps, "flags": {"mode": mode}}


class Env:
    def __init__(self, a):
        self.a = a
        self.tmp = Path(tempfile.mkdtemp(prefix="a6gate_"))
        self.c2 = C.load_cases(C.DEV2)
        self.g2 = C.Gen(self.c2, seed=11)
        self.dev3 = Path(a.dev3_cases)
        self.g3 = C.Gen(C.load_cases(self.dev3), seed=13) if self.dev3.is_file() else None
        self.c3 = C.load_cases(self.dev3) if self.g3 else None
        self.cache = {}
        self.n = 0

    def uniq(self, stem):
        self.n += 1
        return self.tmp / f"{stem}_{self.n}"

    def want(self, ok, what):
        if not ok:
            raise FixtureError(what)

    def model(self, g, cases, key, auc, wA, wB, seed, sigma=1.0, members=1):
        k = (id(g), key, round(auc, 5), wA, wB, seed, sigma, members)
        if k not in self.cache:
            ps, d, a = g.tune(auc, wA, wB, sigma, seed, members=members)
            self.cache[k] = ps
        return self.cache[k]


def write_entry(env, stem, p, cases, headline=0.999, log=None, prov_sha=None, bind=None):
    """bind = {"model", "adapter", "cases", "run"}: provenance fields the gate ties to the manifest (model, adapter, cases
    sha, ci run id); the train log, when given, carries the same run id in flags.meta."""
    res = env.uniq(stem + "_res").with_suffix(".json")
    per = [{"id": c["id"], "label": c["label"], "p_vuln": float(p[i])} for i, c in enumerate(cases)]
    json.dump({"method": "selective:fixture", "auroc": headline, "pair_veto": {"adapter": headline, "delta": headline},
               "per_case": per}, open(res, "w"))
    prov = env.uniq(stem + "_prov").with_suffix(".json")
    rec = {"kind": "eval", "result_sha256": prov_sha or C.sha256(res)}
    e = {"result": str(res), "provenance": str(prov)}
    if bind:
        rec.update({"ci": {"run_id": bind["run"], "run_attempt": "1"},
                    "inputs": {"model": bind["model"], "adapter": bind["adapter"]}, "cases_file_sha256": bind["cases"]})
        e["adapter"] = bind["adapter"]
    json.dump(rec, open(prov, "w"))
    if log is not None:
        if bind:
            log = json.loads(json.dumps(log))
            log.setdefault("flags", {})["meta"] = f"ci run={bind['run']} sha=e80a9a32 machine=spark"
        lp = env.uniq(stem + "_log").with_suffix(".json")
        json.dump(log, open(lp, "w"))
        e["log"] = str(lp)
    return e


def reprov(path, **upd):
    """rewrite one provenance file in place, keeping every bound field; a None value deletes the key"""
    d = json.loads(Path(path).read_text())
    for k, v in upd.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    Path(path).write_text(json.dumps(d))


MODEL = "Qwen/Qwen2.5-32B-Instruct"
REF_MODEL = "Qwen/Qwen3.8-27B"


def bind_of(env, kind, name, model):
    """kind: p2 / b2 / p3. Adapter tags follow the rules: dev2 pilot vsp_pilot_*, base none, dev3 pilot vsp_pilot_k4b_d3_*."""
    tag = name.lower().replace("-", "_")
    adapter = {"p2": f"vsp_pilot_k4b_{tag}", "b2": "", "p3": f"vsp_pilot_k4b_d3_{tag}"}[kind]
    cases = C.sha256(env.dev3) if kind == "p3" else C.sha256(C.DEV2)
    run = {"p2": "45185319205", "b2": "45183188994", "p3": "45190000000"}[kind]
    return {"model": model, "adapter": adapter, "cases": cases, "run": run}


def cand(env, name, auc, vwin, seed, base_auc=0.60, dwin=(0.0475, 0.0525), bdelta=-5, log=None, p3=0.70,
         headline=0.999, sigma=1.0, ens=None):
    """A candidate: pilot + base on dev2 (wins exact, AUROC tuned) and a pilot on dev3. ens = (auc_E, member index)."""
    g = env.g2
    pref = round(0.45 * g.n["B"])
    w = g.wins_for(vwin[0], vwin[1], pref)
    env.want(w is not None, f"{name}: no integer wins give veto in {vwin}")
    wA, wB, v = w
    if ens:
        ps = env.model(g, env.c2, ("ens", ens[0], name[:0]), ens[0], wA, wB, seed, sigma=sigma, members=2)
        p = ps[ens[1]]
        ensp = ps
    else:
        p, ensp = env.model(g, env.c2, name, auc, wA, wB, seed, sigma=sigma)[0], None
    wBb = wB + bdelta
    vb = None
    for wAb in range(g.n["A"], -1, -1):
        vbase = (wAb / g.n["A"] + wBb / g.n["B"]) / 2.0
        if v - dwin[1] <= vbase < v - dwin[0]:
            vb = (wAb, vbase)
            break
    env.want(vb is not None and 0 <= wBb <= g.n["B"], f"{name}: no base wins give delta in {dwin}")
    b = env.model(g, env.c2, name + "base", base_auc, vb[0], wBb, seed + 1000, sigma=1.0)[0]
    m, mb = C.metrics(env.c2, g.pairs, g.y, p), C.metrics(env.c2, g.pairs, g.y, b)
    ref_v, ref_b = C.cross_check_verdict(env.c2, g.pairs, p)
    env.want(abs(ref_v - m["veto"]) < 1e-12 and ref_b == m["bwins"], "local veto disagrees with imp_verdict")
    env.want(abs(m["veto"] - v) < 1e-9, f"{name}: veto {m['veto']} != wins veto {v}")
    if not ens:
        env.want(abs(m["auroc"] - auc) <= TOL, f"{name}: AUROC {m['auroc']:.5f} vs target {auc:.5f}")
    out = {"name": name, "p2": p, "b2": b, "m": m, "mb": mb, "log": log if log is not None else good_log(),
           "headline": headline, "p3": None}
    if p3 is not None and env.g3 is not None:
        g3 = env.g3
        t3 = p3(m["auroc"]) if callable(p3) else p3
        wA3, wB3 = round(0.85 * g3.n["A"]), round(0.5 * g3.n["B"])
        if ens:
            ps3 = env.model(g3, env.c3, ("ens3", t3), t3, wA3, wB3, seed + 2000, sigma=sigma, members=2)
            out["p3"] = ps3[ens[1]]
        else:
            out["p3"] = env.model(g3, env.c3, name + "d3", t3, wA3, wB3, seed + 2000)[0]
    elif p3 is not None:
        raise FixtureError(f"{env.dev3} is missing: no dev3 fixtures can be built")
    return out


def manifest(env, c_list, ref=None, dev2_cases=None, dev3_cases=None, hook=None):
    cands = []
    for c in c_list:
        n = c["name"]
        ent = {"name": n, "model": MODEL,
               "dev2": {"pilot": write_entry(env, n + "_p2", c["p2"], env.c2, c["headline"], c["log"],
                                             bind=bind_of(env, "p2", n, MODEL)),
                        "base": write_entry(env, n + "_b2", c["b2"], env.c2, c["headline"],
                                            bind=bind_of(env, "b2", n, MODEL))}}
        if c["p3"] is not None:
            ent["dev3"] = {"pilot": write_entry(env, n + "_p3", c["p3"], env.c3, c["headline"],
                                                bind=bind_of(env, "p3", n, MODEL))}
        cands.append(ent)
    mf = {"dev2_cases": str(dev2_cases or C.DEV2), "dev3_cases": str(dev3_cases or env.dev3), "candidates": cands}
    if ref:
        r = {"name": "K4b-27B", "model": REF_MODEL,
             "dev2": {"pilot": write_entry(env, "ref_p2", ref["p2"], env.c2, 0.999, ref["log"],
                                           bind=bind_of(env, "p2", "k4b", REF_MODEL))}}
        if ref["p3"] is not None:
            r["dev3"] = {"pilot": write_entry(env, "ref_p3", ref["p3"], env.c3, 0.999,
                                              bind=bind_of(env, "p3", "k4b", REF_MODEL))}
        mf["reference"] = r
    if hook:
        hook(mf)
    path = env.uniq("manifest").with_suffix(".json")
    json.dump(mf, open(path, "w"))
    return str(path)


def run_gate(env, mf, gate=None):
    out = env.uniq("decision").with_suffix(".json")
    proc = subprocess.run([sys.executable, str(gate or env.a.gate), "--manifest", mf, "--out", str(out)], cwd=ROOT,
                          capture_output=True, text=True, timeout=300)
    dec = json.load(open(out)) if out.is_file() else None
    return proc.returncode, proc.stdout + proc.stderr, dec


def vw(lo, hi):
    return (lo, hi)


COMFY = vw(0.6640, 0.6655)


def build_cases(env):
    """[(label, builder -> manifest path, expected exit, expected winner, members, stderr needle)]"""
    T = []

    def add(label, build, exit_, winner=None, members=None, needle=None):
        T.append((label, build, exit_, winner, members, needle))

    def one(name="A1", seed=100, **kw):
        kw.setdefault("auc", 0.695)
        kw.setdefault("vwin", COMFY)
        return cand(env, name, seed=seed, **kw)

    def single(label, exit_, winner="A1", **kw):
        add(label, lambda: manifest(env, [one(**kw)]), exit_, winner if exit_ == 0 else None)

    single("GO: a comfortable single candidate", 0)
    add("GO: headline fields say 0.5 but per_case says 0.695", lambda: manifest(env, [one(headline=0.5)]), 0, "A1")
    single("NO-GO: headline says 0.999 but per_case AUROC is 0.6843", 3, auc=S1 - EDGE)
    single("S1 AUROC 0.6857 -> GO", 0, auc=S1 + EDGE)
    single("S1 AUROC 0.6843 -> NO-GO", 3, auc=S1 - EDGE)
    single("veto floor: just above 0.6598 -> GO", 0, vwin=vw(VETO + 1e-6, VETO + 0.00145))
    single("veto floor: just below 0.6598 -> NO-GO", 3, vwin=vw(VETO - 0.00145, VETO - 1e-6))
    single("veto delta vs base just above 0.035 -> GO", 0, dwin=(DELTA + 1e-6, DELTA + 0.00145))
    single("veto delta vs base just below 0.035 -> NO-GO", 3, dwin=(DELTA - 0.00145, DELTA - 1e-6))
    single("AUROC delta vs base negative (base 0.70 > pilot 0.695) -> NO-GO", 3, base_auc=0.70, bdelta=-10)
    single("B wins two below the base -> GO", 0, bdelta=2)
    single("B wins three below the base -> NO-GO", 3, bdelta=3)
    single("screen: last200.pair 0.678 -> GO", 0, log=good_log(pair=0.678))
    single("screen: last200.pair 0.679 -> NO-GO", 3, log=good_log(pair=0.679))
    single("screen: linux A/B slot counts differ by 2 -> NO-GO", 3, log=good_log(linux_b=310))
    single("screen: pair_terms == pair_steps == 1627 (not 1628) -> NO-GO", 3, log=good_log(terms=1627, steps=1627))
    single("screen: pair_terms 0 of 1628 steps -> NO-GO", 3, log=good_log(terms=0, steps=1628))
    single("screen: mode 8bit -> NO-GO", 3, log=good_log(mode="8bit"))
    # winner selection and the 0.005 tie rule
    add("tie: A1 0.700 vs B2 0.696 (0.004 apart) -> smaller model B2",
        lambda: manifest(env, [one("A1", 101, auc=0.700), one("B2", 102, auc=0.696)]), 0, "B2")
    add("no tie: A1 0.700 vs B2 0.694 (0.006 apart) -> best A1",
        lambda: manifest(env, [one("A1", 103, auc=0.700), one("B2", 104, auc=0.694)]), 0, "A1")
    add("tie, equal size: A2 0.700 vs A1 0.696, listed A2 first -> list order A1",
        lambda: manifest(env, [one("A2", 105, auc=0.700), one("A1", 106, auc=0.696)]), 0, "A1")
    add("tie of three within 0.005 of the best: B1 0.700, A1 0.697, B2 0.696 -> B2",
        lambda: manifest(env, [one("B1", 107, auc=0.700), one("A1", 108, auc=0.697), one("B2", 109, auc=0.696)]),
        0, "B2")
    # stage 2 (dev3)
    d2 = 0.720
    single("S2 dev3 0.6657 (dev2 0.720) -> GO", 0, auc=d2, p3=S2D3 + EDGE)
    single("S2 dev3 0.6643 (dev2 0.720) -> NO-GO", 3, auc=d2, p3=S2D3 - EDGE)
    single("S2 mean of dev2 and dev3 just above 0.685 -> GO", 0, auc=0.700, p3=lambda r: 2 * (MEAN + EDGE) - r)
    single("S2 mean of dev2 and dev3 just below 0.685 -> NO-GO", 3, auc=0.700, p3=lambda r: 2 * (MEAN - EDGE) - r)
    add("a stage-1 winner with no dev3 results -> incomplete input (exit 2)",
        lambda: manifest(env, [one(p3=None)]), 2, needle="dev3")
    # ensemble fallback: two members, neither S1-eligible alone
    def members(auc_e, vwin, seed=300):
        ref = cand(env, "REF", 0.607, COMFY, 399, p3=0.64)
        a = cand(env, "A1", 0, vwin, seed, ens=(auc_e, 0), sigma=2.0)
        b = cand(env, "B1", 0, vwin, seed, ens=(auc_e, 1), sigma=2.0)
        env.want(max(a["m"]["auroc"], b["m"]["auroc"]) < S1 - 0.002, "ensemble members are not each below S1")
        return [a, b], ref
    for label, auc_e, vwin, exit_ in (("ensemble AUROC 0.6907, veto ok -> GO as ENSEMBLE of A1 and B1", ENS + EDGE, COMFY, 0),
                                      ("ensemble AUROC 0.6893 -> NO-GO", ENS - EDGE, COMFY, 3),
                                      ("ensemble AUROC 0.700 but veto of the ensemble below 0.6598 -> NO-GO", 0.700,
                                       vw(0.640, 0.650), 3)):
        def build(auc_e=auc_e, vwin=vwin):
            cs, ref = members(auc_e, vwin)
            return manifest(env, cs, ref=ref)
        add(label, build, exit_, "ENSEMBLE" if exit_ == 0 else None, ["A1", "B1"] if exit_ == 0 else None)
    return T, add, one, members


def refusal_cases(env, add, one):
    def with_hook(hook, **kw):
        return lambda: manifest(env, [one(**kw)], hook=hook)

    def edit_json(path, fn):
        d = json.load(open(path))
        fn(d)
        json.dump(d, open(path, "w"))

    pilot = lambda mf: mf["candidates"][0]["dev2"]["pilot"]
    R = 2
    add("refuse: dev2 cases is the VSP-T cases file", lambda: manifest(env, [one()], dev2_cases=C.VSPT), R,
        needle="vsp")
    def vspt_path(mf):
        e = pilot(mf)
        dst = Path(e["result"]).with_name("fixture_result_vspt.json")
        shutil.copy(e["result"], dst)
        Path(e["result"]).unlink()
        e["result"] = str(dst)
        reprov(e["provenance"], result_sha256=C.sha256(dst))
    add("refuse: a result file path naming vspt", with_hook(vspt_path), R, needle="vsp")

    def bad_cases(mf):
        cs = json.load(open(C.DEV2))
        cs["cases"][0]["code"] = cs["cases"][0]["code"] + " "
        p = env.uniq("dev2_modified").with_suffix(".json")
        json.dump(cs, open(p, "w"))
        mf["dev2_cases"] = str(p)
    add("refuse: dev2 cases sha is not the pinned 9511373d", with_hook(bad_cases), R)

    def short(mf):
        edit_json(pilot(mf)["result"], lambda d: d.__setitem__("per_case", d["per_case"][:-2]))
        e = pilot(mf)
        reprov(e["provenance"], result_sha256=C.sha256(e["result"]))
    add("refuse: the dev2 pilot result has 1008 rows, not 1010", with_hook(short), R)
    add("refuse: null last200.pair in the train log", with_hook(None, log=good_log(pair=None)), R)

    def nolog(mf):
        edit_json(pilot(mf)["log"], lambda d: d.pop("pair_sampler"))
    add("refuse: missing pair_sampler in the train log", with_hook(nolog), R)
    add("refuse: null pair_terms in the train log", with_hook(None, log=good_log(terms=None)), R)

    def nullp(mf):
        def f(d):
            d["per_case"][5]["p_vuln"] = None
        edit_json(pilot(mf)["result"], f)
        e = pilot(mf)
        reprov(e["provenance"], result_sha256=C.sha256(e["result"]))
    add("refuse: a null p_vuln in per_case", with_hook(nullp), R)

    def prov(mf):
        reprov(pilot(mf)["provenance"], result_sha256="0" * 64)
    add("refuse: provenance result_sha256 does not match the result file", with_hook(prov), R)

    def prov_missing(mf):
        reprov(pilot(mf)["provenance"], result_sha256=None)
    add("refuse: provenance has no result_sha256", with_hook(prov_missing), R)
    add("refuse: candidate Z9 is not on the fixed list", lambda: manifest(env, [one("Z9")]), R)
    add("refuse: candidate named K4b (an old config name) is not on the list", lambda: manifest(env, [one("K4b")]), R)
    add("refuse: no candidates", lambda: manifest(env, []), R)
    add("refuse: dev3 cases is the VSP-T cases file", lambda: manifest(env, [one()], dev3_cases=C.VSPT), R, needle="vsp")

    def bad3(mf):
        cs = json.load(open(env.dev3))
        cs["cases"][0]["code"] = cs["cases"][0]["code"] + " "
        p = env.uniq("dev3_modified").with_suffix(".json")
        json.dump(cs, open(p, "w"))
        mf["dev3_cases"] = str(p)
    add("refuse: dev3 cases file differs from the pinned fold", with_hook(bad3), R)


def static_checks(gate):
    """Constants are literals in the code; no flag other than --manifest / --out / --selftest."""
    p = Path(gate)
    if not p.is_file():
        return False, f"{gate} does not exist (target not built yet)"
    tree = ast.parse(p.read_text(encoding="utf-8"))
    floats = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, float)}
    missing = [c for c in (S1, VETO, ENS, S2D3, DELTA, TIE) if not any(abs(f - c) < 1e-12 for f in floats)]
    flags = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
             and n.value.startswith("--") and len(n.value) > 2 and " " not in n.value}
    extra = sorted(flags - {"--manifest", "--out", "--selftest"})
    return not missing and not extra, f"float literals missing {missing}; flags beyond manifest/out/selftest {extra}"


def evaluate(env, tests, gate, only="", fail_fast=False):
    """Run every test against gate. Returns (n_fail, n_fixture_err, lines)."""
    fails = ferr = 0
    lines = []
    for label, build, exit_, winner, members, needle in tests:
        if only and only not in label:
            continue
        try:
            mf = build()
        except FixtureError as exc:
            ferr += 1
            lines.append(f"FIXTURE-ERROR {label}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001
            ferr += 1
            lines.append(f"FIXTURE-ERROR {label}: {type(exc).__name__}: {exc}")
            continue
        try:
            code, text, dec = run_gate(env, mf, gate)
        except subprocess.TimeoutExpired:
            code, text, dec = -9, "timeout", None
        ok = code == exit_
        if ok and exit_ == 0:
            ok = bool(dec) and dec.get("decision") == "GO" and dec.get("winner") == winner and \
                (members is None or sorted(dec.get("members") or []) == sorted(members))
        if ok and exit_ == 3:
            ok = bool(dec) and dec.get("decision") == "NO-GO"
        if ok and needle and exit_ == 2:
            ok = needle.lower() in text.lower()
        if ok and exit_ == 2 and "Traceback" in text:
            ok = False
        fails += 0 if ok else 1
        lines.append(("ok   " if ok else "FAIL ") + f"{label}: exit {code}" + ("" if ok else f" (want {exit_}; {dec}; {text.strip()[-160:]})"))
        if fail_fast and not ok:
            break
    return fails, ferr, lines


def mutate_gate(src, const, delta):
    tree = ast.parse(src)
    hit = 0
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, float) and abs(n.value - const) < 1e-12:
            n.value = round(n.value + delta, 6)
            hit += 1
    return ast.unparse(tree), hit


def run_mutants(env, tests, gate):
    gate = Path(gate)
    out, uncaught = [], 0
    for const, delta in ((S1, -0.002), (S1, 0.002), (VETO, -0.003), (VETO, 0.003), (ENS, -0.002), (ENS, 0.002),
                         (S2D3, -0.002), (S2D3, 0.002), (DELTA, -0.003), (DELTA, 0.003), (TIE, -0.002), (TIE, 0.002)):
        src, hit = mutate_gate(gate.read_text(encoding="utf-8"), const, delta)
        if not hit:
            out.append(f"MUTANT {const}{delta:+}: constant not found as a float literal")
            uncaught += 1
            continue
        mp = gate.parent / f"_a6mut_{gate.name}"
        mp.write_text(src, encoding="utf-8")
        try:
            fails, _ferr, lines = evaluate(env, tests, mp, fail_fast=True)
        finally:
            mp.unlink()
        caught = fails > 0
        uncaught += 0 if caught else 1
        first = next((ln for ln in lines if ln.startswith("FAIL")), "")[:90]
        out.append(("caught   " if caught else "UNCAUGHT ") + f"mutant {const} {delta:+}: {first}")
    return uncaught, out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", default=str(ROOT / "scripts/imp_a6_gate.py"))
    ap.add_argument("--dev3-cases", default=str(ROOT / "results/vsp_dev3_cases.json"))
    ap.add_argument("--mutants", action="store_true")
    ap.add_argument("--only", default="")
    a = ap.parse_args(argv)
    ok_static, detail = static_checks(a.gate)
    print(("PASS " if ok_static else "FAIL ") + "CONSTANTS_IN_CODE - " + detail, flush=True)
    if not Path(a.gate).is_file():
        print("RESULT: FAIL (gate script missing; no fixture can run)")
        return 1
    env = Env(a)
    try:
        tests, add, one, _members = build_cases(env)
        refusal_cases(env, add, one)
        fails, ferr, lines = evaluate(env, tests, a.gate, a.only)
        for ln in lines:
            print(ln, flush=True)
        total = fails + ferr + (0 if ok_static else 1)
        if a.mutants and total == 0:
            unc, out = run_mutants(env, tests, a.gate)
            for ln in out:
                print(ln, flush=True)
            total += unc
        print(f"RESULT: {'FAIL' if total else 'PASS'} ({fails} gate failures, {ferr} fixture errors"
              f"{'' if ok_static else ', constants/flags'})")
        return 1 if total else 0
    finally:
        shutil.rmtree(env.tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
