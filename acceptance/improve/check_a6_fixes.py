"""Acceptance checker for the five review findings on the attempt-6 tooling (criterion C7 of cyberdef-a6-tooling).

Usage:
  .venv/bin/python acceptance/improve/check_a6_fixes.py [--only SUBSTR]

Every check pairs refusals with an accepted control that differs in one variable. Issues:
  I1 PLAN_D3_TRAIN_ONLY  scripts/ci_plan.py: a TRAIN-ONLY run under a vsp_pilot_k4b_d3* tag with data other than the D3 option
                         is refused, and the D3 data under a tag that does not start with vsp_pilot_k4b_d3 is refused with any
                         steps (train only, train + test) and any final / arbitrary tag. Controls: D3 data + d3 tag accepted.
  I2 TARGET_BINDING      scripts/imp_a6_target.py: sha256 of a seed's result file must appear in the "inputs" map of both of
                         its verdict files (imp_verdict writes path -> sha256), and the three result shas must differ.
                         Refused (exit 2): seed 1 result with seed 0 verdicts; one result registered for all three seeds
                         (also as byte-identical copies); verdicts that do not list the result. Control: bound -> exit 0.
  I3 GATE_PROVENANCE     scripts/imp_a6_gate.py provenance binding. NEW manifest fields (this checker is the spec):
                         candidate "model" (hub id), reference "model", and "adapter" (tag, "" or absent for a base) on every
                         E. Rules: provenance cases_file_sha256 == the pinned sha of that set; provenance inputs.model ==
                         the candidate model (base entries too); provenance inputs.adapter == the entry adapter; a base
                         entry has no adapter; a dev3 pilot adapter starts with vsp_pilot_k4b_d3 and a dev2 pilot adapter
                         starts with vsp_pilot and not vsp_pilot_k4b_d3; the dev2 pilot train log binds to the pilot run:
                         log flags.meta contains "run=<id>" with id == pilot provenance ci.run_id (the binding real runs
                         carry). Each violation -> exit 2. Controls: a fully bound synthetic manifest -> GO; the real
                         27B K4b dev2 pilot artifacts of results/vsp_r2 in manifest form -> exit 3 (NO-GO, not a refusal).
  I4 GATE_EXACT          every bound is compared exactly (no round(x, 9)): veto floor, veto delta, ensemble veto, tie window.
  I5 HYGIENE_MISSING_D3  scripts/ci_data_hygiene.py --check exits nonzero, naming the file, when the d3 pilot file is missing
                         (run in a scratch tree of symlinks; the real file is never touched). Control: present -> exit 0.
VSP-T: only the (id, label) pairs of results/vsp_t_cases.json are read, to build synthetic scores; no VSP-T result is opened.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))
D3_FILE = "results/vsp_pilot_k4b_d3_items.json"
K4B_PILOT = "VSP pilot K4b: K4a + diff-site target (train minus dev2)"
K4B_FINAL = "VSP-SFT K4b final: K4 final + diff-site target"
MODEL14 = "Qwen/Qwen2.5-14B-Instruct"
RESULTS = []


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def record(ok, name, detail):
    RESULTS.append(ok)
    print(("PASS " if ok else "FAIL ") + name + " - " + detail, flush=True)


# ------------------------------------------------------------------ I1
def plan_of(cp, data, tag, steps, test_set=""):
    import io
    from contextlib import redirect_stderr, redirect_stdout
    env = {"MACHINE": "spark", "MODEL": MODEL14, "STEPS": steps, "TAG": tag, "TEST_SET": test_set, "SCORER": "selective",
           "DATA": data}
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return True, cp.plan(env)
    except SystemExit as exc:
        return False, str(exc)


def check_plan():
    import ci_plan as cp
    d3 = [k for k, v in cp.DATA.items() if v[0] == D3_FILE]
    ks = [k for k, v in cp.SET_FILES.items() if v == "results/vsp_dev3_cases.json"]
    dev3 = [n for n, v in cp.TEST_SETS.items() if v == ks]
    if len(d3) != 1 or not dev3:
        return False, f"d3 option {d3}, dev3 set {dev3}: missing"
    d3, dev3 = d3[0], dev3[0]
    refuse = [("train-only, K4b pilot data, d3 tag", K4B_PILOT, "vsp_pilot_k4b_d3_x", "train only", ""),
              ("train-only, default data, d3 tag", "", "vsp_pilot_k4b_d3_x", "train only", ""),
              ("train-only, K4b FINAL data, d3 tag", K4B_FINAL, "vsp_pilot_k4b_d3_x", "train only", ""),
              ("train + test, K4b pilot data, d3 tag, on dev3", K4B_PILOT, "vsp_pilot_k4b_d3_x", "train + test", dev3),
              ("D3 data, tag vsp_pilot_k4b_x, train only", d3, "vsp_pilot_k4b_x", "train only", ""),
              ("D3 data, tag vsp_pilot_k4b_x, train + test on dev3", d3, "vsp_pilot_k4b_x", "train + test", dev3),
              ("D3 data, final tag, train only", d3, "vsp_final_k4b_s0", "train only", ""),
              ("D3 data, arbitrary tag, train only", d3, "d3run", "train only", ""),
              ("D3 data, vsp_pilot_k4_d3 (wrong prefix), train only", d3, "vsp_pilot_k4_d3", "train only", "")]
    accept = [("D3 data, d3 tag, train only", d3, "vsp_pilot_k4b_d3_x", "train only", ""),
              ("D3 data, d3 tag, train + test on dev3", d3, "vsp_pilot_k4b_d3_x", "train + test", dev3),
              ("K4b pilot data, plain pilot tag, train only (existing behaviour)", K4B_PILOT, "vsp_pilot_k4b_x",
               "train only", "")]
    bad = []
    for label, data, tag, steps, ts in refuse:
        if plan_of(cp, data, tag, steps, ts)[0]:
            bad.append(f"ACCEPTED: {label}")
    for label, data, tag, steps, ts in accept:
        ok, msg = plan_of(cp, data, tag, steps, ts)
        if not ok:
            bad.append(f"control REFUSED: {label}: {str(msg)[:70]}")
    return not bad, f"{len(refuse)} refusals + {len(accept)} controls; problems {bad}"


# ------------------------------------------------------------------ I2
def target_verdict(fx, result, verdict="PASS", pinned=False, bound=True):
    inputs = {"/x/cases.json": "543c4346" + "0" * 56, "/x/base.json": ("96cd996c" + "0" * 56) if pinned else "cd" * 32}
    if bound:
        inputs[os.path.abspath(result)] = sha(result)
    path = fx.path("verdict")
    json.dump({"mode": "round", "n": 776, "z": 2.394, "verdict": verdict, "inputs": inputs}, open(path, "w"))
    return str(path)


def target_seed(fx, p, bound=True, result=None, verdicts_of=None):
    res = result or fx.write_result(p)
    v = verdicts_of or res
    return {"result": res, "verdicts": {"own_base": target_verdict(fx, v, bound=bound),
                                        "pinned_27b_base": target_verdict(fx, v, pinned=True, bound=bound)}}


def run_target(fx, seeds):
    mf = fx.path("manifest")
    json.dump({"cases": str(ROOT / "results/vsp_t_cases.json"), "seeds": seeds}, open(mf, "w"))
    out = fx.path("decision")
    p = subprocess.run([sys.executable, str(ROOT / "scripts/imp_a6_target.py"), "--manifest", str(mf), "--out", str(out)],
                       cwd=ROOT, capture_output=True, text=True, timeout=300)
    return p.returncode, (p.stdout + p.stderr).strip()[-120:]


def check_target():
    import check_a6_target as T
    fx = T.Fx()
    try:
        P = {s: fx.scores(k, 40 + s) for s, k in ((0, 105700), (1, 106500), (2, 107300))}
        seeds = {str(s): target_seed(fx, P[s]) for s in (0, 1, 2)}
        bad, notes = [], []
        code, msg = run_target(fx, seeds)
        if code != 0:
            bad.append(f"control (bound, distinct) exit {code}, want 0: {msg}")
        crossed = dict(seeds)
        crossed["1"] = target_seed(fx, P[1], verdicts_of=seeds["0"]["result"])
        same = fx.write_result(P[0])
        copies = [str(shutil.copy(same, fx.path("copy"))) for _ in range(2)]
        one_file = {"0": target_seed(fx, P[0], result=same), "1": target_seed(fx, P[0], result=copies[0]),
                    "2": target_seed(fx, P[0], result=copies[1])}
        exact_same = {s: target_seed(fx, P[0], result=same) for s in "012"}
        unbound = {"0": target_seed(fx, P[0], bound=False), "1": seeds["1"], "2": seeds["2"]}
        half = dict(seeds)
        e = target_seed(fx, P[2])
        e["verdicts"]["pinned_27b_base"] = target_verdict(fx, seeds["0"]["result"], pinned=True)
        half["2"] = e
        for label, mf in (("seed-1 result with seed-0 verdicts", crossed), ("one result file registered for all seeds", exact_same),
                          ("three byte-identical copies of one result", one_file),
                          ("verdicts that do not list the result sha", unbound),
                          ("only the pinned-27B verdict is from another seed", half)):
            code, msg = run_target(fx, mf)
            if code != 2:
                bad.append(f"{label}: exit {code}, want 2")
        return not bad, f"1 control + 5 refusals; problems {bad}"
    finally:
        shutil.rmtree(fx.tmp, ignore_errors=True)


# ------------------------------------------------------------------ I3
GOOD = {"model": "Qwen/Qwen2.5-32B-Instruct", "p_model": None, "p2_ad": "vsp_pilot_k4b_a1", "p2_ad_man": None,
        "b2_ad": "", "p3_ad": "vsp_pilot_k4b_d3_a1", "p3_ad_man": None, "cs2": None, "cs3": None, "run": "45185319205",
        "log_run": None, "drop_cs2": False}


def bind(env, over):
    spec = {**GOOD, **over}
    pin2, pin3 = sha(ROOT / "results/vsp_dev2_cases.json"), sha(env.dev3)

    def hook(mf):
        c = mf["candidates"][0]
        c["model"] = spec["model"]
        pm = spec["p_model"] or spec["model"]

        def rewrite(e, ad_prov, ad_man, cs, run):
            prov = {"kind": "eval", "result_sha256": sha(e["result"]), "ci": {"run_id": run, "run_attempt": "1"},
                    "inputs": {"model": pm, "adapter": ad_prov}, "cases_file_sha256": cs}
            if cs is None:
                del prov["cases_file_sha256"]
            Path(e["provenance"]).write_text(json.dumps(prov))
            e["adapter"] = ad_prov if ad_man is None else ad_man

        rewrite(c["dev2"]["pilot"], spec["p2_ad"], spec["p2_ad_man"], None if spec["drop_cs2"] else (spec["cs2"] or pin2),
                spec["run"])
        rewrite(c["dev2"]["base"], spec["b2_ad"], None, pin2, "45183188994")
        rewrite(c["dev3"]["pilot"], spec["p3_ad"], spec["p3_ad_man"], spec["cs3"] or pin3, "45190000000")
        lp = Path(c["dev2"]["pilot"]["log"])
        log = json.loads(lp.read_text())
        log["flags"]["meta"] = f"ci run={spec['log_run'] or spec['run']} sha=e80a9a32 machine=spark"
        lp.write_text(json.dumps(log))
    return hook


def gate_case(env, over):
    import check_a6_gate as G
    c = G.cand(env, "A1", seed=100, auc=0.695, vwin=G.COMFY)
    mf = G.manifest(env, [c], hook=bind(env, over))
    code, text, dec = G.run_gate(env, mf, str(ROOT / "scripts/imp_a6_gate.py"))
    return code, text, dec


def real_format_control(env):
    r2 = ROOT / "results/vsp_r2/"
    pil = {"result": str(r2 / "ci_ev_vsp_pilot_k4b_vspdev2.json"),
           "provenance": str(r2 / "ci_ev_vsp_pilot_k4b_vspdev2.json.provenance.json"),
           "log": str(r2 / "imp_vsp_pilot_k4b_imp_train_log.json"), "adapter": "vsp_pilot_k4b"}
    base = {"result": str(r2 / "ci_ev_qwen3.8-27b_vspdev2.json"),
            "provenance": str(r2 / "ci_ev_qwen3.8-27b_vspdev2.json.provenance.json"), "adapter": ""}
    mf = {"dev2_cases": str(ROOT / "results/vsp_dev2_cases.json"), "dev3_cases": None,
          "candidates": [{"name": "A1", "model": "Qwen/Qwen3.8-27B", "dev2": {"pilot": pil, "base": base}}]}
    path = env.uniq("realmf").with_suffix(".json")
    json.dump(mf, open(path, "w"))
    import check_a6_gate as G
    return G.run_gate(env, str(path), str(ROOT / "scripts/imp_a6_gate.py"))


def check_gate_provenance():
    import argparse as ap
    import check_a6_gate as G
    env = G.Env(ap.Namespace(dev3_cases=str(ROOT / "results/vsp_dev3_cases.json")))
    try:
        bad = []
        code, text, dec = gate_case(env, {})
        if code != 0 or not dec or dec.get("winner") != "A1":
            bad.append(f"bound control: exit {code} {text.strip()[-90:]}")
        code, text, dec = real_format_control(env)
        if code != 3 or not dec or dec.get("decision") != "NO-GO":
            bad.append(f"real 27B K4b artifacts: exit {code} (want 3 NO-GO) {text.strip()[-90:]}")
        wrong = [("dev2 pilot provenance cases sha is the dev3 sha", {"cs2": sha(env.dev3)}),
                 ("dev3 pilot provenance cases sha is the dev2 sha", {"cs3": sha(ROOT / "results/vsp_dev2_cases.json")}),
                 ("dev2 pilot provenance has no cases_file_sha256", {"drop_cs2": True}),
                 ("provenance model differs from the candidate model", {"p_model": "Qwen/Qwen2.5-7B-Instruct"}),
                 ("dev3 pilot adapter is not a d3 tag", {"p3_ad": "vsp_pilot_k4b_x"}),
                 ("dev3 pilot adapter is a final tag", {"p3_ad": "vsp_final_k4b_s0"}),
                 ("dev3 pilot: manifest adapter differs from provenance", {"p3_ad_man": "vsp_pilot_k4b_d3_other"}),
                 ("dev2 pilot: manifest adapter differs from provenance", {"p2_ad_man": "vsp_pilot_k4b_other"}),
                 ("dev2 pilot adapter is a d3 adapter", {"p2_ad": "vsp_pilot_k4b_d3_a1"}),
                 ("dev2 pilot adapter is not a pilot tag", {"p2_ad": "bowlr"}),
                 ("a base entry carries an adapter", {"b2_ad": "vsp_pilot_k4b_a1"}),
                 ("train log is from another run", {"log_run": "999"})]
        for label, over in wrong:
            code, text, _dec = gate_case(env, over)
            if code != 2:
                bad.append(f"{label}: exit {code}, want 2")
        return not bad, f"2 controls + {len(wrong)} refusals; problems {bad}"
    finally:
        shutil.rmtree(env.tmp, ignore_errors=True)


# ------------------------------------------------------------------ I4
EXACT_CODE = """
import json, sys
sys.path.insert(0, "scripts")
import imp_a6_gate as g
m = {"auroc": 0.69, "veto": 0.70, "bwins": 12.0}
mb = {"auroc": 0.60, "veto": 0.60, "bwins": 12.0}
out = {}
out["veto floor minus 1e-10 refused"] = not g.s1_eligible({**m, "veto": g.VETO_FLOOR - 1e-10}, {**mb, "veto": 0.55}, True)[0]
out["veto floor exactly accepted"] = g.s1_eligible({**m, "veto": g.VETO_FLOOR}, {**mb, "veto": 0.55}, True)[0]
out["veto delta minus 1e-10 refused"] = not g.s1_eligible({**m, "veto": 0.70}, {**mb, "veto": 0.70 - (g.VETO_DELTA_MIN - 1e-10)}, True)[0]
out["ensemble veto minus 1e-10 refused"] = not g.ensemble_eligible({"auroc": 0.70, "veto": g.VETO_FLOOR - 1e-10})
out["ensemble auroc minus 1e-10 refused"] = not g.ensemble_eligible({"auroc": g.ENSEMBLE_AUROC_MIN - 1e-10, "veto": 0.70})
out["tie window plus 1e-10 is not a tie"] = g.pick_winner([("A1", 0.700), ("B2", 0.700 - g.TIE - 1e-10)]) == "A1"
out["tie window exactly is a tie"] = g.pick_winner([("A1", 0.75), ("B2", 0.75 - g.TIE + 1e-12)]) == "B2"
print(json.dumps(out))
"""


def check_exact():
    p = subprocess.run([sys.executable, "-c", EXACT_CODE], cwd=ROOT, capture_output=True, text=True)
    try:
        out = json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return False, f"could not run the probe: {p.stderr.strip()[-200:]}"
    bad = [k for k, v in out.items() if not v]
    return not bad, f"{len(out)} probes; wrong: {bad}"


# ------------------------------------------------------------------ I5
def hygiene_run(skip):
    tmp = Path(tempfile.mkdtemp(prefix="a6hyg_"))
    try:
        (tmp / "results").mkdir()
        for f in os.listdir(ROOT / "results"):
            if f not in skip:
                os.symlink(ROOT / "results" / f, tmp / "results" / f)
        for d in ("src", "data"):
            if (ROOT / d).exists():
                os.symlink(ROOT / d, tmp / d)
        p = subprocess.run([sys.executable, str(ROOT / "scripts/ci_data_hygiene.py"), "--check"], cwd=tmp,
                           capture_output=True, text=True, timeout=900)
        return p.returncode, p.stdout + p.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_hygiene():
    name = Path(D3_FILE).name
    ctrl, _ = hygiene_run(set())
    only_d3, o1 = hygiene_run({name})
    both, o2 = hygiene_run({name, "vsp_dev3_cases.json"})   # dev3 cases absent too: the vspt EXTRA_POOLS path runs alone
    ok = ctrl == 0 and only_d3 != 0 and both != 0 and name in o2
    return ok, (f"control (all present) exit {ctrl}; d3 pilot missing exit {only_d3}; d3 pilot and dev3 cases missing "
                f"exit {both}, message names the file {name in o2}: {o2.strip()[-100:]!r}")


CHECKS = [("I1 PLAN_D3_TRAIN_ONLY", check_plan), ("I2 TARGET_BINDING", check_target),
          ("I3 GATE_PROVENANCE", check_gate_provenance), ("I4 GATE_EXACT", check_exact),
          ("I5 HYGIENE_MISSING_D3", check_hygiene)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    for name, fn in CHECKS:
        if a.only and a.only not in name:
            continue
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001  a missing file or a crash is a FAIL
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        record(ok, name, detail)
    failed = RESULTS.count(False)
    print("RESULT: " + ("FAIL" if failed else "PASS") + f" ({failed} failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
