"""Acceptance checker for the attempt-6 CI planner changes (criterion C5 of cyberdef-a6-tooling).

Usage:
  .venv/bin/python acceptance/improve/check_a6_plan.py

Calls ci_plan.plan(env) directly (nothing is dispatched, no machine contacted), as check_ci_k4.py does.
Discovery by FILE, never by name: the d3 pilot DATA option is the key whose items file is results/vsp_pilot_k4b_d3_items.json;
the dev3 test set is the TEST_SETS choice whose only set key maps to results/vsp_dev3_cases.json.
Checks (one PASS/FAIL line each; exit 0 only if all pass):
  D3_OPTION        a DATA option for the d3 pilot file with the K4b recipe flags (--pair-batches --pair-loss 1 --pair-sampler
                   balanced_by_domain); its name must NOT contain K4: check_ci_k4.py (guard G2, unchanged) treats every
                   "VSP pilot ... K4" option as a K4 pilot that must be accepted on dev2, which the d3 pilot must never be.
  DEV3_SET         a dev3 test-set choice exists and maps to exactly one set key for results/vsp_dev3_cases.json.
  D3_ACCEPTED      d3 pilot data + tag vsp_pilot_k4b_d3_x on dev3 (train + test); tag vsp_pilot_k4b_d3_x test only; the base
                   model (blank tag) on dev3; the bare prefix tag vsp_pilot_k4b_d3. Plan fields are checked (items file,
                   dev3 test set, train / test flags).
  D3_REFUSED       d3 pilot (data and/or tag) on dev2 (message names dev2) and on VSP-T (names VSP-T); a non-d3 adapter on
                   dev3: K4a / K4b pilot tags, an arbitrary tag, a K2 pilot tag (names dev3); a K4b final or any final on dev3
                   (names dev3); training the d3 pilot data under a non-pilot tag (names pilot).
  EXISTING_GUARDS  unchanged behaviour: K4b pilot on dev2 accepted, on VSP-T refused; K4 final on dev2 refused, on VSP-T accepted;
                   K2 pilot on VSP-T refused; probe set refuses a non-pilot adapter and accepts the base model.
  WORKFLOWS        the d3 option and the dev3 choice appear in .github/workflows/gpu.yml and spark.yml.
  K4_CHECK_UNCHANGED  acceptance/improve/check_ci_k4.py still exits 0 (guard G2 run as part of this criterion).
Every refusal must come from the intended guard (its message mentions the subject) and is paired with an accepted control
that differs in one variable.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
MODEL = "Qwen/Qwen3.8-27B"
D3_FILE, DEV3_FILE = "results/vsp_pilot_k4b_d3_items.json", "results/vsp_dev3_cases.json"
DEV2_FILE = "results/vsp_dev2_cases.json"
BASE_FLAGS = ("--pair-batches", "--pair-loss 1", "--pair-sampler balanced_by_domain")
K4B_PILOT = "VSP pilot K4b: K4a + diff-site target (train minus dev2)"
K4B_FINAL = "VSP-SFT K4b final: K4 final + diff-site target"
K2_PILOT = "VSP pilot K2: K1 + linux V-longer pairs (train minus dev)"


def plan_of(cp, data, tag, test_set, steps="train + test"):
    env = {"MACHINE": "spark", "MODEL": MODEL, "STEPS": steps, "TAG": tag, "TEST_SET": test_set,
           "SCORER": "selective", "DATA": data}
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return True, cp.plan(env)
    except SystemExit as exc:
        return False, str(exc)


def keys_for(cp, path):
    return [k for k, v in cp.SET_FILES.items() if v == path]


def choice_of(cp, path, exclusive=True):
    ks = keys_for(cp, path)
    return [n for n, v in cp.TEST_SETS.items() if any(k in v for k in ks) and (not exclusive or len(v) == len(ks))]


def d3_options(cp):
    return [k for k, v in cp.DATA.items() if v[0] == D3_FILE]


def check_d3_option(cp):
    opts = d3_options(cp)
    if len(opts) != 1:
        return False, f"{len(opts)} DATA options map to {D3_FILE}; need exactly 1"
    items_file, flags = cp.DATA[opts[0]]
    bad = [f for f in BASE_FLAGS if f not in flags]
    problems = []
    if bad:
        problems.append(f"flags lack {bad}")
    if "K4" in opts[0]:
        problems.append(f"name {opts[0]!r} contains K4 (check_ci_k4 would classify it as a K4 pilot allowed on dev2)")
    if not (ROOT / items_file).is_file():
        problems.append(f"items file {items_file} does not exist")
    if not opts[0].startswith("VSP pilot"):
        problems.append("name must start with VSP pilot so the existing pilot guards apply")
    return not problems, f"option {opts[0]!r}; " + ("; ".join(problems) or "recipe flags and name ok")


def check_dev3_set(cp):
    ks = keys_for(cp, DEV3_FILE)
    ch = choice_of(cp, DEV3_FILE)
    return len(ks) == 1 and len(ch) == 1, f"SET_FILES keys {ks}; exclusive test-set choices {ch}"


def ctx(cp):
    opts = d3_options(cp)
    dev3 = choice_of(cp, DEV3_FILE)
    dev2 = choice_of(cp, DEV2_FILE)
    vspt = [n for n, v in cp.TEST_SETS.items() if "vspt" in v]
    if not (opts and dev3 and dev2 and vspt):
        raise RuntimeError(f"d3 option {opts}, dev3 {dev3}, dev2 {dev2}, VSP-T sets {len(vspt)}: something is missing")
    return opts[0], dev3[0], dev2[0], vspt


def check_accepted(cp):
    d3, dev3, _dev2, _vspt = ctx(cp)
    cases = [("d3 pilot, d3 tag, dev3, train + test", d3, "vsp_pilot_k4b_d3_x", dev3, "train + test"),
             ("d3 tag, test only", "", "vsp_pilot_k4b_d3_x", dev3, "test only"),
             ("base model (blank tag), test only", "", "", dev3, "test only"),
             ("bare prefix tag vsp_pilot_k4b_d3", d3, "vsp_pilot_k4b_d3", dev3, "train + test")]
    bad = []
    for label, data, tag, ts, steps in cases:
        ok, res = plan_of(cp, data, tag, ts, steps)
        if not ok:
            bad.append(f"{label}: REFUSED ({str(res)[:90]})")
            continue
        if "vspdev3=" + DEV3_FILE not in res["test_sets"]:
            bad.append(f"{label}: test_sets {res['test_sets']!r} lacks vspdev3={DEV3_FILE}")
        if steps == "train + test" and (res["items_file"] != D3_FILE or not res["train"] or not res["test"]):
            bad.append(f"{label}: items_file {res['items_file']!r} train {res['train']} test {res['test']}")
    return not bad, f"{len(cases)} cases; problems {bad[:3]}"


def check_refused(cp):
    d3, dev3, dev2, vspt = ctx(cp)
    k4a = "VSP pilot K4a: domain-crossed low-replay sampler (train minus dev2)"
    cases = [("d3 pilot, d3 tag, on dev2", d3, "vsp_pilot_k4b_d3_x", dev2, "train + test", "dev2"),
             ("d3 tag test only on dev2", "", "vsp_pilot_k4b_d3_x", dev2, "test only", "dev2"),
             ("d3 pilot data, other pilot tag, on dev2", d3, "vsp_pilot_k4b_x", dev2, "train + test", "dev2"),
             ("K4b pilot tag on dev3", K4B_PILOT, "vsp_pilot_k4b_x", dev3, "train + test", "dev3"),
             ("K4a pilot on dev3", k4a, "vsp_pilot_k4_x", dev3, "train + test", "dev3"),
             ("tag vsp_pilot_k4b_x test only on dev3", "", "vsp_pilot_k4b_x", dev3, "test only", "dev3"),
             ("arbitrary tag on dev3", "", "bowlr", dev3, "test only", "dev3"),
             ("K2 pilot tag on dev3", K2_PILOT, "vsp_pilot_k2_x", dev3, "train + test", "dev3"),
             ("K4b final on dev3", K4B_FINAL, "vsp_final_k4b_x", dev3, "train + test", "dev3"),
             ("final tag, test only, on dev3", "", "vsp_final_k4b_x", dev3, "test only", "dev3"),
             ("d3 pilot data under a non-pilot tag", d3, "d3run", dev3, "train + test", "pilot")]
    for ts in vspt:
        cases.append(("d3 pilot, d3 tag, on VSP-T", d3, "vsp_pilot_k4b_d3_x", ts, "train + test", "vsp-t"))
        cases.append(("d3 tag test only on VSP-T", "", "vsp_pilot_k4b_d3_x", ts, "test only", "vsp-t"))
    bad = []
    for label, data, tag, ts, steps, kw in cases:
        ok, res = plan_of(cp, data, tag, ts, steps)
        if ok:
            bad.append(f"{label}: ACCEPTED")
        elif kw not in str(res).lower():
            bad.append(f"{label}: refused for another reason: {str(res)[:90]}")
    return not bad, f"{len(cases)} refusals; problems {bad[:3]}"


def check_existing(cp):
    dev2 = choice_of(cp, DEV2_FILE)
    probe = choice_of(cp, "results/vsp_probe_cases.json")
    vspt = [n for n, v in cp.TEST_SETS.items() if "vspt" in v]
    if not (dev2 and probe and vspt):
        return False, "dev2, probe or VSP-T test set missing"
    acc = [("K4b pilot on dev2", K4B_PILOT, "vsp_pilot_k4b_x", dev2[0], "train + test"),
           ("K4b final on VSP-T", K4B_FINAL, "vsp_final_k4b_x", vspt[0], "train + test"),
           ("base model on the probe set", "", "", probe[0], "test only")]
    ref = [("K4b pilot on VSP-T", K4B_PILOT, "vsp_pilot_k4b_x", vspt[0], "train + test", "vsp-t"),
           ("K4b final on dev2", K4B_FINAL, "vsp_final_k4b_x", dev2[0], "train + test", "dev"),
           ("K2 pilot on VSP-T", K2_PILOT, "vsp_pilot_k2_x", vspt[0], "train + test", "vsp-t"),
           ("final tag on the probe set", "", "vsp_final_k4b_x", probe[0], "test only", "probe")]
    bad = [f"{label}: REFUSED ({str(plan_of(cp, d, t, s, st)[1])[:80]})" for label, d, t, s, st in acc
           if not plan_of(cp, d, t, s, st)[0]]
    for label, d, t, s, st, kw in ref:
        ok, res = plan_of(cp, d, t, s, st)
        if ok or kw not in str(res).lower():
            bad.append(f"{label}: {'ACCEPTED' if ok else 'wrong reason: ' + str(res)[:80]}")
    return not bad, f"{len(acc) + len(ref)} cases; problems {bad[:3]}"


def check_workflows(cp):
    d3, dev3, _dev2, _vspt = ctx(cp)
    bad = []
    for wf in ("gpu.yml", "spark.yml"):
        text = (ROOT / ".github/workflows" / wf).read_text(encoding="utf-8")
        bad += [f"{wf}: {w[:45]}" for w in (d3, dev3) if '"' + w + '"' not in text]
    return not bad, f"missing {bad}"


def check_k4_unchanged(cp):
    p = subprocess.run([sys.executable, str(ROOT / "acceptance/improve/check_ci_k4.py")], cwd=ROOT, capture_output=True, text=True)
    fails = [ln[:110] for ln in p.stdout.splitlines() if ln.startswith("FAIL")]
    return p.returncode == 0, f"check_ci_k4.py exit {p.returncode}; {fails[:3]}"


CHECKS = [("D3_OPTION", check_d3_option), ("DEV3_SET", check_dev3_set), ("D3_ACCEPTED", check_accepted),
          ("D3_REFUSED", check_refused), ("EXISTING_GUARDS", check_existing), ("WORKFLOWS", check_workflows),
          ("K4_CHECK_UNCHANGED", check_k4_unchanged)]


def main():
    import ci_plan as cp
    failed = 0
    for name, fn in CHECKS:
        try:
            ok, detail = fn(cp)
        except Exception as exc:  # noqa: BLE001  a missing option or file is a FAIL, never a crash
            ok, detail = False, type(exc).__name__ + ": " + str(exc)
        print(("PASS " if ok else "FAIL ") + name + " - " + detail, flush=True)
        failed += 0 if ok else 1
    print("RESULT: " + ("FAIL" if failed else "PASS") + f" ({failed} failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
