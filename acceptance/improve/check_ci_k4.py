"""Acceptance checker for the CI planner K4 options and guards (spec C9): scripts/ci_plan.py, the two workflows, the
data manifest. Calls ci_plan.plan(env) directly; nothing is dispatched and no machine is contacted.

Usage:
  .venv/bin/python acceptance/improve/check_ci_k4.py

Discovery (the spec names no option strings, so they are found by pattern; resolved ambiguity):
  K4 pilot options  keys of ci_plan.DATA that start with "VSP pilot" and contain "K4"
  K4 final options  keys that start with "VSP-SFT K" and contain "K4"
  dev2 / probe test sets  SET_FILES keys whose file is results/vsp_dev2_cases.json / results/vsp_probe_cases.json, and
                    the TEST_SETS choices that list them.
Checks (one PASS/FAIL line each; exit 0 only if all pass):
  K4_OPTIONS         pilot options cover results/vsp_pilot_k4_items.json and vsp_pilot_k4b_items.json, a final option
                     covers results/vsp_sft_k4_items.json; every K4 option carries --pair-batches --pair-loss 1
                     --pair-sampler balanced_by_domain; item files exist.
  TEST_SET_KEYS      dev2 and probe each have a SET_FILES key and at least one TEST_SETS choice.
  PILOT_VSPT_REFUSED every K4 pilot option, and every vsp_pilot* tag, is refused with every test set that includes VSP-T.
  PILOT_ALLOWED      controls: K4 pilot + vsp_pilot tag + dev2 accepted; pilot tag on the probe set accepted; a pilot
                     data option with a non-vsp_pilot tag refused when training.
  FINAL_DEV2_REFUSED every K4 final option is refused with every test set that includes dev2 or cycle-1 dev;
                     control: K4 final on VSP-T accepted.
  PROBE_NON_PILOT_REFUSED  any non-pilot adapter (final tag, arbitrary tag, K4 final data, K2 final) on any probe test
                     set is refused; controls: the base model (blank tag) and a vsp_pilot* adapter are accepted.
  EXISTING_GUARDS    K2 pilot on VSP-T refused, K2 final on cycle-1 dev refused, K2 pilot on cycle-1 dev accepted.
  WORKFLOWS          every K4 option and every new test-set choice appears in .github/workflows/gpu.yml and spark.yml.
  MANIFEST           data/DATA_MANIFEST.json and ci_data_manifest.CANONICAL list the dev2, probe, K4 pilot, K4b pilot and
                     K4 final files with the right sha256, byte size and count; ci_data_manifest --check passes.
Ambiguity resolved: a refusal must come from the intended guard, so each refusal message must mention its subject
(probe / dev / VSP-T) and every refusal is paired with an accepted control that differs in one variable.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.environ.get("CI_K4_SCRIPTS", str(ROOT / "scripts")))   # env: checker self-test only
MODEL = "Qwen/Qwen3.8-27B"
DEV2_FILE, PROBE_FILE = "results/vsp_dev2_cases.json", "results/vsp_probe_cases.json"
PILOT_FILES = ("results/vsp_pilot_k4_items.json", "results/vsp_pilot_k4b_items.json")
FINAL_FILE = "results/vsp_sft_k4_items.json"
K2_PILOT = "VSP pilot K2: K1 + linux V-longer pairs (train minus dev)"
K2_FINAL = "VSP-SFT K2 final: + linux V-longer pairs"
BASE_FLAGS = ("--pair-batches", "--pair-loss 1", "--pair-sampler balanced_by_domain")


def plan_of(cp, data, tag, test_set, steps):
    env = {"MACHINE": "spark", "MODEL": MODEL, "STEPS": steps, "TAG": tag, "TEST_SET": test_set,
           "SCORER": "selective", "DATA": data}
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return True, str(cp.plan(env))
    except SystemExit as exc:
        return False, str(exc)


def sets_with(cp, key):
    return [name for name, keys in cp.TEST_SETS.items() if key in keys]


def keys_for(cp, path):
    return [k for k, v in cp.SET_FILES.items() if v == path]


def choices(cp, path, exclusive=True):
    """TEST_SETS choices that include the set of this file (exclusive: and nothing else)."""
    ks = keys_for(cp, path)
    return [n for n, v in cp.TEST_SETS.items() if any(k in v for k in ks) and (not exclusive or len(v) == len(ks))]


def refuse_cases(cp, cases):
    """cases: (label, data, tag, test_set, steps, keyword). Returns problem strings."""
    bad = []
    for label, data, tag, ts, steps, kw in cases:
        ok, msg = plan_of(cp, data, tag, ts, steps)
        if ok:
            bad.append(f"{label}: ACCEPTED ({ts})")
        elif kw.lower() not in msg.lower():
            bad.append(f"{label}: refused for another reason: {msg[:90]}")
    return bad


def accept_cases(cp, cases):
    bad = []
    for label, data, tag, ts, steps in cases:
        ok, msg = plan_of(cp, data, tag, ts, steps)
        if not ok:
            bad.append(f"{label}: REFUSED ({msg[:100]})")
    return bad


def k4_options(cp):
    pilots = [k for k in cp.DATA if k.startswith("VSP pilot") and "K4" in k]
    finals = [k for k in cp.DATA if k.startswith("VSP-SFT K") and "K4" in k]
    return pilots, finals


def check_options(cp):
    pilots, finals = k4_options(cp)
    files = {cp.DATA[k][0] for k in pilots}
    problems = []
    if not set(PILOT_FILES) <= files:
        problems.append(f"pilot options cover {sorted(files)}, need {list(PILOT_FILES)}")
    if FINAL_FILE not in {cp.DATA[k][0] for k in finals}:
        problems.append(f"no K4 final option for {FINAL_FILE}")
    for k in pilots + finals:
        items_file, flags = cp.DATA[k]
        missing = [f for f in BASE_FLAGS if f not in flags]
        if missing or not (ROOT / items_file).is_file():
            problems.append(f"{k}: flags lack {missing}; items file {items_file} exists: {(ROOT / items_file).is_file()}")
    return not problems, f"{len(pilots)} pilot and {len(finals)} final K4 options; " + ("; ".join(problems) or "all consistent")


def check_set_keys(cp):
    out = {}
    for name, path in (("dev2", DEV2_FILE), ("probe", PROBE_FILE)):
        out[name] = (keys_for(cp, path), choices(cp, path))
    ok = all(k and c for k, c in out.values())
    return ok, "; ".join(f"{n}: SET_FILES keys {k}, test-set choices {len(c)}" for n, (k, c) in out.items())


def check_pilot_vspt(cp):
    pilots, _ = k4_options(cp)
    vspt_sets = sets_with(cp, "vspt")
    if not pilots or not vspt_sets:
        return False, f"{len(pilots)} K4 pilot options, {len(vspt_sets)} VSP-T test sets: nothing to test"
    cases = []
    for ts in vspt_sets:
        for k in pilots:
            cases.append((f"pilot option {k[:20]} train+test", k, "vsp_pilot_k4x", ts, "train + test", "vsp-t"))
            cases.append((f"pilot option {k[:20]} test only, non-pilot tag", k, "foo", ts, "test only", "vsp-t"))
        cases.append(("vsp_pilot tag, default data, test only", "", "vsp_pilot_k4x", ts, "test only", "vsp-t"))
    bad = refuse_cases(cp, cases)
    return not bad, f"{len(cases)} combinations over {len(vspt_sets)} VSP-T test sets; problems {bad[:3]}"


def check_pilot_allowed(cp):
    pilots, _ = k4_options(cp)
    dev2 = choices(cp, DEV2_FILE)
    probe = choices(cp, PROBE_FILE)
    if not pilots or not dev2 or not probe:
        return False, "K4 pilot options, dev2 or probe test sets missing"
    acc = [(f"{k[:20]} on dev2", k, "vsp_pilot_k4x", dev2[0], "train + test") for k in pilots]
    acc.append(("pilot adapter tag on the probe set", "", "vsp_pilot_k4x", probe[0], "test only"))
    bad = accept_cases(cp, acc)
    bad += refuse_cases(cp, [("pilot data with a non-pilot tag", pilots[0], "k4x_run", dev2[0], "train + test", "pilot")])
    return not bad, f"{len(acc) + 1} cases; problems {bad[:3]}"


def check_final_dev2(cp):
    _, finals = k4_options(cp)
    targets = sets_with(cp, keys_for(cp, DEV2_FILE)[0]) if keys_for(cp, DEV2_FILE) else []
    targets += sets_with(cp, "vspdev")
    if not finals or not targets:
        return False, f"{len(finals)} K4 final options, {len(targets)} dev / dev2 test sets: nothing to test"
    cases = [(f"final {k[:22]} on dev", k, "vsp_final_k4x", ts, "train + test", "dev") for ts in targets for k in finals]
    bad = refuse_cases(cp, cases)
    vspt = sets_with(cp, "vspt")
    bad += accept_cases(cp, [(f"final {k[:22]} on VSP-T", k, "vsp_final_k4x", vspt[0], "train + test") for k in finals]) \
        if vspt else ["no VSP-T test set to run the control"]
    return not bad, f"{len(cases)} refusals + controls; problems {bad[:3]}"


def check_probe_non_pilot(cp):
    _, finals = k4_options(cp)
    probe_all = sets_with(cp, keys_for(cp, PROBE_FILE)[0]) if keys_for(cp, PROBE_FILE) else []
    probe_only = choices(cp, PROBE_FILE)
    if not probe_all or not probe_only:
        return False, "no probe test set"
    cases = []
    for ts in probe_all:
        cases += [("final tag, K4 final data", finals[0] if finals else K2_FINAL, "vsp_final_k4x", ts, "train + test", "probe"),
                  ("arbitrary tag, test only", "", "bowlr", ts, "test only", "probe"),
                  ("K2 final data, test only", K2_FINAL, "vsp_sft_k2_final", ts, "test only", "probe"),
                  ("pilot data with non-pilot tag", K2_PILOT, "k2_run", ts, "test only", "probe")]
    bad = refuse_cases(cp, cases)
    ctrl = [("base model (blank tag) on the probe set", "", "", probe_only[0], "test only"),
            ("K2 pilot adapter on the probe set", "", "vsp_pilot_k2", probe_only[0], "test only")]
    bad += accept_cases(cp, ctrl)
    return not bad, f"{len(cases)} refusals over {len(probe_all)} probe test sets + {len(ctrl)} controls; problems {bad[:3]}"


def check_existing(cp):
    dev = choices(cp, "results/vsp_dev_cases.json")
    vspt = sets_with(cp, "vspt")
    if not dev or not vspt:
        return False, "cycle-1 dev or VSP-T test set missing"
    bad = refuse_cases(cp, [("K2 pilot on VSP-T", K2_PILOT, "vsp_pilot_k2x", vspt[0], "train + test", "vsp-t"),
                            ("K2 final on cycle-1 dev", K2_FINAL, "vsp_final_k2x", dev[0], "train + test", "dev")])
    bad += accept_cases(cp, [("K2 pilot on cycle-1 dev", K2_PILOT, "vsp_pilot_k2x", dev[0], "train + test")])
    return not bad, f"3 cases; problems {bad[:3]}"


def check_workflows(cp):
    pilots, finals = k4_options(cp)
    want = pilots + finals
    for path in (DEV2_FILE, PROBE_FILE):
        want += choices(cp, path, exclusive=False)
    if not pilots or not finals:
        return False, "no K4 options to look for"
    bad = []
    for wf in ("gpu.yml", "spark.yml"):
        text = (ROOT / ".github/workflows" / wf).read_text(encoding="utf-8")
        bad += [f"{wf}: {w[:40]}" for w in want if '"' + w + '"' not in text]
    return not bad, f"{len(want)} options x 2 workflows; missing {bad[:3]}"


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def count_of(p):
    d = json.load(open(p, encoding="utf-8"))
    return next(len(d[k]) for k in ("cases", "items") if k in d)


def check_manifest(cp):
    import ci_data_manifest as dm
    man = json.load(open(ROOT / "data/DATA_MANIFEST.json", encoding="utf-8"))["files"]
    canon = {p for p, _ in dm.CANONICAL}
    need = [DEV2_FILE, PROBE_FILE, *PILOT_FILES, FINAL_FILE]
    bad = []
    for f in need:
        e = man.get(f)
        if f not in canon:
            bad.append(f"{f}: not in ci_data_manifest.CANONICAL")
        if not e:
            bad.append(f"{f}: not in DATA_MANIFEST.json")
        elif not (ROOT / f).is_file() or e["sha256"] != sha256(ROOT / f) or e["bytes"] != (ROOT / f).stat().st_size \
                or e["n"] != count_of(ROOT / f) or not e.get("what"):
            bad.append(f"{f}: manifest sha256 / bytes / n / what does not match the file")
    proc = subprocess.run([sys.executable, str(ROOT / "scripts/ci_data_manifest.py"), "--check"], cwd=ROOT,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        bad.append("ci_data_manifest --check exit " + str(proc.returncode))
    return not bad, f"{len(need)} K4 files; problems {bad[:4]}"


CHECKS = [("K4_OPTIONS", check_options), ("TEST_SET_KEYS", check_set_keys), ("PILOT_VSPT_REFUSED", check_pilot_vspt),
          ("PILOT_ALLOWED", check_pilot_allowed), ("FINAL_DEV2_REFUSED", check_final_dev2),
          ("PROBE_NON_PILOT_REFUSED", check_probe_non_pilot), ("EXISTING_GUARDS", check_existing),
          ("WORKFLOWS", check_workflows), ("MANIFEST", check_manifest)]


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
