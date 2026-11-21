"""Self-test for check_vsp_dev2.py: each planted defect must be caught by the check named for it, and the unmutated
real files must pass in full.

Usage:
  .venv/bin/python acceptance/improve/check_vsp_dev2_selftest.py [--dir RESULTS_DIR] [--skip-clean]

Mutants (built from the real vsp_dev2_cases.json and vsp_pilot_k4_items.json in a temp dir):
  1 WRONG_SALT            top-level salt changed to vspdev-v1|                         -> SALT
  2 CYCLE1_DEV_REUSED     two cycle-1 dev cases appended to dev2                       -> DEV2_NOT_CYCLE1
  3 LINUX_PROJECT         a round-1 linux pair appended to dev2                        -> DEV2_NO_LINUX
  4 B_FLOOR               stratum-B pairs removed until B < 105                        -> B_FLOOR
  5 NEARDUP_IN_TRAINING   a dev2 pair, lightly edited under a new id, put in the pilot -> PILOT_NO_DEV2_NEARDUP
  6 VSPT_PROJECT          a VSP-T pair appended to dev2                                -> DEV2_NOT_VSPT
  7 PILOT_SHARES_PROJECT  a dev2 pair appended unchanged to the pilot                  -> PILOT_NO_DEV2_PROJECT
  8 CORE_PAIR_MISSING     one stratum-A core pair removed from dev2                    -> DEV2_CORE_RULE
Exit 0 only if every mutant is caught (exit non-zero AND the named check printed FAIL) and the clean run passes.
Missing real files make the self-test fail (exit 1): nothing can be proven without them.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import k4_common as k4
from k4_common import cd

HERE = Path(__file__).resolve().parent
ROOT = k4.ROOT
FILES = {"dev2": "vsp_dev2_cases.json", "k4_pilot": "vsp_pilot_k4_items.json"}
FAILED = []


def item_of(pair, label, code, project, src_idx):
    return {"id": f"vspsft:{pair}:{label[0]}", "code": code, "code_chars": len(code), "toks": 1, "label": label,
            "pair": pair, "project": project, "src_idx": src_idx, "cwe": [], "rank": 1}


def m_salt(data, st):
    out = copy.deepcopy(data)
    out["dev2"]["salt"] = "vspdev-v1|"
    return out


def m_cycle1(data, st):
    out = copy.deepcopy(data)
    out["dev2"]["cases"] += copy.deepcopy(st.dev[:2])
    return out


def m_linux(data, st):
    out = copy.deepcopy(data)
    pair = next(it["pair"] for it in st.r1 if it["project"] == k4.LINUX)
    for it in st.r1:
        if it["pair"] == pair:
            out["dev2"]["cases"].append({k: (it[k] if k in it else {"lines": it["code"].count("\n") + 1,
                                                                    "truncated": False}[k])
                                         for k in cd.REQUIRED_CASE_KEYS})
    return out


def m_bfloor(data, st):
    import check_vsp_dev2 as c2
    out = copy.deepcopy(data)
    cs = out["dev2"]["cases"]
    b_pairs = sorted(p for p, s in k4.strata(cs).items() if s == "B")
    drop = set(b_pairs[: max(1, len(b_pairs) - (c2.MIN_B - 1))])
    out["dev2"]["cases"] = [c for c in cs if c["pair"] not in drop]
    return out


def m_neardup(data, st):
    out = copy.deepcopy(data)
    pm = cd.pair_map(out["dev2"]["cases"])
    pair = sorted(pm)[0]
    for side, label in (("V", "VULNERABLE"), ("S", "SAFE")):
        out["k4_pilot"]["items"].append(item_of("9999991", label, pm[pair][side]["code"] + "\n int zz_extra;",
                                                k4.LINUX, 9999991))
    return out


def m_vspt(data, st):
    out = copy.deepcopy(data)
    pair = st.tcases[0]["pair"]
    out["dev2"]["cases"] += [{k: c[k] for k in cd.REQUIRED_CASE_KEYS} for c in st.tcases if c["pair"] == pair]
    return out


def m_pilot_project(data, st):
    out = copy.deepcopy(data)
    first = out["dev2"]["cases"][0]
    for c in out["dev2"]["cases"]:
        if c["pair"] == first["pair"]:
            out["k4_pilot"]["items"].append(item_of(c["pair"], c["label"], c["code"], c["project"], int(c["pair"])))
    return out


def m_core_missing(data, st):
    out = copy.deepcopy(data)
    r1_proj = k4.r1_projects(st)
    proj_of = {c["pair"]: c["project"] for c in out["dev2"]["cases"]}
    victim = next(p for p, s in sorted(k4.strata(out["dev2"]["cases"]).items()) if s == "A" and proj_of[p] in r1_proj)
    out["dev2"]["cases"] = [c for c in out["dev2"]["cases"] if c["pair"] != victim]
    return out


MUTANTS = [("WRONG_SALT", m_salt, {"SALT"}), ("CYCLE1_DEV_REUSED", m_cycle1, {"DEV2_NOT_CYCLE1"}),
           ("LINUX_PROJECT", m_linux, {"DEV2_NO_LINUX"}), ("B_FLOOR", m_bfloor, {"B_FLOOR"}),
           ("NEARDUP_IN_TRAINING", m_neardup, {"PILOT_NO_DEV2_NEARDUP"}),
           ("VSPT_PROJECT", m_vspt, {"DEV2_NOT_VSPT"}),
           ("PILOT_SHARES_PROJECT", m_pilot_project, {"PILOT_NO_DEV2_PROJECT"}),
           ("CORE_PAIR_MISSING", m_core_missing, {"DEV2_CORE_RULE"})]


def run_checker(data):
    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for key, name in FILES.items():
            paths[key] = str(Path(tmp) / name)
            json.dump(data[key], open(paths[key], "w", encoding="utf-8"))
        cmd = [sys.executable, str(HERE / "check_vsp_dev2.py"), "--dev2", paths["dev2"],
               "--k4-pilot", paths["k4_pilot"], "--k4b-pilot", ""]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    failed = {ln.split()[1] for ln in proc.stdout.splitlines() if ln.startswith("FAIL ")}
    return proc.returncode, failed, proc.stdout


def report(name, ok, detail):
    print(("PASS " if ok else "FAIL ") + name + " - " + detail, flush=True)
    if not ok:
        FAILED.append(name)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(ROOT / "results"))
    ap.add_argument("--skip-clean", action="store_true", help="debug only")
    a = ap.parse_args(argv)
    missing = [n for n in FILES.values() if not (Path(a.dir) / n).is_file()]
    if missing:
        print(f"FAIL REAL_FILES - target not built yet, missing in {a.dir}: {missing}; nothing can be proven without them")
        return 1
    data = {k: json.load(open(Path(a.dir) / n, encoding="utf-8")) for k, n in FILES.items()}
    st = k4.make_state()
    for name, fn, expect in MUTANTS:
        try:
            code, failed, _ = run_checker(fn(data, st))
            ok = code != 0 and expect <= failed
            detail = f"checker exit {code}; expected FAIL {sorted(expect)}; got FAIL {sorted(failed)}"
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"mutant could not be built: {type(exc).__name__}: {exc}"
        report("MUTANT_" + name, ok, detail)
    if not a.skip_clean:
        code, failed, out = run_checker(data)
        report("CLEAN_REAL_FILES", code == 0, f"checker exit {code}; failing checks {sorted(failed)}")
        if code != 0:
            print("\n".join("    " + ln for ln in out.splitlines() if ln.startswith("FAIL")))
    print("RESULT:", "ALL PASS" if not FAILED else f"FAIL {FAILED}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
