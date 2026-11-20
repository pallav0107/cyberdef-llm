"""Self-test for check_vsp_dev.py: each planted defect must be caught by the named check, and the
unmutated real files must pass in full.

Usage:
  .venv/bin/python acceptance/improve/check_vsp_dev_selftest.py [--dir RESULTS_DIR] [--builder F]
      [--skip-clean]

Mutants (each built from the real files in a temp dir; the slow whole-pipeline checks REBUILD and
VERDICT are skipped for mutants only, since none of the mutants concern them):
  1 LEAK_DEV_INTO_K1   a dev pair appended to pilot k1
  2 VSPT_IN_DEV        a VSP-T pair (a VSP-T project) added to the dev cases
  3 DEV_CODE_ALTERED   one dev code string altered
  4 S_LONGER_EXTRA     one linux extra replaced by an S-longer linux pair (k2 pilot and final)
  5 R1_PAIR_MISSING    one round-1 pair removed from k2 final
  6 CAMELCASE_COPY     one linux extra replaced by a VSP-T pair with every identifier converted camelCase ->
                       snake_case (what the real pair 205630 was: raw Jaccard passes < 0.5, normalised does not)
Exit 0 only if every mutant is caught (the expected check FAILs, exit non-zero) and the clean run
passes. Missing real files make the self-test fail (exit 1): nothing can be proven without them.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_vsp_dev as cd  # noqa: E402

ROOT = cd.ROOT
FILES = {"dev": "vsp_dev_cases.json", "k1": "vsp_pilot_k1_items.json",
         "k2_pilot": "vsp_pilot_k2_items.json", "k2_final": "vsp_sft_k2_items.json"}
FIELD = {"dev": "cases", "k1": "items", "k2_pilot": "items", "k2_final": "items"}
SKIP = "REBUILD,VERDICT"
FAILED = []


def load_real(real_dir):
    return {k: json.load(open(Path(real_dir) / name, encoding="utf-8")) for k, name in FILES.items()}


def pair_items(items, pair):
    return [it for it in items if it["pair"] == pair]


def mutant_leak(data, st):
    out = copy.deepcopy(data)
    pair = data["dev"]["cases"][0]["pair"]
    out["k1"]["items"] += copy.deepcopy(pair_items(st.r1, pair))
    return out, {"TRAIN_DEV_DISJOINT", "PILOT_NO_DEV_LEAK", "K1_RULE"}


def mutant_vspt_in_dev(data, st):
    out = copy.deepcopy(data)
    t = st.tcases
    pair = t[0]["pair"]
    for c in t:
        if c["pair"] == pair:
            out["dev"]["cases"].append({k: c[k] for k in cd.REQUIRED_CASE_KEYS})
    return out, {"DEV_PROJECT_RULE", "DEV_SUBSET_NO_LINUX", "DEV_NOT_VSPT"}


def mutant_dev_code(data, st):
    out = copy.deepcopy(data)
    out["dev"]["cases"][0]["code"] += " "
    return out, {"DEV_CODE_BYTES"}


def s_longer_linux_pair(st):
    """A linux train pair outside round 1, high confidence, otherwise eligible, S side longer."""
    df, train = st.table, st.train_split
    r1_pairs = set(cd.pair_map(st.r1))
    sub = df[(df.project == cd.LINUX) & df.idx.isin(train) & df.is_vulnerable & df.fixed_func_idx.notna()]
    for _, v in sub.iterrows():
        fx = int(v["fixed_func_idx"])
        pair = str(int(v["idx"]))
        if fx not in train or pair in r1_pairs or v["label_confidence"] != "high":
            continue
        vc, sc = cd.strip_comments(v["func_body"]), cd.strip_comments(df.loc[fx]["func_body"])
        if vc.strip() and sc.strip() and len(sc) > len(vc) and len(sc) < cd.MAX_CHARS:
            return int(v["idx"]), fx, vc, sc
    raise RuntimeError("no S-longer linux pair found for mutant 4")


def swap_first_extra(items, st, new):
    vi, fx, vc, sc = new
    extras = cd.extras_of(items, st.r1)
    victim = sorted(extras)[0]
    kept = [it for it in items if it["pair"] != victim]
    add = [{"id": f"vspsft:{vi}:{lab[0]}", "code": code, "code_chars": len(code), "toks": 1, "label": lab,
            "pair": str(vi), "project": cd.LINUX, "src_idx": src, "cwe": [], "rank": 0}
           for lab, src, code in (("VULNERABLE", vi, vc), ("SAFE", fx, sc))]
    return kept + add


def mutant_s_longer(data, st):
    out = copy.deepcopy(data)
    new = s_longer_linux_pair(st)
    for key in ("k2_pilot", "k2_final"):
        out[key]["items"] = swap_first_extra(out[key]["items"], st, new)
    return out, {"EXTRAS_PROPS"}


def mutant_r1_missing(data, st):
    out = copy.deepcopy(data)
    victim = st.r1[0]["pair"]
    out["k2_final"]["items"] = [it for it in out["k2_final"]["items"] if it["pair"] != victim]
    return out, {"K2_FINAL"}


def to_snake(code):
    return re.sub(r"[A-Za-z_][A-Za-z0-9_]*", lambda m: cd._CAMEL.sub("_", m.group()).lower(), code)


def mutant_camelcase_copy(data, st):
    """Needs a VSP-T pair whose V side is longer, so the planted pair is also a valid stratum-B extra."""
    out = copy.deepcopy(data)
    sides = {}
    for c in st.tcases:
        sides.setdefault(c["pair"], {})[c["label"]] = c["code"]
    pair = next(p for p, d in sorted(sides.items())
                if len(d.get("VULNERABLE", "")) > len(d.get("SAFE", "")) > 0 and to_snake(d["VULNERABLE"]) != d["VULNERABLE"])
    new = (999999001, 999999002, to_snake(sides[pair]["VULNERABLE"]), to_snake(sides[pair]["SAFE"]))
    for key in ("k2_pilot", "k2_final"):
        out[key]["items"] = swap_first_extra(out[key]["items"], st, new)
    return out, {"NORM_NEAR_DUP"}


MUTANTS = [("LEAK_DEV_INTO_K1", mutant_leak), ("VSPT_IN_DEV", mutant_vspt_in_dev),
           ("DEV_CODE_ALTERED", mutant_dev_code), ("S_LONGER_EXTRA", mutant_s_longer),
           ("R1_PAIR_MISSING", mutant_r1_missing),
           ("CAMELCASE_COPY", mutant_camelcase_copy)]


def run_checker(paths, extra_args=()):
    cmd = [sys.executable, str(HERE / "check_vsp_dev.py"),
           "--dev", paths["dev"], "--k1", paths["k1"], "--k2-pilot", paths["k2_pilot"],
           "--k2-final", paths["k2_final"], *extra_args]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    failed = {ln.split()[1] for ln in proc.stdout.splitlines() if ln.startswith("FAIL ")}
    return proc.returncode, failed, proc.stdout


def write_variant(data, tmp):
    paths = {}
    for key, name in FILES.items():
        paths[key] = str(Path(tmp) / name)
        json.dump(data[key], open(paths[key], "w", encoding="utf-8"))
    return paths


def report(name, ok, detail):
    print(("PASS " if ok else "FAIL ") + name + " - " + detail)
    if not ok:
        FAILED.append(name)


def run_mutants(real_dir, st):
    data = load_real(real_dir)
    for name, fn in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            mutated, expect = fn(data, st)
            code, failed, out = run_checker(write_variant(mutated, tmp), ("--skip-checks", SKIP))
        caught = code != 0 and expect <= failed
        report("MUTANT_" + name, caught, f"checker exit {code}; expected FAIL {sorted(expect)}; "
               f"got FAIL {sorted(failed)}")


def run_clean(real_dir, builder):
    paths = {k: str(Path(real_dir) / n) for k, n in FILES.items()}
    code, failed, out = run_checker(paths, ("--builder", builder))
    report("CLEAN_REAL_FILES", code == 0, f"checker exit {code}; failing checks {sorted(failed)}")
    if code != 0:
        print("\n".join("    " + ln for ln in out.splitlines() if ln.startswith("FAIL")))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(ROOT / "results"))
    ap.add_argument("--builder", default=str(ROOT / cd.DEFAULTS["builder"][1]))
    ap.add_argument("--skip-clean", action="store_true", help="debug only: skip the slow clean run")
    a = ap.parse_args(argv)
    missing = [n for n in FILES.values() if not (Path(a.dir) / n).is_file()]
    if missing:
        print(f"FAIL REAL_FILES - missing in {a.dir}: {missing}; nothing can be proven without them")
        return 1
    paths = {k: str(Path(a.dir) / n) for k, n in FILES.items()}
    st = cd.State({**{k: str(ROOT / v[1]) for k, v in cd.DEFAULTS.items()}, **paths})
    run_mutants(a.dir, st)
    if not a.skip_clean:
        run_clean(a.dir, a.builder)
    print("RESULT:", "ALL PASS" if not FAILED else f"FAIL {FAILED}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
