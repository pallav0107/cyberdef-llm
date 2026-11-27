"""Acceptance checker for the attempt-6 confirmation fold dev3 (criterion C2 of cyberdef-a6-tooling).

Usage:
  .venv/bin/python acceptance/improve/check_a6_dev3.py [--dev3 F] [--pilot F] [--builder F] [--no-rebuild]
      [--skip-checks NAME,NAME]

The fold is recomputed HERE from results/vsp_sft_k4b_items.json, results/vsp_dev2_cases.json and
results/vsp_t_cases.json, independently of scripts/imp_build_vsp_dev3.py (the builder is only run for the rebuild
check). Rule (CURRENT_PLAN.md section 3, stage 2):
  candidates   projects of the final file that are not linux and not a dev2 project (299 projects, 837 pairs)
  order        sha256 of "vspdev3-v1|" + project, hex ascending
  take         whole projects until the pair count is >= 400
  expected     122 projects, 400 pairs, strata A 357 / B 27 / E 16 (stratum by code length, V longer = B)
  d3 pilot     final items minus every dev3 project minus every pair with a side whose raw or identifier-normalised
               token-set Jaccard to a dev3 function is >= 0.5; V,S adjacent; items byte-equal to those of the final
               file (so the K4b two-line target VERDICT/SITE is kept); about 1,457 pairs
Overlap: dev3 shares 0 projects and 0 normalised-code hashes with VSP-T (543c4346...) and dev2 (9511373d...); the
pilot shares 0 projects, 0 hashes and 0 near pairs with dev3.
Rebuild: scripts/imp_build_vsp_dev3.py is run ONCE with no arguments from the repo root and both output files must
keep their sha256 (byte-identical rebuild).
Exit 0 only if every check passes; a missing file is FAIL, never a crash. --skip-checks exists for the mutant test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import k4_common as k4  # noqa: E402
from k4_common import cd  # noqa: E402

SALT, MIN_PAIRS = "vspdev3-v1|", 400
WANT = {"projects": 122, "pairs": 400, "A": 357, "B": 27, "E": 16}
PIN = {"vspt": "543c4346", "dev2": "9511373d"}
FINAL, DEV2, VSPT = "results/vsp_sft_k4b_items.json", "results/vsp_dev2_cases.json", "results/vsp_t_cases.json"
REQ_KEYS = {"id", "code", "label", "pair", "project"}
_C = {}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def need(p):
    if not Path(p).is_file():
        raise FileNotFoundError(f"target not built yet: {p}")


def load(p, field):
    need(p)
    return json.load(open(p, encoding="utf-8"))[field]


def memo(key, fn):
    if key not in _C:
        _C[key] = fn()
    return _C[key]


def final_items():
    return memo("final", lambda: load(ROOT / FINAL, "items"))


def dev2_cases():
    return memo("dev2", lambda: load(ROOT / DEV2, "cases"))


def vspt_cases():
    return memo("vspt", lambda: load(ROOT / VSPT, "cases"))


def expected_fold():
    def go():
        pm = cd.pair_map(final_items())
        by_proj = defaultdict(list)
        for k, p in pm.items():
            by_proj[p["V"]["project"]].append(k)
        dev2p = {c["project"] for c in dev2_cases()}
        cand = [p for p in by_proj if p != "linux" and p not in dev2p]
        cand.sort(key=lambda p: hashlib.sha256((SALT + p).encode()).hexdigest())
        sel, n = [], 0
        for p in cand:
            if n >= MIN_PAIRS:
                break
            sel.append(p)
            n += len(by_proj[p])
        pairs = {k for p in sel for k in by_proj[p]}
        strata = Counter(cd.stratum_of(pm[k]) for k in pairs)
        return {"cand": len(cand), "projects": sel, "pairs": pairs, "strata": strata, "pm": pm}
    return memo("fold", go)


def expected_pilot():
    def go():
        f = expected_fold()
        dev_codes = [it["code"] for it in final_items() if it["pair"] in f["pairs"]]
        ref = k4.RefSet(dev_codes)
        rest = {k: p for k, p in f["pm"].items() if p["V"]["project"] not in set(f["projects"])}
        near = set(k4.near_pairs(ref, rest))
        return {"pairs": set(rest) - near, "near": near}
    return memo("pilot", go)


def fold_cases(a):
    return load(a.dev3, "cases")


def pilot_items(a):
    return load(a.pilot, "items")


def check_files(a):
    miss = [str(p) for p in (a.dev3, a.pilot, a.builder) if not Path(p).is_file()]
    return not miss, "dev3, d3 pilot and builder present" if not miss else "target not built yet: " + ", ".join(miss)


def check_fold_rule(a):
    f, cs = expected_fold(), fold_cases(a)
    got_pairs = {c["pair"] for c in cs}
    got_proj = {c["project"] for c in cs}
    sizes_ok = (len(f["projects"]), len(f["pairs"]), f["strata"]["A"], f["strata"]["B"], f["strata"]["E"]) == \
        (WANT["projects"], WANT["pairs"], WANT["A"], WANT["B"], WANT["E"])
    ok = sizes_ok and got_pairs == f["pairs"] and got_proj == set(f["projects"]) and len(cs) == 2 * len(got_pairs)
    return ok, (f"recomputed fold {len(f['projects'])} projects / {len(f['pairs'])} pairs / {dict(f['strata'])} "
                f"(spec {WANT}); file {len(got_proj)} projects / {len(got_pairs)} pairs / {len(cs)} cases; "
                f"missing pairs {sorted(f['pairs'] - got_pairs)[:3]} unexpected {sorted(got_pairs - f['pairs'])[:3]}")


def check_fold_cases(a):
    cs = fold_cases(a)
    fin = {(it["pair"], it["label"]): it for it in final_items()}
    ids = Counter(c.get("id") for c in cs)
    dup = [i for i, n in ids.items() if n > 1]
    bad_keys = [c.get("id") for c in cs if not REQ_KEYS <= set(c)]
    diff = [c.get("id") for c in cs if (c.get("pair"), c.get("label")) not in fin
            or fin[(c["pair"], c["label"])]["code"] != c.get("code")
            or fin[(c["pair"], c["label"])]["project"] != c.get("project")]
    pm = cd.pair_map(cs)
    odd = [k for k, p in pm.items() if not (p["V"] and p["S"])]
    lin = [c["id"] for c in cs if c["project"] == "linux"]
    ok = not (dup or bad_keys or diff or odd or lin)
    return ok, (f"{len(cs)} cases; duplicate ids {dup[:2]}; missing keys on {bad_keys[:2]}; code/label/project differs "
                f"from the final file on {diff[:3]}; pairs without both sides {odd[:3]}; linux cases {lin[:2]}")


def overlap(codes_a, proj_a, cases_b):
    hb = {cd.norm_hash(c["code"]) for c in cases_b}
    return sorted(proj_a & {c["project"] for c in cases_b}), sum(1 for c in codes_a if cd.norm_hash(c) in hb)


def check_no_overlap_refs(a):
    cs = fold_cases(a)
    codes, projs = [c["code"] for c in cs], {c["project"] for c in cs}
    out, bad = [], False
    for name, ref in (("VSP-T", vspt_cases()), ("dev2", dev2_cases())):
        p, h = overlap(codes, projs, ref)
        bad |= bool(p or h)
        out.append(f"{name}: {len(p)} shared projects {p[:3]}, {h} shared code hashes")
    return not bad, "; ".join(out)


def check_ref_shas(a):
    got = {"vspt": sha(ROOT / VSPT)[:8], "dev2": sha(ROOT / DEV2)[:8]}
    return got == PIN, f"reference files {got}, pinned {PIN}"


def check_pilot_rule(a):
    e, items = expected_pilot(), pilot_items(a)
    got = {it["pair"] for it in items}
    fin = {it["id"]: it for it in final_items()}
    notsame = [it.get("id") for it in items if fin.get(it.get("id")) != it]
    ok = got == e["pairs"] and len(items) == 2 * len(got) and not notsame and 1400 <= len(got) <= 1500
    return ok, (f"rule gives {len(e['pairs'])} pairs ({len(e['near'])} near-neighbour pairs removed); file has {len(got)} "
                f"pairs / {len(items)} items; missing {sorted(e['pairs'] - got)[:3]} unexpected {sorted(got - e['pairs'])[:3]}; "
                f"items not byte-equal to the final file {notsame[:3]}")


def check_pilot_adjacent_targets(a):
    items = pilot_items(a)
    bad = cd.adjacency_problems(items)
    tbad = []
    for it in items:
        lines = it.get("target", "").split("\n")
        if len(lines) != 2 or lines[0] != f"VERDICT: {it['label']}" or not lines[1].startswith("SITE:"):
            tbad.append(it["id"])
    return not bad and not tbad, f"adjacency problems {bad[:2]}; items without a two-line VERDICT/SITE target {tbad[:3]}"


def check_pilot_vs_dev3(a):
    cs, items = fold_cases(a), pilot_items(a)
    p, h = overlap([i["code"] for i in items], {i["project"] for i in items}, cs)
    ref = k4.RefSet([c["code"] for c in cs])
    near = k4.near_pairs(ref, cd.pair_map(items))
    return not (p or h or near), f"{len(p)} shared projects {p[:3]}; {h} shared hashes; {len(near)} near pairs {near[:3]}"


def check_pilot_vs_vspt(a):
    items = pilot_items(a)
    p, h = overlap([i["code"] for i in items], {i["project"] for i in items}, vspt_cases())
    return not (p or h), f"{len(p)} shared projects {p[:3]}; {h} shared hashes with VSP-T"


def check_rebuild(a):
    need(a.dev3), need(a.pilot), need(a.builder)
    if a.no_rebuild:
        return True, "skipped (--no-rebuild)"
    before = (sha(a.dev3), sha(a.pilot))
    proc = subprocess.run([sys.executable, str(a.builder)], cwd=ROOT, capture_output=True, text=True)
    after = (sha(a.dev3), sha(a.pilot))
    return proc.returncode == 0 and before == after, (f"builder exit {proc.returncode}; dev3 {before[0][:8]}->{after[0][:8]}; "
                                                      f"pilot {before[1][:8]}->{after[1][:8]}; {proc.stderr.strip()[-150:]}")


CHECKS = [("FILES", check_files), ("REF_SHAS", check_ref_shas), ("FOLD_RULE", check_fold_rule),
          ("FOLD_CASES", check_fold_cases), ("NO_OVERLAP_REFS", check_no_overlap_refs), ("PILOT_RULE", check_pilot_rule),
          ("PILOT_ADJACENT_TARGETS", check_pilot_adjacent_targets), ("PILOT_VS_DEV3", check_pilot_vs_dev3),
          ("PILOT_VS_VSPT", check_pilot_vs_vspt), ("REBUILD", check_rebuild)]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev3", default=str(ROOT / "results/vsp_dev3_cases.json"))
    ap.add_argument("--pilot", default=str(ROOT / "results/vsp_pilot_k4b_d3_items.json"))
    ap.add_argument("--builder", default=str(ROOT / "scripts/imp_build_vsp_dev3.py"))
    ap.add_argument("--no-rebuild", action="store_true", help="checker self-test only")
    ap.add_argument("--skip-checks", default="", help="mutant self-test only")
    a = ap.parse_args(argv)
    skip = {x for x in a.skip_checks.split(",") if x}
    failed = 0
    for name, fn in CHECKS:
        if name in skip:
            print(f"SKIP {name}")
            continue
        try:
            ok, detail = fn(a)
        except Exception as exc:  # noqa: BLE001  a missing or malformed file is a FAIL, never a crash
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        print(("PASS " if ok else "FAIL ") + name + " - " + detail, flush=True)
        failed += 0 if ok else 1
    print("RESULT: " + ("FAIL" if failed else "PASS") + f" ({failed} failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
