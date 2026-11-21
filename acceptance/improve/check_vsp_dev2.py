"""Acceptance checker for the cycle-2 dev split results/vsp_dev2_cases.json (spec C1).

Usage:
  .venv/bin/python acceptance/improve/check_vsp_dev2.py [--dev2 F] [--k4-pilot F] [--k4b-pilot F]
      [--skip-checks NAME,NAME]

--k4b-pilot "" skips the K4b file (it is checked when it exists). --skip-checks exists for the mutant self-test.
Prints one PASS/FAIL line per named check; exit 0 only if every check passed.

The rule is recomputed here (k4_common.expected_dev2), independently of any builder:
  core        every non-linux round-1 project that is not a cycle-1 dev project and holds >= 1 stratum-B pair,
              all its round-1 pairs, code byte-identical to round 1.
  supplement  VulSpot test-split pairs of projects in none of VSP-T, round 1, cycle-1 dev, FORK_PROJECTS, passing every
              round-1 filter and the identifier-normalised rule; code = comment-stripped parquet text;
              each supplement case must carry its parquet label_confidence in a label_confidence field.
Floors: >= 105 stratum-B pairs and >= 350 pairs. Salt: the file top-level "salt" must be vspdev-v2| (the split is
ordering / reporting only: the project set does not depend on it). Pilot files (K4a, K4b) must share no project
with dev2 and hold no pair with a side whose raw or identifier-normalised Jaccard to a dev2 function is >= 0.5.
Final files fold dev2 back by design and are therefore not checked here (check_vsp_k4_items.py does).
Ambiguity resolved: "any K4 training file" in the spec means the pilot files; finals contain dev2 core on purpose.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

import k4_common as k4
from k4_common import cd, ci

MIN_B, MIN_PAIRS = 105, 350


def dev2_cases(st):
    k4.need(st, "dev2")
    return k4.cases(st, "dev2")


def dev2_pm(st):
    return cd.pair_map(dev2_cases(st))


def check_files(st):
    missing = [n for n in ("dev2", "k4_pilot") if not k4.present(st, n)]
    return not missing, ("dev2 and K4 pilot files present" if not missing else
                         "target not built yet: " + ", ".join(st.paths[n] for n in missing))


def check_schema(st):
    cs = dev2_cases(st)
    tkeys = set(st.tcases[0]) | set(k4.EXTRA_CASE_KEYS)
    bad = k4.case_schema_problems(cs)
    extra = [c.get("id") for c in cs if not set(c) <= tkeys]
    ids = Counter(c.get("id") for c in cs)
    dup = [i for i, n in ids.items() if n > 1]
    pm = dev2_pm(st)
    odd = [k for k, p in pm.items() if not (p["V"] and p["S"])]
    ok = not bad and not extra and not dup and not odd and len(cs) == 2 * len(pm)
    return ok, (f"{len(cs)} cases / {len(pm)} pairs; missing keys {bad[:2]}; unknown keys on {extra[:2]}; "
                f"duplicate ids {dup[:2]}; pairs without both sides {odd[:3]}")


def check_salt(st):
    import json
    top = json.load(open(st.paths["dev2"], encoding="utf-8"))
    salt = top.get("salt")
    return salt == k4.DEV2_SALT, f"top-level salt {salt!r}, expected {k4.DEV2_SALT!r}"


def check_core_rule(st):
    exp = k4.expected_dev2(st)
    r1_proj = k4.r1_projects(st)
    pm = dev2_pm(st)
    got = {k for k, p in pm.items() if cd.pair_project(p) in r1_proj}
    r1_by_key = {(it["pair"], it["label"]): it for it in st.r1}
    altered = [c["id"] for c in dev2_cases(st) if c["project"] in r1_proj and (c["pair"], c["label"]) in r1_by_key
               and r1_by_key[(c["pair"], c["label"])]["code"] != c["code"]]
    ok = got == exp["core"] and not altered
    return ok, (f"core: {len(got)} pairs in file, rule gives {len(exp['core'])} in {len(exp['core_projects'])} "
                f"projects; missing {sorted(exp['core'] - got)[:3]} unexpected {sorted(got - exp['core'])[:3]}; "
                f"codes altered {altered[:3]}")


def check_supplement_rule(st):
    exp = k4.expected_dev2(st)["supp"]
    r1_proj = k4.r1_projects(st)
    cs = [c for c in dev2_cases(st) if c["project"] not in r1_proj]
    pm = cd.pair_map(cs)
    got = set(pm)
    bad = []
    for k in got & set(exp):
        e = exp[k]
        for side, code in (("V", e["vc"]), ("S", e["sc"])):
            c = pm[k][side]
            if c is None or c["code"] != code:
                bad.append(f"{k}:{side} code")
            elif c.get("label_confidence") != e["conf"]:
                bad.append(f"{k}:{side} label_confidence {c.get('label_confidence')!r} != {e['conf']!r}")
    ok = got == set(exp) and not bad
    return ok, (f"supplement: {len(got)} pairs in file, rule gives {len(exp)}; missing {sorted(set(exp) - got)[:3]} "
                f"unexpected {sorted(got - set(exp))[:3]}; field problems {bad[:3]}")


def check_no_linux(st):
    n = sorted({c["pair"] for c in dev2_cases(st) if c["project"] == k4.LINUX})
    return not n, f"{len(n)} linux pairs {n[:3]}"


def check_not_cycle1(st):
    dev1 = {c["project"] for c in st.dev}
    both = sorted({c["project"] for c in dev2_cases(st)} & dev1)
    pairs = sorted({c["pair"] for c in dev2_cases(st)} & {c["pair"] for c in st.dev})
    return not both and not pairs, f"{len(both)} shared projects {both[:3]}; {len(pairs)} shared pair ids {pairs[:3]}"


def check_not_vspt(st):
    cs = dev2_cases(st)
    tp = {c["project"] for c in st.tcases}
    hashes = {cd.norm_hash(c["code"]) for c in st.tcases}
    over = sorted({c["project"] for c in cs} & tp)
    dup = sum(1 for c in cs if cd.norm_hash(c["code"]) in hashes)
    ref = k4.vspt_ref(st)
    near = sorted({c["pair"] for c in cs if ref.score(c["code"]) >= ci.JACCARD_MAX})
    ok = not over and not dup and not near
    return ok, (f"VSP-T projects in dev2 {over[:3]}; VSP-T hash matches {dup}; pairs with raw or normalised Jaccard "
                f">= {ci.JACCARD_MAX} to VSP-T {near[:3]}")


def check_no_fork(st):
    f = sorted({c["project"] for c in dev2_cases(st)} & set(ci.FORK_PROJECTS))
    return not f, f"fork projects in dev2 {f}"


def check_b_floor(st):
    s = Counter(k4.strata(dev2_cases(st)).values())
    return s["B"] >= MIN_B, f"stratum B {s['B']} (need >= {MIN_B}); strata {dict(s)}"


def check_pair_floor(st):
    s = Counter(k4.strata(dev2_cases(st)).values())
    n = sum(s.values())
    return n >= MIN_PAIRS, f"{n} pairs (need >= {MIN_PAIRS}); strata {dict(s)}"


def pilot_names(st):
    return [n for n in ("k4_pilot", "k4b_pilot") if k4.present(st, n)]


def check_pilot_no_project(st):
    dev2 = {c["project"] for c in dev2_cases(st)}
    msgs, ok = [], True
    for n in pilot_names(st):
        both = sorted(k4.projects_of(k4.items(st, n)) & dev2)
        ok &= not both
        msgs.append(f"{n}: {len(both)} dev2 projects {both[:3]}")
    return ok and bool(msgs), "; ".join(msgs) or "no pilot file present"


def check_pilot_no_neardup(st):
    ref = k4.ref_of(st, "dev2", "dev2", "cases")
    msgs, ok = [], True
    for n in pilot_names(st):
        hits = k4.near_pairs(ref, cd.pair_map(k4.items(st, n)))
        ok &= not hits
        msgs.append(f"{n}: {len(hits)} pairs with a side at Jaccard >= {ci.JACCARD_MAX} (raw or normalised) "
                    f"to a dev2 function {hits[:3]}")
    return ok and bool(msgs), "; ".join(msgs) or "no pilot file present"


CHECKS = [
    ("FILES", check_files),
    ("DEV2_SCHEMA", check_schema),
    ("SALT", check_salt),
    ("DEV2_CORE_RULE", check_core_rule),
    ("DEV2_SUPPLEMENT_RULE", check_supplement_rule),
    ("DEV2_NO_LINUX", check_no_linux),
    ("DEV2_NOT_CYCLE1", check_not_cycle1),
    ("DEV2_NOT_VSPT", check_not_vspt),
    ("DEV2_NO_FORK", check_no_fork),
    ("B_FLOOR", check_b_floor),
    ("PAIR_FLOOR", check_pair_floor),
    ("PILOT_NO_DEV2_PROJECT", check_pilot_no_project),
    ("PILOT_NO_DEV2_NEARDUP", check_pilot_no_neardup),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dev2")
    ap.add_argument("--k4-pilot")
    ap.add_argument("--k4b-pilot")
    ap.add_argument("--skip-checks", default="", help="mutant self-test only")
    a = ap.parse_args(argv)
    skip = {x for x in a.skip_checks.split(",") if x}
    unknown = skip - {n for n, _ in CHECKS}
    if unknown:
        ap.error(f"unknown check names {sorted(unknown)}")
    st = k4.make_state({"dev2": a.dev2, "k4_pilot": a.k4_pilot, "k4b_pilot": a.k4b_pilot})
    return k4.run_checks(CHECKS, st, skip)


if __name__ == "__main__":
    sys.exit(main())
