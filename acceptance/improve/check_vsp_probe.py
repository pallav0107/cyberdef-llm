"""Acceptance checker for the linux held-out set results/vsp_probe_cases.json (spec C6; also probe P1).

Usage:
  .venv/bin/python acceptance/improve/check_vsp_probe.py [--probe F] [--dev2 F] [--k4-pilot F] [--k4-final F]
      [--k4b-pilot F] [--skip-checks NAME,NAME]

Prints one PASS/FAIL line per named check; exit 0 only if every check passed. Recomputed independently here
(k4_common.probe_pool), reusing check_vsp_dev / check_vsp_items by import.

Rules:
  PROBE_COUNTS      exactly 150 stratum-A and 150 stratum-B pairs, none equal-length, every project linux.
  PROBE_VAL_SPLIT   both rows of every pair are in the VulSpot val split (project_holdout.json), the vulnerable row has
                    its fixed twin, label_confidence high, code = comment-stripped parquet text.
  PROBE_ELIGIBLE    every pair passes the round-1 filters (non-empty, differing, < 4000 chars, no VSP-T hash, raw
                    Jaccard < 0.5 to VSP-T) and the normalised VSP-T rule, is not a vendored ACPICA function, and is
                    not a round-1 pair.
  PROBE_NOT_IN_FILES  no probe pair id or row index in VSP-T, cycle-1 dev, dev2, round 1, the K1 / K2 / K4 item files.
  PROBE_NEAR        every probe function has raw and identifier-normalised Jaccard < 0.5 to every function of VSP-T,
                    cycle-1 dev, dev2 and every training item file (round 1, K1, K2 pilot / final, K4 pilot / final,
                    K4b pilot when present).
  PROBE_SELECTION   the file equals the first 150 A and first 150 B of the leak-clean eligible pool in sha256 order of
                    (vspprobe-v1 + pair id). The spec writes no separator; a "|" separator is accepted too
                    (ambiguity resolved the way check_vsp_dev resolved its sort-key ambiguity).
Missing inputs are FAIL (target not built yet), never a traceback.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

import k4_common as k4
from k4_common import cd, ci

TRAIN_FILES = (("r1", "round1"), ("k1", "k1"), ("k2_pilot", "k2_pilot"), ("k2_final", "k2_final"),
               ("k4_pilot", "k4_pilot"), ("k4_final", "k4_final"), ("k4b_pilot", "k4b_pilot"))
REQUIRED = ("probe", "dev2", "k4_pilot", "k4_final", "k1", "k2_pilot", "k2_final", "round1")


def probe_cases(st):
    k4.need(st, "probe")
    return k4.cases(st, "probe")


def train_item_lists(st):
    """(name, items) for every training file that exists; the K4b pilot only if present."""
    out = []
    for name, key in TRAIN_FILES:
        if k4.present(st, key):
            out.append((name, k4.items(st, key)))
    return out


def refs(st):
    def go():
        train = [i["code"] for _, items in train_item_lists(st) for i in items]
        return {"VSP-T": k4.vspt_ref(st), "cycle-1 dev": k4.RefSet([c["code"] for c in st.dev]),
                "dev2": k4.RefSet([c["code"] for c in k4.cases(st, "dev2")]), "training": k4.RefSet(train)}
    return st.cached("probe_refs", go)


def check_files(st):
    missing = [st.paths[n] for n in REQUIRED if not k4.present(st, n)]
    return not missing, "all inputs present" if not missing else "target not built yet: " + ", ".join(missing)


def check_schema(st):
    cs = probe_cases(st)
    bad = k4.case_schema_problems(cs)
    tkeys = set(st.tcases[0]) | set(k4.EXTRA_CASE_KEYS)
    extra = [c.get("id") for c in cs if not set(c) <= tkeys]
    pm = cd.pair_map(cs)
    odd = [k for k, p in pm.items() if not (p["V"] and p["S"])]
    dup = [i for i, n in Counter(c["id"] for c in cs).items() if n > 1]
    ok = not bad and not extra and not odd and not dup and len(cs) == 2 * len(pm)
    return ok, (f"{len(cs)} cases / {len(pm)} pairs; missing keys {bad[:2]}; unknown keys {extra[:2]}; "
                f"incomplete pairs {odd[:3]}; duplicate ids {dup[:2]}")


def check_counts(st):
    cs = probe_cases(st)
    s = Counter(k4.strata(cs).values())
    non_linux = sorted({c["project"] for c in cs} - {k4.LINUX})
    ok = s["A"] == k4.PROBE_N and s["B"] == k4.PROBE_N and not s["E"] and not non_linux
    return ok, f"strata {dict(s)} (need A {k4.PROBE_N}, B {k4.PROBE_N}, E 0); non-linux projects {non_linux}"


def check_val_split(st):
    cs = probe_cases(st)
    df, val = st.table, k4.split_set(st, "val")
    bad = []
    for pair, p in cd.pair_map(cs).items():
        vi = int(pair)
        if vi not in df.index:
            bad.append(f"{pair}: not a parquet row")
            continue
        v = df.loc[vi]
        fx = v["fixed_func_idx"]
        fx = None if fx != fx else int(fx)
        if vi not in val or fx is None or fx not in val:
            bad.append(f"{pair}: not both rows in the val split")
        elif v["project"] != k4.LINUX or not v["is_vulnerable"] or v["label_confidence"] != "high":
            bad.append(f"{pair}: project/vulnerable/confidence {v['project']}/{v['is_vulnerable']}/{v['label_confidence']}")
        elif fx not in df.index or cd.strip_comments(v["func_body"]) != p["V"]["code"] \
                or cd.strip_comments(df.loc[fx]["func_body"]) != p["S"]["code"]:
            bad.append(f"{pair}: code differs from the stripped parquet text")
    conf = sorted({c["label_confidence"] for c in cs if "label_confidence" in c} - {"high"})
    return not bad and not conf, f"{len(bad)} pairs failing {bad[:3]}; non-high label_confidence fields {conf}"


def check_eligible(st):
    cs = probe_cases(st)
    pool = k4.probe_pool(st)
    strata = k4.strata(cs)
    bad = [f"{k}: not in the eligible pool" if k not in pool else f"{k}: stratum {s} != {pool[k]['stratum']}"
           for k, s in strata.items() if k not in pool or pool[k]["stratum"] != s]
    return not bad, f"pool {len(pool)} pairs ({dict(Counter(p['stratum'] for p in pool.values()))}); {len(bad)} bad {bad[:3]}"


def held_ids(st):
    """Pair ids and row indices that make a pair a training / benchmark pair."""
    ids = {c["pair"] for c in st.tcases} | {c["pair"] for c in st.dev}
    if k4.present(st, "dev2"):
        ids |= {c["pair"] for c in k4.cases(st, "dev2")}
    for _, items in train_item_lists(st):
        ids |= {i["pair"] for i in items} | {str(i["src_idx"]) for i in items}
    return ids


def check_not_in_files(st):
    cs = probe_cases(st)
    held = held_ids(st)
    pool = k4.probe_pool(st)
    hit = []
    for pair in cd.pair_map(cs):
        fx = str(pool[pair]["fx"]) if pair in pool else ""
        if pair in held or fx in held:
            hit.append(pair)
    return not hit, f"{len(hit)} probe pairs also in VSP-T, dev, dev2 or a training file {hit[:4]}"


def check_near(st):
    cs = probe_cases(st)
    pm = cd.pair_map(cs)
    msgs, ok = [], True
    for name, ref in refs(st).items():
        hits = k4.near_pairs(ref, pm)
        ok &= not hits
        msgs.append(f"{name} ({ref.n} functions): {len(hits)} probe pairs at Jaccard >= {ci.JACCARD_MAX} {hits[:3]}")
    return ok, "; ".join(msgs)


def select(st, salt):
    """First PROBE_N A and B pairs of the leak-clean eligible pool in sha256 order of salt + pair id."""
    pool = k4.probe_pool(st)
    held = held_ids(st)
    rs = refs(st)
    sel = {"A": [], "B": []}
    for pair in k4.sha_order(salt, pool):
        p = pool[pair]
        if len(sel[p["stratum"]]) >= k4.PROBE_N or pair in held or str(p["fx"]) in held:
            continue
        if any(max(r.score(p["vc"]), r.score(p["sc"])) >= ci.JACCARD_MAX for r in rs.values()):
            continue
        sel[p["stratum"]].append(pair)
    return sel


def check_selection(st):
    got = set(cd.pair_map(probe_cases(st)))
    notes = []
    for salt in (k4.PROBE_SALT, k4.PROBE_SALT + "|"):
        sel = select(st, salt)
        want = set(sel["A"]) | set(sel["B"])
        if want == got:
            return True, f"file equals the first {k4.PROBE_N} A and B of the clean pool under salt {salt!r}"
        notes.append(f"salt {salt!r}: pool gives A {len(sel['A'])} B {len(sel['B'])}, {len(want - got)} missing, "
                     f"{len(got - want)} unexpected")
    return False, "; ".join(notes)


CHECKS = [
    ("FILES", check_files),
    ("PROBE_SCHEMA", check_schema),
    ("PROBE_COUNTS", check_counts),
    ("PROBE_VAL_SPLIT", check_val_split),
    ("PROBE_ELIGIBLE", check_eligible),
    ("PROBE_NOT_IN_FILES", check_not_in_files),
    ("PROBE_NEAR", check_near),
    ("PROBE_SELECTION", check_selection),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for opt in ("probe", "dev2", "k4-pilot", "k4-final", "k4b-pilot"):
        ap.add_argument("--" + opt)
    ap.add_argument("--skip-checks", default="", help="mutant self-test only")
    a = ap.parse_args(argv)
    skip = {x for x in a.skip_checks.split(",") if x}
    unknown = skip - {n for n, _ in CHECKS}
    if unknown:
        ap.error(f"unknown check names {sorted(unknown)}")
    st = k4.make_state({"probe": a.probe, "dev2": a.dev2, "k4_pilot": a.k4_pilot, "k4_final": a.k4_final,
                        "k4b_pilot": a.k4b_pilot})
    return k4.run_checks(CHECKS, st, skip)


if __name__ == "__main__":
    sys.exit(main())
