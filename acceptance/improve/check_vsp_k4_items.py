"""Acceptance checker for the K4 pilot and final training item files (spec C3).

Usage:
  .venv/bin/python acceptance/improve/check_vsp_k4_items.py PILOT.json FINAL.json [--dev2 F] [--probe F]
      [--skip-checks NAME,NAME]

PILOT.json = results/vsp_pilot_k4_items.json, FINAL.json = results/vsp_sft_k4_items.json. Prints one PASS/FAIL line
per named check; exit 0 only if every check passed. Everything is recomputed here (k4_common) and reuses
check_vsp_dev / check_vsp_items by import.

Rules:
  NEAR_*        no pair has a side whose raw or identifier-normalised token-set Jaccard is >= 0.5 to a function of
                VSP-T, the linux probe, or dev2. The final file holds the dev2 core pairs on purpose (finals fold dev2
                back), so the final is checked against the dev2 SUPPLEMENT only; the pilot against all of dev2.
  HELDOUT       no probe pair id or src_idx in either file; no dev2 pair in the pilot; no dev2 supplement pair in the
                final. FINAL_HAS_DEV2_CORE: every dev2 core pair is in the final, items identical to round 1.
  NO_ACPICA     no K4 extra (pair beyond round 1) is a vendored ACPICA core function (VENDORED_RE on func_name).
  LINUX_AB_EQUAL  linux stratum-A pair count equals stratum-B pair count in each file.
  COUNTS        linux A and B each in [295, 320] (spec 308); pilot non-linux B in [40, 50] (spec 45; a few may be
                dropped as dev2 near-duplicates); final non-linux B equals the round-1 count.
  PILOT_R1_RULE the round-1 part of the pilot is exactly the round-1 pairs whose project is not a dev2 project and
                that are not near (raw or normalised) any dev2 or probe function: cycle-1 dev is folded back, dev2
                removed. PILOT_NO_DEV2_PROJECT repeats the project test on its own.
  EXTRAS_*      each pair beyond round 1 is a linux VulSpot train-split pair, high label confidence, comment-stripped
                parquet text, vulnerable row with its fixed twin, strata A or B, < 4000 chars; the final holds
                exactly the pilot extras (same items).
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

import k4_common as k4
from k4_common import cd, ci

LINUX_RANGE = (295, 320)
NONLINUX_B_PILOT = (40, 50)


def both(st):
    k4.need(st, "k4_pilot", "k4_final")
    return {"pilot": k4.items(st, "k4_pilot"), "final": k4.items(st, "k4_final")}


def r1_pm(st):
    return st.cached("r1pm", lambda: cd.pair_map(st.r1))


def dev2_split(st):
    """(all dev2 pair ids, core pair ids, supplement pair ids)."""
    k4.need(st, "dev2")
    r1p = k4.r1_projects(st)
    pm = cd.pair_map(k4.cases(st, "dev2"))
    core = {k for k, p in pm.items() if p["V"]["project"] in r1p}
    return set(pm), core, set(pm) - core


def extras_of(st, items):
    r1 = set(r1_pm(st))
    return {k for k in cd.pair_map(items) if k not in r1}


def check_files(st):
    missing = [st.paths[n] for n in ("k4_pilot", "k4_final", "dev2", "probe") if not k4.present(st, n)]
    return not missing, "all four inputs present" if not missing else "target not built yet: " + ", ".join(missing)


def check_schema(st):
    d, msgs, ok = both(st), [], True
    r1_by_id = {it["id"]: it for it in st.r1}
    for name, items in d.items():
        adj = cd.adjacency_problems(items)
        miss = [it.get("id") for it in items if not all(k in it for k in cd.ITEM_FIELDS)]
        dup = [i for i, n in Counter(it["id"] for it in items).items() if n > 1]
        diffs = cd.item_diffs(items, r1_by_id)
        ok &= not (adj or miss or dup or diffs)
        msgs.append(f"{name}: {len(items) // 2} pairs; adjacency {adj[:2]}; missing fields {len(miss)}; "
                    f"duplicate ids {dup[:2]}; round-1 items altered {diffs[:2]}")
    return ok, "; ".join(msgs)


def near_check(st, which, name):
    d = both(st)
    refs = {"vspt": k4.vspt_ref(st), "probe": k4.ref_of(st, "probe", "probe", "cases")}
    msgs, ok = [], True
    for fname, items in d.items():
        hits = k4.near_pairs(refs[which], cd.pair_map(items))
        ok &= not hits
        msgs.append(f"{fname}: {len(hits)} pairs near {name} (Jaccard >= {ci.JACCARD_MAX}, raw or normalised) {hits[:3]}")
    return ok, "; ".join(msgs)


def check_near_vspt(st):
    return near_check(st, "vspt", "VSP-T")


def check_near_probe(st):
    k4.need(st, "probe")
    return near_check(st, "probe", "the linux probe set")


def check_near_dev2(st):
    d = both(st)
    all_ids, core, supp = dev2_split(st)
    cs = k4.cases(st, "dev2")
    ref_all = k4.ref_of(st, "dev2", "dev2", "cases")
    ref_supp = st.cached(("ref", "dev2supp"), lambda: k4.RefSet([c["code"] for c in cs if c["pair"] in supp]))
    hp = k4.near_pairs(ref_all, cd.pair_map(d["pilot"]))
    hf = k4.near_pairs(ref_supp, cd.pair_map(d["final"])) if supp else []
    return not hp and not hf, (f"pilot: {len(hp)} pairs near dev2 {hp[:3]}; final: {len(hf)} pairs near the dev2 "
                               f"supplement {hf[:3]} (final may hold the dev2 core)")


def check_heldout(st):
    d = both(st)
    all_ids, core, supp = dev2_split(st)
    pm_probe = cd.pair_map(k4.cases(st, "probe"))
    probe = set(pm_probe)
    out, ok = [], True
    for name, items in d.items():
        ids = {it["pair"] for it in items}
        srcs = {str(it["src_idx"]) for it in items}
        bad_probe = sorted(probe & (ids | srcs))
        bad_dev2 = sorted((all_ids if name == "pilot" else supp) & ids)
        ok &= not bad_probe and not bad_dev2
        out.append(f"{name}: probe pairs in training {len(bad_probe)} {bad_probe[:3]}; "
                   f"dev2 pairs that must be absent but present {len(bad_dev2)} {bad_dev2[:3]}")
    return ok, "; ".join(out)


def check_pilot_no_dev2_project(st):
    d = both(st)
    dev2_proj = k4.projects_of(k4.cases(st, "dev2"))
    over = sorted(k4.projects_of(d["pilot"]) & dev2_proj)
    return not over, f"{len(over)} dev2 projects in the pilot {over[:4]}"


def check_final_has_core(st):
    d = both(st)
    all_ids, core, supp = dev2_split(st)
    have = {it["id"]: it for it in d["final"]}
    r1_by_id = {it["id"]: it for it in st.r1}
    miss = [it["id"] for it in st.r1 if it["pair"] in core and it["id"] not in have]
    alt = [i for i in have if i in r1_by_id and not cd.same_item(have[i], r1_by_id[i]) and r1_by_id[i]["pair"] in core]
    return not miss and not alt and bool(core), (f"{len(core)} dev2 core pairs; {len(miss)} items missing from the "
                                                  f"final {miss[:3]}; {len(alt)} altered {alt[:3]}")


def check_no_fork(st):
    over = {n: sorted(k4.projects_of(i) & set(ci.FORK_PROJECTS)) for n, i in both(st).items()}
    return not any(over.values()), f"fork projects: {over}"


def check_no_acpica(st):
    d, df, bad = both(st), st.table, []
    for name, items in d.items():
        pm = cd.pair_map(items)
        for pair in sorted(extras_of(st, items)):
            v = pm[pair]["V"]
            fn = str(df.loc[v["src_idx"]]["func_name"]) if v and v["src_idx"] in df.index else ""
            if cd.VENDORED_RE.match(fn):
                bad.append(f"{name}:{pair}:{fn}")
    return not bad, f"{len(bad)} vendored-ACPICA extras {bad[:4]}"


def linux_counts(items):
    c = Counter(s for k, s in k4.strata(items).items() if cd.pair_project(cd.pair_map(items)[k]) == k4.LINUX)
    return c["A"], c["B"]


def check_linux_equal(st):
    out, ok = [], True
    for name, items in both(st).items():
        a, b = linux_counts(items)
        ok &= a == b
        out.append(f"{name}: linux A {a} B {b}")
    return ok, "; ".join(out)


def check_counts(st):
    d = both(st)
    out, ok = [], True
    for name, items in d.items():
        a, b = linux_counts(items)
        good = LINUX_RANGE[0] <= a <= LINUX_RANGE[1] and LINUX_RANGE[0] <= b <= LINUX_RANGE[1]
        ok &= good
        out.append(f"{name} linux A {a} B {b} (range {LINUX_RANGE})")
    nb = {n: sum(1 for k, s in k4.strata(i).items() if s == "B" and cd.pair_project(cd.pair_map(i)[k]) != k4.LINUX)
          for n, i in d.items()}
    r1_nb = sum(1 for k, s in k4.strata(st.r1).items() if s == "B" and cd.pair_project(r1_pm(st)[k]) != k4.LINUX)
    ok &= NONLINUX_B_PILOT[0] <= nb["pilot"] <= NONLINUX_B_PILOT[1] and nb["final"] == r1_nb
    out.append(f"non-linux B pilot {nb['pilot']} (range {NONLINUX_B_PILOT}), final {nb['final']} (round 1 has {r1_nb})")
    return ok, "; ".join(out)


def check_pilot_r1_rule(st):
    d = both(st)
    dev2_proj = k4.projects_of(k4.cases(st, "dev2"))
    ref2 = k4.ref_of(st, "dev2", "dev2", "cases")
    refp = k4.ref_of(st, "probe", "probe", "cases")
    r1p = r1_pm(st)
    want = {k for k, p in r1p.items() if cd.pair_project(p) not in dev2_proj
            and ref2.pair_score(p) < ci.JACCARD_MAX and refp.pair_score(p) < ci.JACCARD_MAX}
    got = set(cd.pair_map(d["pilot"])) & set(r1p)
    dev1 = {c["project"] for c in st.dev}
    fold = {k for k in want if cd.pair_project(r1p[k]) in dev1}
    fold_got = {k for k in got if cd.pair_project(r1p[k]) in dev1}
    return want == got, (f"round-1 pairs in the pilot {len(got)}, rule gives {len(want)}; missing "
                         f"{sorted(want - got)[:3]} unexpected {sorted(got - want)[:3]}; cycle-1 dev folded back "
                         f"{len(fold_got)} of {len(fold)}")


def extra_problems(st, pair, pm):
    df, train = st.table, st.train_split
    p = pm[pair]
    out = []
    if not (p["V"] and p["S"]):
        return [f"{pair}: missing side"]
    if p["V"]["project"] != k4.LINUX or p["S"]["project"] != k4.LINUX:
        out.append(f"{pair}: project {p['V']['project']}")
    vi, si = p["V"]["src_idx"], p["S"]["src_idx"]
    if str(vi) != pair or vi not in df.index or si not in df.index:
        return out + [f"{pair}: src_idx is not a parquet row"]
    v, s = df.loc[vi], df.loc[si]
    vc, sc = p["V"]["code"], p["S"]["code"]
    if vi not in train or si not in train:
        out.append(f"{pair}: not both rows in the train split")
    if v["label_confidence"] != "high":
        out.append(f"{pair}: label_confidence {v['label_confidence']}")
    if not v["is_vulnerable"] or s["is_vulnerable"] or v["fixed_func_idx"] != si:
        out.append(f"{pair}: not a vulnerable row with its fixed twin")
    if cd.strip_comments(v["func_body"]) != vc or cd.strip_comments(s["func_body"]) != sc:
        out.append(f"{pair}: code is not comment-stripped parquet text")
    if len(vc) == len(sc) or not vc.strip() or not sc.strip() or max(len(vc), len(sc)) >= cd.MAX_CHARS:
        out.append(f"{pair}: equal, empty or over-long code")
    return out


def check_extras_props(st):
    d = both(st)
    problems, n = [], 0
    for name, items in d.items():
        pm = cd.pair_map(items)
        ex = sorted(extras_of(st, items))
        n += len(ex)
        for pair in ex:
            problems += [f"{name} {m}" for m in extra_problems(st, pair, pm)]
    return not problems, f"{n} extras checked, {len(problems)} problems: {problems[:4]}"


def check_final_matches_pilot(st):
    d = both(st)
    pp, fp = cd.pair_map(d["pilot"]), cd.pair_map(d["final"])
    ep, ef = extras_of(st, d["pilot"]), extras_of(st, d["final"])
    same = all(cd.same_item(pp[k][s], fp[k][s]) for k in ep & ef for s in "VS")
    sub = set(pp) <= set(fp)
    return ep == ef and same and sub, (f"pilot extras {len(ep)}, final extras {len(ef)}, identical sets {ep == ef}, "
                                       f"identical items {same}; every pilot pair is in the final: {sub}")


CHECKS = [
    ("FILES", check_files),
    ("ITEMS_SCHEMA", check_schema),
    ("NEAR_VSPT", check_near_vspt),
    ("NEAR_DEV2", check_near_dev2),
    ("NEAR_PROBE", check_near_probe),
    ("HELDOUT_NOT_TRAIN", check_heldout),
    ("PILOT_NO_DEV2_PROJECT", check_pilot_no_dev2_project),
    ("PILOT_R1_RULE", check_pilot_r1_rule),
    ("FINAL_HAS_DEV2_CORE", check_final_has_core),
    ("NO_FORK", check_no_fork),
    ("NO_ACPICA", check_no_acpica),
    ("LINUX_AB_EQUAL", check_linux_equal),
    ("COUNTS", check_counts),
    ("EXTRAS_PROPS", check_extras_props),
    ("FINAL_MATCHES_PILOT", check_final_matches_pilot),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("pilot")
    ap.add_argument("final")
    ap.add_argument("--dev2")
    ap.add_argument("--probe")
    ap.add_argument("--skip-checks", default="", help="mutant self-test only")
    a = ap.parse_args(argv)
    skip = {x for x in a.skip_checks.split(",") if x}
    unknown = skip - {n for n, _ in CHECKS}
    if unknown:
        ap.error(f"unknown check names {sorted(unknown)}")
    st = k4.make_state({"k4_pilot": a.pilot, "k4_final": a.final, "dev2": a.dev2, "probe": a.probe})
    return k4.run_checks(CHECKS, st, skip)


if __name__ == "__main__":
    sys.exit(main())
