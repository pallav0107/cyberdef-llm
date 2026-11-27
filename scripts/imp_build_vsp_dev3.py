#!/usr/bin/env python3
"""Build the attempt-6 confirmation fold (dev3) and its matching d3 pilot item file. No arguments; deterministic.

Reads results/vsp_sft_k4b_items.json (final K4b items) and results/vsp_dev2_cases.json (to exclude dev2 projects).
Never reads any VSP-T result; results/vsp_t_cases.json is not read at all (the fold is a subset of the final file,
which is already leak-filtered against it).

Fold rule (CURRENT_PLAN.md section 3, stage 2): projects of the final file that are not "linux" and not a dev2
project, ordered by sha256("vspdev3-v1|" + project) hex ascending; whole projects are taken until the pair count is
>= 400.

Writes (byte-identical on every rebuild):
  results/vsp_dev3_cases.json            the fold, in the dev-case schema (ids vspdev3:<pair>:<V|S>)
  results/vsp_pilot_k4b_d3_items.json    final items minus every dev3 project minus every pair with a side at raw or
                                         identifier-normalised token-set Jaccard >= 0.5 to a dev3 function; item
                                         dicts and order are those of the final file (K4b two-line targets kept)
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import imp_build_vsp_k4 as bk

ROOT = bk.ROOT
SALT = "vspdev3-v1|"
MIN_PAIRS = 400
FINAL = ROOT / "results/vsp_sft_k4b_items.json"
DEV2 = ROOT / "results/vsp_dev2_cases.json"
OUT_CASES = ROOT / "results/vsp_dev3_cases.json"
OUT_PILOT = ROOT / "results/vsp_pilot_k4b_d3_items.json"
NOTE_CASES = ("VSP-DEV3 (attempt 6 confirmation fold): whole non-linux, non-dev2 projects of the K4b final file in "
              "sha256('vspdev3-v1|' + project) order until >= 400 pairs; scored only for the stage-1 winner trained on "
              "the d3 pilot file; build rules in scripts/imp_build_vsp_dev3.py")
NOTE_PILOT = ("K4b final items minus every dev3 project and minus pairs at Jaccard >= 0.5 to a dev3 function; "
              "built by scripts/imp_build_vsp_dev3.py")


def main():
    items = json.load(open(FINAL, encoding="utf-8"))["items"]
    dev2_projects = {c["project"] for c in json.load(open(DEV2, encoding="utf-8"))["cases"]}
    pm = bk.pair_map(items)
    by_proj = defaultdict(list)
    for pair, p in pm.items():
        by_proj[p["V"]["project"]].append(pair)
    cand = sorted((p for p in by_proj if p != bk.LINUX and p not in dev2_projects),
                  key=lambda p: hashlib.sha256((SALT + p).encode()).hexdigest())
    chosen, n = [], 0
    for proj in cand:
        if n >= MIN_PAIRS:
            break
        chosen.append(proj)
        n += len(by_proj[proj])
    chosen_set = set(chosen)
    pairs = {k for p in chosen for k in by_proj[p]}

    cases = []
    for proj in chosen:
        for pair in sorted(by_proj[proj], key=int):
            for side in ("V", "S"):
                it = pm[pair][side]
                cases.append(bk.case_of("vspdev3", it, it["code"], it["label"], pair, proj, it["cwe"], "final_k4b"))
    cpm = bk.pair_map(cases)
    st = Counter(bk.stratum(p["V"]["code"], p["S"]["code"]) for p in cpm.values())

    ref = bk.Ref([c["code"] for c in cases])
    rest = {k: p for k, p in pm.items() if p["V"]["project"] not in chosen_set}
    near = {k for k, p in rest.items() if ref.pair_near(p["V"]["code"], p["S"]["code"])}
    keep = set(rest) - near
    pilot = [it for it in items if it["pair"] in keep]
    ppm = bk.pair_map(pilot)
    pc = Counter(("linux" if p["V"]["project"] == bk.LINUX else "other", bk.stratum(p["V"]["code"], p["S"]["code"]))
                 for p in ppm.values())

    stats = {"projects": len(chosen), "pairs": len(cpm), "A": st["A"], "B": st["B"], "E": st["E"],
             "candidate_projects": len(cand), "salt": SALT, "min_pairs": MIN_PAIRS}
    bk.dump(OUT_CASES, {"split": "vsp_dev3", "note": NOTE_CASES, "salt": SALT, "stats": stats, "cases": cases})
    bk.dump(OUT_PILOT, {"items": pilot, "note": NOTE_PILOT,
                        "stats": {"n_pairs": len(pilot) // 2, "near_pairs_removed": len(near),
                                  "dev3_pairs_removed": len(pairs),
                                  "counts": {f"{d}_{s}": v for (d, s), v in sorted(pc.items())}}})
    print("dev3:", json.dumps(stats))
    print("d3 pilot:", len(pilot) // 2, "pairs,", len(near), "near-neighbour pairs removed")


if __name__ == "__main__":
    main()
