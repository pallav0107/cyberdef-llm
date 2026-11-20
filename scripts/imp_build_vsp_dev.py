#!/usr/bin/env python3
"""Build the VSP-DEV split and the pilot / k2 training sets from the round-1 VSP-SFT items.

Writes, deterministically, into --out-dir (default results/):
  vsp_dev_cases.json      held-out DEV pairs (round-1 projects, never linux) for choosing a recipe BEFORE VSP-T
  vsp_pilot_k1_items.json round-1 items minus dev projects minus pairs near-duplicating a dev function
  vsp_pilot_k2_items.json k1 + 300 extra linux pairs (the pilot arm for the V-longer top-up)
  vsp_sft_k2_items.json   every round-1 item + the same 300 extra linux pairs (the final k2 training set)

Rules (acceptance contract: acceptance/improve/check_vsp_dev.py):
  dev projects  round-1 projects except linux, ordered by sha256("vspdev-v1|" + project); take projects with at
                least one B pair (vulnerable side longer) in that order until the dev B pairs reach 45, then the
                first ceil(10%) of the remaining untaken non-linux projects, in the same order.
  pilot k1      round-1 items of other projects, minus every pair with a side whose token-set Jaccard to any dev
                function is >= JACCARD_MAX (the round-1 near-duplicate rule, applied to dev instead of VSP-T).
  extras        linux VulSpot train-split pairs (both rows train) passing every round-1 eligibility filter, vulnerable
                side strictly longer after stripping, label_confidence "high", not in round 1, Jaccard < JACCARD_MAX to
                every dev function, identifier-normalised (camelCase/snake_case folded) Jaccard < JACCARD_MAX to every
                VSP-T and every dev function, and not a vendored ACPICA core function (linux func_name matching
                VENDORED_RE: acpica is a VSP-T project, round-1 rule 5b); sorted numerically by pair id; random.Random(0).sample(300); re-sorted.
VSP-T is touched only through the round-1 leak rules (imp_build_vsp_train functions, check_vsp_items.Ctx).

  .venv/bin/python scripts/imp_build_vsp_dev.py [--out-dir DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

import imp_build_vsp_train as bt   # its import also puts scripts/ and acceptance/improve/ on sys.path
from check_vsp_items import Ctx, FORK_PROJECTS, JACCARD_MAX, max_jaccard, token_set
from check_vsp_items import TOKEN as check_vsp_items_TOKEN

ROOT = bt.ROOT
ROUND1 = ROOT / "results/vsp_sft_items.json"
DEV_SALT = "vspdev-v1|"
DEV_B_TARGET = 45
DEV_EXTRA_FRAC = 0.10
N_EXTRAS = 300
EXTRA_SEED = 0
LINUX = "linux"
COLS = ("idx", "project", "is_vulnerable", "fixed_func_idx", "func_body", "cwe_1003_list", "label_confidence",
        "func_name")
VENDORED_RE = re.compile(r"^acpi_(ps|ds|ex|ut|ns|tb|rs|ev|hw|db|dm|nm)_")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
FILES = {"dev": "vsp_dev_cases.json", "k1": "vsp_pilot_k1_items.json",
         "k2_pilot": "vsp_pilot_k2_items.json", "k2_final": "vsp_sft_k2_items.json"}
DEV_NOTE = ("VSP-DEV: held-out round-1 projects (never linux, never VSP-T) for choosing a recipe before VSP-T is "
            "read; build rules in scripts/imp_build_vsp_dev.py")
ITEMS_NOTE = "built by scripts/imp_build_vsp_dev.py from results/vsp_sft_items.json; see that file for the rules"


def pair_map(items):
    """pair -> {"V": item, "S": item} (round-1 items are pair-adjacent, V then S)."""
    out = defaultdict(dict)
    for it in items:
        out[it["pair"]]["V" if it["label"] == "VULNERABLE" else "S"] = it
    return dict(out)


def is_b(pm):
    return len(pm["V"]["code"]) > len(pm["S"]["code"])


def pick_dev_projects(pairs):
    """Dev project set from a pair map, per the module docstring."""
    b_by_proj, projects = Counter(), set()
    for pm in pairs.values():
        proj = pm["V"]["project"]
        if proj == LINUX:
            continue
        projects.add(proj)
        b_by_proj[proj] += is_b(pm)
    order = sorted(projects, key=lambda p: hashlib.sha256((DEV_SALT + p).encode()).hexdigest())
    taken, b_total = [], 0
    for proj in order:
        if b_total >= DEV_B_TARGET:
            break
        if b_by_proj[proj] >= 1:
            taken.append(proj)
            b_total += b_by_proj[proj]
    rest = [p for p in order if p not in set(taken)]
    return set(taken) | set(rest[:math.ceil(DEV_EXTRA_FRAC * len(rest))])


def dev_case(it):
    code = it["code"]
    return {"id": it["id"].replace("vspsft:", "vspdev:", 1), "code": code, "code_chars": len(code),
            "lines": code.count("\n") + 1, "label": it["label"], "pair": it["pair"], "project": it["project"],
            "cwe": list(it["cwe"]), "truncated": False}


def norm_token_set(code):
    """token_set with identifiers case-folded and camelCase -> snake_case, so a renamed vendored copy still matches."""
    def norm(tok):
        return _CAMEL.sub("_", tok).lower() if (tok[0].isalpha() or tok[0] == "_") else tok
    return frozenset(norm(t) for t in check_vsp_items_TOKEN.findall(code))


def near_dev(pm, dev_tokens):
    """True if either side of the pair is >= JACCARD_MAX similar to any dev function."""
    return any(max_jaccard(token_set(pm[s]["code"]), dev_tokens) >= JACCARD_MAX for s in "VS")


def linux_extras(ctx, r1_pairs, dev_tokens, dev_norm):
    """Sampled extra pairs [(v_idx, s_idx, v_code, s_code, cwe)] sorted by numeric pair id."""
    import pandas as pd
    train = set(json.load(open(bt.SPLITS))["train"])
    t_projects, t_hashes = ctx.test
    t_tokens = ctx.test_tokens
    df = pd.read_parquet(bt.PARQUET, columns=list(COLS)).set_index("idx", drop=False)
    sub = df[(df.project == LINUX) & df.idx.isin(train) & df.is_vulnerable & df.fixed_func_idx.notna()]
    t_norm = [norm_token_set(c["code"]) for c in json.load(open(bt.TEST_CASES, encoding="utf-8"))["cases"]]
    stats, pool, excl = Counter(), [], Counter()
    for _, v in sub.iterrows():
        fx = int(v["fixed_func_idx"])
        pair = str(int(v["idx"]))
        if fx not in train or pair in r1_pairs or v["label_confidence"] != "high":
            continue
        if bt.in_test_project(v["project"], t_projects, stats) or v["project"] in FORK_PROJECTS:
            continue
        vc, sc = bt.strip_comments(v["func_body"]), bt.strip_comments(df.loc[fx]["func_body"])
        if not bt.keep_pair(vc, sc, stats) or bt.in_test_hash(vc, sc, t_hashes, stats):
            continue
        if max(max_jaccard(token_set(vc), t_tokens), max_jaccard(token_set(sc), t_tokens)) >= JACCARD_MAX:
            continue
        if len(vc) <= len(sc):   # stratum B only: the point of the extras is more vulnerable-longer pairs
            continue
        if max(max_jaccard(token_set(vc), dev_tokens), max_jaccard(token_set(sc), dev_tokens)) >= JACCARD_MAX:
            continue
        if VENDORED_RE.match(str(v["func_name"])):   # vendored ACPICA core (rule 5b: VSP-T project acpica)
            excl["vendored_acpica"] += 1
            excl["vendored_ids"] = excl.get("vendored_ids", []) + [int(v["idx"])]
            continue
        nvc, nsc = norm_token_set(vc), norm_token_set(sc)
        if max(max_jaccard(nvc, t_norm), max_jaccard(nsc, t_norm), max_jaccard(nvc, dev_norm),
               max_jaccard(nsc, dev_norm)) >= JACCARD_MAX:   # renamed copy of a VSP-T or dev function
            excl["norm_near_dup"] += 1
            excl["norm_ids"] = excl.get("norm_ids", []) + [int(v["idx"])]
            continue
        pool.append((int(v["idx"]), fx, vc, sc, list(v["cwe_1003_list"])))
    pool.sort(key=lambda r: r[0])
    picked = random.Random(EXTRA_SEED).sample(pool, N_EXTRAS)
    print(f"extras: excluded by the new rules: {dict(excl)}")
    print(f"extras: eligibility pool {len(pool)} linux pairs, sampled {len(picked)}")
    return sorted(picked, key=lambda r: r[0])


def extra_items(extras, first_rank):
    """Round-1 item schema, V then S per pair; rank continues after round 1 (rank 0 would switch the pair term off)."""
    items, rank = [], first_rank
    for vi, fx, vc, sc, cwe in extras:
        row = {"project": LINUX}
        items.append(bt.make_item(row, vc, "VULNERABLE", str(vi), vi, cwe, rank))
        items.append(bt.make_item(row, sc, "SAFE", str(vi), fx, cwe, rank + 1))
        rank += 2
    return items


def dump(path, obj):
    Path(path).write_text(json.dumps(obj, indent=1), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out-dir", default=str(ROOT / "results"))
    out = Path(ap.parse_args().out_dir)
    out.mkdir(parents=True, exist_ok=True)
    r1 = json.load(open(ROUND1, encoding="utf-8"))["items"]
    pairs = pair_map(r1)
    dev_projects = pick_dev_projects(pairs)
    cases = [dev_case(it) for it in r1 if it["project"] in dev_projects]
    dev_tokens = [token_set(c["code"]) for c in cases]
    k1 = [it for it in r1 if it["project"] not in dev_projects and not near_dev(pairs[it["pair"]], dev_tokens)]
    extras = extra_items(linux_extras(Ctx(), set(pairs), dev_tokens, [norm_token_set(c["code"]) for c in cases]), max(it["rank"] for it in r1) + 1)
    n_b = sum(is_b(pairs[p]) for p in {c["pair"] for c in cases})
    stats = {"dev_projects": len(dev_projects), "dev_pairs": len(cases) // 2, "dev_B_pairs": n_b,
             "k1_pairs": len(k1) // 2, "extra_pairs": len(extras) // 2}
    dump(out / FILES["dev"], {"split": "vsp_dev", "note": DEV_NOTE, "seed": EXTRA_SEED, "salt": DEV_SALT,
                              "stats": stats, "cases": cases})
    for key, items in (("k1", k1), ("k2_pilot", k1 + extras), ("k2_final", r1 + extras)):
        dump(out / FILES[key], {"items": items, "note": ITEMS_NOTE, "stats": {**stats, "n_pairs": len(items) // 2}})
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
