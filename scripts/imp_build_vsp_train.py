#!/usr/bin/env python3
"""Build results/vsp_sft_items.json (the VSP-SFT verdict-only TRAINING set) from VulSpot.

Implements /tmp/brief_vsp_items.txt: vulnerable/fixed function pairs from
data/vulspot/cpp/full in split "train" of splits/project_holdout.json (both
sides of a pair must be train rows), pairs touching a VSP-T project dropped,
C/C++ comments stripped from both sides with the same stripper VSP-T used
(scripts/imp_build_vsp.py strip_comments), drops per the brief's fixed rule
order (every drop counted in "stats"), a VSP-T normalised-hash overlap rule,
and a 40-pairs-per-project cap (sorted keys, seeded sample). The acceptance
contract is acceptance/improve/check_vsp_items.py.

  .venv/bin/python scripts/imp_build_vsp_train.py [OUT.json]
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from imp_build_vsp import strip_comments  # noqa: E402  the VSP-T stripper

PARQUET = ROOT / "data/vulspot/cpp/full/data.parquet"
SPLITS = ROOT / "data/vulspot/cpp/full/splits/project_holdout.json"
TEST_CASES = ROOT / "results/vsp_t_cases.json"
OUT = ROOT / "results/vsp_sft_items.json"
MAX_CHARS = 4000        # check_vsp.py TRUNC_LEN: drop, never truncate
MAX_PER_PROJECT = 40    # check_vsp_items.py MAX_PAIRS_PER_PROJECT
SEED = 0
COLS = ("idx", "project", "is_vulnerable", "fixed_func_idx", "func_body",
        "cwe_1003_list")
NOTE = ("VSP-SFT verdict-only training pairs (owner decision 17 Nov); "
        "build rules in scripts/imp_build_vsp_train.py")


def norm_hash(code):
    """Exactly acceptance/improve/check_vsp.py norm_hash."""
    return hashlib.sha256(" ".join(code.split()).encode("utf-8")).hexdigest()


def load_pool():
    import pandas as pd
    splits = json.load(open(SPLITS))
    df = pd.read_parquet(PARQUET, columns=COLS)
    df = df.set_index("idx", drop=False)
    return df, set(splits["train"])


def test_projects_hashes():
    """(VSP-T project names, VSP-T stripped-code normalised hashes)."""
    cases = json.load(open(TEST_CASES, encoding="utf-8"))["cases"]
    return ({c["project"] for c in cases},
            {norm_hash(c["code"]) for c in cases})


def iter_pairs(df, train_idx):
    """(vuln_row, fixed_row) for train vulnerable rows with a train fixed twin."""
    sub = df[df["idx"].isin(train_idx)]
    vuln = sub[sub["is_vulnerable"] & sub["fixed_func_idx"].notna()]
    for _, row in vuln.iterrows():
        fx = int(row["fixed_func_idx"])
        if fx in train_idx:
            yield row, df.loc[fx]


def keep_pair(v_code, s_code, stats):
    """Apply drop rule 4 (empty / identical / too long); count drops."""
    if not v_code.strip() or not s_code.strip():
        stats["drop_empty"] += 1
        return False
    if v_code == s_code:
        stats["drop_identical"] += 1
        return False
    if len(v_code) >= MAX_CHARS or len(s_code) >= MAX_CHARS:
        stats["drop_too_long"] += 1
        return False
    return True


def in_test_project(project, t_projects, stats):
    """Drop rule 2: the pair's project appears in VSP-T."""
    if project in t_projects:
        stats["drop_test_project"] += 1
        return True
    return False


def in_test_hash(v_code, s_code, t_hashes, stats):
    """Drop rule 5: either side's normalised hash equals a VSP-T case's."""
    if norm_hash(v_code) in t_hashes or norm_hash(s_code) in t_hashes:
        stats["drop_test_hash"] += 1
        return True
    return False


def cap_per_project(pairs, stats):
    """Drop rule 6: at most MAX_PER_PROJECT pairs per project (sorted, seeded)."""
    by_proj = {}
    for p in pairs:
        by_proj.setdefault(p["project"], []).append(p)
    kept = []
    for proj in sorted(by_proj):
        keys = sorted(by_proj[proj], key=lambda p: p["pair"])
        k = min(MAX_PER_PROJECT, len(keys))
        if len(keys) > k:
            stats["drop_project_cap"] += len(keys) - k
        kept.extend(random.Random(SEED).sample(keys, k))
    return kept


def make_item(v, code, label, pair, src_idx, cwe, rank):
    """One output item per the brief's item format."""
    return {"id": "vspsft:%s:%s" % (pair, "V" if label == "VULNERABLE" else "S"),
            "code": code, "code_chars": len(code), "toks": max(1, len(code) // 3),
            "label": label, "pair": pair, "project": v["project"],
            "src_idx": int(src_idx), "cwe": list(cwe), "rank": rank}


def main():
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    df, train_idx = load_pool()
    t_projects, t_hashes = test_projects_hashes()
    stats = Counter()
    pairs = []
    for v, s in iter_pairs(df, train_idx):
        stats["candidate_pairs"] += 1
        pair = str(int(v["idx"]))
        if in_test_project(v["project"], t_projects, stats):
            continue
        v_code, s_code = strip_comments(v["func_body"]), strip_comments(s["func_body"])
        if not keep_pair(v_code, s_code, stats):
            continue
        if in_test_hash(v_code, s_code, t_hashes, stats):
            continue
        pairs.append({"project": v["project"], "pair": pair, "v": v, "s": s,
                      "v_code": v_code, "s_code": s_code})
    kept = cap_per_project(pairs, stats)
    items, rank = [], 0
    for p in sorted(kept, key=lambda p: (p["project"], p["pair"])):
        cwe = p["v"]["cwe_1003_list"]
        items.append(make_item(p["v"], p["v_code"], "VULNERABLE", p["pair"],
                               p["v"]["idx"], cwe, rank))
        rank += 1
        items.append(make_item(p["s"], p["s_code"], "SAFE", p["pair"],
                               p["s"]["idx"], cwe, rank))
        rank += 1
    per_proj = Counter(p["project"] for p in kept)
    stats["final_pairs"] = len(kept)
    stats["final_projects"] = len(per_proj)
    stats["linux_pairs"] = per_proj.get("linux", 0)
    stats["pairs_per_project_hist"] = dict(sorted(Counter(per_proj.values()).items()))
    stats["cwe_counts"] = dict(sorted(Counter(c for p in kept
                                              for c in p["v"]["cwe_1003_list"]).items()))
    out = {"items": items, "note": NOTE, "stats": stats}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1))
    print(json.dumps(dict(stats), indent=1, default=str))
    print("wrote %d items to %s" % (len(items), out_path))


if __name__ == "__main__":
    main()
