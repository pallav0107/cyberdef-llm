#!/usr/bin/env python3
"""Build results/vsp_t_cases.json (the VSP-T real-world test set) from VulSpot.

Implements part (A) of the VSP-T brief (/tmp/brief_vsp.txt): vulnerable/fixed
function pairs from data/vulspot/cpp/full (split "test_paired_high" of
splits/project_holdout.json, paired via fixed_func_idx), C/C++ comments
stripped from both sides, drops per the brief's fixed rule order (every drop
counted in "pool"), the train-overlap rule exactly as
acceptance/improve/check_vsp.py defines it, and a 10-pairs-per-project cap.
The acceptance contract is acceptance/improve/check_vsp.py.

  .venv/bin/python scripts/imp_build_vsp.py [OUT.json]
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARQUET = ROOT / "data/vulspot/cpp/full/data.parquet"
SPLITS = ROOT / "data/vulspot/cpp/full/splits/project_holdout.json"
OUT = ROOT / "results/vsp_t_cases.json"
MAX_CHARS = 4000        # check_vsp.py TRUNC_LEN: drop, never truncate
MAX_PER_PROJECT = 10    # check_vsp.py MAX_PAIRS_PER_PROJECT
SEED = 0
COLS = ("idx", "project", "is_vulnerable", "fixed_func_idx", "func_body",
        "cwe_1003_list", "commit_id")


def strip_comments(code):
    """Remove C/C++ comments, respecting string and char literals."""
    out, i, n = [], 0, len(code)
    state = "code"
    while i < n:
        ch, nx = code[i], code[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nx == "/":
                state, i = "line", i + 2
            elif ch == "/" and nx == "*":
                state, i = "block", i + 2
            else:
                out.append(ch)
                state = "str" if ch == '"' else "char" if ch == "'" else "code"
                i += 1
        elif state == "line":
            if ch == "\n":
                out.append(ch)
                state = "code"
            i += 1
        elif state == "block":
            if ch == "*" and nx == "/":
                state, i = "code", i + 2
            else:
                if ch == "\n":
                    out.append(ch)
                i += 1
        else:  # str / char literal
            lit = '"' if state == "str" else "'"
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(code[i + 1])
                i += 2
            else:
                if ch == lit:
                    state = "code"
                i += 1
    return "".join(out)


def norm_hash(code):
    """Exactly acceptance/improve/check_vsp.py norm_hash."""
    return hashlib.sha256(" ".join(code.split()).encode("utf-8")).hexdigest()


def load_pool():
    import pandas as pd
    splits = json.load(open(SPLITS))
    df = pd.read_parquet(PARQUET, columns=COLS)
    df = df.set_index("idx", drop=False)
    return df, splits["train"], splits["test_paired_high"]


def train_hashes(df, train_idx):
    """check_vsp.py load_train: train project names + raw-body normalised hashes."""
    tr = df[df["idx"].isin(set(train_idx))]
    projects = set(tr["project"])
    hashes = {norm_hash(b) for b in tr["func_body"] if isinstance(b, str)}
    return projects, hashes


def iter_pairs(df, test_idx):
    """(vuln_row, fixed_row) for every vulnerable row of the split."""
    sub = df[df["idx"].isin(set(test_idx))]
    vuln = sub[sub["is_vulnerable"] == True]  # noqa: E712
    for _, row in vuln.iterrows():
        fixed = df.loc[int(row["fixed_func_idx"])]
        yield row, fixed


def keep_pair(v_code, s_code, stats):
    """Apply drop rules 3 (empty / identical / too long); count drops."""
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


def in_train(project, v_code, s_code, tr_projects, tr_hashes, stats):
    """Drop rule 4: project in train split or either side's hash is a train hash."""
    if project in tr_projects:
        stats["drop_train_project"] += 1
        return True
    if norm_hash(v_code) in tr_hashes or norm_hash(s_code) in tr_hashes:
        stats["drop_train_hash"] += 1
        return True
    return False


def cap_per_project(pairs, stats):
    """Drop rule 5: at most MAX_PER_PROJECT pairs per project (sorted, seeded)."""
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


def make_case(row, code, label, pair):
    """One output case per the brief's case format."""
    return {"id": "vsp:%s:%s" % (pair, "V" if label == "VULNERABLE" else "S"),
            "code": code, "code_chars": len(code),
            "lines": code.count("\n") + 1, "label": label, "pair": pair,
            "project": row["project"], "cwe": list(row["cwe_1003_list"]),
            "commit": row["commit_id"], "truncated": False}


def main():
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    df, train_idx, test_idx = load_pool()
    tr_projects, tr_hashes = train_hashes(df, train_idx)
    stats = Counter()
    pairs = []
    for v, s in iter_pairs(df, test_idx):
        stats["candidate_pairs"] += 1
        pair = str(int(v["idx"]))
        v_code, s_code = strip_comments(v["func_body"]), strip_comments(s["func_body"])
        if not keep_pair(v_code, s_code, stats):
            continue
        if in_train(v["project"], v_code, s_code, tr_projects, tr_hashes, stats):
            continue
        pairs.append({"project": v["project"], "pair": pair,
                      "v": make_case(v, v_code, "VULNERABLE", pair),
                      "s": make_case(s, s_code, "SAFE", pair)})
    kept = cap_per_project(pairs, stats)
    cases = [c for p in sorted(kept, key=lambda p: (p["project"], p["pair"]))
             for c in (p["v"], p["s"])]
    per_proj = Counter(p["project"] for p in kept)
    pool = {"source_rows": len(test_idx), **stats,
            "final_pairs": len(kept), "final_projects": len(per_proj),
            "pairs_per_project_hist": dict(sorted(Counter(per_proj.values()).items())),
            "cwe_counts": dict(sorted(Counter(cwe for p in kept for cwe in p["v"]["cwe"]).items()))}
    out = {"cases": cases, "split": "VSP-T from test_paired_high", "seed": SEED,
           "pool": pool}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1))
    print(json.dumps(pool, indent=1))
    print("wrote %d cases to %s" % (len(cases), out_path))


if __name__ == "__main__":
    main()
