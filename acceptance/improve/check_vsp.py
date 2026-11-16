"""Acceptance checker for the VSP-T real-world test set (results/vsp_t_cases.json).

Usage:
  .venv/bin/python acceptance/improve/check_vsp.py CASES.json [--expect-refuse CODE1,CODE2]

Without --expect-refuse: exit 0 iff no refusal code fires.
With --expect-refuse:    exit 0 iff EVERY listed code fires (a test of the checker itself).
Exit 2 on unreadable input / unknown code.

Schema facts relied on (data/vulspot/cpp/full):
  data.parquet columns: idx (== row position), project (short name), func_body.
  splits/project_holdout.json keys: train/val/test/test_high/test_paired_high/...; each is a
  list of parquet idx values. Train projects = project of the rows whose idx is in "train".
Case format: {"cases": [{"id","code","label","pair","project","truncated"?}]}.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from cyberdef.imp_common import auroc  # noqa: E402

PARQUET = ROOT / "data/vulspot/cpp/full/data.parquet"
SPLITS = ROOT / "data/vulspot/cpp/full/splits/project_holdout.json"
TRUNC_LEN = 4000
MAX_PAIRS_PER_PROJECT = 10
BAND = (0.45, 0.55)
LINE_AUROC_MAX = 0.60
LINE_MIN_FRAC = 0.01
MIN_PAIRS, MIN_PROJECTS = 300, 100
CODES = ["IDENTICAL_PAIRS", "TRUNCATED", "PAIR_INCOMPLETE", "PROJECT_CAP",
         "PROJECT_BALANCE", "TRAIN_OVERLAP", "BANDS", "LINE_SCAN", "TOO_SMALL"]


def norm_hash(code):
    return hashlib.sha256(" ".join(code.split()).encode("utf-8")).hexdigest()


def is_true(v):
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def group_pairs(cases):
    pairs = defaultdict(list)
    for c in cases:
        pairs[str(c.get("pair"))].append(c)
    return pairs


def is_complete(members):
    labels = sorted(m["label"] for m in members)
    return labels == ["SAFE", "VULNERABLE"]


def check_identical(cases):
    bad = []
    for pid, m in group_pairs(cases).items():
        if is_complete(m):
            v = next(x for x in m if x["label"] == "VULNERABLE")
            s = next(x for x in m if x["label"] == "SAFE")
            if v["code"] == s["code"]:
                bad.append(pid)
    return bool(bad), f"{len(bad)} identical pairs"


def check_truncated(cases):
    n = sum(1 for c in cases if is_true(c.get("truncated")) or len(c["code"]) >= TRUNC_LEN)
    return n > 0, f"{n} truncated cases of {len(cases)}"


def check_incomplete(cases):
    pairs = group_pairs(cases)
    bad = sum(1 for m in pairs.values() if not is_complete(m))
    return bad > 0, f"{bad} incomplete pairs of {len(pairs)}"


def project_pairs(cases):
    out = defaultdict(set)
    for c in cases:
        out[c["project"]].add(str(c.get("pair")))
    return out


def check_cap(cases):
    pp = project_pairs(cases)
    over = {p: len(s) for p, s in pp.items() if len(s) > MAX_PAIRS_PER_PROJECT}
    mx = max((len(s) for s in pp.values()), default=0)
    return bool(over), f"{len(over)} projects over cap {MAX_PAIRS_PER_PROJECT}; max {mx}"


def check_balance(cases):
    cnt = defaultdict(Counter)
    for c in cases:
        cnt[c["project"]][c["label"]] += 1
    bad = [p for p, k in cnt.items() if k["VULNERABLE"] != k["SAFE"]]
    return bool(bad), f"{len(bad)} unbalanced projects of {len(cnt)}"


def load_train():
    """Return (train project names, train normalised code hashes)."""
    import pandas as pd
    train_idx = set(json.load(open(SPLITS))["train"])
    df = pd.read_parquet(PARQUET, columns=["idx", "project", "func_body"])
    df = df[df["idx"].isin(train_idx)]
    projects = set(df["project"])
    hashes = {norm_hash(b) for b in df["func_body"] if isinstance(b, str)}
    return projects, hashes


def check_train_overlap(cases, train=None):
    projects, hashes = train if train is not None else load_train()
    proj = {c["project"] for c in cases} & projects
    n_hash = sum(1 for c in cases if norm_hash(c["code"]) in hashes)
    msg = f"{len(proj)} test projects in train {sorted(proj)[:5]}; {n_hash} cases with train code hash"
    return bool(proj) or n_hash > 0, msg


def best_auroc(scores, labels):
    a = auroc(scores, labels)
    return None if a is None else max(a, 1 - a)


def band_features(code):
    return {"chars": len(code), "lines": code.count("\n") + 1,
            "if": len(re.findall(r"\bif\b", code)), "static": len(re.findall(r"\bstatic\b", code)),
            "comments": len(re.findall(r"/\*|(?<![:\\])//", code))}   # a fix comment on the SAFE side only is a label cue


def fmt_auroc(a):
    return "NA" if a is None else str(round(a, 4))


def check_bands(cases):
    labels = [1 if c["label"] == "VULNERABLE" else 0 for c in cases]
    feats = [band_features(c["code"]) for c in cases]
    res = {k: best_auroc([f[k] for f in feats], labels) for k in feats[0]} if feats else {}
    out = [k for k, a in res.items() if a is None or not BAND[0] <= a <= BAND[1]]
    return bool(out), " ".join(k + "=" + fmt_auroc(a) for k, a in res.items())


def line_keys(code):
    lines = [ln.strip() for ln in code.split("\n")]
    nonempty = [ln for ln in lines if ln]
    keys = {("any", ln) for ln in nonempty}
    if nonempty:
        keys.add(("first", nonempty[0]))
        keys.add(("last", nonempty[-1]))
    return keys


def check_line_scan(cases):
    nv = Counter()
    ns = Counter()
    for c in cases:
        (nv if c["label"] == "VULNERABLE" else ns).update(line_keys(c["code"]))
    tv = sum(1 for c in cases if c["label"] == "VULNERABLE")
    ts = len(cases) - tv
    if tv == 0 or ts == 0:
        return True, "single-class input"
    best, best_key = 0.5, None
    for key in set(nv) | set(ns):
        if key[0] == "any" and nv[key] + ns[key] < LINE_MIN_FRAC * len(cases):
            continue
        a = 0.5 + (nv[key] / tv - ns[key] / ts) / 2
        a = max(a, 1 - a)
        if a > best:
            best, best_key = a, key
    shown = best_key[0] + ":" + repr(best_key[1][:40]) if best_key else "-"
    return best > LINE_AUROC_MAX, f"max line AUROC={best:.4f} ({shown})"


def check_too_small(cases):
    pairs = len({str(c.get("pair")) for c in cases})
    projects = len({c["project"] for c in cases})
    return pairs < MIN_PAIRS or projects < MIN_PROJECTS, f"{pairs} pairs (min {MIN_PAIRS}), {projects} projects (min {MIN_PROJECTS})"


def run_all(cases, train=None):
    checks = {
        "IDENTICAL_PAIRS": check_identical, "TRUNCATED": check_truncated,
        "PAIR_INCOMPLETE": check_incomplete, "PROJECT_CAP": check_cap,
        "PROJECT_BALANCE": check_balance,
        "TRAIN_OVERLAP": lambda c: check_train_overlap(c, train),
        "BANDS": check_bands, "LINE_SCAN": check_line_scan, "TOO_SMALL": check_too_small,
    }
    return {code: checks[code](cases) for code in CODES}


def load_cases(path):
    try:
        data = json.load(open(path, encoding="utf-8"))
        cases = data["cases"]
        for c in cases:
            c["code"], c["label"], c["project"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"ERROR: cannot read cases from {path}: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
    return cases


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cases")
    ap.add_argument("--expect-refuse", default="")
    args = ap.parse_args(argv)
    expect = [x for x in args.expect_refuse.split(",") if x]
    unknown = [x for x in expect if x not in CODES]
    if unknown:
        print(f"ERROR: unknown codes {unknown}", file=sys.stderr)
        return 2
    results = run_all(load_cases(args.cases))
    for code in CODES:
        fired, msg = results[code]
        print(code + ": " + ("REFUSE" if fired else "PASS") + " - " + msg)
    if expect:
        missing = [c for c in expect if not results[c][0]]
        print("expect-refuse:", "OK" if not missing else f"NOT FIRED {missing}")
        return 0 if not missing else 1
    return 1 if any(f for f, _ in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
