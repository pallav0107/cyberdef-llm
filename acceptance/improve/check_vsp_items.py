"""Acceptance checker for the TRAINING set of real-world before/after fix pairs (results/vsp_sft_items.json).

Usage:
  .venv/bin/python acceptance/improve/check_vsp_items.py ITEMS.json [--expect-refuse CODE1,CODE2]

Without --expect-refuse: exit 0 iff no code refuses.
With --expect-refuse:    exit 0 iff EVERY listed code refuses (a test of the checker itself).
Exit 2 on unreadable input or unknown code. An empty items list refuses every code (never vacuous).

Schema facts relied on (data/vulspot/cpp/full):
  data.parquet: idx == row position; project; is_vulnerable (bool); fixed_func_idx (float, NaN when
  absent; the SAFE twin idx for a vulnerable row); func_body (raw text, WITH comments).
  splits/project_holdout.json: key "train" = list of parquet idx.
  results/vsp_t_cases.json: {"cases": [{"code","project",...}]} (the fixed TEST set).
Items format: {"items": [{"id","code","label","pair","project","src_idx",...}]}.
Reused from check_vsp.py by import: SPLITS, PARQUET, TRUNC_LEN, BAND, norm_hash, is_true,
group_pairs, project_pairs, band_features, best_auroc, fmt_auroc.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_vsp as cv  # noqa: E402

ROOT = cv.ROOT
TEST_CASES = ROOT / "results/vsp_t_cases.json"
MAX_PAIRS_PER_PROJECT = 40
MATCH_FRAC = 0.99
MIN_PAIRS, MIN_PROJECTS = 600, 150
CODES = ["PAIRS", "LENGTH", "TRAIN_SPLIT", "LABEL_SOURCE", "TEXT_SOURCE",
         "TEST_OVERLAP", "PROJECT_CAP", "BANDS", "FLOOR"]
REQUIRED = ("code", "label", "pair", "project", "src_idx")
SQ, DQ = chr(39), chr(34)


def strip_comments(src):
    """Remove // and /* */ comments, respecting string and char literals (own state machine)."""
    out, i, n = [], 0, len(src)
    while i < n:
        i = _step(src, i, n, out)
    return "".join(out)


def _step(src, i, n, out):
    c = src[i]
    if c == DQ or (c == SQ and not _digit_sep(src, i)):
        j = _literal_end(src, i, n)
        out.append(src[i:j])
        return j
    if src.startswith("//", i):
        return _line_comment_end(src, i, n, out)
    if src.startswith("/*", i):
        j = src.find("*/", i + 2)
        out.append(" ")
        return n if j < 0 else j + 2
    out.append(c)
    return i + 1


def _digit_sep(src, i):
    """C++14 digit separator (digit, quote, hex digit) is not the start of a char literal."""
    return 0 < i < len(src) - 1 and src[i - 1].isdigit() and src[i + 1] in "0123456789abcdefABCDEF"


def _literal_end(src, i, n):
    q, j = src[i], i + 1
    while j < n and src[j] != q:
        if src[j] == "\n" and q == SQ:
            return j
        j += 2 if src[j] == "\\" else 1
    return min(j + 1, n)


def _line_comment_end(src, i, n, out):
    j = i + 2
    while j < n and src[j] != "\n":
        j += 2 if src[j] == "\\" and j + 1 < n else 1
    out.append(" ")
    return min(j, n)


def squash(text):
    return "".join(text.split())


class Ctx:
    """Lazily loaded ground truth: train idx, parquet columns, VSP-T projects and hashes."""

    def __init__(self):
        self._train = self._rows = self._test = None

    @property
    def train(self):
        if self._train is None:
            self._train = set(json.load(open(cv.SPLITS))["train"])
        return self._train

    @property
    def rows(self):
        if self._rows is None:
            import pandas as pd
            cols = ["idx", "project", "is_vulnerable", "fixed_func_idx", "func_body"]
            self._rows = pd.read_parquet(cv.PARQUET, columns=cols)
        return self._rows

    @property
    def test(self):
        if self._test is None:
            cases = json.load(open(TEST_CASES, encoding="utf-8"))["cases"]
            self._test = ({c["project"] for c in cases}, {cv.norm_hash(c["code"]) for c in cases})
        return self._test

    def row(self, idx):
        """(is_vulnerable, fixed_func_idx, func_body) for a parquet idx, or None if not a valid row."""
        if not isinstance(idx, int) or isinstance(idx, bool) or not 0 <= idx < len(self.rows):
            return None
        r = self.rows.iloc[idx]
        fx = r["fixed_func_idx"]
        return bool(r["is_vulnerable"]), (None if fx != fx else int(fx)), r["func_body"]


def check_pairs(items, ctx):
    pairs = cv.group_pairs(items)
    bad = 0
    for m in pairs.values():
        v = [x for x in m if x["label"] == "VULNERABLE"]
        s = [x for x in m if x["label"] == "SAFE"]
        if len(m) != 2 or len(v) != 1 or len(s) != 1 or v[0]["code"] == s[0]["code"]:
            bad += 1
    return bad > 0, f"{bad} bad pairs of {len(pairs)}"


def check_length(items, ctx):
    n = sum(1 for c in items if len(c["code"]) >= cv.TRUNC_LEN)
    return n > 0, f"{n} items >= {cv.TRUNC_LEN} chars of {len(items)}"


def check_train_split(items, ctx):
    n = sum(1 for c in items if c["src_idx"] not in ctx.train)
    return n > 0, f"{n} items with src_idx outside train of {len(items)}"


def label_ok(item, vitem, ctx):
    r = ctx.row(item["src_idx"])
    if r is None:
        return False
    if item["label"] == "VULNERABLE":
        return r[0]
    vr = ctx.row(vitem["src_idx"]) if vitem else None
    return vr is not None and vr[1] is not None and item["src_idx"] == vr[1]


def check_label_source(items, ctx):
    bad = 0
    for m in cv.group_pairs(items).values():
        v = next((x for x in m if x["label"] == "VULNERABLE"), None)
        for x in m:
            known = x["label"] in ("VULNERABLE", "SAFE")
            bad += 0 if known and label_ok(x, v, ctx) else 1
    return bad > 0, f"{bad} items with wrong label source of {len(items)}"


def text_ok(item, ctx):
    r = ctx.row(item["src_idx"])
    return r is not None and isinstance(r[2], str) and squash(item["code"]) == squash(strip_comments(r[2]))


def check_text_source(items, ctx):
    bad = sum(1 for c in items if not text_ok(c, ctx))
    frac = 1 - bad / len(items)
    return frac < MATCH_FRAC, f"{bad} mismatching items of {len(items)} ({frac:.4f} match, min {MATCH_FRAC})"


def check_test_overlap(items, ctx):
    projects, hashes = ctx.test
    p = {c["project"] for c in items} & projects
    h = sum(1 for c in items if cv.norm_hash(c["code"]) in hashes)
    return bool(p) or h > 0, f"{len(p)} item projects in VSP-T {sorted(p)[:5]}; {h} items with VSP-T code hash"


def check_cap(items, ctx):
    pp = cv.project_pairs(items)
    over = {p: len(s) for p, s in pp.items() if len(s) > MAX_PAIRS_PER_PROJECT}
    mx = max((len(s) for s in pp.values()), default=0)
    return bool(over), f"{len(over)} projects over cap {MAX_PAIRS_PER_PROJECT}; max {mx}"


def band_values(items):
    labels = [1 if c["label"] == "VULNERABLE" else 0 for c in items]
    feats = [cv.band_features(c["code"]) for c in items]
    return {k: cv.best_auroc([f[k] for f in feats], labels) for k in feats[0]}


def check_bands(items, ctx):
    res = band_values(items)
    out = [k for k, a in res.items() if a is None or not cv.BAND[0] <= a <= cv.BAND[1]]
    return bool(out), " ".join(k + "=" + cv.fmt_auroc(a) for k, a in res.items()) + f" out={out}"


def check_floor(items, ctx):
    pairs = len(cv.group_pairs(items))
    projects = len({c["project"] for c in items})
    return pairs < MIN_PAIRS or projects < MIN_PROJECTS, \
        f"{pairs} pairs (min {MIN_PAIRS}), {projects} projects (min {MIN_PROJECTS})"


CHECKS = {"PAIRS": check_pairs, "LENGTH": check_length, "TRAIN_SPLIT": check_train_split,
          "LABEL_SOURCE": check_label_source, "TEXT_SOURCE": check_text_source,
          "TEST_OVERLAP": check_test_overlap, "PROJECT_CAP": check_cap,
          "BANDS": check_bands, "FLOOR": check_floor}


def run_all(items, ctx=None):
    if not items:
        return {code: (True, "no items") for code in CODES}
    ctx = ctx or Ctx()
    return {code: CHECKS[code](items, ctx) for code in CODES}


def load_items(path):
    try:
        items = json.load(open(path, encoding="utf-8"))["items"]
        for c in items:
            for k in REQUIRED:
                c[k]
            if not isinstance(c["code"], str):
                raise TypeError("code is not a string")
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"ERROR: cannot read items from {path}: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
    return items


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("items")
    ap.add_argument("--expect-refuse", default="")
    args = ap.parse_args(argv)
    expect = [x for x in args.expect_refuse.split(",") if x]
    unknown = [x for x in expect if x not in CODES]
    if unknown:
        print(f"ERROR: unknown codes {unknown}", file=sys.stderr)
        return 2
    results = run_all(load_items(args.items))
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
