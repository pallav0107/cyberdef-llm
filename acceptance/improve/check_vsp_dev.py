"""Acceptance checker for the VSP-DEV split and the pilot / k2 training sets.

Usage:
  .venv/bin/python acceptance/improve/check_vsp_dev.py [--dev F] [--k1 F] [--k2-pilot F]
      [--k2-final F] [--round1 F] [--tcases F] [--builder F] [--skip-checks NAME,NAME]

Every path may also be set through an env var (VSPDEV_DEV, VSPDEV_K1, VSPDEV_K2_PILOT,
VSPDEV_K2_FINAL, VSPDEV_ROUND1, VSPDEV_TCASES, VSPDEV_BUILDER). Prints one PASS/FAIL line per
named check and exits 0 only if every check passed. --skip-checks exists for the mutant
self-test only (check_vsp_dev_selftest.py skips the two slow whole-pipeline checks, REBUILD and
VERDICT); a skipped check prints SKIP and the run then reports "(N skipped)".

Rules recomputed here, independently of the builder (scripts/imp_build_vsp_dev.py, not read):
  dev projects: round-1 projects except linux, ordered by sha256("vspdev-v1|"+project) hex
  ascending; take projects having >= 1 B pair in that order until dev B pairs >= 45, then add the
  first ceil(10% of the remaining non-linux not-yet-taken projects) in the same order.
  Stratum from len(code): A = fixed side longer, B = vulnerable side longer, E = equal.
  Extras: linux pairs, VulSpot train split (both rows), every round-1 eligibility filter
  (scripts/imp_build_vsp_train.py: non-empty, differing, < 4000 chars after comment stripping,
  no VSP-T hash, token-set Jaccard < 0.5 to every VSP-T function), vulnerable side strictly
  longer (stratum B), label_confidence == "high", not in round 1, Jaccard < 0.5 to every dev
  function, identifier-normalised Jaccard < 0.5 to every VSP-T and every dev function (camelCase
  and snake_case fold to one form), and not a vendored ACPICA core function (linux func_name
  matching VENDORED_RE; ACPICA is a VSP-T project); sorted by pair id; random.Random(0).sample(300). The sort key is ambiguous in the
  brief (pair ids are strings), so the sample is accepted under numeric OR lexicographic order.
Reused by import: check_vsp_items (token_set, max_jaccard, JACCARD_MAX, FORK_PROJECTS, Ctx,
run_all, CODES) and imp_build_vsp (strip_comments, norm_hash).

Schema assumptions: dev file {"cases": [...]} with vsp_t_cases.json keys (id, code, code_chars,
lines, label, pair, project, cwe, truncated; "commit" optional because round-1 items do not
carry it); a dev case is matched to its round-1 item by (pair, label) (ids are not assumed);
items files are {"items": [...]} with the round-1 item schema.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import check_vsp_items as ci  # noqa: E402
from imp_build_vsp import norm_hash, strip_comments  # noqa: E402

PY = sys.executable
PARQUET = ROOT / "data/vulspot/cpp/full/data.parquet"
SPLITS = ROOT / "data/vulspot/cpp/full/splits/project_holdout.json"
DEV_SALT = "vspdev-v1|"
DEV_B_TARGET = 45
DEV_EXTRA_FRAC = 0.10
MIN_DEV_B, MIN_DEV_A = 45, 150
N_EXTRAS = 300
EXTRA_SEED = 0
MAX_CHARS = 4000
LINUX = "linux"
LINUX_CAP_AFTER_EXTRAS = 340
VENDORED_RE = re.compile(r"^acpi_(ps|ds|ex|ut|ns|tb|rs|ev|hw|db|dm|nm)_")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
REQUIRED_CASE_KEYS = ("id", "code", "code_chars", "lines", "label", "pair", "project", "cwe", "truncated")
ITEM_FIELDS = ("id", "code", "label", "pair", "project", "src_idx")
DEFAULTS = {
    "dev": ("VSPDEV_DEV", "results/vsp_dev_cases.json"),
    "k1": ("VSPDEV_K1", "results/vsp_pilot_k1_items.json"),
    "k2_pilot": ("VSPDEV_K2_PILOT", "results/vsp_pilot_k2_items.json"),
    "k2_final": ("VSPDEV_K2_FINAL", "results/vsp_sft_k2_items.json"),
    "round1": ("VSPDEV_ROUND1", "results/vsp_sft_items.json"),
    "tcases": ("VSPDEV_TCASES", "results/vsp_t_cases.json"),
    "builder": ("VSPDEV_BUILDER", "scripts/imp_build_vsp_dev.py"),
}
BUILD_NAMES = {"dev": "vsp_dev_cases.json", "k1": "vsp_pilot_k1_items.json",
               "k2_pilot": "vsp_pilot_k2_items.json", "k2_final": "vsp_sft_k2_items.json"}
RESULTS = []


class State:
    """Lazy, cached loaders so each file or the parquet is read once per run."""

    def __init__(self, paths):
        self.paths = paths
        self._c = {}

    def cached(self, key, fn):
        if key not in self._c:
            self._c[key] = fn()
        return self._c[key]

    def load(self, which, field):
        def go():
            with open(self.paths[which], encoding="utf-8") as f:
                return json.load(f)[field]
        return self.cached(("file", which), go)

    @property
    def r1(self):
        return self.load("round1", "items")

    @property
    def dev(self):
        return self.load("dev", "cases")

    @property
    def tcases(self):
        return self.load("tcases", "cases")

    @property
    def vspt(self):
        return self.cached("vspt", lambda: ci.Ctx())

    @property
    def dev_tokens(self):
        return self.cached("devtok", lambda: [ci.token_set(c["code"]) for c in self.dev])

    @property
    def table(self):
        def go():
            import pandas as pd
            cols = ["idx", "project", "is_vulnerable", "fixed_func_idx", "func_body", "label_confidence", "func_name"]
            return pd.read_parquet(PARQUET, columns=cols).set_index("idx", drop=False)
        return self.cached("table", go)

    @property
    def train_split(self):
        return self.cached("train", lambda: set(json.load(open(SPLITS))["train"]))

    @property
    def vspt_norm(self):
        return self.cached("vsptnorm", lambda: [norm_token_set(c["code"]) for c in self.tcases])

    @property
    def dev_norm(self):
        return self.cached("devnorm", lambda: [norm_token_set(c["code"]) for c in self.dev])

    def norm_to(self, which, code):
        """Identifier-normalised max Jaccard of `code` to every VSP-T ("t") or dev ("d") function."""
        memo = self.cached(("nmemo", which), dict)
        if code not in memo:
            memo[code] = ci.max_jaccard(norm_token_set(code), self.vspt_norm if which == "t" else self.dev_norm)
        return memo[code]

    def jaccard_to_dev(self, code):
        memo = self.cached("jmemo", dict)
        if code not in memo:
            memo[code] = ci.max_jaccard(ci.token_set(code), self.dev_tokens)
        return memo[code]


# ---------------------------------------------------------------- helpers

def norm_ident(tok):
    """camelCase / PascalCase -> snake_case, lower-cased; non-identifier tokens are only lower-cased."""
    if tok[0].isalpha() or tok[0] == "_":
        return _CAMEL.sub("_", tok).lower()
    return tok


def norm_token_set(code):
    """check_vsp_items tokeniser, identifiers case-folded and camel/snake unified."""
    return frozenset(norm_ident(t) for t in ci.TOKEN.findall(code))


def pair_map(items):
    """pair -> {"V": item, "S": item}; duplicates or odd labels are kept visible via a list."""
    out = defaultdict(lambda: {"V": None, "S": None})
    for it in items:
        side = "V" if it["label"] == "VULNERABLE" else "S"
        out[it["pair"]][side] = it
    return dict(out)


def stratum_of(pm):
    lv, ls = len(pm["V"]["code"]), len(pm["S"]["code"])
    return "A" if ls > lv else ("B" if lv > ls else "E")


def adjacency_problems(items):
    bad = []
    if len(items) % 2:
        bad.append(f"odd item count {len(items)}")
    for i in range(len(items) // 2):
        v, s = items[2 * i], items[2 * i + 1]
        if v["label"] != "VULNERABLE" or s["label"] != "SAFE" or v["pair"] != s["pair"]:
            bad.append(f"slot {i}: {v['label']}/{s['label']} {v['pair']}/{s['pair']}")
    return bad


def pair_project(pm):
    return pm["V"]["project"]


def same_item(a, b):
    return all(a.get(k) == b.get(k) for k in ITEM_FIELDS)


def item_diffs(items, ref_by_id):
    """Items whose recorded fields differ from the round-1 item of the same id."""
    return [it["id"] for it in items if it["id"] in ref_by_id and not same_item(it, ref_by_id[it["id"]])]


def expected_dev_projects(r1):
    pm = pair_map(r1)
    b_by_proj, projects = Counter(), set()
    for p in pm.values():
        proj = pair_project(p)
        if proj == LINUX:
            continue
        projects.add(proj)
        if stratum_of(p) == "B":
            b_by_proj[proj] += 1
    order = sorted(projects, key=lambda x: hashlib.sha256((DEV_SALT + x).encode()).hexdigest())
    taken, b_total = [], 0
    for proj in order:
        if b_total >= DEV_B_TARGET:
            break
        if b_by_proj[proj] >= 1:
            taken.append(proj)
            b_total += b_by_proj[proj]
    rest = [p for p in order if p not in set(taken)]
    taken += rest[:math.ceil(DEV_EXTRA_FRAC * len(rest))]
    return set(taken)


def r1_pairs_by_project(r1):
    out = defaultdict(set)
    for pair, p in pair_map(r1).items():
        out[pair_project(p)].add(pair)
    return out


def jaccard_drop_pairs(state, pairs):
    """Pairs (from a pair map) with either side Jaccard >= JACCARD_MAX to any dev function."""
    return {k for k, p in pairs.items()
            if max(state.jaccard_to_dev(p["V"]["code"]), state.jaccard_to_dev(p["S"]["code"])) >= ci.JACCARD_MAX}


def extras_of(big, base):
    """Pair ids present in the item list `big` but not in `base` (both item lists)."""
    return set(pair_map(big)) - set(pair_map(base))


def linux_pool(state):
    """All linux pairs passing the round-1 eligibility filters, stratum B, high, not in r1, dev-clean."""
    def go():
        df, train = state.table, state.train_split
        vsp_hashes = {norm_hash(c["code"]) for c in state.tcases}
        t_tokens = state.vspt.test_tokens
        r1_pairs = set(pair_map(state.r1))
        sub = df[(df.project == LINUX) & df.idx.isin(train) & df.is_vulnerable & df.fixed_func_idx.notna()]
        pool = []
        for _, v in sub.iterrows():
            fx = int(v["fixed_func_idx"])
            pair = str(int(v["idx"]))
            if fx not in train or pair in r1_pairs or v["label_confidence"] != "high":
                continue
            vc, sc = strip_comments(v["func_body"]), strip_comments(df.loc[fx]["func_body"])
            if not _round1_eligible(vc, sc, vsp_hashes, t_tokens) or len(vc) <= len(sc):
                continue
            if max(state.jaccard_to_dev(vc), state.jaccard_to_dev(sc)) >= ci.JACCARD_MAX:
                continue
            if VENDORED_RE.match(str(v["func_name"])):
                continue
            if max(state.norm_to("t", vc), state.norm_to("t", sc), state.norm_to("d", vc),
                   state.norm_to("d", sc)) >= ci.JACCARD_MAX:
                continue
            pool.append((int(v["idx"]), fx, vc, sc))
        return pool
    return state.cached("pool", go)


def _round1_eligible(vc, sc, vsp_hashes, t_tokens):
    if not vc.strip() or not sc.strip() or vc == sc or len(vc) >= MAX_CHARS or len(sc) >= MAX_CHARS:
        return False
    if norm_hash(vc) in vsp_hashes or norm_hash(sc) in vsp_hashes:
        return False
    return max(ci.max_jaccard(ci.token_set(vc), t_tokens), ci.max_jaccard(ci.token_set(sc), t_tokens)) < ci.JACCARD_MAX


def sample_variants(pool):
    """The two readings of 'sorted by pair id' -> the pair-id sets random.Random(0).sample picks."""
    out = {}
    for name, key in (("numeric", lambda r: r[0]), ("lexicographic", lambda r: str(r[0]))):
        ordered = sorted(pool, key=key)
        if len(ordered) >= N_EXTRAS:
            out[name] = {str(r[0]) for r in random.Random(EXTRA_SEED).sample(ordered, N_EXTRAS)}
    return out


# ---------------------------------------------------------------- checks

def check_dev_rule(st):
    want, got = expected_dev_projects(st.r1), {c["project"] for c in st.dev}
    ok = want == got
    return ok, (f"{len(got)} dev projects match the rule" if ok else
                f"rule gives {len(want)} projects, file has {len(got)}; "
                f"missing {sorted(want - got)[:4]} unexpected {sorted(got - want)[:4]}")


def check_dev_subset(st):
    r1_projects = {it["project"] for it in st.r1}
    dev = {c["project"] for c in st.dev}
    extra, linux = sorted(dev - r1_projects), LINUX in dev
    ok = not extra and not linux
    return ok, f"{len(dev)} dev projects; not in round 1: {extra[:4]}; linux present: {linux}"


def check_dev_not_vspt(st):
    t_projects = {c["project"] for c in st.tcases}
    hashes = {norm_hash(c["code"]) for c in st.tcases}
    over = sorted({c["project"] for c in st.dev} & t_projects)
    dup = sum(1 for c in st.dev if norm_hash(c["code"]) in hashes)
    return not over and not dup, f"dev projects in VSP-T {over[:4]}; dev codes with a VSP-T hash {dup}"


def check_train_dev_disjoint(st):
    dev = {c["project"] for c in st.dev}
    msgs, ok = [], True
    for name in ("k1", "k2_pilot", "k2_final"):
        both = sorted({it["project"] for it in st.load(name, "items")} & dev)
        if name != "k2_final" and both:
            ok = False
        msgs.append(f"{name}: {len(both)} dev projects {both[:3]}")
    return ok, "; ".join(msgs) + " (k2_final is every round-1 item plus extras: dev overlap there is the design)"


def check_pilot_no_dev_leak(st):
    bad, msgs = 0, []
    for name in ("k1", "k2_pilot"):
        pm = pair_map(st.load(name, "items"))
        drops = jaccard_drop_pairs(st, pm)
        bad += len(drops)
        msgs.append(f"{name}: {len(drops)} of {len(pm)} pairs with a side Jaccard >= {ci.JACCARD_MAX} to a dev function")
    return bad == 0, "; ".join(msgs)


def check_dev_code_bytes(st):
    by_key = {(it["pair"], it["label"]): it for it in st.r1}
    bad = [c["id"] for c in st.dev if (c["pair"], c["label"]) not in by_key
           or by_key[(c["pair"], c["label"])]["code"] != c["code"]]
    dev_projects = {c["project"] for c in st.dev}
    want_pairs = {p for proj, ps in r1_pairs_by_project(st.r1).items() if proj in dev_projects for p in ps}
    dev_pairs = pair_map(st.dev)
    sets_ok = set(dev_pairs) == want_pairs and all(m["V"] and m["S"] for m in dev_pairs.values())
    return not bad and sets_ok, (f"{len(st.dev)} cases; {len(bad)} with code differing from or absent in "
                                 f"round 1 {bad[:3]}; pair set equals all round-1 pairs of dev projects: {sets_ok}")


def check_dev_counts(st):
    strata = Counter(stratum_of(p) for p in pair_map(st.dev).values() if p["V"] and p["S"])
    ok = strata["B"] >= MIN_DEV_B and strata["A"] >= MIN_DEV_A
    return ok, f"dev strata {dict(strata)} (need B >= {MIN_DEV_B}, A >= {MIN_DEV_A})"


def check_dev_schema(st):
    tkeys = set(st.tcases[0])
    need = set(REQUIRED_CASE_KEYS)
    if not need <= tkeys:
        return False, f"vsp_t_cases keys {sorted(tkeys)} lack {sorted(need - tkeys)}"
    bad = [c.get("id") for c in st.dev if not need <= set(c) or not set(c) <= tkeys]
    top = json.load(open(st.paths["dev"]))
    return not bad and "cases" in top, f"{len(bad)} cases whose keys are not within vsp_t_cases keys {bad[:3]}"


def check_k1_rule(st):
    dev_projects = {c["project"] for c in st.dev}
    r1_by_id = {it["id"]: it for it in st.r1}
    outside = {k: p for k, p in pair_map(st.r1).items() if pair_project(p) not in dev_projects}
    want = set(outside) - jaccard_drop_pairs(st, outside)
    items = st.load("k1", "items")
    got = set(pair_map(items))
    diffs, adj = item_diffs(items, r1_by_id), adjacency_problems(items)
    foreign = [it["id"] for it in items if it["id"] not in r1_by_id]
    ok = want == got and not diffs and not adj and not foreign
    return ok, (f"k1 {len(got)} pairs vs expected {len(want)}; missing {len(want - got)} unexpected {len(got - want)}; "
                f"items altered {len(diffs)}; not in round 1 {len(foreign)}; adjacency problems {adj[:2]}")


def check_k2_pilot(st):
    k1, k2 = st.load("k1", "items"), st.load("k2_pilot", "items")
    extras = extras_of(k2, k1)
    r1_by_id = {it["id"]: it for it in st.r1}
    k1_ids = {it["id"] for it in k1}
    base_in_k2 = {it["id"] for it in k2} >= k1_ids
    ok = base_in_k2 and len(extras) == N_EXTRAS and not item_diffs(k2, r1_by_id) and not adjacency_problems(k2)
    return ok, (f"k2 pilot has {len(extras)} pairs beyond k1; contains every k1 item: {base_in_k2}; "
                f"adjacency problems {adjacency_problems(k2)[:2]}")


def check_k2_final(st):
    r1, k2 = st.r1, st.load("k2_final", "items")
    r1_ids = {it["id"] for it in r1}
    have = {it["id"]: it for it in k2}
    missing = [i for i in r1_ids if i not in have]
    altered = item_diffs(k2, {it["id"]: it for it in r1})
    extras = extras_of(k2, r1)
    ok = not missing and not altered and len(extras) == N_EXTRAS and not adjacency_problems(k2)
    return ok, (f"{len(missing)} round-1 items missing from k2 final; {len(altered)} altered; "
                f"{len(extras)} pairs beyond round 1; adjacency problems {adjacency_problems(k2)[:2]}")


def check_extras_identical(st):
    a = extras_of(st.load("k2_pilot", "items"), st.load("k1", "items"))
    b = extras_of(st.load("k2_final", "items"), st.r1)
    pa, pb = pair_map(st.load("k2_pilot", "items")), pair_map(st.load("k2_final", "items"))
    same_items = all(same_item(pa[k][s], pb[k][s]) for k in a & b for s in "VS")
    ok = len(a) == len(b) == N_EXTRAS and a == b and same_items
    return ok, f"extras pilot {len(a)} final {len(b)}; identical pair sets {a == b}; identical items {same_items}"


def check_extras_props(st):
    final = st.load("k2_final", "items")
    extras = extras_of(final, st.r1)
    pm, df, train = pair_map(final), st.table, st.train_split
    problems = []
    for pair in sorted(extras):
        p = pm[pair]
        problems += _extra_problems(st, pair, p, df, train)
    return not problems, f"{len(extras)} extras, {len(problems)} problems: {problems[:4]}"


def _extra_problems(st, pair, p, df, train):
    out = []
    if not (p["V"] and p["S"]):
        return [f"{pair}: missing side"]
    if pair_project(p) != LINUX or p["S"]["project"] != LINUX:
        out.append(f"{pair}: project {pair_project(p)}")
    if stratum_of(p) != "B":
        out.append(f"{pair}: stratum {stratum_of(p)} (vulnerable not strictly longer)")
    vi, si = p["V"]["src_idx"], p["S"]["src_idx"]
    if str(vi) != pair or vi not in df.index or si not in df.index:
        return out + [f"{pair}: src_idx not a parquet row"]
    v, s = df.loc[vi], df.loc[si]
    if vi not in train or si not in train:
        out.append(f"{pair}: not both in train split")
    if v["label_confidence"] != "high":
        out.append(f"{pair}: label_confidence {v['label_confidence']}")
    if not v["is_vulnerable"] or s["is_vulnerable"] or v["fixed_func_idx"] != si:
        out.append(f"{pair}: not a vulnerable row with its fixed twin")
    if strip_comments(v["func_body"]) != p["V"]["code"] or strip_comments(s["func_body"]) != p["S"]["code"]:
        out.append(f"{pair}: code is not comment-stripped parquet text")
    if max(st.jaccard_to_dev(p["V"]["code"]), st.jaccard_to_dev(p["S"]["code"])) >= ci.JACCARD_MAX:
        out.append(f"{pair}: Jaccard >= {ci.JACCARD_MAX} to a dev function")
    return out


def check_extras_not_in_r1(st):
    r1 = set(pair_map(st.r1))
    r1_src = {it["src_idx"] for it in st.r1}
    final = st.load("k2_final", "items")
    pm = pair_map(final)
    extras = extras_of(final, st.r1)
    clash = [p for p in extras if p in r1 or any(pm[p][s] and pm[p][s]["src_idx"] in r1_src for s in "VS")]
    all_r1_present = r1 <= set(pm)
    return not clash and all_r1_present, (f"{len(clash)} extras colliding with round 1; "
                                          f"every round-1 pair in k2 final: {all_r1_present}")


def check_extras_sample(st):
    pool = linux_pool(st)
    extras = {str(p) for p in extras_of(st.load("k2_final", "items"), st.r1)}
    in_pool = extras <= {str(r[0]) for r in pool}
    variants = sample_variants(pool)
    hit = [n for n, s in variants.items() if s == extras]
    ok = in_pool and bool(hit)
    return ok, (f"eligibility pool {len(pool)} pairs; extras all in pool: {in_pool}; "
                f"equals random.Random(0).sample(300) under: {hit or 'neither numeric nor lexicographic order'}")


def check_norm_near_dup(st):
    """Identifier-normalised near-duplicates: any file side vs VSP-T, and pilot sides vs dev."""
    jobs = (("dev", st.dev, "t"), ("k1", st.load("k1", "items"), "t"), ("k2_pilot", st.load("k2_pilot", "items"), "t"),
            ("k2_final", st.load("k2_final", "items"), "t"), ("round1", st.r1, "t"),
            ("k1", st.load("k1", "items"), "d"), ("k2_pilot", st.load("k2_pilot", "items"), "d"))
    hits, best = [], 0.0
    for name, items, which in jobs:
        for it in items:
            j = st.norm_to(which, it["code"])
            best = max(best, j)
            if j >= ci.JACCARD_MAX:
                hits.append(f"{name}~{'VSP-T' if which == 't' else 'dev'}:{it['pair']}:{it['label'][0]}={j:.2f}")
    hits = sorted(set(hits))
    return not hits, (f"{len(hits)} side(s) with identifier-normalised Jaccard >= {ci.JACCARD_MAX} {hits[:6]}; "
                      f"max {best:.3f}")


def check_vendored_acpica(st):
    """No K2 extra whose linux function is a vendored ACPICA core function (ACPICA is a VSP-T project)."""
    df, bad = st.table, []
    for name, base in (("k2_pilot", st.load("k1", "items")), ("k2_final", st.r1)):
        items = st.load(name, "items")
        pm = pair_map(items)
        for pair in sorted(extras_of(items, base)):
            fn = str(df.loc[pm[pair]["V"]["src_idx"]]["func_name"]) if pm[pair]["V"] else ""
            if VENDORED_RE.match(fn):
                bad.append(f"{name}:{pair}:{fn}")
    r1_hits = sum(1 for it in st.r1 if it["project"] == LINUX and it["label"] == "VULNERABLE"
                  and VENDORED_RE.match(str(df.loc[it["src_idx"]]["func_name"])))
    return not bad, f"{len(bad)} vendored-ACPICA extras {bad[:6]}; (info: round-1 linux vendored-ACPICA pairs {r1_hits})"


def vspt_verdict(st, name, items, pilot):
    results = ci.run_all(items, st.vspt)
    fired = {c: msg for c, (f, msg) in results.items() if f}
    pp = defaultdict(set)
    for it in items:
        pp[it["project"]].add(it["pair"])
    over = {p for p, s in pp.items() if len(s) > ci.MAX_PAIRS_PER_PROJECT}
    tolerated = []
    if "PROJECT_CAP" in fired and over == {LINUX} and len(pp[LINUX]) <= LINUX_CAP_AFTER_EXTRAS:
        tolerated.append("PROJECT_CAP")
    if "FLOOR" in fired and pilot:
        tolerated.append("FLOOR")
    bad = sorted(set(fired) - set(tolerated))
    return not bad, f"{name}: refused {bad or 'none'}; tolerated {tolerated or 'none'}" + "".join(
        f"\n    {c}: {fired[c]}" for c in bad)


def check_vspt(which, pilot):
    def run(st):
        items = st.load(which, "items")
        return vspt_verdict(st, which, items, pilot)
    return run


def check_rebuild(st):
    builder = Path(st.paths["builder"])
    if not builder.is_file():
        return False, f"builder {builder} does not exist"
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run([PY, str(builder), "--out-dir", tmp], cwd=ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            return False, f"builder exit {proc.returncode}: {(proc.stderr or proc.stdout).strip()[-300:]}"
        bad = []
        for key, name in BUILD_NAMES.items():
            rebuilt = Path(tmp) / name
            if not rebuilt.is_file():
                bad.append(f"{name} not written")
            elif _sha(rebuilt) != _sha(Path(st.paths[key])):
                bad.append(f"{name} differs")
    return not bad, "rebuilt files byte-identical (sha256) to the committed ones" if not bad else "; ".join(bad)


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_verdict_dev(st):
    cases = st.dev
    rng = random.Random(7)
    with tempfile.TemporaryDirectory() as tmp:
        files = {}
        for arm, sig, noise in (("adapter", 0.22, 0.25), ("base", 0.02, 0.25)):
            per = [{"id": c["id"], "label": c["label"],
                    "p_vuln": min(1.0, max(0.0, 0.5 + (sig if c["label"] == "VULNERABLE" else -sig)
                                           + rng.uniform(-noise, noise)))} for c in cases]
            files[arm] = os.path.join(tmp, arm + ".json")
            json.dump({"method": "logprob-scored (synthetic acceptance fixture)", "per_case": per},
                      open(files[arm], "w"))
        out = os.path.join(tmp, "verdict.json")
        cmd = [PY, "scripts/imp_verdict.py", "round", "--cases", st.paths["dev"], "--adapter", files["adapter"],
               "--base", files["base"], "--z", "2.394", "--cluster-bootstrap", "--cluster-by", "project",
               "--pair-veto", "--baselines", "length,lines,if_count,static_count", "--out", out]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            return False, f"imp_verdict exit {proc.returncode}: {proc.stderr.strip()[-300:]}"
        pv = json.load(open(out)).get("pair_veto", {})
    n_v = pv.get("n_v_longer", -1)
    return n_v >= MIN_DEV_B, f"imp_verdict exit 0; pair_veto n_v_longer={n_v} n_s_longer={pv.get('n_s_longer')}"


CHECKS = [
    ("DEV_PROJECT_RULE", check_dev_rule),
    ("DEV_SUBSET_NO_LINUX", check_dev_subset),
    ("DEV_NOT_VSPT", check_dev_not_vspt),
    ("TRAIN_DEV_DISJOINT", check_train_dev_disjoint),
    ("PILOT_NO_DEV_LEAK", check_pilot_no_dev_leak),
    ("DEV_CODE_BYTES", check_dev_code_bytes),
    ("DEV_COUNTS", check_dev_counts),
    ("DEV_SCHEMA", check_dev_schema),
    ("K1_RULE", check_k1_rule),
    ("K2_PILOT", check_k2_pilot),
    ("K2_FINAL", check_k2_final),
    ("EXTRAS_IDENTICAL", check_extras_identical),
    ("EXTRAS_PROPS", check_extras_props),
    ("EXTRAS_NOT_IN_R1", check_extras_not_in_r1),
    ("EXTRAS_SAMPLE", check_extras_sample),
    ("NORM_NEAR_DUP", check_norm_near_dup),
    ("VENDORED_ACPICA", check_vendored_acpica),
    ("VSPT_K2_FINAL", check_vspt("k2_final", False)),
    ("VSPT_K1", check_vspt("k1", True)),
    ("VSPT_K2_PILOT", check_vspt("k2_pilot", True)),
    ("REBUILD", check_rebuild),
    ("VERDICT", check_verdict_dev),
]


def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    for key, (env, default) in DEFAULTS.items():
        ap.add_argument("--" + key.replace("_", "-"), default=os.environ.get(env, str(ROOT / default)))
    ap.add_argument("--skip-checks", default="", help="mutant self-test only")
    a = ap.parse_args(argv)
    skip = {x for x in a.skip_checks.split(",") if x}
    unknown = skip - {n for n, _ in CHECKS}
    if unknown:
        ap.error(f"unknown check names {sorted(unknown)}")
    return {k: getattr(a, k) for k in DEFAULTS}, skip


def main(argv=None):
    paths, skip = parse(argv)
    state = State(paths)
    failed = 0
    for name, fn in CHECKS:
        if name in skip:
            print(f"SKIP {name}")
            continue
        try:
            ok, detail = fn(state)
        except Exception as exc:  # noqa: BLE001  a missing or malformed file is a FAIL, never a crash
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        print(("PASS " if ok else "FAIL ") + name + " - " + detail)
        failed += 0 if ok else 1
    print(f"RESULT: {'PASS' if not failed else 'FAIL'} ({failed} failed" +
          (f", {len(skip)} skipped" if skip else "") + ")")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
