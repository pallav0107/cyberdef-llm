"""Shared helpers for the K4 acceptance checkers (check_vsp_dev2.py, check_vsp_k4_items.py, check_vsp_probe.py,
check_site_targets.py, check_pairdom.py, check_ci_k4.py). Not a checker itself.

Everything here is recomputed from the parquet, results/vsp_sft_items.json, results/vsp_t_cases.json and the
cycle-1 dev file, independently of any K4 builder (none exists yet). check_vsp_dev (cd) and check_vsp_items (ci)
are reused by import, as the cycle-1 checkers do.

Rules encoded (CURRENT_PLAN.md, Amendment 1):
  dev2 core        every non-linux round-1 project that is not a cycle-1 dev project and holds >= 1 stratum-B pair:
                   all of its round-1 pairs.
  dev2 supplement  VulSpot test-split pairs (both rows in the test split) of projects that are in neither VSP-T,
                   round 1, cycle-1 dev nor FORK_PROJECTS, passing every round-1 filter (non-empty, differing,
                   < 4000 chars after comment stripping, no VSP-T hash, raw Jaccard < 0.5 to VSP-T) plus the
                   identifier-normalised Jaccard < 0.5 rule; label_confidence any, flagged per case.
  probe pool       linux pairs with both rows in the VulSpot val split, label_confidence high, the same round-1
                   filters and normalised rule, strata A or B only, not a vendored ACPICA function, not a round-1
                   pair; the probe is the first 150 A and first 150 B of the leak-clean pool in sha256 order.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _p in (HERE, ROOT / "scripts", ROOT / "src"):
    sys.path.insert(0, str(_p))
import check_vsp_dev as cd  # noqa: E402
import check_vsp_items as ci  # noqa: E402

DEV2_SALT = "vspdev-v2|"
PROBE_SALT = "vspprobe-v1"          # the spec writes sha256(vspprobe-v1 + pair id); a "|" separator is also accepted
PROBE_N = 150
LINUX = cd.LINUX
PATHS = {
    "dev2": "results/vsp_dev2_cases.json",
    "probe": "results/vsp_probe_cases.json",
    "k4_pilot": "results/vsp_pilot_k4_items.json",
    "k4_final": "results/vsp_sft_k4_items.json",
    "k4b_pilot": "results/vsp_pilot_k4b_items.json",
}
EXTRA_CASE_KEYS = ("label_confidence", "source")   # dev2 / probe cases may carry these beyond vsp_t_cases keys


def make_state(overrides=None):
    """cd.State with the cycle-1 paths plus the K4 paths; an override of empty string means not used."""
    paths = {k: str(ROOT / v[1]) for k, v in cd.DEFAULTS.items()}
    paths.update({k: str(ROOT / v) for k, v in PATHS.items()})
    for k, v in (overrides or {}).items():
        if v is not None:
            paths[k] = v
    return cd.State(paths)


def present(st, which):
    p = st.paths.get(which, "")
    return bool(p) and Path(p).is_file()


def need(st, *names):
    """Raise FileNotFoundError (reported as target not built yet) for the first missing path."""
    for n in names:
        p = st.paths.get(n, "")
        if not p or not Path(p).is_file():
            raise FileNotFoundError(p or n)


def cases(st, which):
    return st.load(which, "cases")


def items(st, which):
    return st.load(which, "items")


def splits(st):
    return st.cached("splits", lambda: json.load(open(cd.SPLITS)))


def split_set(st, name):
    return st.cached(("split", name), lambda: set(splits(st)[name]))


class RefSet:
    """Reference functions; score(code) = max(raw token-set Jaccard, identifier-normalised Jaccard)."""

    def __init__(self, codes):
        uniq = sorted(set(codes))
        self.n = len(uniq)
        self.raw = [ci.token_set(c) for c in uniq]
        self.norm = [cd.norm_token_set(c) for c in uniq]
        self.memo = {}

    def score(self, code):
        if code not in self.memo:
            self.memo[code] = max(ci.max_jaccard(ci.token_set(code), self.raw),
                                  ci.max_jaccard(cd.norm_token_set(code), self.norm))
        return self.memo[code]

    def pair_score(self, pm):
        return max(self.score(pm["V"]["code"]), self.score(pm["S"]["code"]))


def ref_of(st, key, which, field):
    """Cached RefSet over the codes of one cases / items file."""
    return st.cached(("ref", key), lambda: RefSet([c["code"] for c in st.load(which, field)]))


def vspt_ref(st):
    return st.cached(("ref", "vspt"), lambda: RefSet([c["code"] for c in st.tcases]))


def near_pairs(ref, pm, skip=()):
    """Pair ids of pair map pm with a side (raw or normalised) Jaccard >= JACCARD_MAX to ref."""
    return sorted(k for k, p in pm.items() if k not in skip and p["V"] and p["S"]
                  and ref.pair_score(p) >= ci.JACCARD_MAX)


def strata(items_):
    return {k: cd.stratum_of(p) for k, p in cd.pair_map(items_).items() if p["V"] and p["S"]}


def projects_of(items_):
    return {it["project"] for it in items_}


def r1_projects(st):
    return {it["project"] for it in st.r1}


def sha_order(salt, ids):
    return sorted(ids, key=lambda i: hashlib.sha256((salt + str(i)).encode()).hexdigest())


# ------------------------------------------------------------------ dev2 reference

def round1_clean(st, vc, sc):
    """Round-1 pair filters + the identifier-normalised VSP-T rule, on comment-stripped code."""
    vsp_hashes = st.cached("vsphash", lambda: {cd.norm_hash(c["code"]) for c in st.tcases})
    if not cd._round1_eligible(vc, sc, vsp_hashes, st.vspt.test_tokens):
        return False
    return max(st.norm_to("t", vc), st.norm_to("t", sc)) < ci.JACCARD_MAX


def expected_dev2(st):
    """core_projects, core (pair ids) and supp (pair -> dict(vidx, fx, vc, sc, conf, project))."""
    def go():
        pm = cd.pair_map(st.r1)
        dev1 = {c["project"] for c in st.dev}
        b = Counter()
        for p in pm.values():
            proj = cd.pair_project(p)
            if proj != LINUX and proj not in dev1 and cd.stratum_of(p) == "B":
                b[proj] += 1
        core_projects = {proj for proj, n in b.items() if n >= 1}
        core = {k for k, p in pm.items() if cd.pair_project(p) in core_projects}
        df, test = st.table, split_set(st, "test")
        excluded = {c["project"] for c in st.tcases} | r1_projects(st) | dev1 | set(ci.FORK_PROJECTS) | {LINUX}
        sub = df[df.is_vulnerable & df.fixed_func_idx.notna() & df.idx.isin(test) & ~df.project.isin(excluded)]
        supp = {}
        for _, v in sub.iterrows():
            fx = int(v["fixed_func_idx"])
            if fx not in test or fx not in df.index:
                continue
            vc, sc = cd.strip_comments(v["func_body"]), cd.strip_comments(df.loc[fx]["func_body"])
            if round1_clean(st, vc, sc):
                supp[str(int(v["idx"]))] = {"vidx": int(v["idx"]), "fx": fx, "vc": vc, "sc": sc,
                                            "conf": v["label_confidence"], "project": v["project"]}
        return {"core_projects": core_projects, "core": core, "supp": supp}
    return st.cached("exp_dev2", go)


# ------------------------------------------------------------------ probe pool

def probe_pool(st):
    """Eligible val-split linux pairs before the leak filters against dev / dev2 / training: pair -> dict."""
    def go():
        df, val = st.table, split_set(st, "val")
        r1_pairs = set(cd.pair_map(st.r1))
        sub = df[(df.project == LINUX) & df.idx.isin(val) & df.is_vulnerable & df.fixed_func_idx.notna()]
        out = {}
        for _, v in sub.iterrows():
            fx = int(v["fixed_func_idx"])
            pair = str(int(v["idx"]))
            if fx not in val or fx not in df.index or pair in r1_pairs or v["label_confidence"] != "high":
                continue
            if cd.VENDORED_RE.match(str(v["func_name"])):
                continue
            vc, sc = cd.strip_comments(v["func_body"]), cd.strip_comments(df.loc[fx]["func_body"])
            if len(vc) == len(sc) or not round1_clean(st, vc, sc):
                continue
            out[pair] = {"vidx": int(v["idx"]), "fx": fx, "vc": vc, "sc": sc,
                         "stratum": "A" if len(sc) > len(vc) else "B"}
        return out
    return st.cached("probe_pool", go)


# ------------------------------------------------------------------ runner

def run_checks(checks, st, skip=()):
    failed = 0
    for name, fn in checks:
        if name in skip:
            print("SKIP " + name)
            continue
        try:
            ok, detail = fn(st)
        except FileNotFoundError as exc:
            ok, detail = False, "target not built yet: " + str(exc.filename or exc)
        except Exception as exc:  # noqa: BLE001  a missing or malformed file is a FAIL, never a crash
            ok, detail = False, type(exc).__name__ + ": " + str(exc)
        print(("PASS " if ok else "FAIL ") + name + " - " + detail, flush=True)
        failed += 0 if ok else 1
    word = "FAIL" if failed else "PASS"
    extra = f", {len(skip)} skipped" if skip else ""
    print(f"RESULT: {word} ({failed} failed{extra})")
    return 1 if failed else 0


def case_schema_problems(case_list):
    """Dev-style cases must carry every vsp_t_cases key the scorer needs."""
    need_keys = set(cd.REQUIRED_CASE_KEYS)
    return [f"{c.get(chr(105) + chr(100))}: missing {sorted(need_keys - set(c))}" for c in case_list
            if not need_keys <= set(c)]
