#!/usr/bin/env python3
"""Build the K4 data: cycle-2 dev split (dev2), the K4a / K4b pilot item files, the K4 final item file and the
linux held-out probe set. Deterministic; reads only the round-1 items, the cycle-1 dev / K2 files, the VulSpot parquet
and (for leak rules only) results/vsp_t_cases.json. No per-pair VSP-T result is ever read.

Writes into --out-dir (default results/):
  vsp_dev2_cases.json        cycle-2 dev split (CURRENT_PLAN.md, Amendment 1)
  vsp_pilot_k4_items.json    K4a pilot training items
  vsp_pilot_k4b_items.json   K4b pilot items: the same items, target = "VERDICT: <label>\\nSITE: <line>"
  vsp_sft_k4_items.json      K4 final training items (dev2 folded back)
  vsp_sft_k4b_items.json     K4b final items: the K4 final items, target = "VERDICT: <label>\nSITE: <line>" (attempt 5)
  vsp_probe_cases.json       linux held-out set (150 A + 150 B), descriptive / probe P1

Rules (acceptance contract: acceptance/improve/check_vsp_dev2.py, check_vsp_k4_items.py, check_vsp_probe.py,
check_site_targets.py):
  dev2 core        every non-linux round-1 project that is not a cycle-1 dev project and holds >= 1 stratum-B pair:
                   all its round-1 pairs, code unchanged.
  dev2 supplement  VulSpot test-split pairs (both rows test) of projects in none of VSP-T, round 1, cycle-1 dev, the fork
                   list or linux, passing the round-1 filters plus the identifier-normalised VSP-T rule.
  pilot            round-1 pairs of non-dev2 projects, minus pairs with a side at raw or identifier-normalised Jaccard
                   >= 0.5 to a dev2 or probe function (cycle-1 dev is folded back), plus the linux extras.
  linux extras     the K2 extras (stratum B, existing seed 0 sample; those near a dev2 function dropped) plus new
                   stratum-A extras drawn with the same rule and seed (sorted by numeric pair id, random.Random(0).sample)
                   until linux A equals linux B.
  final            round-1 pairs minus pairs near a VSP-T / dev2-supplement / probe function, plus the same extras
                   (dev2 core stays in).
  probe            val-split linux pairs, label_confidence high, round-1 filters + normalised rule, not vendored ACPICA,
                   not round 1; the first 150 A and 150 B, in sha256(vspprobe-v1 + pair id) order, whose functions are
                   below Jaccard 0.5 to VSP-T, cycle-1 dev, dev2 and every training file.
  K4b target       difflib on the pair's lines: the first line of that side changed by the fix; with no changed line on
                   that side, the first line after the edit point, else the last line before it.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

import imp_build_vsp_dev as bd   # its import also puts scripts/ and acceptance/improve/ on sys.path
from imp_build_vsp_dev import LINUX, VENDORED_RE, norm_token_set, pair_map

bt = bd.bt
ROOT = bd.ROOT
token_set, max_jaccard, JACCARD_MAX, FORK_PROJECTS = bd.token_set, bd.max_jaccard, bd.JACCARD_MAX, bd.FORK_PROJECTS

DEV2_SALT = "vspdev-v2|"
PROBE_SALT = "vspprobe-v1"
PROBE_N = 150
EXTRA_SEED = bd.EXTRA_SEED
MAX_CHARS = bt.MAX_CHARS
FILES = {"dev2": "vsp_dev2_cases.json", "pilot": "vsp_pilot_k4_items.json", "pilot_b": "vsp_pilot_k4b_items.json",
         "final": "vsp_sft_k4_items.json", "final_b": "vsp_sft_k4b_items.json", "probe": "vsp_probe_cases.json"}
COLS = ("idx", "project", "is_vulnerable", "fixed_func_idx", "func_body", "cwe_1003_list", "label_confidence",
        "func_name")
DEV2_NOTE = ("VSP-DEV2 (cycle 2): every remaining non-linux round-1 project holding a stratum-B pair (core) plus "
             "VulSpot test-split pairs of projects in neither VSP-T, round 1, cycle-1 dev nor the fork list "
             "(supplement); pilot-only test set (never VSP-T); build rules in scripts/imp_build_vsp_k4.py")
PROBE_NOTE = ("Linux held-out set (probe P1): 150 A + 150 B high-confidence VulSpot val-split linux pairs. NOT "
              "project-disjoint from training (linux is split by pair): descriptive only, outside the gate unless "
              "the owner signs off in writing; build rules in scripts/imp_build_vsp_k4.py")
ITEMS_NOTE = "built by scripts/imp_build_vsp_k4.py from results/vsp_sft_items.json; see that file for the rules"


class Ref:
    """Reference functions; score(code) = max(raw token-set Jaccard, identifier-normalised Jaccard)."""

    def __init__(self, codes):
        uniq = sorted(set(codes))
        self.n = len(uniq)
        self.raw = [token_set(c) for c in uniq]
        self.norm = [norm_token_set(c) for c in uniq]
        self.memo = {}

    def score(self, code):
        if code not in self.memo:
            self.memo[code] = max(max_jaccard(token_set(code), self.raw), max_jaccard(norm_token_set(code), self.norm))
        return self.memo[code]

    def pair_near(self, vc, sc):
        return max(self.score(vc), self.score(sc)) >= JACCARD_MAX


def stratum(vc, sc):
    return "A" if len(sc) > len(vc) else ("B" if len(vc) > len(sc) else "E")


def case_of(prefix, item_or_row, code, label, pair, project, cwe, source, conf=None):
    c = {"id": f"{prefix}:{pair}:{'V' if label == 'VULNERABLE' else 'S'}", "code": code, "code_chars": len(code),
         "lines": code.count("\n") + 1, "label": label, "pair": pair, "project": project, "cwe": list(cwe),
         "truncated": False, "source": source}
    if conf is not None:
        c["label_confidence"] = conf
    return c


class Build:
    def __init__(self):
        import pandas as pd
        self.r1 = json.load(open(bd.ROUND1, encoding="utf-8"))["items"]
        self.r1pm = pair_map(self.r1)
        self.dev1 = json.load(open(ROOT / "results/vsp_dev_cases.json", encoding="utf-8"))["cases"]
        self.dev1_projects = {c["project"] for c in self.dev1}
        self.tcases = json.load(open(bt.TEST_CASES, encoding="utf-8"))["cases"]   # leak rules only
        self.t_projects = {c["project"] for c in self.tcases}
        self.t_hashes = {bt.norm_hash(c["code"]) for c in self.tcases}
        self.vspt = Ref([c["code"] for c in self.tcases])
        self.splits = {k: set(v) for k, v in json.load(open(bt.SPLITS)).items() if isinstance(v, list)}
        self.df = pd.read_parquet(bt.PARQUET, columns=list(COLS)).set_index("idx", drop=False)
        self.stats = {}

    # ---------------------------------------------------------------- shared filter
    def clean(self, vc, sc):
        """Round-1 pair filters + identifier-normalised VSP-T rule, on comment-stripped code."""
        if not vc.strip() or not sc.strip() or vc == sc or len(vc) >= MAX_CHARS or len(sc) >= MAX_CHARS:
            return False
        if bt.norm_hash(vc) in self.t_hashes or bt.norm_hash(sc) in self.t_hashes:
            return False
        return not self.vspt.pair_near(vc, sc)

    # ---------------------------------------------------------------- dev2
    def dev2(self):
        b = Counter()
        for p in self.r1pm.values():
            proj = p["V"]["project"]
            if proj != LINUX and proj not in self.dev1_projects and len(p["V"]["code"]) > len(p["S"]["code"]):
                b[proj] += 1
        core_projects = {p for p, n in b.items() if n >= 1}
        order = sorted(core_projects, key=lambda p: hashlib.sha256((DEV2_SALT + p).encode()).hexdigest())
        rank = {p: i for i, p in enumerate(order)}
        core_pairs = sorted((k for k, p in self.r1pm.items() if p["V"]["project"] in core_projects),
                            key=lambda k: (rank[self.r1pm[k]["V"]["project"]], int(k)))
        cases = []
        for k in core_pairs:
            for side in ("V", "S"):
                it = self.r1pm[k][side]
                cases.append(case_of("vspdev2", it, it["code"], it["label"], k, it["project"], it["cwe"], "core"))
        # supplement
        df, test = self.df, self.splits["test"]
        excluded = self.t_projects | {it["project"] for it in self.r1} | self.dev1_projects | set(FORK_PROJECTS) | {LINUX}
        sub = df[df.is_vulnerable & df.fixed_func_idx.notna() & df.idx.isin(test) & ~df.project.isin(excluded)]
        supp = []
        for _, v in sub.iterrows():
            fx = int(v["fixed_func_idx"])
            if fx not in test or fx not in df.index:
                continue
            vc, sc = bt.strip_comments(v["func_body"]), bt.strip_comments(df.loc[fx]["func_body"])
            if self.clean(vc, sc):
                supp.append((int(v["idx"]), fx, vc, sc, v, df.loc[fx]))
        supp.sort(key=lambda r: (hashlib.sha256((DEV2_SALT + r[4]["project"]).encode()).hexdigest(), r[0]))
        n_supp = 0
        for vi, fx, vc, sc, v, s in supp:
            cwe = [str(x) for x in v["cwe_1003_list"]]
            cases.append(case_of("vspdev2", v, vc, "VULNERABLE", str(vi), v["project"], cwe, "supplement",
                                 v["label_confidence"]))
            cases.append(case_of("vspdev2", s, sc, "SAFE", str(vi), v["project"], cwe, "supplement",
                                 v["label_confidence"]))
            n_supp += 1
        pm = pair_map(cases)
        st = Counter(stratum(p["V"]["code"], p["S"]["code"]) for p in pm.values())
        core_set = set(core_pairs)
        st_core = Counter(stratum(pm[k]["V"]["code"], pm[k]["S"]["code"]) for k in core_set)
        self.stats["dev2"] = {"projects": len({c["project"] for c in cases}), "core_projects": len(core_projects),
                              "pairs": len(pm), "core_pairs": len(core_set), "supplement_pairs": n_supp,
                              "A": st["A"], "B": st["B"], "E": st["E"], "core_A": st_core["A"],
                              "core_B": st_core["B"], "core_E": st_core["E"]}
        self.dev2_cases, self.dev2_core_pairs = cases, core_set
        self.dev2_projects = {c["project"] for c in cases}
        self.dev2_supp_ref = Ref([c["code"] for c in cases if c["pair"] not in core_set])
        self.dev2_ref = Ref([c["code"] for c in cases])

    # ---------------------------------------------------------------- K4 items
    def k2_extras(self):
        """The 300 K2 linux extras (items beyond round 1), in file order."""
        k2 = json.load(open(ROOT / "results/vsp_sft_k2_items.json", encoding="utf-8"))["items"]
        return [it for it in k2 if it["pair"] not in self.r1pm]

    def a_pool(self):
        """Linux stratum-A pool, mirroring bd.linux_extras but for A, against VSP-T and dev2."""
        df, train = self.df, self.splits["train"]
        sub = df[(df.project == LINUX) & df.idx.isin(train) & df.is_vulnerable & df.fixed_func_idx.notna()]
        pool, excl = [], Counter()
        for _, v in sub.iterrows():
            fx = int(v["fixed_func_idx"])
            pair = str(int(v["idx"]))
            if fx not in train or pair in self.r1pm or v["label_confidence"] != "high":
                continue
            if VENDORED_RE.match(str(v["func_name"])):
                excl["vendored_acpica"] += 1
                continue
            vc, sc = bt.strip_comments(v["func_body"]), bt.strip_comments(df.loc[fx]["func_body"])
            if len(sc) <= len(vc) or not self.clean(vc, sc):
                continue
            if self.dev2_ref.pair_near(vc, sc):
                excl["near_dev2"] += 1
                continue
            pool.append((int(v["idx"]), fx, vc, sc, [str(x) for x in v["cwe_1003_list"]]))
        pool.sort(key=lambda r: r[0])
        self.stats["a_pool"] = {"pool": len(pool), "excluded": dict(excl)}
        return pool

    def k4_items(self):
        r1 = self.r1
        d2p, ref2 = self.dev2_projects, self.dev2_ref
        pilot_r1 = [it for it in r1 if it["project"] not in d2p
                    and not ref2.pair_near(self.r1pm[it["pair"]]["V"]["code"], self.r1pm[it["pair"]]["S"]["code"])]
        dropped_near = sorted({it["pair"] for it in r1 if it["project"] not in d2p} - {it["pair"] for it in pilot_r1},
                              key=int)
        # final: dev2 folded back; only leak-style drops (near dev2 supplement)
        final_r1, final_dropped = [], []
        for it in r1:
            p = self.r1pm[it["pair"]]
            if self.dev2_supp_ref.pair_near(p["V"]["code"], p["S"]["code"]) or self.vspt.pair_near(
                    p["V"]["code"], p["S"]["code"]):
                final_dropped.append(it["pair"])
            else:
                final_r1.append(it)
        # linux B extras: the K2 extras minus those near dev2
        k2x = self.k2_extras()
        k2p = pair_map(k2x)
        keep_b = [k for k in k2p if not ref2.pair_near(k2p[k]["V"]["code"], k2p[k]["S"]["code"])]
        b_items = [it for it in k2x if it["pair"] in set(keep_b)]
        # linux A / B in each file before A extras
        def lin(items):
            c = Counter()
            for k, p in pair_map(items).items():
                if p["V"]["project"] == LINUX:
                    c[stratum(p["V"]["code"], p["S"]["code"])] += 1
            return c
        cp, cf = lin(pilot_r1 + b_items), lin(final_r1 + b_items)
        self.stats["linux_before_A_extras"] = {"pilot": dict(cp), "final": dict(cf)}
        need = cp["B"] - cp["A"]
        pool = self.a_pool()
        picked = sorted(random.Random(EXTRA_SEED).sample(pool, need), key=lambda r: r[0])
        rank0 = max(it["rank"] for it in self.k2_extras() + r1) + 1
        a_items = bd.extra_items(picked, rank0)
        extras = b_items + a_items
        pilot, final = pilot_r1 + extras, final_r1 + extras
        self.stats["k4"] = {"pilot_r1_dropped_near_dev2_or_probe": dropped_near, "final_r1_dropped": final_dropped,
                            "linux_B_extras": len(keep_b), "linux_B_extras_dropped": sorted(set(k2p) - set(keep_b)),
                            "linux_A_extras": len(picked)}
        self.extras = extras
        return pilot, final

    # ---------------------------------------------------------------- K4b
    @staticmethod
    def site_line(vcode, scode, side):
        a, b = vcode.split("\n"), scode.split("\n")
        ops = [o for o in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes() if o[0] != "equal"]
        mine = a if side == "V" else b
        for _tag, i1, i2, j1, j2 in ops:
            lo, hi = (i1, i2) if side == "V" else (j1, j2)
            if hi > lo:
                return mine[lo]
        lo = ops[0][1] if side == "V" else ops[0][3]
        return mine[lo] if lo < len(mine) else mine[lo - 1]

    def k4b_items(self, pilot):
        pm = pair_map(pilot)
        out = []
        for it in pilot:
            site = self.site_line(pm[it["pair"]]["V"]["code"], pm[it["pair"]]["S"]["code"],
                                  "V" if it["label"] == "VULNERABLE" else "S")
            out.append({**it, "target": f"VERDICT: {it['label']}\nSITE: {site}"})
        return out

    # ---------------------------------------------------------------- probe
    def probe(self, pilot, final):
        df, val = self.df, self.splits["val"]
        train_items = self.r1 + pilot + final + json.load(open(ROOT / "results/vsp_pilot_k1_items.json"))["items"] \
            + json.load(open(ROOT / "results/vsp_pilot_k2_items.json"))["items"] \
            + json.load(open(ROOT / "results/vsp_sft_k2_items.json"))["items"]
        held = {str(c["pair"]) for c in self.tcases} | {c["pair"] for c in self.dev1} | \
            {c["pair"] for c in self.dev2_cases} | {i["pair"] for i in train_items} | \
            {str(i["src_idx"]) for i in train_items}
        refs = [self.vspt, Ref([c["code"] for c in self.dev1]), self.dev2_ref, Ref([i["code"] for i in train_items])]
        sub = df[(df.project == LINUX) & df.idx.isin(val) & df.is_vulnerable & df.fixed_func_idx.notna()]
        pool = {}
        for _, v in sub.iterrows():
            fx = int(v["fixed_func_idx"])
            pair = str(int(v["idx"]))
            if fx not in val or fx not in df.index or pair in self.r1pm or v["label_confidence"] != "high":
                continue
            if VENDORED_RE.match(str(v["func_name"])):
                continue
            vc, sc = bt.strip_comments(v["func_body"]), bt.strip_comments(df.loc[fx]["func_body"])
            if len(vc) == len(sc) or not self.clean(vc, sc):
                continue
            pool[pair] = (int(v["idx"]), fx, vc, sc, stratum(vc, sc), v, df.loc[fx])
        sel = {"A": [], "B": []}
        skipped = Counter()
        for pair in sorted(pool, key=lambda i: hashlib.sha256((PROBE_SALT + i).encode()).hexdigest()):
            vi, fx, vc, sc, s, v, _ = pool[pair]
            if len(sel[s]) >= PROBE_N:
                continue
            if pair in held or str(fx) in held:
                skipped["held"] += 1
                continue
            if any(r.pair_near(vc, sc) for r in refs):
                skipped["near"] += 1
                continue
            sel[s].append(pair)
        cases = []
        for pair in sorted(sel["A"] + sel["B"], key=lambda i: hashlib.sha256((PROBE_SALT + i).encode()).hexdigest()):
            vi, fx, vc, sc, s, v, _ = pool[pair]
            cwe = [str(x) for x in v["cwe_1003_list"]]
            cases.append(case_of("vspprobe", v, vc, "VULNERABLE", pair, LINUX, cwe, "probe", "high"))
            cases.append(case_of("vspprobe", v, sc, "SAFE", pair, LINUX, cwe, "probe", "high"))
        pc = Counter(p[4] for p in pool.values())
        self.stats["probe"] = {"pool_before_leak_filters": dict(pc), "A": len(sel["A"]), "B": len(sel["B"]),
                               "skipped": dict(skipped)}
        if len(sel["A"]) < PROBE_N or len(sel["B"]) < PROBE_N:
            print(f"WARNING: probe short: A {len(sel['A'])} B {len(sel['B'])} of {PROBE_N}")
        return cases


def dump(path, obj):
    Path(path).write_text(json.dumps(obj, indent=1), encoding="utf-8", newline="\n")


def count_k4(items):
    c = Counter()
    for k, p in pair_map(items).items():
        dom = "linux" if p["V"]["project"] == LINUX else "other"
        c[(dom, stratum(p["V"]["code"], p["S"]["code"]))] += 1
    return {f"{d}_{s}": n for (d, s), n in sorted(c.items())}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out-dir", default=str(ROOT / "results"))
    out = Path(ap.parse_args().out_dir)
    out.mkdir(parents=True, exist_ok=True)
    b = Build()
    b.dev2()
    print("dev2:", json.dumps(b.stats["dev2"]), flush=True)
    pilot, final = b.k4_items()
    pilot_b = b.k4b_items(pilot)
    final_b = b.k4b_items(final)
    print("k4:", json.dumps({k: v for k, v in b.stats["k4"].items()}), flush=True)
    print("linux before A extras:", b.stats["linux_before_A_extras"], "A pool:", b.stats["a_pool"], flush=True)
    probe = b.probe(pilot, final)
    print("probe:", json.dumps(b.stats["probe"]), flush=True)
    stats = {**b.stats, "pilot_counts": count_k4(pilot), "final_counts": count_k4(final)}
    dump(out / FILES["dev2"], {"split": "vsp_dev2", "note": DEV2_NOTE, "seed": EXTRA_SEED, "salt": DEV2_SALT,
                               "stats": b.stats["dev2"], "cases": b.dev2_cases})
    dump(out / FILES["probe"], {"split": "vsp_probe", "note": PROBE_NOTE, "salt": PROBE_SALT,
                                "stats": b.stats["probe"], "cases": probe})
    for key, items in (("pilot", pilot), ("pilot_b", pilot_b), ("final", final), ("final_b", final_b)):
        dump(out / FILES[key], {"items": items, "note": ITEMS_NOTE,
                                "stats": {"n_pairs": len(items) // 2, "counts": count_k4(items),
                                          "build": {"pilot_b": "same items as K4a + target", "final_b": "same items as K4 final + target"}.get(key, b.stats["k4"])}})
    print("pilot counts:", count_k4(pilot))
    print("final counts:", count_k4(final))


if __name__ == "__main__":
    main()
