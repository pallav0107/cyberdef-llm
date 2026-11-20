"""Acceptance checker for src/cyberdef/imp_pairs.py epoch ordering.

Usage:
  .venv/bin/python acceptance/improve/check_pairbal.py ITEMS.json --mode {sequential,shuffle,balanced}
      [--seeds 0,1,2] [--epochs 2] [--expect-refuse CODE]

ITEMS.json is {"items": [...]} in pair-adjacent order (item 2i VULNERABLE, 2i+1 its SAFE fix).
Strata are recomputed here from len(code): A = fixed side longer, B = vulnerable side
longer, E = equal. Failure codes: BALANCE LENGTH EVEN DETERMINISM VARIES ADJACENT STRATUM
(STRATUM: imp_pairs.stratum disagrees with the independent recomputation) SEQUENTIAL
(sequential mode is not the identity).
Prints "FAIL <CODE> <detail>" per failure. Exit 0 iff no failure; with --expect-refuse CODE,
exit 0 iff at least one failure with that CODE occurred. Exit 2 on usage or import error.
In sequential mode VARIES is not evaluated (the identity order cannot vary).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODES = ("BALANCE", "LENGTH", "EVEN", "DETERMINISM", "VARIES", "ADJACENT",
         "STRATUM", "SEQUENTIAL")
MODES = ("sequential", "shuffle", "balanced")
ACC_TOL = 0.01
FAILS = []


def fail(code, detail):
    FAILS.append(code)
    print(f"FAIL {code} {detail}")


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def load_items(path):
    try:
        items = json.load(open(path, encoding="utf-8"))["items"]
        for it in items:
            it["code"], it["label"], it["pair"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        die(f"cannot read items from {path}: {type(exc).__name__}: {exc}")
    return items


def my_stratum(len_v, len_s):
    if len_s > len_v:
        return "A"
    return "B" if len_v > len_s else "E"


def split_pairs(items):
    """Return (strata, adjacency problems) from adjacent items."""
    bad = []
    if len(items) % 2:
        bad.append(f"odd item count {len(items)}")
    strata = []
    for i in range(len(items) // 2):
        v, s = items[2 * i], items[2 * i + 1]
        if v["label"] != "VULNERABLE" or s["label"] != "SAFE" or v["pair"] != s["pair"]:
            bad.append(f"pair slot {i}: {v['label']}/{s['label']} {v['pair']}/{s['pair']}")
        strata.append(my_stratum(len(v["code"]), len(s["code"])))
    return strata, bad


def length_only_acc(order, strata):
    score = {"A": 1.0, "B": 0.0, "E": 0.5}
    return sum(score[strata[i]] for i in order) / len(order)


def check_balance(order, strata, tag):
    cnt = Counter(strata[i] for i in order)
    if abs(cnt["A"] - cnt["B"]) > 1:
        fail("BALANCE", f"{tag}: |A-B| = {abs(cnt['A'] - cnt['B'])} (A={cnt['A']} B={cnt['B']})")
    e_idx = [i for i, s in enumerate(strata) if s == "E"]
    e_used = Counter(i for i in order if strata[i] == "E")
    if any(e_used.get(i, 0) != 1 for i in e_idx) or sum(e_used.values()) != len(e_idx):
        fail("BALANCE", f"{tag}: E pairs not each exactly once "
                        f"({sum(e_used.values())} slots, {len(e_idx)} E pairs)")
    acc = length_only_acc(order, strata)
    if abs(acc - 0.5) > ACC_TOL:
        fail("BALANCE", f"{tag}: length-only accuracy {acc:.4f} outside 0.50 +/- {ACC_TOL}")


def valid_order(order, n, tag):
    if not isinstance(order, (list, tuple)) or len(order) != n:
        size = len(order) if hasattr(order, "__len__") else "?"
        fail("LENGTH", f"{tag}: order length {size} != {n}")
        return False
    if not all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i < n for i in order):
        fail("LENGTH", f"{tag}: indices not ints in [0, {n})")
        return False
    return True


def check_even(orders, strata, seed):
    use = Counter(i for o in orders for i in o)
    for st in "ABE":
        idx = [i for i, s in enumerate(strata) if s == st]
        if not idx:
            continue
        counts = [use.get(i, 0) for i in idx]
        if max(counts) - min(counts) > 1:
            fail("EVEN", f"seed {seed} stratum {st}: use counts span {min(counts)}..{max(counts)}")


def check_varies(per_seed, epochs):
    seeds = sorted(per_seed)
    for ep in range(epochs):
        if len(seeds) > 1 and len({tuple(per_seed[s][ep]) for s in seeds}) < 2:
            fail("VARIES", f"epoch {ep}: every seed gave the same order")
    for s in seeds:
        if epochs > 1 and len({tuple(o) for o in per_seed[s]}) < 2:
            fail("VARIES", f"seed {s}: every epoch gave the same order")


def check_stratum_fn(ip, items):
    cases = [(5, 9), (9, 5), (7, 7), (0, 1), (1, 0), (100, 100)]
    cases += [(len(items[2 * i]["code"]), len(items[2 * i + 1]["code"]))
              for i in range(min(50, len(items) // 2))]
    wrong = [(a, b) for a, b in cases if ip.stratum(a, b) != my_stratum(a, b)]
    if wrong:
        fail("STRATUM", f"imp_pairs.stratum wrong for {wrong[:3]} (len_v, len_s)")


def run(ip, items, mode, seeds, epochs):
    strata, bad = split_pairs(items)
    for b in bad[:3]:
        fail("ADJACENT", b)
    if bad:
        fail("ADJACENT", f"{len(bad)} adjacency problems in total")
    n = len(strata)
    print(f"items: {len(items)} pairs: {n} strata: {dict(Counter(strata))} mode: {mode}")
    check_stratum_fn(ip, items)
    per_seed = {}
    for seed in seeds:
        orders = []
        for ep in range(epochs):
            tag = f"seed {seed} epoch {ep}"
            o1 = list(ip.epoch_order(strata, mode, seed, ep))
            o2 = list(ip.epoch_order(strata, mode, seed, ep))
            if o1 != o2:
                fail("DETERMINISM", f"{tag}: two calls differ")
            orders.append(o1)
            if not valid_order(o1, n, tag):
                continue
            check_balance(o1, strata, tag)
            if mode == "sequential" and o1 != list(range(n)):
                fail("SEQUENTIAL", f"{tag}: not the identity order")
        per_seed[seed] = orders
        if all(valid_order(o, n, f"seed {seed}") for o in orders):
            check_even(orders, strata, seed)
    if mode != "sequential":
        check_varies(per_seed, epochs)


def parse(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("items")
    ap.add_argument("--mode", required=True, choices=MODES)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--expect-refuse", default="")
    a = ap.parse_args(argv)
    try:
        seeds = [int(x) for x in a.seeds.split(",") if x != ""]
    except ValueError:
        die(f"bad --seeds {a.seeds!r}")
    if not seeds or a.epochs < 1:
        die("need at least one seed and one epoch")
    if a.expect_refuse and a.expect_refuse not in CODES:
        die(f"unknown code {a.expect_refuse!r}; known {CODES}")
    return a, seeds


def main(argv=None):
    a, seeds = parse(argv)
    sys.path.insert(0, os.environ.get("PAIRBAL_SRC", str(ROOT / "src")))  # env: checker self-test only
    try:
        from cyberdef import imp_pairs as ip
        ip.stratum, ip.epoch_order
    except (ImportError, AttributeError) as exc:
        die(f"cannot import cyberdef.imp_pairs API: {type(exc).__name__}: {exc}")
    items = load_items(a.items)
    try:
        run(ip, items, a.mode, seeds, a.epochs)
    except Exception as exc:  # noqa: BLE001  an API that raises is a usage-level error
        die(f"imp_pairs call raised {type(exc).__name__}: {exc}")
    kinds = sorted(set(FAILS))
    if a.expect_refuse:
        hit = a.expect_refuse in FAILS
        print(f"expect-refuse {a.expect_refuse}: {'OK (fired)' if hit else 'NOT FIRED'}; fired={kinds}")
        return 0 if hit else 1
    print("RESULT:", "FAIL " + ",".join(kinds) if FAILS else "PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
