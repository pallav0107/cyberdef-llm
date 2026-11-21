"""Acceptance checker for the domain-crossed pair sampler (src/cyberdef/imp_pairs.py, mode balanced_by_domain).

Usage:
  .venv/bin/python acceptance/improve/check_pairdom.py ITEMS.json --mode {sequential,shuffle,balanced,balanced_by_domain}
      [--seeds 0,1,2] [--epochs 2] [--expect-refuse CODE]

ITEMS.json is {"items": [...]} in pair-adjacent order (item 2i VULNERABLE, 2i+1 its fix). Strata are recomputed from
len(code): A = fix longer, B = vulnerable longer, E = equal. Domain of a pair = "linux" if its project is linux,
otherwise "other".

Interface this checker requires of the implementation (the spec does not fix it; this is the minimal extension of the
existing API, recorded as a resolved ambiguity):
  imp_pairs.MODES contains "balanced_by_domain";
  imp_pairs.epoch_order(strata, mode, seed, epoch, domains=None) -> list of pair indices (a pair may repeat);
  domains is a list, one entry per pair, equal to "linux" or "other" (the string "linux" marks the linux domain);
  mode balanced_by_domain without domains must raise ValueError; the other modes ignore domains.
The scripts/imp_train.py trainer must build and pass domains (checked as WIRING: the source mentions "domain").
Unlike the old modes, an epoch of balanced_by_domain is NOT a permutation: len(order) is free, indices repeat.

Failure codes (one FAIL line each):
  ADJACENT STRATUM     bad item order / imp_pairs.stratum disagrees with the recomputation
  SIGNATURE            epoch_order rejects domains=, or MODES lacks the mode
  LENGTH               order is empty or holds an index outside [0, n_pairs)
  DOMAIN               inside linux or inside other the A and B slot counts differ by more than 1, or the
                       per-domain length-only accuracy (E scores 0.5) is outside 0.50 +/- 0.01
  MAXTWICE             a pair appears more than twice in one epoch
  EALL                 an E pair is missing from an epoch
  LINUXONCE            (when linux holds equal A and B pairs) a linux A or B pair does not appear exactly once
  OTHERBTWICE          a non-linux B pair does not appear exactly twice (plan: every B pair twice per epoch)
  DETERMINISM VARIES   two calls differ; every seed gives the same order / every epoch gives the same order
  WIRING               scripts/imp_train.py does not mention domains
Exit 0 iff no failure. With --expect-refuse CODE: exit 0 iff a failure with that CODE occurred (the fail-first
control: the old global balanced mode, called without domains, must fire DOMAIN on the K4 items).
Exit 1 on any other outcome, including a missing items file or a missing API (clear message, no traceback).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODES = ("ADJACENT", "STRATUM", "SIGNATURE", "LENGTH", "DOMAIN", "MAXTWICE", "EALL", "LINUXONCE", "OTHERBTWICE",
         "DETERMINISM", "VARIES", "WIRING")
MODES = ("sequential", "shuffle", "balanced", "balanced_by_domain")
ACC_TOL = 0.01
FAILS = []


def fail(code, detail):
    FAILS.append(code)
    print(f"FAIL {code} {detail}")


def stop(msg):
    print(f"FAIL SETUP {msg}")
    print("RESULT: FAIL (cannot evaluate)")
    sys.exit(1)


def my_stratum(len_v, len_s):
    if len_s > len_v:
        return "A"
    return "B" if len_v > len_s else "E"


def load(path):
    try:
        items = json.load(open(path, encoding="utf-8"))["items"]
    except FileNotFoundError:
        stop(f"target not built yet: {path}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        stop(f"cannot read items from {path}: {type(exc).__name__}: {exc}")
    return items


def split_pairs(items):
    bad, strata, domains = [], [], []
    if len(items) % 2:
        bad.append(f"odd item count {len(items)}")
    for i in range(len(items) // 2):
        v, s = items[2 * i], items[2 * i + 1]
        if v["label"] != "VULNERABLE" or s["label"] != "SAFE" or v["pair"] != s["pair"]:
            bad.append("slot " + str(i) + ": " + v["label"] + "/" + s["label"] + " " + v["pair"] + "/" + s["pair"])
        strata.append(my_stratum(len(v["code"]), len(s["code"])))
        domains.append("linux" if v["project"] == "linux" else "other")
    return strata, domains, bad


def acc(slots, strata):
    score = {"A": 1.0, "B": 0.0, "E": 0.5}
    return sum(score[strata[i]] for i in slots) / len(slots) if slots else float("nan")


def check_domain_balance(order, strata, domains, tag):
    for dom in ("linux", "other"):
        slots = [i for i in order if domains[i] == dom]
        c = Counter(strata[i] for i in slots)
        n_a, n_b, n_e = c["A"], c["B"], c["E"]
        if not slots:
            fail("DOMAIN", f"{tag}: no {dom} slots at all")
            continue
        a = acc(slots, strata)
        if abs(n_a - n_b) > 1 or abs(a - 0.5) > ACC_TOL:
            fail("DOMAIN", f"{tag}: {dom} slots A={n_a} B={n_b} E={n_e} length-only accuracy {a:.4f} "
                           f"(need |A-B| <= 1 and 0.50 +/- {ACC_TOL})")


def check_multiplicity(order, strata, domains, tag, linux_even):
    use = Counter(order)
    over = [(i, n) for i, n in use.items() if n > 2]
    if over:
        fail("MAXTWICE", f"{tag}: {len(over)} pairs more than twice, e.g. pair {over[0][0]} x{over[0][1]}")
    missing = [i for i, s in enumerate(strata) if s == "E" and use.get(i, 0) < 1]
    if missing:
        fail("EALL", f"{tag}: {len(missing)} of {strata.count(chr(69))} E pairs absent")
    if linux_even:
        bad = [i for i, s in enumerate(strata) if domains[i] == "linux" and s in "AB" and use.get(i, 0) != 1]
        if bad:
            fail("LINUXONCE", f"{tag}: {len(bad)} linux A/B pairs not exactly once, e.g. pair {bad[0]} x{use.get(bad[0], 0)}")
    bad = [i for i, s in enumerate(strata) if domains[i] == "other" and s == "B" and use.get(i, 0) != 2]
    if bad:
        fail("OTHERBTWICE", f"{tag}: {len(bad)} non-linux B pairs not exactly twice, e.g. pair {bad[0]} x{use.get(bad[0], 0)}")


def run(ip, items, mode, seeds, epochs):
    strata, domains, bad = split_pairs(items)
    for b in bad[:3]:
        fail("ADJACENT", b)
    n = len(strata)
    dc = Counter(zip(domains, strata))
    print(f"pairs: {n} (domain, stratum): {dict(sorted(dc.items()))} mode: {mode}")
    wrong = [(a, b) for a, b in ((5, 9), (9, 5), (7, 7), (0, 1), (1, 0)) if ip.stratum(a, b) != my_stratum(a, b)]
    if wrong:
        fail("STRATUM", f"imp_pairs.stratum wrong for {wrong[:3]}")
    if mode not in ip.MODES:
        fail("SIGNATURE", f"mode {mode} is not in imp_pairs.MODES {tuple(ip.MODES)}")
        return
    use_domains = mode == "balanced_by_domain"
    kw = {"domains": domains} if use_domains else {}
    if use_domains:
        try:
            ip.epoch_order(strata, mode, 0, 0)
            fail("SIGNATURE", "balanced_by_domain accepted a call without domains (must raise ValueError)")
        except ValueError:
            pass
        except TypeError as exc:
            fail("SIGNATURE", f"epoch_order(strata, mode, seed, epoch, domains=None) signature missing: {exc}")
            return
    linux_even = dc[("linux", "A")] == dc[("linux", "B")]
    per_seed = {}
    for seed in seeds:
        orders = []
        for ep in range(epochs):
            tag = f"seed {seed} epoch {ep}"
            try:
                o1 = list(ip.epoch_order(strata, mode, seed, ep, **kw))
                o2 = list(ip.epoch_order(strata, mode, seed, ep, **kw))
            except TypeError as exc:
                fail("SIGNATURE", f"epoch_order rejects domains=: {exc}")
                return
            orders.append(o1)
            if o1 != o2:
                fail("DETERMINISM", f"{tag}: two calls differ")
            if not o1 or not all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i < n for i in o1):
                fail("LENGTH", f"{tag}: empty order or indices outside [0, {n})")
                continue
            check_domain_balance(o1, strata, domains, tag)
            if use_domains:
                check_multiplicity(o1, strata, domains, tag, linux_even)
        per_seed[seed] = orders
    if mode != "sequential":
        for ep in range(epochs):
            if len(seeds) > 1 and len({tuple(per_seed[s][ep]) for s in seeds}) < 2:
                fail("VARIES", f"epoch {ep}: every seed gave the same order")
        for s in seeds:
            if epochs > 1 and len({tuple(o) for o in per_seed[s]}) < 2:
                fail("VARIES", f"seed {s}: every epoch gave the same order")


def check_wiring():
    src = Path(os.environ.get("PAIRDOM_TRAIN", str(ROOT / "scripts/imp_train.py"))).read_text(encoding="utf-8")
    if "domain" not in src:
        fail("WIRING", "scripts/imp_train.py never mentions domains: balanced_by_domain would get no domain list")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("items")
    ap.add_argument("--mode", required=True, choices=MODES)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--expect-refuse", default="")
    a = ap.parse_args(argv)
    seeds = [int(x) for x in a.seeds.split(",") if x != ""]
    if not seeds or a.epochs < 1:
        stop("need at least one seed and one epoch")
    if a.expect_refuse and a.expect_refuse not in CODES:
        stop(f"unknown code {a.expect_refuse}; known {CODES}")
    sys.path.insert(0, os.environ.get("PAIRDOM_SRC", str(ROOT / "src")))   # env: checker self-test only
    try:
        from cyberdef import imp_pairs as ip
        ip.stratum, ip.epoch_order, ip.MODES
    except (ImportError, AttributeError) as exc:
        stop(f"cannot import the cyberdef.imp_pairs API: {type(exc).__name__}: {exc}")
    items = load(a.items)
    try:
        run(ip, items, a.mode, seeds, a.epochs)
        if a.mode == "balanced_by_domain":
            check_wiring()
    except Exception as exc:  # noqa: BLE001
        fail("SIGNATURE", f"imp_pairs call raised {type(exc).__name__}: {exc}")
    kinds = sorted(set(FAILS))
    if a.expect_refuse:
        hit = a.expect_refuse in FAILS
        word = "OK (fired)" if hit else "NOT FIRED"
        print("expect-refuse " + a.expect_refuse + ": " + word + "; fired=" + str(kinds))
        print("RESULT: " + ("PASS" if hit else "FAIL"))
        return 0 if hit else 1
    print("RESULT: " + ("FAIL " + ",".join(kinds) if FAILS else "PASS"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
