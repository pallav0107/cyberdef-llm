"""Pair ordering for pair-batched training (pure python, no torch).

A pair is two adjacent training items, the vulnerable function first, its fix second. Its length stratum is
decided by the code lengths: "A" = the fix (SAFE side) is longer, "B" = the vulnerable side is longer, "E" = equal.
Under plain sequential or shuffled order the A/B mix of the data is whatever the data has, so a model can score on
"the fix is longer". The balanced sampler removes that: each epoch it shows every E pair once and fills the
remaining slots half from A and half from B, so the length-only accuracy of every epoch is 0.50.

epoch_order(strata, mode, seed, epoch) -> list of pair indices, len == len(strata); deterministic.
"""
from __future__ import annotations

import random

MODES = ("sequential", "shuffle", "balanced")
SCORE = {"A": 1.0, "B": 0.0, "E": 0.5}   # what a "the longer side is the fix" rule scores on each stratum


def stratum(len_v, len_s):
    """A: SAFE side longer; B: VULNERABLE side longer; E: equal lengths."""
    if len_s > len_v:
        return "A"
    return "B" if len_v > len_s else "E"


def strata_of_items(items):
    """Strata of pair-adjacent items (2i vulnerable, 2i+1 its fix). ValueError if the order is not pair-adjacent."""
    if len(items) % 2:
        raise ValueError(f"odd item count {len(items)}: not pair-adjacent")
    out = []
    for i in range(len(items) // 2):
        v, s = items[2 * i], items[2 * i + 1]
        if v["label"] != "VULNERABLE" or s["label"] != "SAFE" or v["pair"] != s["pair"]:
            raise ValueError(f"slot {i} is not a VULNERABLE/SAFE pair of one id: "
                             f"{v['label']}/{s['label']} {v['pair']}/{s['pair']}")
        out.append(stratum(len(v["code"]), len(s["code"])))
    return out


def counts(strata, order):
    """{"A": n, "B": n, "E": n} over the pairs of `order`."""
    c = {"A": 0, "B": 0, "E": 0}
    for i in order:
        c[strata[i]] += 1
    return c


def length_only_acc(c):
    """Accuracy of the rule "the longer side is the fix" given stratum counts (E scores 0.5)."""
    n = sum(c.values())
    return sum(SCORE[k] * v for k, v in c.items()) / n if n else float("nan")


def _quota(n_rest, seed, epoch):
    """(slots from A, slots from B) among the n_rest non-E slots of one epoch; |A - B| <= 1.
    With an odd n_rest the extra slot alternates between A and B from epoch to epoch."""
    n_a, n_b = n_rest // 2, n_rest - n_rest // 2
    return (n_b, n_a) if (epoch + seed) % 2 else (n_a, n_b)


def _draw(members, name, k, seed, start):
    """k members taken from the endless stream perm_0 + perm_1 + ... (each a seeded permutation of `members`),
    beginning at stream position `start`. Consecutive draws continue the stream, so across the run every
    member of the stratum is used a number of times that differs by at most one."""
    out, pos, n = [], start, len(members)
    if k and not n:
        raise ValueError(f"stratum {name} is empty but {k} slots must come from it")
    while len(out) < k:
        cycle, off = divmod(pos, n)
        perm = list(members)
        random.Random(f"{seed}|{name}|{cycle}").shuffle(perm)
        take = min(k - len(out), n - off)
        out.extend(perm[off:off + take])
        pos += take
    return out


def _balanced(strata, seed, epoch):
    n = len(strata)
    e_idx = [i for i, s in enumerate(strata) if s == "E"]
    members = {st: [i for i, s in enumerate(strata) if s == st] for st in "AB"}
    rest = n - len(e_idx)
    used_a = used_b = 0
    for ep in range(epoch):   # stream positions where this epoch resumes
        qa, qb = _quota(rest, seed, ep)
        used_a, used_b = used_a + qa, used_b + qb
    qa, qb = _quota(rest, seed, epoch)
    order = e_idx + _draw(members["A"], "A", qa, seed, used_a) + _draw(members["B"], "B", qb, seed, used_b)
    random.Random(f"o|{seed}|{epoch}").shuffle(order)
    return order


def epoch_order(strata, mode, seed, epoch):
    """Pair indices visited in `epoch` (0-based) under `mode`; len == len(strata)."""
    n = len(strata)
    if mode == "sequential":
        return list(range(n))
    if mode == "shuffle":
        order = list(range(n))
        random.Random(f"s|{seed}|{epoch}").shuffle(order)
        return order
    if mode == "balanced":
        return _balanced(strata, seed, epoch)
    raise ValueError(f"unknown pair-sampler mode {mode!r}; expected one of {MODES}")
