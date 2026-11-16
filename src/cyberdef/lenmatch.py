"""Length matching: pair each vulnerable function with a safe one of near-identical length, so that
function length carries (almost) no label information. Used both to build the held-out EVAL set
(scripts/build_lenmatch_eval.py) and the TRAIN set (train_devign.py --length-match).

Matching is 1:1 without replacement, nearest neighbour, with a caliper on BOTH log(chars) and
log(tokens) (token count from the base model's tokenizer). Vulnerable functions with no safe
partner inside the caliper are dropped (reported). Rows are dicts with at least 'code'."""
from __future__ import annotations
import bisect
import math
import random


def attach_len(rows, tok):
    for r in rows:
        r["chars"] = len(r["code"])
        r["toks"] = None
    return rows


def _toks(r, tok):
    if r["toks"] is None:
        r["toks"] = max(1, len(tok(r["code"], add_special_tokens=False)["input_ids"]))
    return r["toks"]


def match_pairs(vulns, safes, tok, tol=0.03, seed=0):
    """Return (pairs, dropped_vulns). pairs = list of (vuln_row, safe_row). tol is the caliper on
    |ln(chars_s/chars_v)| and |ln(toks_s/toks_v)|."""
    rng = random.Random(seed)
    safes = sorted(safes, key=lambda r: r["chars"])
    sc = [max(1, r["chars"]) for r in safes]
    used, pairs, dropped = set(), [], []
    order = sorted(vulns, key=lambda r: -r["chars"])      # sparse (long) end first
    for v in order:
        cv = max(1, v["chars"])
        lo = bisect.bisect_left(sc, cv * math.exp(-tol))
        hi = bisect.bisect_right(sc, cv * math.exp(tol))
        cands = [(abs(math.log(sc[i] / cv)) + rng.random() * 1e-6, i) for i in range(lo, hi) if i not in used]
        cands.sort()
        tv = _toks(v, tok)
        pick = None
        for dc, i in cands:
            if abs(math.log(_toks(safes[i], tok) / tv)) <= tol:
                pick = i
                break
        if pick is None:
            dropped.append(v)
            continue
        used.add(pick)
        pairs.append((v, safes[pick]))
    return pairs, dropped
