"""Shared fixture helpers for check_a6_gate.py and check_a6_target.py (attempt-6 tooling acceptance). Not a checker.

Everything here is independent of the scripts under test: AUROC (tie-averaged), the pair-veto (length-balanced
within-pair win share; stratum A = S code longer, B = V code longer; equal length excluded) and the B-stratum win count
are recomputed from per-case scores with numpy only, and cross-checked against the pinned scripts/imp_verdict.py.
Synthetic per-case scores are built on the REAL dev2 / dev3 case files (ids, labels, pairs, code lengths) because the
gate and the target script pin the cases sha256 and n.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEV2 = ROOT / "results/vsp_dev2_cases.json"
VSPT = ROOT / "results/vsp_t_cases.json"
PINS = {"dev2": "9511373d", "vspt": "543c4346"}


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_cases(p):
    return json.load(open(p, encoding="utf-8"))["cases"]


def structure(cases):
    """[(iV, iS, stratum)] for every pair with exactly one V and one S case."""
    by = {}
    for i, c in enumerate(cases):
        by.setdefault(c["pair"], []).append(i)
    out = []
    for ix in by.values():
        if len(ix) != 2 or cases[ix[0]]["label"] == cases[ix[1]]["label"]:
            continue
        v, s = (ix[0], ix[1]) if cases[ix[0]]["label"] == "VULNERABLE" else (ix[1], ix[0])
        lv, ls = len(cases[v]["code"]), len(cases[s]["code"])
        out.append((v, s, "A" if ls > lv else ("B" if lv > ls else "E")))
    return out


def labels01(cases):
    return np.array([1 if c["label"] == "VULNERABLE" else 0 for c in cases])


def auroc(scores, y):
    s = np.asarray(scores, float)
    uniq, inv, cnt = np.unique(s, return_inverse=True, return_counts=True)
    csum = np.cumsum(cnt)
    avg = (csum - cnt + 1 + csum) / 2.0
    r = avg[inv]
    n1 = int(y.sum())
    n0 = len(y) - n1
    return float((r[y == 1].sum() - n1 * (n1 + 1) / 2.0) / (n1 * n0))


def veto_and_bwins(cases, pairs, scores):
    """(balanced within-pair win share, sum of stratum-B wins)."""
    w = {"A": [], "B": []}
    for v, s, st in pairs:
        if st in w:
            w[st].append(1.0 if scores[v] > scores[s] else (0.5 if scores[v] == scores[s] else 0.0))
    return (sum(w["A"]) / len(w["A"]) + sum(w["B"]) / len(w["B"])) / 2.0, sum(w["B"])


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.asarray(z, float)))


def logit(p):
    p = np.asarray(p, float)
    return np.log(p / (1.0 - p))


def metrics(cases, pairs, y, p):
    v, b = veto_and_bwins(cases, pairs, p)
    return {"auroc": auroc(p, y), "veto": v, "bwins": b}


def cross_check_verdict(cases, pairs, p):
    """Cross-check the local veto against the pinned imp_verdict (guards the checker itself)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import imp_verdict as iv
    keys = [(c["id"], c["label"]) for c in cases]
    groups = iv.pair_groups(cases, keys)
    wins, _eq, _skip = iv.pair_wins(cases, keys, groups, list(p))
    return iv.pair_balanced(wins), sum(wins["B"])


class Gen:
    """Synthetic per-case logits with exactly controlled within-pair wins and a tunable pooled AUROC.

    Each valid pair gets a pair mean m ~ N(0, sigma) and a gap +/- d*u/2: pair stratum wins are chosen as exact
    integer counts (so the veto and the B-wins are exact), d is bisected so the pooled AUROC lands on a target."""

    def __init__(self, cases, seed=7):
        self.cases, self.pairs, self.y = cases, structure(cases), labels01(cases)
        rng = np.random.default_rng(seed)
        self.u = rng.uniform(0.6, 1.4, size=len(self.pairs))
        self.idx = {}
        for st in "ABE":
            ix = [j for j, p in enumerate(self.pairs) if p[2] == st]
            rng.shuffle(ix)
            self.idx[st] = ix
        self.n = {st: len(self.idx[st]) for st in "ABE"}

    def logits(self, wA, wB, d, sigma, noise_seed):
        sign = np.full(len(self.pairs), -1.0)
        for st, k in (("A", wA), ("B", wB), ("E", self.n["E"])):
            sign[self.idx[st][:k]] = 1.0
        m = np.random.default_rng(noise_seed).normal(0.0, sigma, len(self.pairs))
        z = np.random.default_rng(noise_seed + 1).normal(0.0, sigma, len(self.cases))
        for j, (v, s, _st) in enumerate(self.pairs):
            z[v] = m[j] + sign[j] * d * self.u[j] / 2.0
            z[s] = m[j] - sign[j] * d * self.u[j] / 2.0
        return z

    def tune(self, target, wA, wB, sigma, noise_seed, members=1, tol=2e-4):
        """Bisect d so the AUROC of sigmoid(mean of member logits) is within tol of target."""
        def auc(d):
            zs = [self.logits(wA, wB, d, sigma, noise_seed + 10 * k) for k in range(members)]
            return auroc(sigmoid(np.mean(zs, axis=0)), self.y), zs
        lo, hi = 0.0, 14.0
        a_hi = auc(hi)[0]
        if a_hi < target:
            raise ValueError(f"target AUROC {target:.4f} unreachable (limit {a_hi:.4f}) with wins A {wA} B {wB}")
        for _ in range(45):
            mid = (lo + hi) / 2.0
            if auc(mid)[0] < target:
                lo = mid
            else:
                hi = mid
        a, zs = auc(hi)
        if abs(a - target) > tol:
            raise ValueError(f"cannot hit AUROC {target:.4f} (got {a:.4f})")
        return [sigmoid(z) for z in zs], hi, a

    def wins_for(self, veto_lo, veto_hi, wB_pref):
        """(wA, wB) with veto in [veto_lo, veto_hi), wB as close to wB_pref as possible."""
        nA, nB = self.n["A"], self.n["B"]
        best = None
        for dB in range(0, 12):
            for wB in sorted({wB_pref - dB, wB_pref + dB}):
                if not 0 <= wB <= nB:
                    continue
                for wA in range(nA, -1, -1):
                    v = (wA / nA + wB / nB) / 2.0
                    if veto_lo <= v < veto_hi:
                        return wA, wB, v
        return best
