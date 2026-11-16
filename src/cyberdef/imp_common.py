"""Shared metrics for the imp_* improvement experiments (pure python, no deps)."""
from __future__ import annotations
import math


def auroc(scores, labels):
    """Mann-Whitney AUROC with tie-averaged ranks. labels: 1 = vulnerable. None if one class is missing."""
    n1 = sum(1 for y in labels if y == 1)
    n0 = len(labels) - n1
    if n1 == 0 or n0 == 0:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return (sum(ranks[i] for i in range(len(scores)) if labels[i] == 1) - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def hm_se(a, n1, n0):
    """Hanley-McNeil standard error of an AUROC."""
    if a is None or n1 == 0 or n0 == 0:
        return None
    q1, q2 = a / (2 - a), 2 * a * a / (1 + a)
    v = (a * (1 - a) + (n1 - 1) * (q1 - a * a) + (n0 - 1) * (q2 - a * a)) / (n1 * n0)
    return math.sqrt(max(v, 0.0))


def auroc_se(scores, labels):
    a = auroc(scores, labels)
    n1 = sum(labels)
    return a, hm_se(a, n1, len(labels) - n1)


def diff_se(se1, se2):
    return math.sqrt(se1 * se1 + se2 * se2)


def r4(x):
    return None if x is None else round(x, 4)
