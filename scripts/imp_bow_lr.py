#!/usr/bin/env python3
"""Bag-of-words logistic-regression baseline for the real-world fine-tune round.

Implements /tmp/brief_pairveto_bowlr.txt part (B): TF-IDF over 1-2-gram code
tokens (min_df 2 over the training items, sublinear tf, idf from the training
items only, L2-normalised rows) fit on the VSP-SFT training items ONLY with an
L2-regularised logistic regression (C = 1.0) solved deterministically with
numpy/scipy (no randomness; seed 0 where any were needed), then scored on the
VSP-T cases. The cases' labels are NEVER read during fitting or scoring; they
are only copied into per_case. The acceptance contract is
acceptance/improve/check_bowlr.py.

  .venv/bin/python scripts/imp_bow_lr.py --items results/vsp_sft_items.json \
      --cases results/vsp_t_cases.json --out OUT.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import numpy as np
from scipy.optimize import minimize
from scipy.sparse import csr_matrix
from scipy.special import expit

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberdef.imp_common import auroc  # noqa: E402

METHOD = "logprob-scored bow_lr baseline (imp_bow_lr, TF-IDF 1-2gram LR C=1, fit on VSP-SFT only)"
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")
MIN_DF = 2          # brief: feature must occur in >= 2 training items
C = 1.0             # brief: L2 inverse regularisation strength
MAX_ITER = 500      # fixed iteration budget of the deterministic solver
TOL = 1e-10         # fixed tolerance of the deterministic solver
SEED = 0            # brief: seed 0 where any randomness exists (none does)


def tokens(code):
    """Code tokens per the brief's regex."""
    return TOKEN_RE.findall(code)


def features(toks):
    """Unigram + bigram feature keys of a token list."""
    return [("u", t) for t in toks] + [("b", a, b) for a, b in zip(toks, toks[1:])]


def build_vocab(codes):
    """Vocabulary: features with df >= MIN_DF over these (training) docs,
    sorted so the index is deterministic."""
    df = {}
    for code in codes:
        for f in set(features(tokens(code))):
            df[f] = df.get(f, 0) + 1
    feats = sorted(f for f, n in df.items() if n >= MIN_DF)
    return feats, {f: i for i, f in enumerate(feats)}


def count_matrix(codes, index):
    """Sparse doc x vocab count matrix over a fixed vocabulary."""
    rows, cols, vals = [], [], []
    for i, code in enumerate(codes):
        cnt = {}
        for f in features(tokens(code)):
            j = index.get(f)
            if j is not None:
                cnt[j] = cnt.get(j, 0) + 1
        rows += [i] * len(cnt)
        cols += list(cnt)
        vals += list(cnt.values())
    return csr_matrix((vals, (rows, cols)), shape=(len(codes), len(index)), dtype=float)


def idf_vector(mat, n_docs):
    """Smoothed idf from the training count matrix: ln((1 + N) / (1 + df)) + 1."""
    df = np.asarray((mat > 0).sum(axis=0)).ravel()
    return np.log((1.0 + n_docs) / (1.0 + df)) + 1.0


def tfidf(mat, idf):
    """Sublinear tf (1 + ln tf) x train idf, L2-normalised rows."""
    m = mat.copy()
    m.data = 1.0 + np.log(m.data)
    m = m.multiply(csr_matrix(idf))
    norms = np.sqrt(np.asarray(m.multiply(m).sum(axis=1)).ravel())
    norms[norms == 0.0] = 1.0
    return m.multiply(csr_matrix(1.0 / norms).T)


def fit_lr(X, y, c=C, iters=MAX_ITER, tol=TOL):
    """L2 logistic regression (intercept unpenalised) via deterministic
    L-BFGS (fixed iteration count and tolerance; no randomness, seed 0)."""
    n, d = X.shape
    y = np.asarray(y, dtype=float)

    def obj(w):
        b, v = w[0], w[1:]
        z = X @ v + b
        loss = float(np.logaddexp(0.0, z).sum() - y @ z + 0.5 * (v @ v) / c)
        p = expit(z) - y
        return loss, np.concatenate(([p.sum()], X.T @ p + v / c))

    res = minimize(obj, np.zeros(d + 1), jac=True, method="L-BFGS-B",
                   options={"maxiter": iters, "ftol": tol, "gtol": tol})
    return res.x


def predict_p(X, w):
    """P(VULNERABLE) per row."""
    return np.asarray(expit(X @ w[1:] + w[0])).ravel()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--items", required=True, help="VSP-SFT training items JSON")
    ap.add_argument("--cases", required=True, help="VSP-T cases JSON")
    ap.add_argument("--out", required=True, help="output JSON (deterministic)")
    a = ap.parse_args()

    items = json.load(open(a.items, encoding="utf-8"))["items"]
    train_codes = [it["code"] for it in items]
    y = [1 if it["label"] == "VULNERABLE" else 0 for it in items]

    vocab, index = build_vocab(train_codes)
    ctr = count_matrix(train_codes, index)
    idf = idf_vector(ctr, len(train_codes))
    w = fit_lr(tfidf(ctr, idf), y)
    p_train = predict_p(tfidf(ctr, idf), w)

    cases = json.load(open(a.cases, encoding="utf-8"))["cases"]
    cte = tfidf(count_matrix([c["code"] for c in cases], index), idf)
    p_case = predict_p(cte, w)

    out = {"method": METHOD,
           "per_case": [{"id": c["id"], "label": c["label"], "p_vuln": float(p)}
                        for c, p in zip(cases, p_case)],
           "n": len(cases), "train_items": len(items),
           "train_sha256": hashlib.sha256(open(a.items, "rb").read()).hexdigest(),
           "vocab_size": len(vocab),
           "train_auroc": auroc(list(p_train), y)}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
