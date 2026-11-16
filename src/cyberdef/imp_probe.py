"""Linear-probe machinery for Stage I (does the hidden state encode vulnerable/safe better than the output?). CPU, torch only (no sklearn on these hosts).
Rigor rules built in: (1) every score is OUT-OF-FOLD: a probe is never fitted and scored on the same cases; (2) folds are GROUPED (a matched pair, and every case of one project, stay in the same fold) so pair
partners / project style cannot leak between train and test; (3) layer AND regularisation are chosen by an INNER cross-validation on the training part of each outer fold only (nested), so picking the best of
several layers cannot inflate the held-out number; (4) controls use the identical pipeline: shuffled labels, length-only features."""
from __future__ import annotations
import hashlib, math
import numpy as np
import torch
from .imp_common import auroc, hm_se


PCA_DIMS = 128


def group_folds(groups, k=5, seed=0):
    """deterministic grouped fold ids: whole groups go to one fold, balanced by hash order"""
    gs = sorted(set(groups), key=lambda g: hashlib.sha1(f"{seed}:{g}".encode()).hexdigest())
    fid = {g: i % k for i, g in enumerate(gs)}
    return np.array([fid[g] for g in groups])


def _std(Xtr, Xte):
    mu = Xtr.mean(0, keepdims=True); sd = Xtr.std(0, keepdims=True) + 1e-6
    return (Xtr - mu) / sd, (Xte - mu) / sd


def fit_predict(Xtr, ytr, Xte, C, n_classes=2, iters=40):
    """L2 logistic / softmax regression (LBFGS). Returns scores for Xte: P(class 1) for binary, probability matrix for multiclass. Penalty = ||W||^2 / (2 C n)."""
    Xtr, Xte = _std(Xtr.astype(np.float32), Xte.astype(np.float32))
    if Xtr.shape[1] > 512:      # PCA to PCA_DIMS fitted on the TRAINING fold only (speed; no test information used)
        U, S, V = torch.pca_lowrank(torch.from_numpy(Xtr), q=PCA_DIMS, center=False, niter=3)
        Xtr = (torch.from_numpy(Xtr) @ V).numpy(); Xte = (torch.from_numpy(Xte) @ V).numpy()
    xt = torch.from_numpy(Xtr); yt = torch.from_numpy(np.asarray(ytr)).long()
    k = 1 if n_classes == 2 else n_classes
    W = torch.zeros(Xtr.shape[1], k, requires_grad=True); b = torch.zeros(k, requires_grad=True)
    opt = torch.optim.LBFGS([W, b], lr=1.0, max_iter=iters, line_search_fn="strong_wolfe")
    n = Xtr.shape[0]

    def closure():
        opt.zero_grad()
        z = xt @ W + b
        if n_classes == 2:
            loss = torch.nn.functional.binary_cross_entropy_with_logits(z.squeeze(1), yt.float())
        else:
            loss = torch.nn.functional.cross_entropy(z, yt)
        loss = loss + (W ** 2).sum() / (2.0 * C * n)
        loss.backward()
        return loss
    opt.step(closure)
    with torch.no_grad():
        z = torch.from_numpy(Xte) @ W + b
        return (torch.sigmoid(z.squeeze(1)) if n_classes == 2 else torch.softmax(z, 1)).numpy()


def cv_auroc(X, y, groups, C, k=3, seed=1):
    f = group_folds(groups, k, seed)
    oof = np.zeros(len(y))
    for i in range(k):
        te = f == i
        oof[te] = fit_predict(X[~te], y[~te], X[te], C)
    return auroc(list(oof), list(y)) or 0.5


def oof_plain(X, y, groups, C, k=5, seed=0):
    """out-of-fold probe scores with a fixed C (used per layer for the descriptive per-layer table and for the controls)"""
    f = group_folds(groups, k, seed)
    oof = np.zeros(len(y))
    for i in range(k):
        te = f == i
        oof[te] = fit_predict(X[~te], y[~te], X[te], C)
    return oof


def oof_nested(Xs, y, groups, Cs=(3e-4, 3e-3, 3e-2), k=5, inner=3, seed=0):
    """Xs: dict layer -> X. Per outer fold, (layer, C) is chosen by inner-CV AUROC on the TRAINING part only; the chosen probe scores the held-out fold. Returns oof scores and the choices."""
    f = group_folds(groups, k, seed)
    oof = np.zeros(len(y)); choices = []
    for i in range(k):
        te, tr = f == i, f != i
        best, bl, bc = -1, None, None
        for L, X in Xs.items():
            for C in Cs:
                a = cv_auroc(X[tr], y[tr], [g for g, t in zip(groups, tr) if t], C, inner, seed + 7)
                if a > best:
                    best, bl, bc = a, L, C
        oof[te] = fit_predict(Xs[bl][tr], y[tr], Xs[bl][te], bc)
        choices.append({"fold": i, "layer": bl, "C": bc, "inner_auroc": round(best, 4)})
    return oof, choices


def summarise(oof, y):
    a = auroc(list(oof), list(y)); n1 = int(sum(y))
    return {"auroc": round(a, 4), "se_hm": round(hm_se(a, n1, len(y) - n1), 4), "n": len(y)}
