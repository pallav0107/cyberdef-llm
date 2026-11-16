"""Stage I class probe: does the hidden state encode WHICH KIND of weakness a vulnerable program has (oracle class: asan/integer/lsan/tsan/resource/sqli/path_traversal/cmd_injection/format_string/none)
better than the model's printed CWE (output K ~4%)? Clean-label pools only (Juliet / Juliet2 / CASTLE vulnerable programs; ids/labels from results/imp_probe_class_cases.json).
  .venv/bin/python scripts/imp_probe_class.py --tag base7b      -> results/imp_probe_class_<tag>.json
Two held-out evaluations, both out-of-sample: (A) TRANSFER: fit on Juliet+Juliet2, score CASTLE (a different corpus), layer/C chosen by grouped inner CV on the TRAIN corpus only, test classes restricted to
classes present in train; (B) grouped 5-fold CV over everything (group = pair base / castle-<cwe>). Each is compared with the majority-class baseline and a shuffled-label control through the same pipeline.
A probe 'carries class information' only if accuracy exceeds the better of majority and shuffled-mean+2sd by > 2 binomial SE. No claim is made about detection."""
import argparse, json, math, sys
import numpy as np
sys.path.insert(0, "src")
from cyberdef import imp_probe as P

LAYERS = [4, 8, 12, 16, 20, 24, 28]
CS = (3e-4, 3e-3, 3e-2)


def acc_se(a, n):
    return math.sqrt(max(a * (1 - a), 1e-9) / max(n, 1))


def fit_choose(Xs, y, groups, k, tr_idx_list=None):
    """pick (layer, C) by grouped inner CV accuracy on the given training part only"""
    best, bl, bc = -1, None, None
    f = P.group_folds(groups, 3, 11)
    for L, X in Xs.items():
        for C in CS:
            correct = 0
            for i in range(3):
                te = f == i
                if te.sum() == 0 or (~te).sum() == 0:
                    continue
                p = P.fit_predict(X[~te], y[~te], X[te], C, n_classes=k).argmax(1)
                correct += int((p == y[te]).sum())
            if correct > best:
                best, bl, bc = correct, L, C
    return bl, bc, best / len(y)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--shuffles", type=int, default=3)
    a = ap.parse_args()
    z = np.load(f"results/imp_acts_{a.tag}_class.npz")
    cases = {c["id"] + "|" + c["label"]: c for c in json.load(open("results/imp_probe_class_cases.json"))["cases"]}
    ids = [str(i) for i in z["ids"]]
    cs = [cases[i] for i in ids]
    Xs = {L: z[f"L{L}"].astype(np.float32) for L in LAYERS}
    cls = sorted({c["oracle_class"] for c in cs}); ci = {c: i for i, c in enumerate(cls)}
    y = np.array([ci[c["oracle_class"]] for c in cs])
    src = np.array([c["source"] for c in cs]); grp = [c["group"] for c in cs]
    res = {"experiment": "imp_probe_class", "tag": a.tag, "classes": cls, "n": len(y), "note": "fits and scores are on disjoint cases/corpora; shuffled and majority controls through the same pipeline"}

    # (A) transfer Juliet(+2) -> CASTLE
    tr = src != "castle"; te = src == "castle"
    trc = set(y[tr]); te_ok = te & np.isin(y, list(trc))
    ytr_raw = y[tr]; remap = {c: i for i, c in enumerate(sorted(trc))}; inv = {i: c for c, i in remap.items()}
    ytr = np.array([remap[c] for c in ytr_raw]); k = len(remap)
    gtr = [g for g, t in zip(grp, tr) if t]
    Xtr_s = {L: X[tr] for L, X in Xs.items()}
    L_, C_, inner = fit_choose(Xtr_s, ytr, gtr, k)
    pr = P.fit_predict(Xs[L_][tr], ytr, Xs[L_][te_ok], C_, n_classes=k).argmax(1)
    pred = np.array([inv[i] for i in pr]); yt = y[te_ok]
    acc = float((pred == yt).mean()); n = int(te_ok.sum())
    maj = max(trc, key=lambda c: int((y[tr] == c).sum())); majacc = float((yt == maj).mean())
    shuf = []
    for s in range(a.shuffles):
        ys = np.random.RandomState(200 + s).permutation(ytr)
        p = P.fit_predict(Xs[L_][tr], ys, Xs[L_][te_ok], C_, n_classes=k).argmax(1)
        shuf.append(float((np.array([inv[i] for i in p]) == yt).mean()))
    sm, ssd = float(np.mean(shuf)), float(np.std(shuf))
    bar = max(majacc, sm + 2 * ssd)
    res["A_transfer_juliet_to_castle"] = {"layer": L_, "C": C_, "inner_acc": round(inner, 4), "n_test": n, "acc": round(acc, 4), "se": round(acc_se(acc, n), 4), "majority_class": cls[maj], "majority_acc": round(majacc, 4),
                                          "shuffled_accs": [round(x, 4) for x in shuf], "shuffled_mean": round(sm, 4), "bar": round(bar, 4), "above_bar_by_2se": bool(acc - bar > 2 * acc_se(acc, n))}
    res["per_case_A"] = [{"id": i, "true": cls[t], "pred": cls[p_]} for i, t, p_ in zip(np.array(ids)[te_ok], yt, pred)]

    # (B) grouped 5-fold over everything (fixed C = 3e-3 per layer, descriptive) + nested headline
    f = P.group_folds(grp, 5, 0)
    k_all = len(cls)

    def cv_pred(Xd, yy):
        out = np.zeros(len(yy), int)
        for i in range(5):
            t = f == i
            out[t] = P.fit_predict(Xd[~t], yy[~t], Xd[t], 3e-3, n_classes=k_all).argmax(1)
        return out
    per_layer = {}
    for L in LAYERS:
        p = cv_pred(Xs[L], y); per_layer[str(L)] = round(float((p == y).mean()), 4)
    bestL = max(per_layer, key=per_layer.get)
    majB = float((y == np.bincount(y).argmax()).mean())
    shufB = []
    for s in range(a.shuffles):
        ys = np.random.RandomState(300 + s).permutation(y)
        shufB.append(float((cv_pred(Xs[int(bestL)], ys) == ys).mean()))
    smB, ssdB = float(np.mean(shufB)), float(np.std(shufB))
    accB = per_layer[bestL]
    res["B_grouped_cv"] = {"per_layer_acc": per_layer, "best_layer_descriptive": int(bestL), "acc_at_best_layer": accB, "majority_acc": round(majB, 4), "shuffled_mean": round(smB, 4),
                           "shuffled_sd": round(ssdB, 4), "n": len(y), "se": round(acc_se(accB, len(y)), 4),
                           "note": "best layer picked on the same CV: optimistic by selection; the transfer test A is the headline. Shuffled control is run at that same layer.",
                           "above_bar_by_2se": bool(accB - max(majB, smB + 2 * ssdB) > 2 * acc_se(accB, len(y)))}
    res["output_K_reference"] = 0.04
    json.dump(res, open(f"results/imp_probe_class_{a.tag}.json", "w"), indent=1)
    print(json.dumps({k_: res[k_] for k_ in ("A_transfer_juliet_to_castle", "B_grouped_cv")}, indent=1))


if __name__ == "__main__":
    main()
