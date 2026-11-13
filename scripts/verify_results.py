"""Independent re-computation of every headline metric from the recorded per_case arrays.

This deliberately does NOT import the eval code that produced the numbers: it re-derives
accuracy, AUROC, ECE and selective accuracy (acc@25%, acc@10%) from scratch, then compares to
the stored summary. A MISMATCH means the summary cannot be trusted. This is the "recompute from
primary data" gate -- a result is only reportable if it reproduces here.
"""
import json, glob, math, sys, os

def auroc(scores, pos):
    # P(score_pos > score_neg), ties count 0.5. O(n_pos*n_neg), fine for n=200/400.
    P = [s for s, y in zip(scores, pos) if y]
    N = [s for s, y in zip(scores, pos) if not y]
    if not P or not N:
        return None
    wins = 0.0
    for a in P:
        for b in N:
            wins += 1.0 if a > b else (0.5 if a == b else 0.0)
    return wins / (len(P) * len(N))

def ece(conf, correct, bins=10):
    N = len(conf)
    tot = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i in range(N) if (conf[i] > lo or (b == 0 and conf[i] == 0)) and conf[i] <= hi]
        if not idx:
            continue
        acc = sum(correct[i] for i in idx) / len(idx)
        cf = sum(conf[i] for i in idx) / len(idx)
        tot += (len(idx) / N) * abs(acc - cf)
    return tot

def sel_acc(conf, correct, frac):
    N = len(conf)
    k = max(1, round(frac * N))
    order = sorted(range(N), key=lambda i: conf[i], reverse=True)[:k]
    return sum(correct[i] for i in order) / k

def close(a, b, tol=0.02):
    if a is None or b is None:
        return a is None and b is None
    return abs(a - b) <= tol

fails = 0
for f in sorted(glob.glob("results/cls_*.json") + glob.glob("results/xdataset_*.json")):
    d = json.load(open(f))
    pc = d["per_case"]
    label = [1 if c["label"] == "VULNERABLE" else 0 for c in pc]
    pred = [1 if c["pred"] == "VULNERABLE" else 0 for c in pc]
    p_vuln = [c["p_vuln"] for c in pc]
    conf = [c["conf"] for c in pc]
    correct = [1 if pred[i] == label[i] else 0 for i in range(len(pc))]
    # also cross-check the stored 'correct' flag is internally consistent
    stored_correct = [c["correct"] for c in pc]
    r_acc = sum(correct) / len(pc)
    r_auc = auroc(p_vuln, label)
    r_ece = ece(conf, correct)
    r_a25 = sel_acc(conf, correct, 0.25)
    r_a10 = sel_acc(conf, correct, 0.10)
    s_acc = d["accuracy"]; s_auc = d["auroc"]; s_ece = d["ece"]
    s_a25 = d["risk_coverage"]["0.25"]["accuracy"]; s_a10 = d["risk_coverage"]["0.10"]["accuracy"]
    checks = {
        "correct_flag": correct == stored_correct,
        "acc": close(r_acc, s_acc), "auroc": close(r_auc, s_auc),
        "ece": close(r_ece, s_ece, 0.03), "acc@25": close(r_a25, s_a25),
        "acc@10": close(r_a10, s_a10),
    }
    ok = all(checks.values())
    fails += (0 if ok else 1)
    tag = os.path.basename(f)
    verdict = "PASS" if ok else "***MISMATCH***"
    print(f"{verdict}  {tag}")
    print(f"   acc  stored={s_acc:.3f} recomp={r_acc:.3f} | auroc stored={s_auc} recomp={round(r_auc,4) if r_auc else None} | "
          f"ece stored={s_ece} recomp={round(r_ece,4)} | acc@25 {s_a25:.3f}/{r_a25:.3f} | acc@10 {s_a10:.3f}/{r_a10:.3f}")
    if not ok:
        print("   FAILED CHECKS:", [k for k, v in checks.items() if not v])

print(f"\n{'ALL VERIFIED' if fails == 0 else str(fails)+' FILE(S) MISMATCHED'} ({len(glob.glob('results/cls_*.json')+glob.glob('results/xdataset_*.json'))} files)")
sys.exit(1 if fails else 0)
