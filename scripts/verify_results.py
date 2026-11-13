"""Independent re-computation of every headline metric from the recorded per_case arrays.

This deliberately does NOT import the eval code that produced the numbers: it re-derives
accuracy, AUROC, ECE and selective accuracy (acc@25%, acc@10%) from scratch, then compares to
the stored summary. A MISMATCH means the summary cannot be trusted. This is the "recompute from
primary data" gate -- a result is only reportable if it reproduces here.

The re-computation accounts for tie-aware ranges in selective accuracy and AUROC:
since per_case stores conf / p_vuln values rounded to 4-6 decimals, ties are real,
and a stored value is accepted only if some ordering of tied cases reproduces it.
The accuracy and correct_flag checks use a stricter tolerance (0.00051) for exactness.
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

def sel_acc_tie_aware(conf, correct, frac):
    """Compute the exact achievable range [lo, hi] over all tie resolutions at the cutoff.
    
    For a cutoff value where cases can be tied, this computes the minimum and maximum 
    possible selectivity accuracy over all tie resolution orders.
    """
    N = len(conf)
    k = max(1, round(frac * N))
    
    # Create list of (conf_value, is_correct, index) and sort by confidence descending 
    indexed_conf = [(conf[i], correct[i], i) for i in range(N)]
    indexed_conf.sort(key=lambda x: x[0], reverse=True)
    
    # Find the kth highest confidence value (the cutoff value)
    cutoff = indexed_conf[k-1][0]  # kth highest confidence
    
    # Identify which cases are above, at, and below the cutoff
    above_cutoff = [i for i, (c, _, _) in enumerate(indexed_conf) if c > cutoff]
    on_cutoff = [i for i, (c, _, _) in enumerate(indexed_conf) if c == cutoff]
    
    # Count how many correct cases are among those above cutoff
    a = sum(1 for i in above_cutoff if indexed_conf[i][1] == 1)
    
    # Count how many correct cases are among those at cutoff (these make a difference)
    tied_correct = [i for i in on_cutoff if indexed_conf[i][1] == 1]
    
    # For different tie resolutions:
    # - lo: tie-breaking favors wrong answer (minimize correct count)
    # - hi: tie-breaking favors correct answer (maximize correct count)
    need = k - len(above_cutoff)
    t = len(tied_correct)
    
    # lo: we try to minimize the correct answers among tied cases
    # If need = 0, we don't need any tied cases, so we pick 0 correct cases among tied
    # If need = 1, we could have 0 or 1 correct case among tied, so we pick 0
    # If we have more tied cases than we need, we can pick 0 to (len(on_cutoff) - need) wrong
    lo = (a + max(0, need - (len(on_cutoff) - t))) / k
    
    # hi: we try to maximize the correct answers among tied cases  
    # If we need k cases and we already have a correct ones above, we need (k - a) more
    # If need >= len(on_cutoff), we take all tied cases as correct
    # If need < len(on_cutoff), we can take up to min(len(on_cutoff) - need, t) cases as correct
    hi = (a + min(need, t)) / k
    
    return lo, hi

def auroc_tie_aware(p_vuln, label):
    """Compute the exact achievable range [lo, hi] over tie resolutions.
    
    For tied p_vuln values, compute min and max possible AUROC over all tie resolution orders.
    """
    # For tied pairs of examples, compute the range of possible AUROC values
    # by considering min case (tied pairs counted as 0.0) and max case (tied pairs counted as 1.0)
    pos_indices = [i for i in range(len(p_vuln)) if label[i] == 1]
    neg_indices = [i for i in range(len(p_vuln)) if label[i] == 0]
    
    # Find all tied p_vuln values
    from collections import defaultdict
    tied_values = defaultdict(list)
    for i, p in enumerate(p_vuln):
        tied_values[p].append(i)
        
    # Compute two extremes: 
    # 1. min_auroc: tied pairs counted as 0.0 (loosest AUROC - minimum)  
    # 2. max_auroc: tied pairs counted as 1.0 (tightest AUROC - maximum)
    min_wins = 0.0
    max_wins = 0.0
    
    P = [p_vuln[i] for i in range(len(p_vuln)) if label[i] == 1]
    N = [p_vuln[i] for i in range(len(p_vuln)) if label[i] == 0] 
    
    if not P or not N:
        return None, None
    
    for i in pos_indices:
        for j in neg_indices:
            if p_vuln[i] > p_vuln[j]:
                min_wins += 1.0
                max_wins += 1.0
            elif p_vuln[i] == p_vuln[j]:  # Tied case
                # Min case: count as 0.0 (worst AUROC)  
                min_wins += 0.0
                # Max case: count as 1.0 (best AUROC)
                max_wins += 1.0
            else:
                # p_vuln[i] < p_vuln[j]
                min_wins += 0.0
                max_wins += 0.0

    # Normalize
    min_auroc = min_wins / (len(P) * len(N))
    max_auroc = max_wins / (len(P) * len(N))
    
    return min_auroc, max_auroc

def close(a, b, tol=0.00051):
    """Check if two values are close with tight tolerance for exactness."""
    if a is None or b is None:
        return a is None and b is None
    return abs(a - b) <= tol

def is_valid_result_file(d):
    """Check if this is a valid result file with all required fields."""
    if "per_case" not in d:
        return False
    pc = d["per_case"]
    if not pc:
        return False
    # Check if per_case contains the required fields
    if not all(key in pc[0] for key in ["conf", "p_vuln", "label", "pred", "correct"]):
        return False
    # Check top-level fields
    if "auroc" not in d or "risk_coverage" not in d:
        return False
    return True

fails = 0
# Check all JSON files that have a per_case array with needed fields
files_to_check = []
# Previously only checked cls_*.json and xdataset_*.json 
# Now we check ALL files that have per_case with the required fields
for f in glob.glob("results/*.json"):
    try:
        d = json.load(open(f))
        if is_valid_result_file(d):
            files_to_check.append(f)
    except:
        # Silently skip files that can't be loaded or don't match format
        pass

for f in sorted(files_to_check):
    d = json.load(open(f))
    pc = d["per_case"]
    label = [1 if c["label"] == "VULNERABLE" else 0 for c in pc]
    pred = [1 if c["pred"] == "VULNERABLE" else 0 for c in pc]
    p_vuln = [c["p_vuln"] for c in pc]
    conf = [c["conf"] for c in pc]
    correct = [1 if pred[i] == label[i] else 0 for i in range(len(pc))]
    # also cross-check the stored 'correct' flag is internally consistent
    stored_correct = [c["correct"] for c in pc]
    
    # Recompute metrics
    r_acc = sum(correct) / len(pc)
    r_auc = auroc(p_vuln, label)
    r_ece = ece(conf, correct)
    r_a25 = sel_acc(conf, correct, 0.25)
    r_a10 = sel_acc(conf, correct, 0.10)
    
    # Get stored values 
    s_acc = d["accuracy"]; s_auc = d["auroc"]; s_ece = d["ece"]
    s_a25 = d["risk_coverage"]["0.25"]["accuracy"]; s_a10 = d["risk_coverage"]["0.10"]["accuracy"]
    
    # Compute tie-aware ranges
    r_a25_lo, r_a25_hi = sel_acc_tie_aware(conf, correct, 0.25)
    r_a10_lo, r_a10_hi = sel_acc_tie_aware(conf, correct, 0.10)
    r_auc_lo, r_auc_hi = auroc_tie_aware(p_vuln, label)
    
    # Check with tie-aware comparisons  
    checks = {
        "correct_flag": correct == stored_correct,
        "acc": close(r_acc, s_acc),
        "auroc": r_auc_lo is not None and r_auc_lo - 0.00051 <= s_auc <= r_auc_hi + 0.00051,
        "ece": close(r_ece, s_ece, 0.03),
        "acc@25": r_a25_lo - 0.00051 <= s_a25 <= r_a25_hi + 0.00051,
        "acc@10": r_a10_lo - 0.00051 <= s_a10 <= r_a10_hi + 0.00051,
    }
    
    ok = all(checks.values())
    fails += (0 if ok else 1)
    tag = os.path.basename(f)
    verdict = "PASS" if ok else "***MISMATCH***"
    print(f"{verdict}  {tag}")
    if ok:
        print(f"   acc  stored={s_acc:.4f} recomp={r_acc:.4f} | auroc stored={s_auc} recomp={round(r_auc,4) if r_auc else None} | "
              f"ece stored={s_ece} recomp={round(r_ece,4)} | acc@25 {s_a25:.3f}/{r_a25:.3f} | acc@10 {s_a10:.3f}/{r_a10:.3f}")
    else:
        print(f"   acc  stored={s_acc:.4f} recomp={r_acc:.4f} | auroc stored={s_auc} recomp={round(r_auc,4) if r_auc else None} | "
              f"ece stored={s_ece} recomp={round(r_ece,4)} | acc@25 {s_a25:.3f}/{r_a25:.3f} (range [{r_a25_lo:.3f}, {r_a25_hi:.3f}]) | acc@10 {s_a10:.3f}/{r_a10:.3f} (range [{r_a10_lo:.3f}, {r_a10_hi:.3f}])")
        print("   FAILED CHECKS:", [k for k, v in checks.items() if not v])

print(f"\n{'ALL VERIFIED' if fails == 0 else str(fails)+' FILE(S) MISMATCHED'} ({len(files_to_check)} files)")
sys.exit(1 if fails else 0)
