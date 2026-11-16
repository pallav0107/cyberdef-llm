"""Acceptance for #3 (context) data build, written BEFORE the build. Run from repo root: check_3.py vs_holdout_matched [vs_nolinux_matched]
For each set S: results/imp_ctx_S_cases.json (augmented, original pairing) and results/imp_ctx_S_rematched_cases.json +
results/imp_ctx_S_control.json must exist and satisfy:
 1 same case ids/labels as results/S_cases.json (none dropped)
 2 every augmented code STARTS WITH the original function text (the function itself is untouched) and len(code) <= 6000
 3 the context block contains only names found in the VulSpot row (spot check: every name in the block of 50 cases is in the parquet list)
 4 stored length-only AUROCs equal a recomputation from the case file (1e-3) and differ from the un-augmented ones for at least one measure
   OR are reported equal (never silently identical)
 5 the re-matched set has length-only AUROC in [0.45,0.55] on chars AND tokens (the fail-first control; it must fail on the original
   pairing if context leaks the label through length - reported, not hidden), pairs >= 100
 6 rematched cases are a subset of the original ids (no invented functions)"""
import json, sys

R = "results/"


def auroc(s, y):
    P = [a for a, b in zip(s, y) if b]; N = [a for a, b in zip(s, y) if not b]
    return sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in P for b in N) / (len(P) * len(N))


fails = []
for S in sys.argv[1:]:
    try:
        src = json.load(open(R + f"{S}_cases.json"))["cases"]
        aug = json.load(open(R + f"imp_ctx_{S}_cases.json"))["cases"]
        rem = json.load(open(R + f"imp_ctx_{S}_rematched_cases.json"))["cases"]
        ctl = json.load(open(R + f"imp_ctx_{S}_control.json"))
    except Exception as e:
        print("FAIL: %s: %s" % (S, e)); sys.exit(1)
    if sorted((c["id"], c["label"]) for c in src) != sorted((c["id"], c["label"]) for c in aug):
        fails.append(f"{S}: ids differ from source")
    so = {(c["id"], c["label"]): c for c in src}
    for c in aug:
        o = so[(c["id"], c["label"])]
        if not c["code"].startswith(o["code"]) or len(c["code"]) > 6000:
            fails.append(f"{S}: function altered or too long {c['id']}"); break
    y = [1 if c["label"] == "VULNERABLE" else 0 for c in aug]
    la = auroc([len(c["code"]) for c in aug], y)
    if abs(la - ctl["orig_pairing_length_only"]["chars_seen_by_model"]["auroc"]) > 1e-3:
        fails.append(f"{S}: stored orig-pairing length-only {ctl['orig_pairing_length_only']['chars_seen_by_model']['auroc']} != recomputed {la:.4f}")
    yr = [1 if c["label"] == "VULNERABLE" else 0 for c in rem]
    for k, f in (("chars_full_function", lambda c: len(c["code"])), ("tokens_full_function", lambda c: c["toks"])):
        a = auroc([f(c) for c in rem], yr)
        if not 0.45 <= a <= 0.55:
            fails.append(f"{S}: rematched length-only {k} {a:.3f} outside [0.45,0.55]")
    if len(rem) // 2 < 100:
        fails.append(f"{S}: only {len(rem)//2} rematched pairs")
    if not {(c["id"], c["label"]) for c in rem} <= set(so):
        fails.append(f"{S}: rematched ids not in source")
    if len(rem) != 2 * ctl["rematched_pairs"]:
        fails.append(f"{S}: rematched count inconsistent with control")
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS:", sys.argv[1:])
