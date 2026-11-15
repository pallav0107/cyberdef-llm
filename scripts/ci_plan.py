#!/usr/bin/env python3
"""Plan what one run of a cyberdef workflow does on its machine (GPU · train + test, Spark · train + test,
Spark · trace bank).

Reads the dispatch inputs from the environment and prints GitHub-Actions `name=value` lines for $GITHUB_OUTPUT:
  MACHINE   gpu-box | spark            MODEL   the model ('' = none)
  STEPS     train + test | train only | test only | trace bank | checks + status
  TAG       adapter / output name      TEST_SET, SCORER as in the workflow inputs
Outputs: model, slug, adapter_tag, train, test, bank (true|false), cases_file, set_key, scorer, train_warn.

Adapter name: training writes out/imp_<TAG> (ci_step.sh refuses a TAG whose adapter already exists, so nothing is
overwritten); "test only" reads out/imp_<TAG>, or the base model when TAG is blank.
"""
from __future__ import annotations
import os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ci_route import decide  # noqa: E402

# The SC-CoT grammar bug was fixed by schema v2.3 (commit c8851c0); the fixed file landed on Spark at this epoch
# (2026-11-15 14:01 AEDT). Trace banks and CoT items written before it were decoded under the bug: INVALID.
SC_FIX_EPOCH = 1794711662

# The quick v2.3 bank's make-up is fixed by this amendment; every CoT item build is stamped with it, so a machine can
# never train on items built before it (acceptance/improve/QUICK_BANK_J2_AMENDMENT_2026-11-15.md).
QUICK_BANK_AMENDMENT = "QUICK_BANK_AMENDMENT_2_2026-11-15"   # batch 2: quick + J2 + J3 (<= 500 pairs) + Q

SET_FILES = {
    "pv": "results/lenmatched_eval_cases.json", "pv300": "results/lenmatched_eval_cases_300.json",
    "vh": "results/vs_holdout_matched_cases.json", "vn": "results/vs_nolinux_matched_cases.json",
    "castle": "results/xdata_castle_cases.json", "j3m": "results/j3_heldout_matched_cases.json", "qh": "results/q_heldout_cases.json", "j4m": "results/j4_heldout_matched_cases.json", "j3h": "results/j3_heldout_cases.json", "j3s": "results/j3s_heldout_matched_cases.json", "j4s": "results/j4s_heldout_matched_cases.json", "loc": "results/imp_loc_cases.json", "pairs": "results/imp_vs_pairs_eval_cases.json",
}
PREREG = "pre-registered sets (PrimeVul, VulSpot x2, CASTLE, J3 held-out matched + all; CoT arms add localisation)"
TEST_SETS = {   # choice -> set keys. PREREG is completed per arm in plan() (the queue jobs P60/P61/P86 evaluate exactly these)
    PREREG: ["pv", "vh", "vn", "castle", "j3m", "j3h"],   # j3m (2c, length-matched, primary) and j3h (2b): in-distribution per class
    "PrimeVul length-matched (1,074)": ["pv"],
    "PrimeVul length-matched sample (300)": ["pv300"],
    "VulSpot holdout, length-matched": ["vh"],
    "VulSpot no-linux, length-matched": ["vn"],
    "CASTLE (198 runnable programs)": ["castle"],
    "amendment 3 round sets (J3 matched, SQLi held-out, J4 matched, CASTLE, PrimeVul 300)": ["j3m", "qh", "j4m", "castle", "pv300"],   # addendum 3a
    "amendment 3 category round, J3 (J3 matched, CASTLE, PrimeVul 300)": ["j3m", "castle", "pv300"],
    "amendment 3i round sets (J4s, J3s, CASTLE, PrimeVul 300)": ["j4s", "j3s", "castle", "pv300"],   # addendum 3i: structure-matched primary tests (memory/integer/leak; format string)   # addendum 3a minimum for command injection, path traversal, format string adapters
}
# Training data. CoT arms use the pre-registered recipes of the queue jobs P60 (arm 2) and P61 (arm 6), on the items built
# from the QUICK v2.3 trace bank (imp_cotq_*). Each arm has a verdict-only twin on identical rows: the arm-vs-twin
# comparison is the pre-registered test, so train both, on the same machine.
DATA = {
    # answer-only: the honest default is the length-matched PrimeVul pool (as the pre-registered answer-only arm); the raw
    # pool is kept only as a labelled contrast, because length alone scores 0.82 AUROC on it
    "answer-only, length-matched PrimeVul": ("", "--length-match"),
    "answer-only, raw PrimeVul (length-confounded contrast)": ("", ""),
    "CoT arm 2: traces passing V+P+S": ("results/imp_cotq_2_items.json", "--val-per-class 5 --pair-batches"),
    "CoT arm 2 twin: same rows, verdict only": ("results/imp_cotq_2_twin_items.json", "--val-per-class 5 --pair-batches"),
    "CoT arm 6: counterfactual traces": ("results/imp_cotq_6_items.json", "--val-per-class 5 --pair-batches --pair-loss 1"),
    "CoT arm 6 twin: same rows, verdict only": ("results/imp_cotq_6_twin_items.json", "--val-per-class 5 --pair-batches --pair-loss 1"),
    # arm 7 trains only on execution-confirmed (X_strict) traces; it runs only if the pre-registered gate (>= 200) passes
    "CoT arm 7: execution-grounded traces": ("results/imp_cotq_7_items.json", "--val-per-class 5 --pair-batches"),
    "CoT arm 7 twin: same rows, verdict only": ("results/imp_cotq_7_twin_items.json", "--val-per-class 5 --pair-batches"),
    # amendment 3 / addendum 3a: items written by scripts/imp_st_round.sh; no --pair-batches (filtering does not keep pairs)
    "Qwen3.8 self-training: CoT items (amendment 3; results/<tag>_items.json)": ("@TAG", "--val-per-class 5"),
    "Qwen3.8 self-training: twin (amendment 3; tag ends _twin)": ("@TAG", "--val-per-class 5"),
}
ARM7_GATE_MIN = 200    # pre-registered: arm 7 needs >= 200 X_strict traces in the build it trains on
MODEL_STEPS = {"train + test": (True, True), "train only": (True, False), "test only": (False, True)}
ALL_STEPS = set(MODEL_STEPS) | {"checks + status", "trace bank"}


def slug(model: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", model.split("/")[-1].lower()).strip("-")


def plan(env) -> dict:
    machine = env.get("MACHINE", "").strip()
    if machine not in ("gpu-box", "spark"):
        raise SystemExit(f"plan: unknown machine '{machine}'")
    steps = env.get("STEPS", "").strip() or "checks + status"      # push / schedule runs have no inputs
    if steps not in ALL_STEPS:
        raise SystemExit(f"plan: unknown steps '{steps}'")
    model = env.get("MODEL", "").strip()
    tag = env.get("TAG", "").strip()
    if tag and not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        raise SystemExit(f"plan: tag '{tag}' may only contain letters, digits, '.', '_' and '-'")
    scorer = "zeroshot" if env.get("SCORER", "").startswith("zero") else "selective"
    train, test = MODEL_STEPS.get(steps, (False, False))
    train, test = train and bool(model), test and bool(model)
    bank = steps == "trace bank" and machine == "spark" and bool(model)
    if (train or bank) and not tag:
        raise SystemExit("plan: training and the trace bank need a tag (the output name)")
    if train and scorer == "zeroshot":
        raise SystemExit("plan: zero-shot scoring is for Ollama models; use steps = 'test only'")
    test_set = env.get("TEST_SET", "").strip()
    if test and test_set not in TEST_SETS:
        raise SystemExit(f"plan: unknown test set '{test_set}'")
    warn = ""
    if train:
        auto_lane, _, spark_warn = decide(model, None)
        if machine == "gpu-box" and auto_lane != "gpu-box":
            warn = f"{model} is larger than the 14B box budget (or its size is unknown): put it on Spark, or set ack_oom"
        elif machine == "spark":
            warn = decide(model, "spark")[2] or spark_warn
    s = slug(model) if model else ""
    adapter = tag if (model and (train or test)) else ""
    data = env.get("DATA", "").strip() or "answer-only, length-matched PrimeVul"
    if (train or test) and data not in DATA:
        raise SystemExit(f"plan: unknown training data '{data}'")
    items_file, data_flags = DATA.get(data, ("", "")) if train else ("", "")
    st = data.startswith("Qwen3.8 self-training")
    if st and (train or test):
        if machine != "spark":
            raise SystemExit("plan: Qwen3.8 self-training runs on Spark only")
        if not tag or ("twin" in data) != tag.endswith("_twin"):
            raise SystemExit("plan: self-training needs a tag; the twin's tag must end in _twin and only the twin's")
    if items_file == "@TAG":
        items_file = f"results/{tag}_items.json"
    arm7 = data.startswith("CoT arm 7")
    # scorer: CoT arms are tested the pre-registered way, by generating the SC-CoT (imp_eval_cot.py, vLLM, on Spark);
    # their twins, answer-only adapters and base models by the verdict probability (imp_selective.py)
    cot_arm = (data.startswith("CoT arm") or data.startswith("Qwen3.8 self-training: CoT")) and "twin" not in data
    if scorer != "zeroshot" and cot_arm:
        scorer = "cot"
    keys = list(TEST_SETS[test_set]) if test else []
    if test and test_set == PREREG and cot_arm:
        keys += ["loc"] + (["pairs"] if data.startswith("CoT arm 6") else [])
    test_sets = " ".join(f"{k}={SET_FILES[k]}" for k in keys)
    from ci_route import params_b
    p = params_b(model) if model else None
    return {"model": model, "slug": s, "adapter_tag": adapter, "train": train, "test": test, "bank": bank,
            "test_sets": test_sets, "scorer": scorer, "train_warn": warn,
            "items_file": items_file, "data_flags": data_flags, "params_b": "" if p is None else p,
            "amendment": QUICK_BANK_AMENDMENT, "arm7_gate": ARM7_GATE_MIN if (arm7 and train) else ""}


def main():
    p = plan(os.environ)
    for k, v in p.items():
        print(f"{k}={('true' if v else 'false') if isinstance(v, bool) else v}")
    what = [w for w in ("bank", "train", "test") if p[w]]
    print(f"[plan] {os.environ.get('MACHINE')}: " + (f"{p['model']} -> {', '.join(what) or 'checks only'}" if p["model"] else "no model this run")
          + (f" :: adapter out/imp_{p['adapter_tag']}" if p["adapter_tag"] and (p["train"] or p["test"]) else "")
          + (f" :: test ({p['scorer']}) on {' '.join(t.split('=')[0] for t in p['test_sets'].split())}" if p["test"] else "")
          + (f" :: WARN {p['train_warn']}" if p["train_warn"] else ""),
          file=sys.stderr)


if __name__ == "__main__":
    main()
