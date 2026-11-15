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

TEST_SETS = {
    "PrimeVul length-matched (1,074)": ("results/lenmatched_eval_cases.json", "pv"),
    "PrimeVul length-matched sample (300)": ("results/lenmatched_eval_cases_300.json", "pv300"),
    "VulSpot holdout, length-matched": ("results/vs_holdout_matched_cases.json", "vh"),
    "VulSpot no-linux, length-matched": ("results/vs_nolinux_matched_cases.json", "vn"),
}
# Training data. CoT arms use the pre-registered recipes of the queue jobs P60 (arm 2) and P61 (arm 6), on the items built
# from the QUICK v2.3 trace bank (imp_cotq_*). Each arm has a verdict-only twin on identical rows: the arm-vs-twin
# comparison is the pre-registered test, so train both, on the same machine.
DATA = {
    "answer-only (PrimeVul)": ("", ""),
    "CoT arm 2: traces passing V+P+S": ("results/imp_cotq_2_items.json", "--val-per-class 5 --pair-batches"),
    "CoT arm 2 twin: same rows, verdict only": ("results/imp_cotq_2_twin_items.json", "--val-per-class 5 --pair-batches"),
    "CoT arm 6: counterfactual traces": ("results/imp_cotq_6_items.json", "--val-per-class 5 --pair-batches --pair-loss 1"),
    "CoT arm 6 twin: same rows, verdict only": ("results/imp_cotq_6_twin_items.json", "--val-per-class 5 --pair-batches --pair-loss 1"),
}
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
    cases_file, set_key = TEST_SETS.get(test_set, ("", "")) if test else ("", "")
    data = env.get("DATA", "").strip() or "answer-only (PrimeVul)"
    if train and data not in DATA:
        raise SystemExit(f"plan: unknown training data '{data}'")
    items_file, data_flags = DATA.get(data, ("", "")) if train else ("", "")
    from ci_route import params_b
    p = params_b(model) if model else None
    return {"model": model, "slug": s, "adapter_tag": adapter, "train": train, "test": test, "bank": bank,
            "cases_file": cases_file, "set_key": set_key, "scorer": scorer, "train_warn": warn,
            "items_file": items_file, "data_flags": data_flags, "params_b": "" if p is None else p}


def main():
    p = plan(os.environ)
    for k, v in p.items():
        print(f"{k}={('true' if v else 'false') if isinstance(v, bool) else v}")
    what = [w for w in ("bank", "train", "test") if p[w]]
    print(f"[plan] {os.environ.get('MACHINE')}: " + (f"{p['model']} -> {', '.join(what) or 'checks only'}" if p["model"] else "no model this run")
          + (f" :: adapter out/imp_{p['adapter_tag']}" if p["adapter_tag"] and (p["train"] or p["test"]) else "")
          + (f" :: test set {p['set_key']}" if p["test"] else "") + (f" :: WARN {p['train_warn']}" if p["train_warn"] else ""),
          file=sys.stderr)


if __name__ == "__main__":
    main()
