#!/usr/bin/env python3
"""Decide which self-hosted runner (lane) a cyberdef train/eval job runs on, from the model size.

Rule (the owner's): a model that does not fit the box GPU trains AND tests on Spark.
 - box GPU  = 24 GB CUDA (x86)      -> 4-bit QLoRA; fits models up to BOX_MAX_PARAMS_B
 - spark    = GB10 128 GB (aarch64) -> everything larger

Emits GitHub-Actions `name=value` lines on stdout (append to $GITHUB_OUTPUT):
  lane=["self-hosted","cyberdef","gpu-box"]    # a JSON array -> used via fromJSON() in runs-on
  lane_name=gpu-box
  reason=<human text>
  train_warn=<non-empty if this model cannot be *trained* on the chosen lane>

Routing is overridable: --force gpu-box|spark wins (with a reason), for the rare case the
estimate is wrong. Size is parsed from the model id; unknown ids default to Spark (safe: the
big lane), never to the box, so an unrecognised large model is not silently OOM'd on 24 GB.
"""
from __future__ import annotations
import argparse, re, sys

BOX_MAX_PARAMS_B = 14.0          # <=14B trains 4-bit on the 24GB box; >14B -> Spark
SPARK_BF16_TRAIN_MAX_B = 60.0    # bf16 LoRA that still fits 128GB; above this, training needs working 4-bit
LANE_LABELS = {
    "gpu-box": ["self-hosted", "cyberdef", "gpu-box"],
    "spark": ["self-hosted", "cyberdef", "spark"],
}


def params_b(model: str) -> float | None:
    """Billions of parameters parsed from a model id / ollama tag. None if not found."""
    m = model.lower()
    # explicit NNb / NN-b (e.g. qwen2.5-7b, deepseek-r1:32b, qwen3.8:27b, 72b)
    mt = re.search(r"(\d+(?:\.\d+)?)\s*b(?![a-z0-9])", m)
    if mt:
        return float(mt.group(1))
    return None


def decide(model: str, force: str | None):
    p = params_b(model)
    if force in ("gpu-box", "spark"):
        lane = force
        reason = f"forced lane={force} (override); parsed_params={p}B"
    elif p is None:
        lane = "spark"
        reason = f"could not parse size from '{model}'; defaulting to Spark (safe large lane)"
    elif p <= BOX_MAX_PARAMS_B:
        lane = "gpu-box"
        reason = f"{p}B <= {BOX_MAX_PARAMS_B}B box budget -> box GPU (4-bit QLoRA)"
    else:
        lane = "spark"
        reason = f"{p}B > {BOX_MAX_PARAMS_B}B box budget -> Spark (128GB)"
    # Can this model be *trained* on the chosen lane?
    warn = ""
    if lane == "spark" and p is not None and p > SPARK_BF16_TRAIN_MAX_B:
        warn = (f"{p}B training on Spark needs working 4-bit QLoRA (bnb on aarch64/Blackwell); "
                f"bf16 LoRA for {p}B exceeds 128GB. Treat as EVAL-ONLY unless 4-bit is confirmed.")
    return lane, reason, warn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--force", default="", help="gpu-box | spark | '' (auto)")
    ap.add_argument("--mode", default="train", choices=["train", "eval"],
                    help="eval ignores the train-footprint warning")
    a = ap.parse_args()
    lane, reason, warn = decide(a.model, a.force.strip() or None)
    import json
    print(f'lane={json.dumps(LANE_LABELS[lane])}')
    print(f"lane_name={lane}")
    print(f"reason={reason}")
    if a.mode == "train" and warn:
        print(f"train_warn={warn}")
    # also to stderr so it is visible in the job log, not only in outputs
    print(f"[ci_route] {a.model} -> {lane} :: {reason}" + (f" :: WARN {warn}" if warn and a.mode == "train" else ""),
          file=sys.stderr)


if __name__ == "__main__":
    main()
