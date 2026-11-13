#!/usr/bin/env bash
# Increment 2: train on REAL Devign code, then honest baseline-vs-tuned on the untouched
# test split (and val for a fuller picture). One fixed config, one test eval.
set -euo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1
PY=.venv/bin/python
M=Qwen/Qwen2.5-7B-Instruct
A=out/qlora-devign
MC=4000

echo "=== [1/5] train QLoRA on real Devign train split ==="
$PY scripts/train_devign.py --base "$M" --out "$A" --n-per-class 1000 --epochs 2 --lr 1e-4 --max-chars $MC --seed 0

echo "=== [2/5] baseline on TEST (max_chars=$MC) ==="
$PY scripts/extbench.py --model "$M" --split test --max-chars $MC --out results/devign_test_baseline.json
echo "=== [3/5] tuned on TEST ==="
$PY scripts/extbench.py --model "$M" --adapter "$A" --split test --max-chars $MC --out results/devign_test_tuned.json
echo "=== [4/5] baseline on VALIDATION ==="
$PY scripts/extbench.py --model "$M" --split validation --max-chars $MC --out results/devign_val_baseline.json
echo "=== [5/5] tuned on VALIDATION ==="
$PY scripts/extbench.py --model "$M" --adapter "$A" --split validation --max-chars $MC --out results/devign_val_tuned.json

echo "=== RESULTS (Devign real-data retrain) ==="
$PY - <<PY
import json
def L(tag,f):
    d=json.load(open(f)); c=d['confusion']
    print(f"{tag:16s} score={d['score']:.4f} conf={c} prec={d['precision_vuln']} rec={d['recall_vuln']}")
    return d['score']
bt=L('TEST baseline','results/devign_test_baseline.json')
tt=L('TEST tuned','results/devign_test_tuned.json')
bv=L('VAL  baseline','results/devign_val_baseline.json')
tv=L('VAL  tuned','results/devign_val_tuned.json')
print(f"TEST delta = {round(tt-bt,4)}   VAL delta = {round(tv-bv,4)}")
print("VERDICT:", "POSITIVE (real-data training generalizes)" if tt>bt else "NOT POSITIVE (no generalization gain)")
PY
