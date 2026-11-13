#!/usr/bin/env bash
# Train + evaluate ONE model of the security suite on PrimeVul: QLoRA train (skipped if the
# adapter already exists) -> base-vs-tuned accuracy (extbench) + edge (selective). Writes
# results/suite_<tag>_{base,tuned}.json and results/suite_sel_<tag>_{base,tuned}.json.
# Usage: run_suite.sh <hf_model_id> <tag> [adapter_dir]
set -uo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1
PY=.venv/bin/python
M="$1"; TAG="$2"; A="${3:-out/qlora-$TAG}"; MC=4000; DS=primevul

echo "=== [$TAG] model=$M adapter=$A dataset=$DS ==="
if [ -d "$A" ]; then
  echo "[train] adapter $A already exists -- skipping training"
else
  $PY scripts/train_devign.py --base "$M" --out "$A" --dataset $DS \
      --n-per-class 500 --epochs 2 --lr 1e-4 --max-chars $MC --seed 0
fi

echo "=== [$TAG] accuracy: base vs tuned (TEST) ==="
$PY scripts/extbench.py --model "$M" --dataset $DS --split test --max-chars $MC --out results/suite_${TAG}_base.json
$PY scripts/extbench.py --model "$M" --adapter "$A" --dataset $DS --split test --max-chars $MC --out results/suite_${TAG}_tuned.json

echo "=== [$TAG] edge: base vs tuned (TEST) ==="
$PY scripts/selective_eval.py --model "$M" --dataset $DS --split test --max-chars $MC --out results/suite_sel_${TAG}_base.json
$PY scripts/selective_eval.py --model "$M" --adapter "$A" --dataset $DS --split test --max-chars $MC --out results/suite_sel_${TAG}_tuned.json

echo "=== [$TAG] DONE ==="
