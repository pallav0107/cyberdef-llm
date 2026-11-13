#!/usr/bin/env bash
# All the high-value analyses that need ONLY cached models + cached data (box GPU, no internet).
# Safe to run while the WiFi uplink is down. Each step is non-fatal so one failure cannot abort
# the batch. Every number is written to results/*.json with per_case for later recomputation.
set -uo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src HF_HUB_OFFLINE=1 HF_DATASETS_OFFLINE=1 HF_HUB_DISABLE_XET=1
PY=.venv/bin/python

echo "################ CROSS-DATASET GENERALIZATION ################"
echo "# Our best model was fine-tuned on PrimeVul. Here it is tested on DiverseVul, which it has"
echo "# NEVER seen. If the edge is real (not memorised) it should transfer to an unseen corpus."
$PY scripts/selective_eval.py --model Qwen/Qwen2.5-7B-Instruct \
    --dataset diversevul --split test --n-per-class 200 --max-chars 4000 \
    --out results/xdataset_diversevul_base.json || echo "XD_BASE_FAIL"
$PY scripts/selective_eval.py --model Qwen/Qwen2.5-7B-Instruct --adapter out/qlora-primevul \
    --dataset diversevul --split test --n-per-class 200 --max-chars 4000 \
    --out results/xdataset_diversevul_tuned.json || echo "XD_TUNED_FAIL"

echo "################ IN-CLASS LEADERBOARD: PrimeVul ################"
bash scripts/compare_class.sh primevul out/qlora-primevul || echo "LB_PRIMEVUL_FAIL"

echo "################ IN-CLASS LEADERBOARD: Devign ################"
bash scripts/compare_class.sh devign out/qlora-devign || echo "LB_DEVIGN_FAIL"

echo "ALL_OFFLINE_ANALYSES_DONE"
