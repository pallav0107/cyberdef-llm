#!/usr/bin/env bash
# Multi-seed robustness for the headline cross-dataset claim (PrimeVul-tuned 7B -> DiverseVul).
# seed 0 already exists; add seeds 1,2,3 for base and tuned so the transfer can be reported as
# mean +/- std rather than a single sample. Offline, cached models + cached DiverseVul.
set -uo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src HF_HUB_OFFLINE=1 HF_DATASETS_OFFLINE=1 HF_HUB_DISABLE_XET=1
PY=.venv/bin/python
for S in 1 2 3; do
  echo "### cross-dataset seed $S : base ###"
  $PY scripts/selective_eval.py --model Qwen/Qwen2.5-7B-Instruct \
      --dataset diversevul --split test --n-per-class 200 --max-chars 4000 --seed $S \
      --out results/xdataset_diversevul_base_s${S}.json || echo "XD_BASE_S${S}_FAIL"
  echo "### cross-dataset seed $S : tuned (PrimeVul adapter) ###"
  $PY scripts/selective_eval.py --model Qwen/Qwen2.5-7B-Instruct --adapter out/qlora-primevul \
      --dataset diversevul --split test --n-per-class 200 --max-chars 4000 --seed $S \
      --out results/xdataset_diversevul_tuned_s${S}.json || echo "XD_TUNED_S${S}_FAIL"
done
echo "XDATASET_ROBUST_DONE"
