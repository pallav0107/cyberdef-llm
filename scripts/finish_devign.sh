#!/usr/bin/env bash
# Eval-only: training already produced out/qlora-devign. Run the 4 benchmark evals, refresh
# the generated results tables, then the selective/edge measurement. No retraining.
set -uo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1
PY=.venv/bin/python
M=Qwen/Qwen2.5-7B-Instruct
A=out/qlora-devign
MC=4000

echo "=== extbench: TEST baseline ==="; $PY scripts/extbench.py --model "$M" --split test --max-chars $MC --out results/devign_test_baseline.json
echo "=== extbench: TEST tuned ===";   $PY scripts/extbench.py --model "$M" --adapter "$A" --split test --max-chars $MC --out results/devign_test_tuned.json
echo "=== extbench: VAL baseline ===";  $PY scripts/extbench.py --model "$M" --split validation --max-chars $MC --out results/devign_val_baseline.json
echo "=== extbench: VAL tuned ===";     $PY scripts/extbench.py --model "$M" --adapter "$A" --split validation --max-chars $MC --out results/devign_val_tuned.json

echo "=== refresh generated tables ==="; $PY scripts/make_results_table.py || true

echo "=== INCREMENT-2 SUMMARY ==="
$PY - <<PY
import json, os
def L(t,f):
    if not os.path.exists(f): print(f"{t:14s} MISSING"); return None
    d=json.load(open(f)); c=d['confusion']
    print(f"{t:14s} acc={d['score']:.4f} conf={c} prec={d['precision_vuln']} rec={d['recall_vuln']}")
    return d['score']
bt=L('TEST base','results/devign_test_baseline.json'); tt=L('TEST tuned','results/devign_test_tuned.json')
bv=L('VAL base','results/devign_val_baseline.json');   tv=L('VAL tuned','results/devign_val_tuned.json')
if None not in (bt,tt): print("TEST delta =", round(tt-bt,4))
if None not in (bv,tv): print("VAL  delta =", round(tv-bv,4))
PY

echo "=== EDGE (selective / calibrated) ==="
bash scripts/selective_run.sh
