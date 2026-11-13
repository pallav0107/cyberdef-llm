#!/usr/bin/env bash
# Recognized-benchmark generalization test: baseline vs tuned on CodeXGLUE Defect
# Detection (Devign). Same harness, only the adapter changes.
set -euo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1
PY=.venv/bin/python
M=Qwen/Qwen2.5-7B-Instruct

echo "=== [1/2] baseline on Devign (CodeXGLUE defect) ==="
$PY scripts/extbench.py --model "$M" --out results/extbench_baseline.json

echo "=== [2/2] tuned on Devign (CodeXGLUE defect) ==="
$PY scripts/extbench.py --model "$M" --adapter out/qlora-vuln --out results/extbench_tuned.json

echo "=== RESULTS (Devign / CodeXGLUE Defect Detection) ==="
$PY - <<PY
import json
b=json.load(open('results/extbench_baseline.json'))
t=json.load(open('results/extbench_tuned.json'))
def line(tag,d):
    c=d['confusion']
    print(f"{tag:8s} score={d['score']:.4f}  conf={c}  prec_vuln={d['precision_vuln']} rec_vuln={d['recall_vuln']} trunc={d['truncated_count']}/{d['n']}")
line('baseline',b); line('tuned',t)
print(f"delta    overall={round(t['score']-b['score'],4)}  (n={t['n']}, balanced {t['n_per_class']}/class, seed={t['seed']})")
PY
