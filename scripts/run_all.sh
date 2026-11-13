#!/usr/bin/env bash
# Real increment-1 run on Qwen2.5-7B: baseline -> QLoRA train -> re-benchmark -> gate.
set -euo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1   # Xet backend errors on this box's network; use classic resumable HTTP
PY=.venv/bin/python
M=Qwen/Qwen2.5-7B-Instruct
echo "=== [0/4] prefetch $M (robust, resumable) ==="
$PY scripts/prefetch.py "$M"
echo "=== [1/4] baseline eval on $M ==="
$PY -m cyberdef.evaluate --model "$M" --suite vuln_detect --out results/baseline.json
echo "=== [2/4] QLoRA train on $M ==="
$PY -m cyberdef.train --base "$M" --out out/qlora-vuln --epochs 3
echo "=== [3/4] tuned eval on $M + adapter ==="
$PY -m cyberdef.evaluate --model "$M" --adapter out/qlora-vuln --suite vuln_detect --out results/tuned.json
echo "=== [4/4] acceptance gate ==="
bash acceptance/check.sh
echo "=== RESULTS ==="
$PY -c "import json;b=json.load(open('results/baseline.json'));t=json.load(open('results/tuned.json'));print(f\"baseline score={b['score']} heldout={b['heldout_score']}\");print(f\"tuned    score={t['score']} heldout={t['heldout_score']}\");print(f\"delta    overall={round(t['score']-b['score'],4)} heldout={round((t['heldout_score'] or 0)-(b['heldout_score'] or 0),4)}\")"
