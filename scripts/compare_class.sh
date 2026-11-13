#!/usr/bin/env bash
# "Better in its class?" head-to-head: base, our fine-tune, and open peers, all through the
# SAME logprob-scored harness on a recognized benchmark. Every model is judged identically;
# only "ours" carries a fine-tuned adapter (the peers are evaluated zero-shot, which is the
# honest framing: a small QLoRA adapter vs off-the-shelf open models of the same class).
#
# Usage: compare_class.sh [dataset] [ours_adapter]
#   dataset       default: devign      (any key in benchdata.BENCHES: devign|primevul|diversevul)
#   ours_adapter  default: out/qlora-devign
#
# Runs fully offline against cached models (HF_HUB_OFFLINE=1). One model failing (e.g. not
# downloaded) does NOT abort the rest and simply does not appear in the leaderboard.
set -uo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1
export HF_HUB_OFFLINE=1
export HF_DATASETS_OFFLINE=1
PY=.venv/bin/python
MC=4000
SPLIT=test
DATASET="${1:-devign}"
OURS_ADAPTER="${2:-out/qlora-devign}"
PREFIX="cls_${DATASET}"

run() { # tag  model  [adapter]
  local tag="$1" model="$2" adapter="${3:-}"
  echo "=== $tag : $model ${adapter:+(adapter $adapter)} on ${DATASET} ==="
  if [ -n "$adapter" ]; then
    $PY scripts/selective_eval.py --model "$model" --adapter "$adapter" --dataset "$DATASET" \
        --split $SPLIT --max-chars $MC --out "results/${PREFIX}_${tag}.json" || echo "FAILED $tag"
  else
    $PY scripts/selective_eval.py --model "$model" --dataset "$DATASET" \
        --split $SPLIT --max-chars $MC --out "results/${PREFIX}_${tag}.json" || echo "FAILED $tag"
  fi
}

run base        Qwen/Qwen2.5-7B-Instruct
run ours        Qwen/Qwen2.5-7B-Instruct "$OURS_ADAPTER"
run qwencoder   Qwen/Qwen2.5-Coder-7B-Instruct
run foundsec    fdtn-ai/Foundation-Sec-8B
run mistral     mistralai/Mistral-7B-Instruct-v0.3

echo "=== CLASS LEADERBOARD (${DATASET} ${SPLIT}, logprob-scored, ranked by AUROC) ==="
PFX="$PREFIX" $PY - <<'PY'
import json, glob, os
pfx = os.environ["PFX"]
rows=[]
for f in sorted(glob.glob(f"results/{pfx}_*.json")):
    d=json.load(open(f)); rc=d["risk_coverage"]
    rows.append((os.path.basename(f)[len(pfx)+1:-5], d["accuracy"], d["auroc"], d["ece"],
                 rc["0.25"]["accuracy"], rc["0.10"]["accuracy"]))
rows.sort(key=lambda r: (r[2] or 0), reverse=True)
print(f"{'model':12s} {'acc':>6s} {'auroc':>7s} {'ece':>6s} {'acc@25%':>8s} {'acc@10%':>8s}")
for name,acc,au,ece,a25,a10 in rows:
    print(f"{name:12s} {acc:6.3f} {str(au):>7s} {str(ece):>6s} {a25:8.3f} {a10:8.3f}")
best = rows[0][0] if rows else None
print("\nTop by AUROC:", best, "-- 'ours' is best-in-class only if it is this row AND leads acc@25%.")
PY
