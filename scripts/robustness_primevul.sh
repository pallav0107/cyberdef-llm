#!/usr/bin/env bash
# Lock the 7B edge: re-evaluate the SAME base and SAME tuned adapter on PrimeVul test across
# multiple balanced test samples (seeds) to get mean +/- spread -- i.e. a confidence interval
# on the measured edge, so it is not one lucky sample. (Test-resample variance; training is
# fixed.) Seed 0 reuses the existing primevul_sel_* results.
set -uo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_OFFLINE=1
PY=.venv/bin/python
M=Qwen/Qwen2.5-7B-Instruct
A=out/qlora-primevul
MC=4000

for s in 1 2 3; do
  echo "=== seed $s base ==="
  $PY scripts/selective_eval.py --model "$M" --dataset primevul --split test --max-chars $MC --seed $s --out results/pv_sel_base_s$s.json
  echo "=== seed $s tuned ==="
  $PY scripts/selective_eval.py --model "$M" --adapter "$A" --dataset primevul --split test --max-chars $MC --seed $s --out results/pv_sel_tuned_s$s.json
done

echo "=== ROBUSTNESS AGGREGATE (PrimeVul test, selective, seeds 0-3) ==="
$PY - <<PY
import json, statistics as st
base=["results/primevul_sel_base.json"]+[f"results/pv_sel_base_s{s}.json" for s in (1,2,3)]
tuned=["results/primevul_sel_tuned.json"]+[f"results/pv_sel_tuned_s{s}.json" for s in (1,2,3)]
def col(files, keyf): return [keyf(json.load(open(f))) for f in files]
def rep(name, keyf):
    b=col(base,keyf); t=col(tuned,keyf)
    print(f"{name:9s} base {st.mean(b):.3f}+/-{st.pstdev(b):.3f}  tuned {st.mean(t):.3f}+/-{st.pstdev(t):.3f}  dMean {st.mean(t)-st.mean(b):+.3f}")
rep("accuracy", lambda d:d["accuracy"])
rep("auroc",    lambda d:d["auroc"])
rep("ece",      lambda d:d["ece"])
rep("acc@25%",  lambda d:d["risk_coverage"]["0.25"]["accuracy"])
rep("acc@10%",  lambda d:d["risk_coverage"]["0.10"]["accuracy"])
print("seeds:", [json.load(open(f))["seed"] for f in base])
PY
