#!/usr/bin/env bash
# PrimeVul increment: train on PrimeVul TRAIN (leakage-deduped), then baseline-vs-tuned on the
# untouched TEST split -- both accuracy (extbench) and the selective/edge metrics.
set -uo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1
PY=.venv/bin/python
M=Qwen/Qwen2.5-7B-Instruct
A=out/qlora-primevul
MC=4000
DS=primevul

echo "=== [1/4] train QLoRA on PrimeVul train ==="
$PY scripts/train_devign.py --base "$M" --out "$A" --dataset $DS --n-per-class 500 --epochs 2 --lr 1e-4 --max-chars $MC --seed 0

echo "=== [2/4] accuracy: base vs tuned on TEST ==="
$PY scripts/extbench.py --model "$M" --dataset $DS --split test --max-chars $MC --out results/primevul_test_baseline.json
$PY scripts/extbench.py --model "$M" --adapter "$A" --dataset $DS --split test --max-chars $MC --out results/primevul_test_tuned.json

echo "=== [3/4] edge (selective): base vs tuned on TEST ==="
$PY scripts/selective_eval.py --model "$M" --dataset $DS --split test --max-chars $MC --out results/primevul_sel_base.json
$PY scripts/selective_eval.py --model "$M" --adapter "$A" --dataset $DS --split test --max-chars $MC --out results/primevul_sel_tuned.json

echo "=== [4/4] PRIMEVUL SUMMARY ==="
$PY - <<PY
import json
def E(t,f):
    d=json.load(open(f)); c=d["confusion"]
    print(f"{t:12s} acc={d['score']:.4f} conf={c} prec={d['precision_vuln']} rec={d['recall_vuln']}")
    return d["score"]
def S(t,f):
    d=json.load(open(f)); rc=d["risk_coverage"]
    print(f"{t:12s} acc={d['accuracy']:.3f} auroc={d['auroc']} ece={d['ece']} "
          f"acc@25%={rc['0.25']['accuracy']:.3f} acc@10%={rc['0.10']['accuracy']:.3f}")
    return d
bt=E("TEST base","results/primevul_test_baseline.json"); tt=E("TEST tuned","results/primevul_test_tuned.json")
print("TEST acc delta =", round(tt-bt,4))
sb=S("SEL base","results/primevul_sel_base.json"); st=S("SEL tuned","results/primevul_sel_tuned.json")
dau=round((st["auroc"] or 0)-(sb["auroc"] or 0),4)
d25=round(st["risk_coverage"]["0.25"]["accuracy"]-sb["risk_coverage"]["0.25"]["accuracy"],4)
d10=round(st["risk_coverage"]["0.10"]["accuracy"]-sb["risk_coverage"]["0.10"]["accuracy"],4)
print(f"EDGE vs base: dAUROC={dau:+} dAcc@25%={d25:+} dAcc@10%={d10:+}")
print("VERDICT:", "EDGE PRESENT" if (dau>0 or d25>0) else "NO EDGE")
PY
