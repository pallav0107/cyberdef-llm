#!/usr/bin/env bash
# Measure the ADOPTION EDGE: does any adapter give a better risk-coverage curve than the
# base model on the recognized benchmark? Run AFTER the GPU is free.
set -euo pipefail
cd ~/missions/cyberdef-llm
export PYTHONPATH=src
export HF_HUB_DISABLE_XET=1
PY=.venv/bin/python
M=Qwen/Qwen2.5-7B-Instruct
MC=4000

echo "=== base (control) ==="
$PY scripts/selective_eval.py --model "$M" --split test --max-chars $MC --out results/sel_base.json
echo "=== real-data adapter (qlora-devign) ==="
$PY scripts/selective_eval.py --model "$M" --adapter out/qlora-devign --split test --max-chars $MC --out results/sel_devign.json
if [ -d out/qlora-vuln ]; then
  echo "=== synthetic adapter (qlora-vuln) ==="
  $PY scripts/selective_eval.py --model "$M" --adapter out/qlora-vuln --split test --max-chars $MC --out results/sel_synthetic.json
fi

echo "=== EDGE SUMMARY (Devign test, logprob-scored) ==="
$PY - <<PY
import json, glob, os
def show(tag,f):
    if not os.path.exists(f): return
    d=json.load(open(f)); rc=d["risk_coverage"]
    print(f"{tag:22s} acc={d['accuracy']:.3f} auroc={d['auroc']} ece={d['ece']} "
          f"| acc@10%={rc['0.10']['accuracy']:.3f} acc@25%={rc['0.25']['accuracy']:.3f} "
          f"acc@50%={rc['0.50']['accuracy']:.3f}")
show("base (control)","results/sel_base.json")
show("qlora-devign (real)","results/sel_devign.json")
show("qlora-vuln (synthetic)","results/sel_synthetic.json")
b=json.load(open("results/sel_base.json"))
import os
if os.path.exists("results/sel_devign.json"):
    t=json.load(open("results/sel_devign.json"))
    da=round(t["accuracy"]-b["accuracy"],4)
    dau=round((t["auroc"] or 0)-(b["auroc"] or 0),4)
    d25=round(t["risk_coverage"]["0.25"]["accuracy"]-b["risk_coverage"]["0.25"]["accuracy"],4)
    print(f"\nEDGE (real adapter vs base): dAUROC={dau:+}  dAcc@25%={d25:+}  dAcc(full)={da:+}")
    print("VERDICT:", "EDGE PRESENT (better selective precision than base)"
          if (d25>0 or dau>0) else "NO EDGE YET (base ranks its cases at least as well)")
PY
