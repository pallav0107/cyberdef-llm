#!/usr/bin/env bash
# Phase 1 follow-up: probe the BEST zero-shot model (highest AUROC on the length-matched set among results/imp_zs_*_pv.json) on the VulSpot matched sets and CASTLE. Runs on the Spark host.
cd ~/cyberdef-lm
BEST=$(python3 - <<'PY'
import glob, json
best = None
for f in glob.glob("results/imp_zs_*_pv.json"):
    d = json.load(open(f))
    if d.get("auroc") is not None and (best is None or d["auroc"] > best[0]):
        best = (d["auroc"], d["model"], d["tag"], d["think"])
print("%s|%s|%s" % best[1:] if best else "")
PY
)
[ -z "$BEST" ] && { echo "no phase-1 result to pick from"; exit 4; }
M=${BEST%%|*}; REST=${BEST#*|}; TAG=${REST%%|*}; TH=${REST#*|}
echo "best zero-shot model: $M ($TAG, think=$TH)"
for s in "vh:results/vs_holdout_matched_cases.json" "vn:results/vs_nolinux_matched_cases.json" "castle:results/xdata_castle_cases.json"; do
  k=${s%%:*}; f=${s#*:}; o=results/imp_zs_${TAG}_${k}.json
  [ -s $o ] || python3 scripts/imp_zs_probe.py --model "$M" --tag $TAG --think $TH --cases-file $f --set $k --out $o --num-predict 4096
done
