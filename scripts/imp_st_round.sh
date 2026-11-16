#!/usr/bin/env bash
# Amendment 3 / addendum 3a: the data half of ONE self-training round of ONE category, on Spark.
#   bash scripts/imp_st_round.sh <category> <round> [adapter_dir]      (round 2: adapter = out/imp_st_<category>_r1)
# 1) the current model (Qwen3.8-27B, + adapter in round 2) writes k=4 SC-CoT traces per function of the category pool (no C pass, 3h);
# 2) the execution check (X_strict) runs on a scratch copy (imp_bank_strictx.py rewrites its input in place);
# 3) imp_st_items.py keeps only correct traces and writes results/st_<category>_r<round>_items.json + _twin_items.json.
# Training and testing then run through CI (spark.yml, data "Qwen3.8 self-training ..."). Log: logs/st_<category>_r<round>.log
set -eo pipefail
cd "$(dirname "$0")/.."
CAT=${1:?category}; RND=${2:?round}; AD=${3:-}
TAG=st_${CAT}_r${RND}; BANK=results/st_bank_${CAT}_r${RND}.jsonl
echo "$(date -Is) round start: $CAT r$RND adapter=${AD:-none}"
# addendum 3b: the category's few-shot file (quick exemplars + templated ones for this category) when one is defined
FS=results/imp_fewshot_exemplars.json
if python3 -c "import sys; sys.path[:0]=['scripts','src']; import imp_build_st_exemplars as X; sys.exit(0 if '$CAT' in X.EXTRA else 1)"; then
  FS=results/imp_fewshot_exemplars_st_${CAT}.json   # built and validated on the box (it needs the Juliet tree); pinned in the manifest
  [ -s "$FS" ] || python3 scripts/imp_build_st_exemplars.py "$CAT"
fi
echo "few-shot: $FS ($(python3 -c "import json; print(len(json.load(open('$FS'))['exemplars']))") exemplars)"
[ -s "results/st_pool_${CAT}.json" ] || python3 scripts/imp_st_pool.py "$CAT"
if [ ! -s "$BANK" ]; then
  source scripts/gpu_job_lib.sh; source scripts/imp_job_lib.sh 2>/dev/null || true; export IMP_PYLIB=/work/imp_pylib
  echo "$$ st-generation local" > .ci_priority         # the (paused) queue must not start a job meanwhile
  trap 'grep -q "^$$ " .ci_priority 2>/dev/null && rm -f .ci_priority' EXIT
  # 3b note: 0.65 (~78 GB) froze Spark on 15 Nov 23:23 (memory thrash, ~10 GB headroom, no OOM kill). 0.55 = ~66 GB holds the
  # 52 GB bf16 weights + KV; start only with 25 GB to spare beyond it.
  GU=0.55; export MEM_GB=$(python3 -c "print(int($GU*121))"); NEED=$((MEM_GB + 25))
  until [ "$(awk '/MemAvailable/{print int($2/1048576)}' /proc/meminfo)" -ge $NEED ]; do echo "waiting: need $NEED GB MemAvailable"; sleep 60; done
  exec 9>.spark_ci.lock; echo "waiting for the Spark CI lock..."; flock 9
  ADARG=(); [ -n "$AD" ] && ADARG=(--adapter "$AD")
  gdock '' scripts/imp_trace_bank.py --gen "g38r${RND}" --model Qwen/Qwen3.8-27B "${ADARG[@]}" --pools "ST:${CAT}" --k 4 --skip-c \
    --fewshot "$FS" --gpu-util "$GU" --out "$BANK"
  flock -u 9
fi
test -s "$BANK" || { echo "no traces written"; exit 1; }
echo "$(date -Is) traces: $(wc -l < "$BANK")"
S="$HOME/st_scratch_${CAT}_r${RND}"; rm -rf "$S"; mkdir -p "$S/results" "$S/imp_juliet"
cp -r scripts src "$S/"; cp "$BANK" "$S/results/imp_trace_bank.jsonl"; echo '{}' > "$S/results/imp_trace_bank_counts.json"
for f in imp_train_juliet2_items.json imp_train_juliet3_items.json imp_train_sqli_items.json; do [ -f "results/$f" ] && cp "results/$f" "$S/results/"; done
docker run --rm --network none --memory 8g --pids-limit 512 --cpus 4 --cap-drop ALL --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -e PYTHONPATH=/work/src -e IMP_JULIET=/work/imp_juliet -v "$S:/work" -v "$PWD/imp_juliet:/work/imp_juliet:ro" -w /work \
  --entrypoint python3 imp-spark-beh:1 scripts/imp_bank_strictx.py
cp "$S/results/imp_trace_bank.jsonl" "${BANK%.jsonl}_x.jsonl"
python3 scripts/ci_bank_funnel.py "${BANK%.jsonl}_x.jsonl" --json "results/${TAG}_funnel.json" --md "logs/${TAG}_funnel.md" || true
python3 scripts/imp_st_items.py --bank "${BANK%.jsonl}_x.jsonl" --category "$CAT" --tag "$TAG"
echo "$(date -Is) round data ready: results/${TAG}_items.json, results/${TAG}_twin_items.json"
