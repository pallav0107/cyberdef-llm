#!/usr/bin/env bash
# One step of the `cyberdef pipeline` workflow. The workflow lists each machine's steps; the work lives here, so the
# Box GPU and Spark jobs run identical logic.
#   scripts/ci_step.sh plan|checks|bank|funnel|train|test|grade|provenance|status
# Inputs arrive as env: MACHINE (gpu-box|spark), MODEL, STEPS, TAG, DATA, TEST_SET, SCORER, ACK_OOM,
# TRAIN_FLAGS, BANK_FLAGS (flags are space-separated, no quoting). `plan` writes $RUNNER_TEMP/cyberdef_plan.env and
# `test` writes $RUNNER_TEMP/cyberdef_result.env; later steps read them.
set -eo pipefail
STEP="${1:?step name}"
cd "${CYBERDEF_REPO:?set CYBERDEF_REPO in the runner .env}"
T="${RUNNER_TEMP:-/tmp}"; PLAN="$T/cyberdef_plan.env"; RES="$T/cyberdef_result.env"
if [ "$STEP" != plan ]; then [ -f "$PLAN" ] || { echo "::error::no plan for this job (step 1 did not run)"; exit 1; }; source "$PLAN"; fi
[ -f "$RES" ] && source "$RES"
PY="${CYBERDEF_PY:-python3}"
LOCK=.box_gpu.lock; [ "$MACHINE" = spark ] && LOCK=.spark_ci.lock
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
wait_mem() { until [ "$(awk '/MemAvailable/{print int($2/1048576)}' /proc/meminfo)" -ge "$1" ]; do echo "waiting: need $1 GB MemAvailable"; sleep 60; done; }
spark_env() { source scripts/gpu_job_lib.sh; source scripts/imp_job_lib.sh 2>/dev/null || true; export IMP_PYLIB=/work/imp_pylib; }
take_gpu() { exec 9>"$LOCK"; echo "waiting for the $MACHINE GPU lock..."; flock 9; }

case "$STEP" in
plan)
  # drift guard: this runner executes the CI scripts in $CYBERDEF_REPO, so they must match the commit being run
  if [ -n "${GITHUB_SHA:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
    for f in scripts/ci_step.sh scripts/ci_plan.py scripts/ci_checks.sh scripts/ci_route.py; do
      if want=$(curl -fsS --max-time 20 "https://raw.githubusercontent.com/$GITHUB_REPOSITORY/$GITHUB_SHA/$f" | sha256sum | cut -c1-64); then
        [ "$want" = "$(sha256sum "$f" | cut -c1-64)" ] || { echo "::error::$CYBERDEF_REPO/$f on $MACHINE is not the version in commit ${GITHUB_SHA:0:7}; sync it, then re-run"; exit 1; }
      else
        echo "::warning::could not fetch $f at ${GITHUB_SHA:0:7} to check this machine's copy"
      fi
    done
  fi
  python3 scripts/ci_plan.py > "$T/plan.out"
  cat "$T/plan.out" >> "${GITHUB_OUTPUT:-/dev/null}"
  while IFS='=' read -r k v; do printf 'P_%s=%q\n' "$k" "$v"; done < "$T/plan.out" > "$PLAN"
  source "$PLAN"
  if [ -n "$P_train_warn" ] && [ "${ACK_OOM:-false}" != true ]; then echo "::error::$P_train_warn"; exit 1; fi
  if [ "$P_train" = true ] && [ -e "out/imp_$P_adapter_tag/adapter_config.json" ]; then
    echo "::error::out/imp_$P_adapter_tag already exists on $MACHINE; training would overwrite it. Pick a new tag (or untick train to test it)"; exit 1; fi
  if [ "$P_test" = true ] && [ "$P_train" != true ] && [ -n "$P_adapter_tag" ] && [ ! -e "out/imp_$P_adapter_tag/adapter_config.json" ]; then
    echo "::error::no adapter out/imp_$P_adapter_tag on $MACHINE to test"; exit 1; fi
  if [ -n "$P_items_file" ]; then
    # CoT items must exist on THIS machine and be built after the schema v2.3 grammar fix (older ones are INVALID)
    [ -s "$P_items_file" ] || { echo "::error::CoT items $P_items_file are not on $MACHINE yet: build them from the v2.3 trace bank first"; exit 1; }
    FIX=$(cd scripts && python3 -c "import ci_plan as c; print(c.SC_FIX_EPOCH)")
    if [ "$(stat -c %Y "$P_items_file")" -lt "$FIX" ]; then
      echo "::error::$P_items_file on $MACHINE was built $(date -d @"$(stat -c %Y "$P_items_file")" '+%F %H:%M'), before the schema v2.3 fix ($(date -d @"$FIX" '+%F %H:%M')): INVALID items, refusing to train on them"; exit 1; fi
    echo "CoT items: $P_items_file ($(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['n'])" "$P_items_file") items)"
  fi
  [ -z "$P_train_warn" ] || echo "::warning::$P_train_warn"
  todo="checks"; [ "$P_bank" = true ] && todo="$todo, trace bank + funnel"; [ "$P_train" = true ] && todo="$todo, train"
  [ "$P_test" = true ] && todo="$todo, test on $P_set_key + grade"; [ "$MACHINE" = gpu-box ] && todo="$todo, status"
  echo "This job runs: $todo${P_model:+ · model $P_model}${P_adapter_tag:+ · adapter out/imp_$P_adapter_tag}"
  ;;
checks)
  bash scripts/ci_checks.sh "$([ "$MACHINE" = spark ] && echo spark || echo box)" "$SUMMARY"
  ;;
bank)
  [ "$MACHINE" = spark ] || { echo "::error::the trace bank runs on Spark only"; exit 1; }
  spark_env; export MEM_GB=56; wait_mem $((MEM_GB + 20)); take_gpu
  OUT="results/imp_bank_${TAG}.jsonl"; read -r -a BF <<< "${BANK_FLAGS:-}"
  echo "generator: $P_model -> $OUT"
  gdock '' scripts/imp_trace_bank.py --model "$P_model" "${BF[@]}" --fewshot results/imp_fewshot_exemplars.json --gpu-util 0.40 --out "$OUT"
  test -s "$OUT" || { echo "::error::no traces written to $OUT"; exit 1; }
  echo "traces: $(wc -l < "$OUT")"
  ;;
funnel)
  python3 scripts/ci_bank_funnel.py "results/imp_bank_${TAG}.jsonl" --json "results/imp_bank_${TAG}_funnel.json" --md "$T/funnel.md"
  cat "$T/funnel.md" >> "$SUMMARY"
  mkdir -p "$GITHUB_WORKSPACE/artifacts"; cp "results/imp_bank_${TAG}_funnel.json" "$GITHUB_WORKSPACE/artifacts/"
  ;;
train)
  OUT="out/imp_$P_adapter_tag"; read -r -a XF <<< "${TRAIN_FLAGS:-}"
  if [ -n "$P_items_file" ]; then   # CoT arm: the pre-registered P60/P61 recipe (items come from the file; n-per-class unused)
    read -r -a DF <<< "$P_data_flags"
    ARGS=(--base "$P_model" --out "$OUT" --dataset primevul --items-file "$P_items_file" --epochs 2 --lr 1e-4 --max-chars 4000 --seed 0 "${DF[@]}"
          --meta "ci run=$GITHUB_RUN_ID sha=$GITHUB_SHA machine=$MACHINE data=$DATA")
  else
    ARGS=(--base "$P_model" --out "$OUT" --dataset primevul --n-per-class 1000 --epochs 2 --lr 1e-4 --seed 0
          --meta "ci run=$GITHUB_RUN_ID sha=$GITHUB_SHA machine=$MACHINE data=answer-only")
  fi
  echo "trainer sha256: $(sha256sum scripts/imp_train.py | cut -c1-16)  adapter: $OUT  data: ${DATA:-answer-only}  extra flags: ${XF[*]:-none}"
  if [ "$MACHINE" = spark ]; then   # torch only inside cyberdef-train:aarch64; admitted like the queue (job + 40 GB reserve)
    spark_env; export MEM_GB=40; wait_mem $((MEM_GB + 40)); take_gpu
    gdock '' scripts/imp_train.py "${ARGS[@]}" "${XF[@]}"
  else
    take_gpu; "$PY" scripts/imp_train.py "${ARGS[@]}" "${XF[@]}"
  fi
  ;;
test)
  test -s "$P_cases_file" || { echo "::error::test set $P_cases_file is missing on $MACHINE"; exit 1; }
  OUT="results/ci_ev_${P_adapter_tag:-$P_slug}_${P_set_key}.json"; printf 'RESULT=%q\n' "$OUT" > "$RES"
  take_gpu
  if [ "$P_scorer" = selective ]; then
    AD=(); [ -n "$P_adapter_tag" ] && AD=(--adapter "out/imp_$P_adapter_tag")
    SEL=(scripts/imp_selective.py --model "$P_model" "${AD[@]}" --cases-file "$P_cases_file" --out "$OUT"
         --meta "ci test run=$GITHUB_RUN_ID sha=$GITHUB_SHA machine=$MACHINE")
    if [ "$MACHINE" = spark ]; then spark_env; export MEM_GB=28; gdock '' "${SEL[@]}"; else "$PY" "${SEL[@]}"; fi
  else
    "$PY" scripts/imp_zs_probe.py --model "$P_model" --tag "$P_slug" --think medium --cases-file "$P_cases_file" --set "$P_set_key" \
      --out "$OUT" --num-predict 4096 --workers 4
  fi
  ;;
grade)
  # the pre-registered bar is fixed here on purpose: it is not a run-time knob
  "$PY" scripts/ci_gate.py --result "$RESULT" --bar 0.60
  ;;
provenance)
  mkdir -p "$GITHUB_WORKSPACE/artifacts"
  IN="model=$P_model;machine=$MACHINE;adapter=$P_adapter_tag;data=${DATA:-answer-only};items=$P_items_file;flags=${TRAIN_FLAGS:-};set=$P_set_key;scorer=$P_scorer"
  if [ "$P_train" = true ]; then
    "$PY" scripts/ci_provenance.py --kind train --out-tag "$P_adapter_tag" --lane "$MACHINE" --inputs "$IN" \
      --out "out/imp_${P_adapter_tag}_provenance.json" || echo "::warning::train provenance failed"
    cp -r "out/imp_$P_adapter_tag" out/imp_"${P_adapter_tag}"_*.json "$GITHUB_WORKSPACE/artifacts/" 2>/dev/null || true
  fi
  if [ -n "${RESULT:-}" ] && [ -f "$RESULT" ]; then
    "$PY" scripts/ci_provenance.py --kind eval --lane "$MACHINE" --result "$RESULT" --inputs "$IN" --out "$RESULT.provenance.json" \
      || echo "::warning::test provenance failed"
    cp "$RESULT" "$RESULT.provenance.json" "$GITHUB_WORKSPACE/artifacts/" 2>/dev/null || true
  fi
  ;;
status)
  LATEST=results/ci_status_latest.md
  if [ "$MACHINE" = gpu-box ]; then
    # the table needs the box's results, so it is computed here; a copy goes to Spark for the Spark job's status step
    "${CYBERDEF_PY:-$CYBERDEF_REPO/.venv/bin/python}" scripts/ci_pipeline.py --status --json "$T/status.json" --md "$T/status.md" > /dev/null
    cp "$T/status.md" "$LATEST"
    SPARK=$(cd scripts && python3 -c "import ci_pipeline as c; print(c.SPARK + ' ' + c.SPARK_REPO)" 2>/dev/null) || SPARK=""
    if [ -n "$SPARK" ]; then
      ssh -o BatchMode=yes -o ConnectTimeout=10 "${SPARK%% *}" "cat > ${SPARK#* }/$LATEST" < "$T/status.md" \
        && echo "status table copied to Spark" || echo "::warning::could not copy the status table to Spark"
    fi
  else
    # Spark cannot read the box's results: show the table the box computed last, with its age
    [ -s "$LATEST" ] || { echo "::notice title=pipeline status::no status table yet; it arrives with the next GPU run"; exit 0; }
    age=$(( ($(date +%s) - $(stat -c %Y "$LATEST")) / 60 ))
    { echo "> Computed on the box $age min ago ($(date -d @"$(stat -c %Y "$LATEST")" '+%Y-%m-%d %H:%M %Z')); Spark cannot read the box's results directly."; echo; } >> "$SUMMARY"
    cp "$LATEST" "$T/status.md"
    [ "$age" -le 360 ] || echo "::warning::the status table is $age min old; run a GPU job to refresh it"
  fi
  cat "$T/status.md" >> "$SUMMARY"
  head -3 "$T/status.md" | tail -1 | sed "s/^/::notice title=pipeline status::/"
  ;;
*) echo "::error::unknown step $STEP"; exit 2 ;;
esac
