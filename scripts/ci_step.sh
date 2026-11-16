#!/usr/bin/env bash
# One step of the `cyberdef pipeline` workflow. The workflow lists each machine's steps; the work lives here, so the
# Box GPU and Spark jobs run identical logic.
#   scripts/ci_step.sh plan|checks|dataset|train|test|grade|provenance|status   (bank|funnel: standalone bank tools)
# Inputs arrive as env: MACHINE (gpu-box|spark), MODEL, STEPS, TAG, DATA, TEST_SET, SCORER, ACK_OOM,
# TRAIN_FLAGS, BANK_FLAGS (flags are space-separated, no quoting). `plan` writes $RUNNER_TEMP/cyberdef_plan.env and
# `test` writes $RUNNER_TEMP/cyberdef_result.env; later steps read them.
set -eo pipefail
STEP="${1:?step name}"
CYBERDEF_REPO="${CYBERDEF_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"; cd "$CYBERDEF_REPO" || exit 1
T="${RUNNER_TEMP:-/tmp}"; PLAN="$T/cyberdef_plan.env"; RES="$T/cyberdef_result.env"
if [ "$STEP" != plan ] && [ "$STEP" != manifest ] && [ "$STEP" != cot_eval ]; then [ -f "$PLAN" ] || { echo "::error::no plan for this job (step 1 did not run)"; exit 1; }; source "$PLAN"; fi
[ -f "$RES" ] && source "$RES"
PY="${CYBERDEF_PY:-python3}"
LOCK=.box_gpu.lock; [ "$MACHINE" = spark ] && LOCK=.spark_ci.lock
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
wait_mem() { until [ "$(awk '/MemAvailable/{print int($2/1048576)}' /proc/meminfo)" -ge "$1" ]; do echo "waiting: need $1 GB MemAvailable"; sleep 60; done; }
spark_env() { source scripts/gpu_job_lib.sh; source scripts/imp_job_lib.sh 2>/dev/null || true; export IMP_PYLIB=/work/imp_pylib; }
take_gpu() { exec 9>"$LOCK"; echo "waiting for the $MACHINE GPU lock..."; flock 9; }
gpu_free_check() {   # box only, after the lock: the 24 GB card must be (nearly) free before a model is loaded on it
  [ "$MACHINE" = gpu-box ] || return 0
  local free; free=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits 2>/dev/null | head -1)
  if [ "${free:-0}" -lt 20000 ]; then
    echo "::error::the box GPU has only ${free:-?} MiB free; these processes hold it:"
    nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader 2>/dev/null
    ollama ps 2>/dev/null | tail -n +2
    exit 1
  fi
  echo "box GPU free: ${free} MiB"
}
# Spark memory a step needs (GB), from the model size: 4-bit QLoRA training ~0.7 GB/B + 24 activations (>= 40);
# bf16 testing ~2.1 GB/B + 12. Unknown size -> the 32B figure.
need_gb() { python3 -c "import sys; p=float(sys.argv[2] or 32); print(max(40, int(0.7*p+24)) if sys.argv[1]=='train' else int(2.1*p+12))" "$1" "${P_params_b:-}"; }
# While a CI step waits for or uses Spark, the Spark queue starts nothing new (a job already running finishes normally).
# The claim holds this step's PID, so a cancelled or crashed step stops blocking the queue on its own.
# Every file the pipeline runs on BOTH machines (box-only execution-oracle modules excluded). Both machines must hold
# byte-identical copies, or the "same steps, same data" comparison is not a comparison.
CODE_FILES="scripts/ci_step.sh scripts/ci_plan.py scripts/ci_route.py scripts/ci_checks.sh scripts/ci_gate.py scripts/ci_provenance.py
  scripts/ci_bank_funnel.py scripts/ci_schema_control.py scripts/ci_per_class.py scripts/ci_data_hygiene.py scripts/imp_train.py scripts/imp_selective.py scripts/imp_zs_probe.py
  scripts/imp_trace_bank.py scripts/imp_bank_merge.py scripts/imp_bank_strictx.py scripts/imp_build_cot_items.py scripts/reason_C_witness.py"
code_manifest() { { printf '%s\n' $CODE_FILES; ls src/cyberdef/*.py | grep -v -E '/(exec_harness|exec_oracle|feed)\.py$'; } \
                  | sort | while read -r f; do [ -f "$f" ] && sha256sum "$f" || echo "MISSING  $f"; done; }
# Pre-registered CoT evaluation (as in the queue jobs P60/P61/P86): SC-CoT greedy generation with vLLM, 4096 tokens,
# verdict-token probability. gpu-util 0.45 as pre-registered, raised only when a larger model needs more to load.
# addendum 3k: on the fair tests (J3s, J4s) every CoT-scored model is decoded K=3 times in shuffled case order (seeds 1-3).
# <out> holds seed 1; <out>_k2.json and <out>_k3.json hold seeds 2 and 3. The verdict averages p_vuln per case (scripts/imp_verdict.py).
cot_k() { case "$(basename "$1")" in j3s_*|j4s_*) echo 3 ;; *) echo 1 ;; esac; }   # cases-file -> K
cot_out() { if [ "$2" -le 1 ]; then echo "$1"; else echo "${1%.json}_k$2.json"; fi; }   # out k -> file of decode k
cot_eval_here() {   # model  adapter-tag-or-''  cases-file  out
  claim_spark; spark_env
  # vLLM reserves gpu-util x 121 GB of Spark's UNIFIED memory: bf16 weights ~1.92 GB/B + 14 GB for KV and activations, and
  # 25 GB must stay free beyond it (15 Nov: a 27B at 0.65 = ~78 GB with ~10 GB spare froze Spark; no OOM kill).
  local U AD=(); U=$(python3 -c "import sys; p=float(sys.argv[1] or 32); print(round(max(0.45, min(0.85, (1.92*p+14)/120)), 2))" "${P_params_b:-}")
  export MEM_GB=$(python3 -c "print(int($U*121))"); echo "CoT eval: gpu-util $U (~${MEM_GB} GB) for ${P_params_b:-?}B"
  wait_mem $((MEM_GB + 25)); take_gpu
  [ -n "$2" ] && AD=(--adapter "out/imp_$2")
  local K k SHF; K=$(cot_k "$3")
  for k in $(seq 1 "$K"); do
    SHF=(); [ "$K" -gt 1 ] && SHF=(--shuffle-seed "$k")
    gdock '' scripts/imp_eval_cot.py --model "$1" "${AD[@]}" --cases-file "$3" --out "$(cot_out "$4" "$k")" --max-tokens 4096 \
      --gpu-util "$U" "${SHF[@]}" --meta "ci test run=${GITHUB_RUN_ID:-} sha=${GITHUB_SHA:-} trained_on=${TRAINED_ON:-$MACHINE} decode=$k/$K"
  done
  flock -u 9
}
claim_spark() { [ "$MACHINE" = spark ] || return 0; echo "$$ $STEP ${GITHUB_RUN_ID:-local}" > "$CYBERDEF_REPO/.ci_priority"
                trap 'grep -q "^$$ " "$CYBERDEF_REPO/.ci_priority" 2>/dev/null && rm -f "$CYBERDEF_REPO/.ci_priority"' EXIT; }

case "$STEP" in
plan)
  # drift guard: this runner executes the CI scripts in $CYBERDEF_REPO, so they must match the commit being run
  if [ -n "${GITHUB_SHA:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
    checked=0
    for f in scripts/ci_step.sh scripts/ci_plan.py scripts/ci_checks.sh scripts/ci_route.py; do
      if want=$(curl -fsS --max-time 20 "https://raw.githubusercontent.com/$GITHUB_REPOSITORY/$GITHUB_SHA/$f" | sha256sum | cut -c1-64); then
        [ "$want" = "$(sha256sum "$f" | cut -c1-64)" ] || { echo "::error::$CYBERDEF_REPO/$f on $MACHINE is not the version in commit ${GITHUB_SHA:0:7}; sync it, then re-run"; exit 1; }
        checked=$((checked + 1))
      else
        echo "::warning::could not fetch $f at ${GITHUB_SHA:0:7} to check this machine's copy"
      fi
    done
    echo "CI scripts on $MACHINE match commit ${GITHUB_SHA:0:7} ($checked/4 checked)"
  fi
  # the two machines must run identical pipeline code (the box can read Spark; Spark compares with the box's last manifest)
  code_manifest > "$T/code_here.txt"
  if [ "$MACHINE" = gpu-box ]; then
    SPARK=$(cd scripts && python3 -c "import ci_pipeline as c; print(c.SPARK + ' ' + c.SPARK_REPO)" 2>/dev/null) || SPARK=""
    if [ -n "$SPARK" ] && ssh -o BatchMode=yes -o ConnectTimeout=10 "${SPARK%% *}" "cd ${SPARK#* } && bash scripts/ci_step.sh manifest" > "$T/code_other.txt" 2>/dev/null; then
      ssh -o BatchMode=yes -o ConnectTimeout=10 "${SPARK%% *}" "cat > ${SPARK#* }/results/ci_code_manifest_box.txt" < "$T/code_here.txt" || true
    else
      echo "::warning::could not read Spark's code fingerprint"; : > "$T/code_other.txt"
    fi
  else
    if [ -s results/ci_code_manifest_box.txt ]; then cp results/ci_code_manifest_box.txt "$T/code_other.txt"
    else echo "::warning::no box code fingerprint on Spark yet (it arrives with the next GPU run)"; : > "$T/code_other.txt"; fi
  fi
  if [ -s "$T/code_other.txt" ]; then
    if ! diff -q "$T/code_here.txt" "$T/code_other.txt" >/dev/null; then
      echo "::error::pipeline code differs between the box and Spark; run scripts/ci_sync_spark.sh on the box, then re-run. Differing files:"
      diff <(awk '{print $2, $1}' "$T/code_here.txt") <(awk '{print $2, $1}' "$T/code_other.txt") | grep '^[<>]' | awk '{print "  " $2}' | sort -u
      exit 1
    fi
    echo "pipeline code identical on box and Spark ($(wc -l < "$T/code_here.txt") files, fingerprint $(sha256sum "$T/code_here.txt" | cut -c1-12))"
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
  [ -z "$P_train_warn" ] || echo "::warning::$P_train_warn"
  todo="checks"; [ "$P_bank" = true ] && todo="$todo, trace bank + funnel"; [ "$P_train" = true ] && todo="$todo, train"
  [ "$P_test" = true ] && todo="$todo, test ($P_scorer) on $(for kv in $P_test_sets; do printf '%s ' "${kv%%=*}"; done)+ grade"
  [ "$MACHINE" = gpu-box ] && todo="$todo, status"
  echo "This job runs: $todo${P_model:+ · model $P_model}${P_adapter_tag:+ · adapter out/imp_$P_adapter_tag}"
  ;;
checks)
  bash scripts/ci_checks.sh "$([ "$MACHINE" = spark ] && echo spark || echo box)" "$SUMMARY"
  ;;
dataset)
  # Both machines must train on byte-identical data. CoT items are built ONCE, on Spark (trace generation needs vLLM),
  # from the quick v2.3 trace bank; the box copies the same file and both print its sha256.
  if [ "$P_train" != true ]; then echo "This run does not train: no training data needed."; exit 0; fi
  if [ -z "$P_items_file" ]; then
    npc=1000; seed=0; read -r -a XF <<< "${TRAIN_FLAGS:-}"   # report what the trainer will really use (flags override)
    for ((i = 0; i < ${#XF[@]}; i++)); do case "${XF[i]}" in --n-per-class) npc="${XF[i+1]}";; --seed) seed="${XF[i+1]}";; esac; done
    echo "Training data: PrimeVul train, answer-only, $npc per class, seed $seed: the same deterministic sampler on both machines."
    echo "**Training data** PrimeVul train, answer-only, $npc per class, seed $seed" >> "$SUMMARY"; exit 0
  fi
  case "$P_items_file" in results/vsp_*)   # VSP_SFT_R1_PREREG: built and gated on the box (check_vsp_items.py); sha256 pinned in the manifest
    [ -s "$P_items_file" ] || { echo "::error::$P_items_file is missing on $MACHINE"; exit 1; }
    read -r N NV NS < <(python3 -c "
import json, sys; it = json.load(open(sys.argv[1]))['items']
print(len(it), sum(i.get('label') == 'VULNERABLE' for i in it), sum(i.get('label') == 'SAFE' for i in it))" "$P_items_file")
    HAVE=$(sha256sum "$P_items_file" | cut -c1-64)
    WANT=$(python3 -c "import json, sys; print(json.load(open('data/DATA_MANIFEST.json'))['files'].get(sys.argv[1], {}).get('sha256', ''))" "$P_items_file")
    [ -n "$WANT" ] && [ "$HAVE" = "$WANT" ] || { echo "::error::$P_items_file sha256 ${HAVE:0:16} does not match the manifest (${WANT:0:16})"; exit 1; }
    printf 'BANK_BUILD=%q\n' "vsp_sft items=${HAVE:0:12}" >> "$PLAN"
    echo "Training data: $P_items_file  n=$N (VULNERABLE $NV, SAFE $NS)  sha256 ${HAVE:0:16} (manifest-pinned)"
    echo "**Training data** \`$P_items_file\` · n=$N (VULNERABLE $NV, SAFE $NS) · sha256 \`${HAVE:0:16}\` (manifest-pinned)" >> "$SUMMARY"
    exit 0 ;;
  esac
  case "$P_items_file" in results/st_*)   # amendment 3: self-training items from scripts/imp_st_round.sh (Spark only)
    [ -s "$P_items_file" ] || { echo "::error::$P_items_file is missing: run scripts/imp_st_round.sh for this category and round first"; exit 1; }
    read -r N NV NS < <(python3 -c "
import json, sys; it = json.load(open(sys.argv[1]))['items']
print(len(it), sum(i.get('label') == 'VULNERABLE' for i in it), sum(i.get('label') == 'SAFE' for i in it))" "$P_items_file")
    HAVE=$(sha256sum "$P_items_file" | cut -c1-64)
    [ "$NV" -ge 20 ] && [ "$NS" -ge 20 ] || { echo "::error::$P_items_file has $NV vulnerable / $NS safe items; addendum 3a needs >= 20 per class"; exit 1; }
    printf 'BANK_BUILD=%q
' "amendment3 items=${HAVE:0:12}" >> "$PLAN"
    python3 scripts/ci_data_hygiene.py --items "$P_items_file" || exit 1   # addendum 3g
    echo "Training data: $P_items_file  n=$N (VULNERABLE $NV, SAFE $NS)  sha256 ${HAVE:0:16}"
    echo "**Training data** \`$P_items_file\` · n=$N (VULNERABLE $NV, SAFE $NS) · sha256 \`${HAVE:0:16}\`" >> "$SUMMARY"
    exit 0 ;;
  esac
  FIX=$(cd scripts && python3 -c "import ci_plan as c; print(c.SC_FIX_EPOCH)")
  AMEND=$(cd scripts && python3 -c "import ci_plan as c; print(c.QUICK_BANK_AMENDMENT)")
  MARK=results/imp_cotq_BUILD_OK.json
  postfix() { [ -s "$1" ] && [ "$(stat -c %Y "$1")" -ge "$FIX" ]; }
  mark_ok() {   # marker: post-fix, stamped with the current bank amendment, and (when given) built from exactly these slices
    postfix "$1" && python3 - "$1" "$AMEND" "${2:-}" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); want = sys.argv[3].split()
sys.exit(0 if m.get("amendment") == sys.argv[2] and (not want or sorted(m.get("pieces", {})) == sorted(want)) else 1)
PY
  }
  echo "Bank make-up: $AMEND (acceptance/improve/$AMEND.md, sha256 $(sha256sum "acceptance/improve/$AMEND.md" 2>/dev/null | cut -c1-16))"
  if [ "$MACHINE" = spark ]; then
    claim_spark; exec 8>.spark_dataset.lock; echo "waiting for the dataset lock..."; flock 8
    PIECES="results/imp_bankq_g14.jsonl results/imp_bankq_g14_j2.jsonl"          # quick subset + J2 (amendment 1)
    [ -s results/imp_train_juliet3_items.json ] && PIECES="$PIECES results/imp_bankq_g14_j3.jsonl"   # + J3 (amendment 2)
    [ -s results/imp_train_sqli_items.json ] && PIECES="$PIECES results/imp_bankq_g14_q.jsonl"      # + Q (amendment 2)
    if mark_ok "$MARK" "$PIECES"; then
      echo "CoT items already built under $AMEND from: $PIECES ($(date -d @"$(stat -c %Y "$MARK")" '+%F %H:%M')): reusing"
    else
      mkdir -p results/invalid_v22      # pre-fix bank pieces and items are INVALID: kept, but moved out of the way
      for f in results/imp_bankq_g*.jsonl results/imp_trace_bank_quick.jsonl results/imp_trace_bank_quick_counts.json results/imp_cotq_*; do
        [ -e "$f" ] && ! postfix "$f" && mv "$f" results/invalid_v22/ && echo "moved pre-fix $f to results/invalid_v22/"
      done
      gen_slice() {   # out-file  generator-flags...   (same generator, schema, few-shot and k as the quick bank)
        local out=$1; shift
        postfix "$out" && { echo "slice $out: present"; return 0; }
        echo "generating slice $out ($*)"
        spark_env; export MEM_GB=56; wait_mem $((MEM_GB + 20)); take_gpu
        gdock '' scripts/imp_trace_bank.py --gen g14 --model Qwen/Qwen2.5-14B-Instruct "$@" --k 2 \
          --fewshot results/imp_fewshot_exemplars.json --gpu-util 0.40 --out "$out"
        flock -u 9; test -s "$out" || { echo "::error::slice $out was not written"; exit 1; }
      }
      if ! postfix results/imp_bankq_g14.jsonl && postfix results/imp_bank_v23_quick_g14.jsonl; then
        cp results/imp_bank_v23_quick_g14.jsonl results/imp_bankq_g14.jsonl; echo "slice results/imp_bankq_g14.jsonl: the finished v2.3 quick bank"
      fi
      gen_slice results/imp_bankq_g14.jsonl --pools J,J2 --subset quick
      gen_slice results/imp_bankq_g14_j2.jsonl --pools J2
      case "$PIECES" in *_j3.jsonl*) gen_slice results/imp_bankq_g14_j3.jsonl --pools J3 ;; esac
      case "$PIECES" in *_q.jsonl*) gen_slice results/imp_bankq_g14_q.jsonl --pools Q ;; esac
      python3 scripts/imp_bank_merge.py quick > /dev/null
      echo "execution check (X_strict) on the merged quick bank"
      docker run --rm --network none --memory 8g --pids-limit 512 --cpus 4 --cap-drop ALL --user "$(id -u):$(id -g)" -e HOME=/tmp \
        -e PYTHONPATH=/work/src -e IMP_JULIET=/work/imp_juliet -v "$PWD:/work" -w /work --entrypoint python3 imp-spark-beh:1 \
        scripts/imp_bank_strictx.py quick
      spark_env; gdock '' IMP_BANK=quick scripts/imp_build_cot_items.py
      python3 scripts/ci_bank_funnel.py results/imp_trace_bank_quick.jsonl --json results/imp_trace_bank_quick_funnel.json --md "$T/funnel.md" \
        && cat "$T/funnel.md" >> "$SUMMARY"
      python3 - "$MARK" "$AMEND" $PIECES <<'PY'
import glob, hashlib, json, sys, time
sha = lambda f: hashlib.sha256(open(f, "rb").read()).hexdigest()
items = {f: {"sha256": sha(f), "n": json.load(open(f))["n"]} for f in sorted(glob.glob("results/imp_cotq_*_items.json"))}
bank = "results/imp_trace_bank_quick.jsonl"
counts = json.load(open("results/imp_trace_bank_quick_counts.json"))
json.dump({"built": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "amendment": sys.argv[2], "pieces": {p: sha(p) for p in sys.argv[3:]},
           "bank": bank, "bank_sha256": sha(bank), "x_strict_traces": counts.get("x_strict_traces_total"),
           "items": items}, open(sys.argv[1], "w"), indent=1)
PY
    fi
  else
    # box: wait for Spark's build under the current amendment, then copy the identical file
    SPARK=$(cd scripts && python3 -c "import ci_pipeline as c; print(c.SPARK + ' ' + c.SPARK_REPO)"); SH="${SPARK%% *}"; SR="${SPARK#* }"
    for i in $(seq 1 240); do   # up to 8 h: Spark may be generating bank slices
      scp -q -p -o BatchMode=yes -o ConnectTimeout=10 "$SH:$SR/$MARK" "$T/mark.json" 2>/dev/null && mark_ok "$T/mark.json" && break
      [ "$i" -eq 240 ] && { echo "::error::Spark has not built the CoT items under $AMEND after 8 h; start the Spark run with the same data"; exit 1; }
      echo "waiting for Spark to build the CoT items under $AMEND (start the Spark run with the same data if it is not running)"; sleep 120
    done
    WANT=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['items'][sys.argv[2]]['sha256'])" "$T/mark.json" "$P_items_file")
    if [ ! -s "$P_items_file" ] || [ "$(sha256sum "$P_items_file" | cut -c1-64)" != "$WANT" ]; then
      mkdir -p results/invalid_v22
      [ -e "$P_items_file" ] && ! postfix "$P_items_file" && mv "$P_items_file" results/invalid_v22/ && echo "moved pre-fix $P_items_file to results/invalid_v22/"
      scp -q -o BatchMode=yes "$SH:$SR/$P_items_file" "$P_items_file"
    fi
    cp "$T/mark.json" "$MARK"
  fi
  postfix "$P_items_file" || { echo "::error::$P_items_file is missing or predates the schema v2.3 fix"; exit 1; }
  HAVE=$(sha256sum "$P_items_file" | cut -c1-64)
  WANT=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['items'][sys.argv[2]]['sha256'])" "$MARK" "$P_items_file")
  [ "$HAVE" = "$WANT" ] || { echo "::error::$P_items_file on $MACHINE does not match the Spark build (sha256 $HAVE vs $WANT)"; exit 1; }
  python3 scripts/ci_data_hygiene.py --items "$P_items_file" || exit 1   # addendum 3g: no label text in what this run trains on
  read -r N NV NS < <(python3 -c "
import json, sys; it = json.load(open(sys.argv[1]))['items']
print(len(it), sum(i.get('label') == 'VULNERABLE' for i in it), sum(i.get('label') == 'SAFE' for i in it))" "$P_items_file")
  echo "Training data: $P_items_file  n=$N (VULNERABLE $NV, SAFE $NS)  sha256 ${HAVE:0:16}  (identical on both machines)"
  echo "**Training data** \`$P_items_file\` · n=$N (VULNERABLE $NV, SAFE $NS) · sha256 \`${HAVE:0:16}\`" >> "$SUMMARY"
  [ "$N" -gt 0 ] || { echo "::error::$P_items_file has no items: this arm cannot be trained from the current bank"; exit 1; }
  if [ -n "${P_arm7_gate:-}" ]; then   # pre-registered gate for arm 7: enough execution-confirmed traces in THIS build
    XS=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('x_strict_traces') or 0)" "$MARK")
    [ "$XS" -ge "$P_arm7_gate" ] || { echo "::error::arm 7 gate not met: $XS X_strict traces in this build, the pre-registered minimum is $P_arm7_gate"; exit 1; }
    echo "arm 7 gate met: $XS X_strict traces (>= $P_arm7_gate)"
  fi
  read -r BANKSHA BANKPIECES < <(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); print(m['bank_sha256'][:12], '+'.join(p.split('_')[-1].replace('.jsonl','') for p in m.get('pieces', {})))" "$MARK")
  printf 'BANK_BUILD=%q\n' "$P_amendment bank=$BANKSHA pieces=$BANKPIECES" >> "$PLAN"
  echo "bank build: $P_amendment bank=$BANKSHA pieces=$BANKPIECES"
  minority=$(( NV < NS ? NV : NS ))
  [ $(( 100 * minority / N )) -ge 20 ] || echo "::warning::class balance is ${NV}/${NS} (VULNERABLE/SAFE): a model trained on this mostly learns the majority answer"
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
  read -r -a DF <<< "${P_data_flags:-}"
  if [ -n "$P_items_file" ]; then   # CoT arm: the pre-registered P60/P61 recipe (items come from the file; n-per-class unused)
    ARGS=(--base "$P_model" --out "$OUT" --dataset primevul --items-file "$P_items_file" --epochs 2 --lr 1e-4 --max-chars 4000 --seed 0 "${DF[@]}"
          --meta "ci run=$GITHUB_RUN_ID sha=$GITHUB_SHA machine=$MACHINE data=$DATA build=${BANK_BUILD:-}")
  else                              # answer-only: length-matched by default (--length-match comes from the data choice)
    ARGS=(--base "$P_model" --out "$OUT" --dataset primevul --n-per-class 1000 --epochs 2 --lr 1e-4 --seed 0 "${DF[@]}"
          --meta "ci run=$GITHUB_RUN_ID sha=$GITHUB_SHA machine=$MACHINE data=$DATA")
  fi
  echo "trainer sha256: $(sha256sum scripts/imp_train.py | cut -c1-16)  adapter: $OUT  data: ${DATA:-answer-only}  extra flags: ${XF[*]:-none}"
  if [ "$MACHINE" = spark ]; then   # torch only inside cyberdef-train:aarch64; admitted like the queue (job + 40 GB reserve)
    claim_spark; spark_env; export MEM_GB=$(need_gb train); echo "needs ${MEM_GB} GB (+40 reserve) for ${P_params_b:-?}B"
    wait_mem $((MEM_GB + 40)); take_gpu
    gdock '' scripts/imp_train.py "${ARGS[@]}" "${XF[@]}"
  else
    take_gpu; gpu_free_check; "$PY" scripts/imp_train.py "${ARGS[@]}" "${XF[@]}"
  fi
  # the CI recipe is 4-bit QLoRA on both machines: a silent fallback to bf16 would change the recipe, so it is refused
  MODE=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['flags'].get('mode'))" "${OUT}_imp_train_log.json" 2>/dev/null || echo missing)
  [ "$MODE" = 4bit ] || { echo "::error::training ran in mode '$MODE', not 4bit; the adapter is not accepted (CI recipe = 4-bit QLoRA)"; exit 1; }
  echo "training mode: $MODE"
  ;;
test)
  # every set of the plan; CoT arms are scored by generating the SC-CoT (vLLM) on Spark, whichever machine trained them
  RESULTS=""; local_lock=0
  for kv in $P_test_sets; do
    key=${kv%%=*}; cases=${kv#*=}
    test -s "$cases" || { echo "::error::test set $cases is missing on $MACHINE"; exit 1; }
    SFX=""   # an untrained base under the CoT scorer gets its own file name (17 Nov: the selective base overwrote it)
    if [ -z "$P_adapter_tag" ] && [ "$P_scorer" = cot ]; then SFX="-cot"; fi
    OUT="results/ci_ev_${P_adapter_tag:-$P_slug}${SFX}_${key}.json"
    echo "::group::test $key ($P_scorer) -> $OUT"
    if [ "$P_scorer" = cot ]; then
      if [ "$MACHINE" = spark ]; then
        cot_eval_here "$P_model" "$P_adapter_tag" "$cases" "$OUT"
      else
        read -r SH SR < <(cd scripts && python3 -c "import ci_pipeline as c; print(c.SPARK, c.SPARK_REPO)")
        if [ -n "$P_adapter_tag" ]; then   # the box's adapter goes to Spark under the same name; never over a different one
          mine=$(sha256sum "out/imp_$P_adapter_tag/adapter_model.safetensors" | cut -c1-64)
          theirs=$(ssh -o BatchMode=yes "$SH" "sha256sum $SR/out/imp_$P_adapter_tag/adapter_model.safetensors 2>/dev/null | cut -c1-64")
          if [ -z "$theirs" ]; then rsync -a "out/imp_$P_adapter_tag/" "$SH:$SR/out/imp_$P_adapter_tag/"; echo "adapter copied to Spark"
          elif [ "$theirs" != "$mine" ]; then echo "::error::Spark already has a different adapter named imp_$P_adapter_tag; use a new tag"; exit 1; fi
        fi
        ssh -o BatchMode=yes "$SH" "cd $SR && MACHINE=spark P_params_b='$P_params_b' GITHUB_RUN_ID='$GITHUB_RUN_ID' GITHUB_SHA='$GITHUB_SHA' TRAINED_ON=gpu-box bash scripts/ci_step.sh cot_eval '$P_model' '$P_adapter_tag' '$cases' '$OUT'"
        scp -q -p -o BatchMode=yes "$SH:$SR/$OUT" "$OUT"
        for k in $(seq 2 "$(cot_k "$cases")"); do scp -q -p -o BatchMode=yes "$SH:$SR/$(cot_out "$OUT" "$k")" "$(cot_out "$OUT" "$k")"; done
      fi
    else
      [ "$local_lock" = 1 ] || { take_gpu; gpu_free_check; local_lock=1; }
      if [ "$P_scorer" = selective ]; then
        AD=(); [ -n "$P_adapter_tag" ] && AD=(--adapter "out/imp_$P_adapter_tag")
        SEL=(scripts/imp_selective.py --model "$P_model" "${AD[@]}" --cases-file "$cases" --out "$OUT"
             --meta "ci test run=$GITHUB_RUN_ID sha=$GITHUB_SHA machine=$MACHINE")
        if [ "$MACHINE" = spark ]; then
          claim_spark; spark_env; export MEM_GB=$(need_gb test); echo "needs ${MEM_GB} GB (+10 margin) for ${P_params_b:-?}B in bf16"
          wait_mem $((MEM_GB + 10)); gdock '' "${SEL[@]}"
        else "$PY" "${SEL[@]}"; fi
      else
        "$PY" scripts/imp_zs_probe.py --model "$P_model" --tag "$P_slug" --think medium --cases-file "$cases" --set "$key" \
          --out "$OUT" --num-predict 4096 --workers 4
      fi
    fi
    echo "::endgroup::"
    test -s "$OUT" || { echo "::error::no result written for $key"; exit 1; }
    RESULTS="$RESULTS $OUT"
    if [ "$P_scorer" = cot ]; then
      for k in $(seq 2 "$(cot_k "$cases")"); do
        x=$(cot_out "$OUT" "$k"); test -s "$x" || { echo "::error::no result written for $key decode $k"; exit 1; }; RESULTS="$RESULTS $x"
      done
    fi
    printf 'RESULTS=%q\n' "$RESULTS" > "$RES"
  done
  ;;
grade)
  # the pre-registered bar is fixed here on purpose: it is not a run-time knob. A NULL never fails; an integrity mismatch does.
  fails=0; { echo "### Results (bar 0.60, recomputed from per_case)"; echo; echo "| set | AUROC | n | verdict |"; echo "|---|---|---|---|"; } >> "$SUMMARY"
  for r in $RESULTS; do
    echo "== $r"; "$PY" scripts/ci_gate.py --result "$r" --bar 0.60 > "$T/gate.txt" 2>&1 || fails=$((fails + 1)); cat "$T/gate.txt"
    python3 - "$r" "$T/gate.txt" >> "$SUMMARY" <<'PY'
import json, re, sys
g = open(sys.argv[2]).read(); key = sys.argv[1].rsplit("_", 1)[-1].replace(".json", "")
a = re.search(r'"recomputed_auroc":\s*([0-9.]+|null)', g); n = re.search(r'"n":\s*(\d+)', g); v = re.search(r'"verdict":\s*"([^"]+)"', g)
print(f"| {key} | {a.group(1) if a else '?'} | {n.group(1) if n else '?'} | {v.group(1) if v else '?'} |")
PY
  done
  for r in $RESULTS; do   # per-class tables (CASTLE by bug family; J3 held-out by CWE, with length-only)
    case "$r" in *_castle.json|*_j3h.json|*_j3m.json|*_qh.json|*_j4m.json) python3 scripts/ci_per_class.py "$r" >> "$SUMMARY" || true ;; esac
  done
  [ "$fails" -eq 0 ]
  ;;
provenance)
  mkdir -p "$GITHUB_WORKSPACE/artifacts"
  IN="model=$P_model;machine=$MACHINE;adapter=$P_adapter_tag;data=${DATA:-answer-only};items=$P_items_file;flags=${TRAIN_FLAGS:-};sets=$P_test_sets;scorer=$P_scorer;build=${BANK_BUILD:-none}"
  if [ "$P_train" = true ]; then
    "$PY" scripts/ci_provenance.py --kind train --out-tag "$P_adapter_tag" --lane "$MACHINE" --inputs "$IN" \
      --out "out/imp_${P_adapter_tag}_provenance.json" || echo "::warning::train provenance failed"
    cp -r "out/imp_$P_adapter_tag" out/imp_"${P_adapter_tag}"_*.json "$GITHUB_WORKSPACE/artifacts/" 2>/dev/null || true
  fi
  for r in ${RESULTS:-}; do
    [ -f "$r" ] || continue
    "$PY" scripts/ci_provenance.py --kind eval --lane "$MACHINE" --result "$r" --inputs "$IN" --out "$r.provenance.json" \
      || echo "::warning::test provenance failed for $r"
    cp "$r" "$r.provenance.json" "$GITHUB_WORKSPACE/artifacts/" 2>/dev/null || true
  done
  ;;
cot_eval)   # on Spark: cot_eval <model> <adapter-tag or ''> <cases-file> <out>  (also called over ssh by the box's test step)
  cot_eval_here "$2" "$3" "$4" "$5"
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
manifest)
  code_manifest
  ;;
*) echo "::error::unknown step $STEP"; exit 2 ;;
esac
