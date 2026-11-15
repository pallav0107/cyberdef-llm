#!/usr/bin/env bash
# Every fail-first control for one machine, as one step of the `cyberdef pipeline` workflow.
#   scripts/ci_checks.sh box   [summary.md]   9 controls (code, router + planner, gate, parser, data, length, oracle, acceptance)
#   scripts/ci_checks.sh spark [summary.md]   the SC-CoT guided-decoding grammar control (needs the Spark container)
# Each control: the real thing must PASS and its deliberately broken mutant must be CAUGHT. Every control runs even if an
# earlier one fails; the script exits non-zero if any failed. A table of results goes to the summary file.
set -u
MACHINE="${1:?box|spark}"; MD="${2:-/dev/null}"
cd "${CYBERDEF_REPO:-$(cd "$(dirname "$0")/.." && pwd)}" || exit 1
PY="${CYBERDEF_PY:-$PWD/.venv/bin/python}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fails=0; rows=()
run() {   # run "<name>" cmd...
  local name="$1"; shift
  echo "::group::$name"
  if "$@"; then rows+=("| ✅ pass | $name |"); else rows+=("| ❌ FAIL | $name |"); fails=$((fails + 1)); echo "::error::check failed: $name"; fi
  echo "::endgroup::"
}

code_loads() {
  "$PY" -m pip check || echo "::warning::pip check reported issues"
  PYTHONPATH=src "$PY" -c "import cyberdef, cyberdef.imp_common, cyberdef.exec_oracle; print('cyberdef imports OK')"
}
env_pin() {   # drift is recorded as a warning, never a failure
  "$PY" -m pip freeze > "$TMP/env_now.txt"
  diff -q constraints.txt "$TMP/env_now.txt" >/dev/null 2>&1 || { echo "::warning::environment differs from constraints.txt"; diff -u constraints.txt "$TMP/env_now.txt" | head -40; }
  true
}
router_planner() (
  # runs in a SUBSHELL (note the parentheses): the job's own inputs (DATA, SCORER, TEST_SET, ...) must not leak into the
  # planner tests, and unsetting them must not touch this script's own variables (MACHINE is this script's argument)
  unset DATA SCORER TEST_SET STEPS MODEL TAG MACHINE ACK_OOM TRAIN_FLAGS
  chk() { local got; got=$(python3 scripts/ci_route.py --mode "$3" --model "$1" 2>/dev/null | grep '^lane_name=' | cut -d= -f2)
          [ "$got" = "$2" ] || { echo "route $1: expected $2, got $got"; return 1; }; echo "route $1 -> $got OK"; }
  chk "Qwen/Qwen2.5-7B-Instruct" gpu-box train && chk "Qwen/Qwen2.5-14B-Instruct" gpu-box train && chk "fdtn-ai/Foundation-Sec-8B" gpu-box train \
    && chk "deepseek-r1:32b" spark eval && chk "qwen3.8:27b" spark eval || return 1
  # planner: adapter naming, per-machine steps, and the refusals it must make
  MACHINE=spark MODEL="Qwen/Qwen2.5-14B-Instruct" STEPS="train + test" TAG=t \
    TEST_SET="PrimeVul length-matched (1,074)" python3 scripts/ci_plan.py > "$TMP/plan.txt" 2>/dev/null || { echo "planner rejected a valid plan"; return 1; }
  grep -qx "adapter_tag=t" "$TMP/plan.txt" && grep -qx "train=true" "$TMP/plan.txt" \
    && grep -qx "test_sets=pv=results/lenmatched_eval_cases.json" "$TMP/plan.txt" && grep -qx "scorer=selective" "$TMP/plan.txt" \
    || { echo "planner output wrong:"; cat "$TMP/plan.txt"; return 1; }
  # CoT arms: the pre-registered generation scorer plus localisation (arm 6 adds pairs); twins stay on the verdict scorer
  PRE="pre-registered sets (PrimeVul, VulSpot x2, CASTLE; CoT arms add localisation)"
  MACHINE=spark MODEL="Qwen/Qwen2.5-14B-Instruct" STEPS="train + test" TAG=t TEST_SET="$PRE" DATA="CoT arm 6: counterfactual traces" \
    python3 scripts/ci_plan.py 2>/dev/null > "$TMP/plan6.txt"
  grep -qx "scorer=cot" "$TMP/plan6.txt" && grep -q "^test_sets=pv=.* vh=.* vn=.* castle=.* loc=.* pairs=" "$TMP/plan6.txt" \
    || { echo "planner: arm 6 not on the pre-registered CoT scorer and sets:"; cat "$TMP/plan6.txt"; return 1; }
  MACHINE=spark MODEL="Qwen/Qwen2.5-14B-Instruct" STEPS="train + test" TAG=t TEST_SET="$PRE" DATA="CoT arm 2 twin: same rows, verdict only" \
    python3 scripts/ci_plan.py 2>/dev/null > "$TMP/plan2t.txt"
  grep -qx "scorer=selective" "$TMP/plan2t.txt" && ! grep -q "loc=" "$TMP/plan2t.txt" \
    || { echo "planner: the arm 2 twin is not on the verdict scorer and the four sets:"; cat "$TMP/plan2t.txt"; return 1; }
  MACHINE=gpu-box MODEL="Qwen/Qwen2.5-32B-Instruct" STEPS="train + test" TAG=t TEST_SET="PrimeVul length-matched (1,074)" \
    python3 scripts/ci_plan.py 2>/dev/null | grep -q "^train_warn=..*" || { echo "planner did not flag a 32B model on the 24 GB box"; return 1; }
  MACHINE=gpu-box MODEL="Qwen/Qwen2.5-7B-Instruct" STEPS="trace bank" TAG=t python3 scripts/ci_plan.py 2>/dev/null | grep -qx "bank=false" \
    || { echo "planner put the trace bank on the box"; return 1; }
  if MACHINE=gpu-box MODEL="Qwen/Qwen2.5-7B-Instruct" STEPS="train only" TAG="" python3 scripts/ci_plan.py >/dev/null 2>&1; then
    echo "planner accepted training without a tag"; return 1; fi
  echo "planner OK"
)
parser_selftest() {
  "$PY" - <<'PY'
import sys; sys.path.insert(0, "scripts")
from imp_witness_common import parse_witness
assert parse_witness('noise {"argv": ["x; CANARY"], "stdin": ""} tail')["argv"] == ["x; CANARY"]
assert parse_witness("no json here") is None
assert parse_witness('{"verdict": "SAFE"}') is None
assert parse_witness('{"env": {"BAD-KEY": "v", "QUERY": "x"}}')["env"] == {"QUERY": "x"}
print("witness parser OK")
PY
}
controls() {  # ci_controls.py group: length | oracle | accept
  local rc
  PYTHONPATH=src "$PY" scripts/ci_controls.py --only "$1" --timeout 900 --out "results/ci_controls_$1.json" --md "$TMP/ctl_$1.md"; rc=$?
  [ -s "$TMP/ctl_$1.md" ] && { echo; cat "$TMP/ctl_$1.md"; } >> "$TMP/details.md"
  return $rc
}
grammar() {
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e HF_HOME=/hf -e HF_HUB_OFFLINE=1 -e PYTHONPATH=/work/src \
    -v "$PWD:/work:ro" -v "$HOME/.cache/huggingface:/hf:ro" -w /work --entrypoint python3 cyberdef-train:aarch64 \
    scripts/ci_schema_control.py
}

if [ "$MACHINE" = "spark" ]; then
  run "CoT grammar admits concrete witnesses (schema v2.3); the stripped-fix mutant is caught" grammar
else
  run "Code loads, dependencies consistent" code_loads
  run "Environment matches the pin (drift is only a warning)" env_pin
  run "Router and planner send each model to the right machine; planner refuses bad plans" router_planner
  run "Result-integrity gate catches a tampered headline" env PYTHONPATH=src "$PY" scripts/ci_gate.py --selftest
  run "Witness parser self-test" parser_selftest
  run "Datasets are byte-identical to their manifest; a corrupted copy is caught" \
      sh -c "'$PY' scripts/ci_data_manifest.py --selftest && '$PY' scripts/ci_data_manifest.py --check"
  run "Test sets are length-matched (length alone ~0.50); a length-leaking mutant leaves the band" controls length
  run "Execution oracle passes and catches its never/always mutants" controls oracle
  run "Acceptance checks pass and catch their --broken mutants" controls accept
fi

{ echo "### Checks on $MACHINE: $(( ${#rows[@]} - fails ))/${#rows[@]} pass"; echo; echo "| | control |"; echo "|---|---|"
  printf '%s\n' "${rows[@]}"
  [ -s "$TMP/details.md" ] && { echo; echo "<details><summary>Control details</summary>"; cat "$TMP/details.md"; echo; echo "</details>"; }
  echo; } >> "$MD"
printf '%s\n' "${rows[@]}"
[ "$fails" -eq 0 ]
