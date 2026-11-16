#!/usr/bin/env bash
# Fail-first check for the K=3 CoT decode wiring in a ci_step.sh copy: stubs every GPU call, extracts the helper functions,
# and checks J3s/J4s get 3 shuffled decodes (seeds 1-3) into out, out_k2, out_k3, while CASTLE gets one unshuffled decode.
F=${1:-scripts/ci_step.sh}; T=$(mktemp -d); fails=0
{ echo 'claim_spark(){ :; }; spark_env(){ :; }; wait_mem(){ :; }; take_gpu(){ :; }; flock(){ :; }'
  echo 'gdock(){ echo "GDOCK $*" >> "$T/calls"; }'
  sed -n '/^cot_k() /p;/^cot_out() /p' "$F"
  sed -n '/^cot_eval_here() {/,/^}/p' "$F"; } > "$T/fns.sh"
for cf in results/j3s_heldout_matched_cases.json results/j4s_heldout_matched_cases.json results/castle_cases.json; do
  : > "$T/calls"
  ( T=$T; source "$T/fns.sh"; P_params_b=27; cot_eval_here M "" "$cf" results/ci_ev_x_set.json ) >/dev/null 2>&1
  n=$(grep -c GDOCK "$T/calls"); case "$cf" in *castle*) want=1 ;; *) want=3 ;; esac
  outs=$(grep -o -- "--out [^ ]*" "$T/calls" | cut -d' ' -f2 | tr '\n' ' ')
  seeds=$(grep -o -- "--shuffle-seed [0-9]*" "$T/calls" | cut -d' ' -f2 | tr '\n' ' ')
  if [ "$want" = 3 ]; then ok_o="results/ci_ev_x_set.json results/ci_ev_x_set_k2.json results/ci_ev_x_set_k3.json "; ok_s="1 2 3 "
  else ok_o="results/ci_ev_x_set.json "; ok_s=""; fi
  if [ "$n" = "$want" ] && [ "$outs" = "$ok_o" ] && [ "$seeds" = "$ok_s" ]; then echo "PASS $(basename $cf): $n decodes, seeds [$seeds]"
  else echo "FAIL $(basename $cf): $n decodes (want $want), outs [$outs], seeds [$seeds]"; fails=$((fails+1)); fi
done
bash -n "$F" && echo "PASS bash -n" || { echo "FAIL bash -n"; fails=$((fails+1)); }
grep -q 'decode \$k' "$F" && echo "PASS test step checks decodes 2..K" || { echo "FAIL test step does not collect decodes 2..K"; fails=$((fails+1)); }
[ "$fails" = 0 ] && echo "ALL PASS" || { echo "$fails failed"; exit 1; }
