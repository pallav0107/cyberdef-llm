#!/usr/bin/env bash
# Fail-first test: an untrained base scored by the CoT scorer must not write the same result file as the same base
# scored by the selective scorer (16-17 Nov: the selective base overwrote the CoT base's files on Spark).
F=${1:-scripts/ci_step.sh}; T=$(mktemp -d); fails=0
sed -n '/^test)/,/^  ;;/p' "$F" | grep -E '^\s*(SFX=|if \[ -z "\$P_adapter_tag" \] && \[ "\$P_scorer" = cot \]|OUT="results/ci_ev_)' > "$T/lines.sh"
name() { ( P_adapter_tag="$1"; P_scorer="$2"; P_slug=qwen3.8-27b; key=j3s; source "$T/lines.sh" >/dev/null 2>&1; echo "$OUT" ); }
a=$(name "" cot); b=$(name "" selective); c=$(name st_x cot)
echo "base+cot: $a | base+selective: $b | adapter+cot: $c"
[ -n "$a" ] && [ "$a" != "$b" ] && echo "PASS base CoT and base selective files differ" || { echo "FAIL base CoT and base selective write the same file"; fails=$((fails+1)); }
[ "$b" = "results/ci_ev_qwen3.8-27b_j3s.json" ] && echo "PASS selective base name unchanged" || { echo "FAIL selective base name changed"; fails=$((fails+1)); }
[ "$c" = "results/ci_ev_st_x_j3s.json" ] && echo "PASS adapter names unchanged" || { echo "FAIL adapter name changed"; fails=$((fails+1)); }
bash -n "$F" && echo "PASS bash -n" || { echo "FAIL bash -n"; fails=$((fails+1)); }
[ "$fails" = 0 ] && echo "ALL PASS" || { echo "$fails failed"; exit 1; }
