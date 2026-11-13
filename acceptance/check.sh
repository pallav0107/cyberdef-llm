#!/usr/bin/env bash
# Gate for cyberdef-llm increment 1: real env + real baseline + real tuned benchmark + adapter.
# Designed to REJECT fabricated results: it requires per_case outputs whose length matches n
# and are mostly non-empty, so a hand-written score cannot pass. Do not edit to force a pass.
set -u
cd "$(dirname "$0")/.." || exit 2
root="$(pwd)"
fail(){ echo "FAIL: $1"; exit 1; }

PY="$root/.venv/bin/python"
[ -x "$PY" ] || fail "no .venv/bin/python (env not set up)"

"$PY" - <<'PY' || fail "torch/cuda/training stack not importable"
import torch, transformers, peft, datasets
assert torch.cuda.is_available(), "torch.cuda.is_available() is False"
print("OK torch", torch.__version__, "cuda", torch.version.cuda)
PY

PYTHONPATH="$root/src" "$PY" -c "import cyberdef, cyberdef.evaluate, cyberdef.train, cyberdef.data" \
  || fail "cyberdef package not importable"

for f in results/baseline.json results/tuned.json; do
  [ -f "$root/$f" ] || fail "missing $f (that run never happened)"
done

"$PY" - <<'PY' || fail "a results file is not a real, auditable run"
import json
for f in ("results/baseline.json", "results/tuned.json"):
    d = json.load(open(f))
    s = d.get("score"); n = d.get("n", 0); pc = d.get("per_case", [])
    assert isinstance(s, (int, float)), f"{f}: score not numeric"
    assert n >= 120, f"{f}: test set too small ({n})"
    assert len(pc) == n, f"{f}: per_case ({len(pc)}) != n ({n}) -> not a real run"
    assert sum(1 for p in pc if p.get('raw')) >= 0.8 * n, f"{f}: most raw outputs empty -> suspect"
    print(f"OK {f}: score={s} n={n} heldout={d.get('heldout_score')}")
PY

[ -f "$root/out/qlora-vuln/adapter_config.json" ] || fail "no out/qlora-vuln/adapter_config.json (training unproven)"
echo "PASS: env + real baseline + real tuned benchmark + trained adapter all present"
