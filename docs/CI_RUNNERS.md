# cyberdef-llm CI: self-hosted runners

The `train` / `eval` / `ci` workflows run GPU work on **self-hosted** runners (GitHub-hosted
runners have no GPU). Jobs are routed to a runner by **model size** (`scripts/ci_route.py`):
`<=14B` → the box (`gpu-box`, 4-bit QLoRA on 24 GB CUDA), larger → Spark (`spark`, GB10 128 GB).

Nothing runs until (1) both runners are registered and (2) the workflow files are committed and
pushed. Neither is done by Claude — see "Owner steps" below.

## Runner labels

| machine | labels | role |
|---|---|---|
| box (x86/CUDA) | `self-hosted, cyberdef, gpu-box, cuda, x86_64` | training ≤14B, HF selective eval |
| Spark (aarch64/GB10) | `self-hosted, cyberdef, spark, gb10, arm64` | train/eval >14B, ollama zero-shot probes |

`runs-on: [self-hosted, cyberdef]` (the `route` job) matches either, so routing can run on whichever is idle.

## Owner steps (Claude cannot do these — `gh` is not installed, and runner registration needs repo-admin tokens)

### 1. Box runner
A runner serves one repo, so use a NEW directory (don't disturb the live `actions-runner-s19a`):
```bash
cd ~ && mkdir actions-runner-cyberdef && cd actions-runner-cyberdef
cp ~/actions-runner/runner.tar.gz . && tar xzf runner.tar.gz      # reuse the binary you already have
# Get <REG_TOKEN> from: github.com/pallav0107/cyberdef-llm -> Settings -> Actions -> Runners -> New self-hosted runner
./config.sh --url https://github.com/pallav0107/cyberdef-llm \
            --token <REG_TOKEN> \
            --name cyberdef-box \
            --labels gpu-box,cuda,x86_64 \
            --work _work --unattended
# point CI at the maintained venv (NOT a checkout-local one — checkout wipes gitignored files):
echo 'CYBERDEF_PY=/home/pallav-pokhriyal/missions/cyberdef-llm/.venv/bin/python' >> .env
sudo ./svc.sh install && sudo ./svc.sh start
```

### 2. Spark runner (aarch64)
```bash
ssh spark-75cf@10.55.0.14
cd ~ && mkdir actions-runner-cyberdef && cd actions-runner-cyberdef
curl -o r.tar.gz -L https://github.com/actions/runner/releases/latest/download/actions-runner-linux-arm64-*.tar.gz
tar xzf r.tar.gz
./config.sh --url https://github.com/pallav0107/cyberdef-llm \
            --token <REG_TOKEN_SPARK> --name cyberdef-spark \
            --labels spark,gb10,arm64 --work _work --unattended
# Spark uses system python3 (packages already installed there); set it explicitly:
echo 'CYBERDEF_PY=python3' >> .env
sudo ./svc.sh install && sudo ./svc.sh start
```
Spark's uplink is slow (~1.4 MB/s) but the Actions control-plane is light long-polling — fine. All
heavy data/models stay local; CI ships nothing large over the wire.

### 3. Commit + push the pipeline
Claude stages the workflows + helpers; you commit under your identity (no AI co-author) and push.
CI only sees committed state.

## How jobs stay off each other (and off the legacy lanes)

- Each train/eval `run:` acquires an `flock` on `.box_gpu.lock` (box) or `.spark_ci.lock` (Spark)
  before touching the GPU, so a CI job and a still-running `imp_box_lane*.sh` serialize instead of
  colliding. During cutover, keep that lock convention; afterwards the lane scripts retire.
- GitHub `concurrency:` groups cap it at one train and one eval per lane, and never cancel a run
  in progress.

## The interpreter (`CYBERDEF_PY`)

`actions/checkout` runs `git clean -ffdx`, which deletes a checkout-local `.venv` (gitignored). So
the interpreter lives OUTSIDE the checkout and is named per-runner in the runner's `.env`
(`CYBERDEF_PY`). Workflows fall back to `python3` if it is unset. Keep each runner's environment
matching `constraints.txt`; `ci.yml` warns (does not fail) on drift, and every run records the
drift in its provenance.

## Cutover (does not disrupt the running campaigns)

1. Register both runners; they sit idle until a workflow is dispatched.
2. Push the workflows.
3. Smoke test: `train` with a tiny model + `--arm "--dry-run"`, then `eval` on a small set — proves
   routing, lock, gate, provenance end to end.
4. Migrate each live arm to a `workflow_dispatch` call; retire the matching `imp_box_lane*.sh`.
5. Let the current in-flight lane/queue jobs finish first — do not kill them to cut over.

## TODO (follow-ups, not blockers)

- Wire the existing `acceptance/improve/check_*.py` fail-first self-tests into `ci.yml` once each
  script's self-test entry point is confirmed (today `ci.yml` proves the router + the `ci_gate`
  recompute gate; the data/model-dependent checks stay in `eval.yml`).
- Evidence storage: `.gitignore` keeps `results/*.json` in git (168 MB and growing). Decide:
  keep / Git LFS for big `per_case` / push as release artifacts.
- Optional `nightly.yml` that runs `run_autopipeline.py` end-to-end (resumable) as a scheduled sweep.
