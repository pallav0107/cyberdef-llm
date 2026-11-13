# cyberdef-llm

A **defensive / blue-team** security LLM pipeline: fine-tune and benchmark an open model to
understand security weaknesses and help defend under attack. Blue-team only — this project
does **not** build exploit or malware generators.

**Capabilities** (modular; implemented first → wired next):
1. `vuln_detect` — classify a code snippet VULNERABLE/SAFE (+CWE). **Implemented end-to-end.**
2. `secure_code` — insecure-code + attack-resistance → Meta **CyberSecEval**. *(module stub)*
3. `soc_triage` — threat-intel / incident triage → **CTIBench / SECURE**. *(module stub)*
4. `robustness` — prompt-injection / jailbreak resistance. *(module stub)*

## Honesty & licensing guardrails
- **Every number is from a real run.** `evaluate.py` records full per-case model outputs; the
  acceptance gate rejects any results file whose `per_case` length ≠ `n` (so a hand-written
  score cannot pass).
- **Open-weight models only.** Student = Qwen2.5-7B-Instruct (Apache-2.0). Any teacher must be
  open-weight & distillation-permitted (Qwen2.5-72B, Apache-2.0). **Never** train on outputs of
  a closed commercial API (OpenAI/Anthropic/Kimi/Gemini/qwen-max|plus|turbo).
- Increment 1 is **teacher-free**: the `vuln_detect` dataset is ground-truth-by-construction
  (`data.py`), with 2 weakness families held out entirely for the test split to measure
  generalisation.

## Run (on the Blackwell box)
```bash
. .venv/bin/activate && pip install -e .
# baseline (base model) on the held-out test benchmark
python -m cyberdef.evaluate --model Qwen/Qwen2.5-7B-Instruct --suite vuln_detect --out results/baseline.json
# train QLoRA on the disjoint train split
python -m cyberdef.train   --base  Qwen/Qwen2.5-7B-Instruct --out out/qlora-vuln
# re-benchmark the tuned model on the SAME test set -> measure the real delta
python -m cyberdef.evaluate --model Qwen/Qwen2.5-7B-Instruct --adapter out/qlora-vuln --suite vuln_detect --out results/tuned.json
bash acceptance/check.sh
```

Increment 1 = environment + eval harness + **measured baseline→tuned delta** on vuln_detect.
Next: integrate CyberSecEval/CTIBench, and open-weight-teacher distillation for the richer
capabilities.
