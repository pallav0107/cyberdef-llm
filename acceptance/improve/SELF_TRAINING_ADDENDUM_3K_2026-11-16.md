# Addendum 3k: pre-flight fixes for the memory round (independent audit) — 2026-11-16 14:28 AEDT

Written while memory round 1 is still generating (1,980/2,000 traces at 14:27), BEFORE its items are built and before its
funnel or any trace verdict has been read; no memory model exists and no model has been scored on J4s by the CoT scorer.
Source: an experiment-auditor review plus a decode-noise measurement, each adversarially re-checked (workflow
wf_5c7b6e6e-273). Nothing in the validator, X_strict, V/P/K/O or the bar is relaxed.

## BLOCKER B1 (fixed): balance classes within source
- X_strict is False for every Juliet vulnerable trace whose bad program already crashes on empty input. That is 84% of
  the pool's Juliet vulnerable functions (151/180). In the 14B bank, X_strict was False on 72/72 traces (0/43 functions
  confirmed). Global class balancing would then make VULNERABLE items mostly real-world and SAFE items mostly Juliet,
  so source alone would predict the label (AUROC 0.71 on the eligible set), and the primary test is all Juliet.
- Fix (scripts/imp_st_items.py, sha256 cfdad12afe254ce0…, on both machines before the items step ran): balance classes
  WITHIN source. Juliet vulnerable vs Juliet safe, and real-world vulnerable vs real-world safe, each drawn down with
  random.Random(0). This only drops rows. The items' stats record the source x label table.
- The floor stays at >= 20 per class in total. If the round falls short, it is reported as "insufficient correct
  traces", and it is NOT rescued by changing filters or exemplars. A likely outcome, given the 14B keep rates.

## MAJOR caveats, pre-registered before any memory verdict
- M1, CoT vs twin compares whole systems: the training target (trace vs verdict), the prompt, the scorer
  (vLLM CoT vs HF logprob) and the engine all differ. The verdict reports the cross cells too, where they can be run:
  the base and the CoT adapter under the selective scorer, and the twin under the CoT scorer. Balanced accuracy is
  reported beside AUROC.
- M2, J4s-memory is in-distribution at the template level: 73% of its pairs are flow variants of pool families. The
  claim is scoped to "held-out flow variants of training templates". The verdict also reports the J4s families absent
  from training (362 functions). CASTLE and PrimeVul-300 are the only transfer evidence.
- M3, lexical cues separate labels in both the pool and J4s: the literal 8 (CWE-124/127, AUROC 0.93-0.98), the free()
  count (CWE-415 1.00/0.98; CWE-416 0.79/0.74) and "Benign, fixed string" (0.64). These cue baselines are reported
  overall and per CWE next to every result. The bar stays as written.
- M4, the verdict analysis is committed as code with a fail-first test (identical arms must fail; a planted delta must
  pass) BEFORE any memory J4s score exists. It covers the memory-CWE subset, a paired bootstrap (10,000 resamples, seed 0,
  resampling unit = function), the three structural baselines and the cue baselines, Hanley-McNeil, per-CWE tables and a
  family-cluster bootstrap.
- M5, tamper evidence: these addenda and the self-training scripts are committed to git (owner identity, no AI
  co-author) before any memory J4s score exists. Result metadata records the scorer sha256 and the image digest. The base
  and adapter J4s evaluations run from one commit and one image.

## CoT-scorer decode noise (measured) and the rule for memory comparisons
- Greedy vLLM decoding at temperature 0 is NOT repeatable here. Byte-identical code got opposite verdicts in 20/156 pairs
  within a run (12.8%), and 37/343 cases flipped between invocations (10.8%). Simulated CASTLE two-run AUROC SD is
  0.024-0.036, as large as case-sampling noise. The logprob (selective) scorer is exactly reproducible (198/198 identical).
- Consequence, recorded: command injection round 1 on CASTLE (base 0.784 vs adapter 0.770) is a null either way;
  decode noise only widens the interval.
- Rule for the memory round: every CoT-scored model in a memory comparison (CoT base, CoT adapter, twin under the CoT
  scorer) is scored K=3 times on J4s-memory with shuffled case order, and p_vuln is averaged per case. The vLLM
  batch-invariant flag cannot run on Qwen3.8 (its GDN layers; the engine refuses). The bar adds a decode-noise
  requirement: a CoT difference counts only if it exceeds 2 x the combined SE (paired case bootstrap AND the measured
  run-to-run SD of the K-averaged score).

## Minor
- m1: the base is re-scored on CASTLE in the current (fla) image, from the same commit as the adapters.
- m2: imp_st_round.sh will refuse to rebuild a missing pool silently (this round's pool sha 2adf7794 matches 3J).
- m3: the J4s case whose family contains the CWE-121 memcpy exemplar is disclosed, with a sensitivity result without it.
- m4: verdicts are computed from per_case values, never from rounded headline numbers.

## Correction, 14:28: M5 wording
M5 above says the addenda and self-training scripts "are committed to git". Committing research scripts that were never
tracked is the owners decision, and it is still open; nothing is committed without that decision. (The line above was cut off by a shell quoting error at 14:28; this completes it.)
Interim tamper evidence: acceptance/improve/PREREG_HASHES_2026-11-16_1428.txt records the sha256 of every addendum,
self-training script, pool and test file at 14:28. It can be committed (hashes only) or published when the owner decides.

Resolved 2026-11-16 15:05 AEDT: the owner delegated the commit decision. These addenda, the self-training scripts, the
acceptance checks and the 14:28 hash manifest are committed in the commit that adds this paragraph. Two files differ from
the 14:28 manifest, both recorded: this addendum (the correction above and this paragraph) and scripts/imp_st_pool.py
(the normalised held-out collision rule of addendum 3l). The memory round was not trained (3l), so no memory J4s score
exists. The format-string round is still generating traces; no format-string adapter or twin exists at commit time.

Correction (2026-11-16 15:27 AEDT): the resolution paragraph above says 15:05; it was written and committed at 15:02:36
(commit b143795). The stated time was a guess, not a clock reading.
