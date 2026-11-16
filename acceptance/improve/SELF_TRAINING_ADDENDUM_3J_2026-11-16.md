# Addendum 3j: the memory round — structure-matched training text, a pool cap, its tests — 2026-11-16 11:24 AEDT

Written before Qwen3.8-27B has written any memory trace, and before any model has been scored on J4s. Command injection round 1
is closed (CASTLE: untrained Qwen3.8 0.784 vs adapter 0.770, a pre-registered null; see hope 11:20). Memory goes next because it
has a fair primary test (3i).

## 1. Training text matches the fair test
- The Juliet pairs in a self-training pool get the same structure rule as J4s (3i): the safe text is ONE good variant (plus
  its helpers), `static` is removed from function definitions, and fn_N names are renumbered. Flow variants _21/_22 are
  dropped. Real-world pairs (pool A) are unchanged.
- Why: the Juliet training text otherwise carries the function-count shortcut (vulnerable = 1 function, safe = 2–5). A
  round could then learn "count the functions", which J4s, by design, gives no credit for.
- Implementation: scripts/imp_st_pool.py <category> --structure. Labels stay execution-verified (the whole good program
  ran and fired nothing). The execution check (X_strict) still runs the original Juliet programs by name.

## 2. Pool cap: 250 pairs, Juliet first
- The memory pool has 633 pairs (453 real-world, 190 Juliet before the structure rule). At k=4 that is about 5,000
  generations (~7 h on Spark) and a training set several times round 1's (which took ~3 h per arm).
- Rule (scripts/imp_st_pool.py --cap 250): keep every Juliet pair, then fill to 250 with the other pairs drawn by
  random.Random(0) in source order. Juliet comes first because the primary test (J4s) is Juliet-based and only Juliet
  functions have an execution oracle.
- Memory pool as built: 250 pairs = 180 Juliet (structure-normalised; 10 dropped as unparsable or _21/_22) + 70 real-world.
  On the Juliet part, function-count-only AUROC is 0.500, static 0.517 and length 0.526; on the whole pool, length 0.510.
  sha256 recorded below.
- Generation: imp_st_round.sh memory 1 (k=4, --skip-c per 3h, the quick few-shot exemplars, text-only vLLM, guard on).
  Item rules unchanged (3a): V∧P∧K∧O, plus X_strict wherever it applies; safe traces V∧P; at least 20 per class.

## 3. Tests and bar for the memory round
- Primary: J4s, MEMORY CWEs only (121, 122, 124, 126, 127, 415, 416), overall and per CWE. The integer and leak parts of J4s
  are reported as transfer and are not part of the bar.
- Bar (3a, unchanged): the CoT adapter beats BOTH the untrained Qwen3.8 (CoT scorer) and its verdict-only twin by > 2 paired
  bootstrap SE (10,000 resamples, seed 0) on the primary, and beats the J4s-memory length-only, function-count and static
  baselines by > 2 SE. The unpaired Hanley-McNeil SE is reported next to it.
- Secondary (reported, not the bar): CASTLE overall and memory class, PrimeVul-300, the integer and leak parts of J4s, J3s.
- If the bar fails, memory round 1 is reported as a null and the programme moves to integer (J4s).

## 4. Training speed
Training-image speed (flash-linear-attention) is decided in a separate note on this addendum, after a benchmark, before
any memory training. Whatever is chosen applies to BOTH arms of the round.

- st_pool_memory.json (3j) sha256: 2adf779462d93899c6cf88eaed77b7956eef0b62f30b6a79e2033fed14f2ba84

## Note, 11:42 AEDT: training image for the memory round (decided before any memory training)
- Benchmark (~/bench_fla.sh on Spark): the identical QLoRA job (Qwen3.8-27B, 8 round-1 items without label text, seed 0,
  1 optimizer step, val 1 per class) in both images. The images differ ONLY by flash-linear-attention 0.6.0 + fla-core 0.6.0
  (pip freeze diff; torch 2.14.0+cu130, triton 3.8.0, transformers 5.22.2, peft 0.21.2 and bitsandbytes 0.50.2 unchanged).
    base image 7dcfcd3fc7a0: train_runtime 182.3 s, train_loss 0.5437
    fla image  b6ad5f6d4aee: train_runtime 160.3 s, train_loss 0.5444   (loss within 0.13%; 12% faster)
  causal-conv1d stays on its reference path in both images (no aarch64 wheel; a source build was not attempted).
- Decision: from the memory round on, Spark training and transformers scoring use the fla image. Mechanically,
  cyberdef-train:aarch64 now points at b6ad5f6d4aee and the original is kept as cyberdef-train:aarch64-base, so it can be
  restored by one `docker tag`. Both arms of every round from memory on train in the same image.
- Scope: vLLM generation and CoT evaluation are unaffected (vLLM uses its own kernels). Qwen2.5 models have no linear-attention
  layers and do not touch these kernels. No Qwen3.8 transformers score has been computed in the old image (the round-1 twin was
  never trained and the selective base has not been scored), so every Qwen3.8 transformers comparison is within the new image.
  The round-1 CoT adapter was trained in the old image; it is not compared with any memory-round adapter.
