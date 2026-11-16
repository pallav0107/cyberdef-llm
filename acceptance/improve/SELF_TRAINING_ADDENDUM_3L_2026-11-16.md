# Addendum 3l: memory round 1 outcome; format string goes next — 2026-11-16 14:38 AEDT

Written before Qwen3.8-27B has written any format-string trace in a self-training round, and before any model has been scored
on J3s with the CoT scorer.

## Memory round 1: insufficient correct traces (pre-registered outcome)
- Items after within-source balancing (3k): 9 per class (Juliet: 0 vulnerable kept / 129 safe; real-world: 9 / 29).
  The floor is 20 per class, so the round is not trained (3a). Nothing is rescued.
- Causes, from the trace bank (imp_st_learn.py; results/st_memory_r1_learn.json on Spark):
  - verdicts are 77% right on vulnerable functions and 82% on safe ones, but 452/1,000 vulnerable and 472/1,000 safe traces
    are rejected for format. Top error: the sink op is a description ("index write", "pointer arithmetic") instead of text
    on the cited line;
  - 230 otherwise-valid vulnerable traces name the wrong CWE (the general class rather than Juliet's specific one);
  - X_strict confirms only 6/284 checked Juliet vulnerable traces. Juliet memory programs crash with no input, so no
    witness can be causal.
- Consequence: under the current rules, memory, leak and constant-data integer cannot yield Juliet training items.
  Whether X_strict should count as "not applicable" for input-independent bugs is a rule change for the OWNER to decide;
  it is not changed here.

## Format string goes next (order change, from a mechanism, not from any test score)
- Its Juliet bugs are input-driven: a stdin or environment string reaches printf. The execution check can confirm them, as
  it confirmed 408 command-injection attacks. It has a fair test: J3s, CWE-134, 56/56, structural and length baselines
  ~0.50.
- Pool: scripts/imp_st_pool.py format_string --structure --cap 250. 104 pairs (98 Juliet + 6 real-world); 71 Juliet pairs
  dropped by the structure rule (unparsable or flow variants _21/_22); 1 exemplar-file pair dropped.
  sha256 8e82e5f58c80fa9c30826340dd314951bd16e29bf196651d191d950e0aae4549.
- New pool rule (a stricter data-hygiene step, recorded): a pool pair whose NORMALISED text equals a held-out case is
  dropped from training and counted. It replaces the earlier hard refusal, which still applies to exact raw duplicates. One
  pair was dropped: a training file's single good variant (CWE134 ..._environment_fprintf_44.c) normalises to the same text
  as a J3s safe case. No .c/.cpp twins are split across train and held-out (0 shared stems); no vulnerable texts collide.
- CAVEAT, pre-registered: in this training pool, LENGTH separates the Juliet labels (AUROC 0.760; function count 0.536,
  static 0.500), because the vulnerable function carries the input-reading code. J3s is length-matched (0.487), so this cue
  cannot earn test credit, but a model may learn it. Reported with every result.
- CAVEAT, power: J3s has 112 functions (Hanley-McNeil SE ~0.05). Only a large gain can pass a 2-SE bar. A null on J3s is
  weak evidence.
- Everything else as 3a/3j/3k: k=4 with --skip-c, exemplars from results/imp_fewshot_exemplars_st_format_string.json (3f),
  items V∧P∧K∧O plus X_strict where it applies, safe V∧P, within-source balance, floor 20 per class. Bar: the CoT adapter
  beats the CoT base and the twin by > 2 SE on J3s (paired bootstrap; CoT-scored models averaged over K=3 shuffled decodes;
  the decode-noise term of 3k), beats the length/structure baselines and is reported with the cue baselines. CASTLE and
  PrimeVul-300 are secondary.
