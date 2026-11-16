# Addendum 3g: label text removed from J3 and J4b; the SQLi held-out taken out of the training pool — 2026-11-16 01:14 AEDT

Written before any model has been scored on any affected test set (J3 held-out, J3 matched, J4/J4b, SQLi held-out), and
before any CoT arm or self-training round has trained on J3 or the SQLi pool. Nothing is relaxed. Two dataset bugs are
fixed, and a control is added that fails on each.

## 1. Juliet's label was in the text of J3 and J4/J4b
- Pools J and J2 were cleaned by scripts/imp_clean_pools.py: comments removed, and CWE/bad/good identifiers renamed to
  fn_N. J3 (amendment 2) and J4/J4b were built later and never added to it.
- Before cleaning, J3 matched held "FIX" comments in 292/576 functions (every safe one), good…() names in 288,
  …_bad() in 118, and the CWE number in all 576. The J3 TRAINING pool (500 pairs) carried the same leaks, and through it so
  did the command-injection, path-traversal and format-string self-training pools. A model could read the answer from the
  comments.
- Fix: imp_clean_pools.py now also cleans imp_train_juliet3_items.json, imp_train_juliet3_items_all.json (the source of
  the J3 held-out sets) and j4b_heldout_all.json. 0 items still leak afterwards. The held-out sets and pools are rebuilt
  from the cleaned texts by their unchanged procedures. Execution checks are unaffected: they use the original Juliet files
  by name.
- Effects (all pre-result):
  - J3 held-out (2b): 840 pairs. Length-only AUROC 0.468 (it was 0.380: the comments themselves were a length signal).
    sha256 52020993eb597afa….
  - J3 matched (2c): 780 functions. Command injection 111/111 (length-only 0.499), CWE-23 105/105 (0.487), CWE-36 127/127
    (0.502), and FORMAT STRING CWE-134 47/47 (0.479). Format string now has a primary test; it failed matching before only
    because of the comments. sha256 46afd0127b161a16….
  - J4b matched (3e): 772 functions, as reported there.
  - Pools: the same sizes (126, 269, 91, 176, 643, 121, 64, 47, 17 pairs), cleaned text.

## 2. Pool Q contained the SQLi held-out
- results/imp_train_sqli_items.json (pool Q: read by imp_trace_bank, imp_build_cot_items and imp_bank_strictx, and by the
  amendment-2 bank) held all 133 pairs, INCLUDING the 44 later reserved as the SQLi held-out. Batch 2 would have trained on
  its own test.
- Fix (scripts/imp_hygiene_3g_sqli.py): pool Q is now the 89-pair TRAINING split. The full 133 pairs are kept as
  imp_train_sqli_all_items.json, tagged by split, and no pool reads it.
- All SQLi texts are cleaned the same way, and ALL 133 cleaned pairs were re-verified by execution with the SQLi builder's own
  sandbox check (both halves compile; the vulnerable half fires on a reference payload and not on benign or empty input; the
  safe half fires on none): 133/133.
  - Fail-first: a "safe" half that is the vulnerable code fires and fails; a truncated program fails to compile.
- An accident on the way, recorded: the first cleaning run applied the Juliet-only tail regex to the SQLi pool, which cut the
  closing "return 0; }" off main() in 256/266 programs. That file was replaced before anything read it, the broken copy is
  kept in results/before_3g/, and the regex now runs only on Juliet files.
- SQLi held-out: 44 pairs, cleaned. Length-only AUROC 0.333, i.e. 0.667 in the best direction (it was 0.672). Every SQLi result
  is judged against 0.667 as well as the 2 SE bar. sha256 3e6d67e14f177421….
- SQLi exemplars (3d) were rebuilt from the cleaned pair: sha256 69778ed2d8ae00467ed9b9717550ea8fed119c9113eefec450f74c00bd124b98.

## 3. Superseded hashes (no model was scored on any of them)
- 3b: J3 held-out 3f6996f6… → 52020993…; J3 matched 18f62ac9… → 46afd012….
- 3d: SQLi exemplars c30bd6a0… → 69778ed2….
- TWIN_REPLICATION_PREREG (00:52): its confirmatory set J3 matched is now 46afd012… (780 functions). The test itself is unchanged.

## 4. Banks built on the old text are invalid
- The amendment-2 bank's J3 and Q slices on Spark (if built) were generated on leaky J3 text and on the 133-pair Q. Their
  traces cite line numbers of uncleaned code and may lean on the comments.
- When Spark is back, they are moved to results/invalid_pre3g/ together with any amendment-2 build marker, so the Dataset
  step regenerates them from the cleaned pools. Batch 1 (the J2 build: quick + J2, both clean) is unaffected.
- The CoT arm-6 items carry a padding comment, "reviewed, no functional change", on SAFE items only (107/672 in the box copy).
  Mixed with other data, that is a shortcut. The per-run check below fails any run that would train on them, until the
  padding is applied to both classes or removed.

## 5. Controls
- scripts/ci_data_hygiene.py --check (a box control in every run): no label text in any Juliet-derived or synthetic item
  of any test set or training pool, and no test case sharing a source key (Juliet file or SQLi pair) or normalised code with
  any training pool.
  - Self-test: a FIX comment, a _bad identifier, a held-out pair in a pool and a duplicate under another id are each caught;
    real-world code is exempt from the label test.
  - On the pre-3g data it FAILS (J3 matched: label text in 576/576; the J3 pool: 1,000; SQLi held-out: 88/88 in a training
    pool). On the fixed data it passes.
- Dataset step, both machines: ci_data_hygiene.py --items <the file this run trains on>. The stale arm-6 copy fails it; the
  current arm-2 items pass.
