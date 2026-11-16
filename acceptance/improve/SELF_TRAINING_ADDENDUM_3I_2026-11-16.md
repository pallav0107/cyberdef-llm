# Addendum 3i: structure-matched Juliet tests; a second cleaning gap closed — 2026-11-16 06:52 AEDT

Written before any model has been scored on the structure-matched sets J3s and J4s. Two more ways Juliet test text gave
the label away were found, one structural and one lexical. Both affect J3 matched (2c), J3 held-out (2b) and J4b matched
(3e). Neither affects CASTLE, PrimeVul, VulSpot or the SQLi held-out.

## 1. Function count gives the label (structural)
- A Juliet vulnerable text holds the bad function (plus any sink helper). The safe text holds every good variant (goodG2B1/2,
  goodB2G1/2…) plus a good() wrapper. Function count alone scores AUROC 0.975 (best direction) on J3 matched and 0.956 on J4b
  matched. Juliet's good functions are `static` and its bad ones are not, so the static keyword count scores 0.885 / 0.754.
  Length matching does not remove either tell. The Juliet training pools have the same layout (J2: vulnerable always 1
  function, safe 2–5), so a model can learn "more functions = safe".
- How it was found: the untrained Qwen2.5-14B scores 0.672 on J3 matched, and the batch-1 14B twin (seed 0) scores 0.949. A
  jump that size called for a check. Seed 0's J3-matched number was seen before this addendum.
- Fix, scripts/imp_build_structure_matched.py, rule fixed now:
  - The SAFE text is ONE good variant: one of the functions called by the good() root (the function nobody else calls),
    chosen with random.Random(sha256(pair)), plus the helpers it calls, after the file prefix. Labels stay
    execution-verified: the good program ran every good variant and fired nothing.
  - In both texts, `static` is removed from function definitions and fn_N names are renumbered in order of appearance.
  - Flow variants _21/_22 are excluded: each good variant's behaviour there depends on a static flag set by good().
  - Then per-CWE length matching as 2c. A CWE is kept only if length-only (chars and tokens), function-count-only and
    static-count-only AUROC all lie in [0.45, 0.55], with at least 20 per class.
- Result:
  - **J4s**, results/j4s_heldout_matched_cases.json: 2,122 functions, sha256 99e5b03294cf16ff…. Memory (CWE-121, 122, 124,
    126, 127, 415, 416), integer (CWE-190, 191, 369) and leak (CWE-401, 108/108). CWE-476 and 590 are dropped (static tell).
    Overall fn-count-only 0.520 and static-count 0.506.
  - **J3s**, results/j3s_heldout_matched_cases.json: 112 functions, sha256 2ed904c0fdb30dd3…. Format string only (CWE-134,
    56/56). fn-count 0.522, static 0.535.
- Command injection (CWE-78) and path traversal (CWE-23/36): NO clean test. A single good variant is systematically shorter
  than the bad function: the bad one carries the input-reading code, while G2B uses a constant. A per-CWE length match then
  leaves under 20 per class or a static tell. A pair-preserving match within 20% keeps only pairs where the vulnerable text is
  longer (length-only 0.83–0.95). J3 matched balanced length only by bundling 2–3 short good functions, which is exactly the
  function-count shortcut. **No claim is made for command injection or path traversal from Juliet.** Their J3-matched
  results are descriptive and are always reported next to the function-count baseline.

## 2. camelCase bad/good identifiers survived cleaning (lexical)
- cyberdef.imp_clean.clean_code's _BADWORD is case-insensitive, so its "(?![a-z])" also rejects uppercase letters.
  badStatic, badVaSinkB, badData, dataBadBuffer, dataGoodBuffer and helperBad were never renamed, and leak_hits() did not
  flag them.
  - In J3 matched, 53/390 vulnerable texts carried them against 6/390 safe.
  - In J4b and pool J, `data = dataBadBuffer` is the flaw itself.
- Fix:
  - A case-sensitive _CAMEL pattern now renames them and leak_hits() flags them. Words such as goodbye or goods are untouched.
  - Re-cleaning is collision-safe: new names start after the highest existing fn_N.
  - scripts/imp_hygiene_3i.py re-cleaned pool J (64 items changed), J2 (6), J3 training (92), J3 source (249) and J4b (516);
    0 leak hits remain.
  - All derived sets and pools were rebuilt by their unchanged procedures: J3 held-out 840 pairs (8cbe0aba…), J3 matched 776
    (ac5a3808…), J4b matched 776 (22b04d3a…); pools unchanged in size. Every exemplar file is byte-identical.

## 3. What changes
- **Primary per-category tests:**
  - memory, integer and leak: J4s, by CWE;
  - format string: J3s;
  - SQL injection: none (the SQLi held-out is saturated, 1.000 for the untrained 14B: see hope, 05:50);
  - command injection and path traversal: none.
- The category order moves to where a fair test exists: memory, integer, leak, format string.
- Command injection round 1 (already training on J3-based items) is scored as planned. Its J3-matched results are descriptive.
  Its usable evidence is CASTLE and PrimeVul-300, plus J4s/J3s for transfer.
- **TWIN_REPLICATION_PREREG:** the confirmatory sets become J4s and J3s, with Holm over the two and the same bar. They are
  scored for the untrained 14B and seeds 0–3, none of which has seen them. The J3-matched and J4b-matched results stay
  descriptive.
- **New control:** ci_data_hygiene.py also computes function-count-only and static-count-only AUROC for every test set and
  fails outside [0.40, 0.60]. Exceptions are the documented descriptive sets j3m, j3h and j4m, which are reported as
  warnings with their values.
- **Superseded hashes** (no model was scored on the new versions): J3 held-out 52020993… → 8cbe0aba…; J3 matched
  46afd012… → ac5a3808…; J4b matched a977fb0b… → 22b04d3a….
