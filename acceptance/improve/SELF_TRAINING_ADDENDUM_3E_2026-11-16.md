# Addendum 3e: J4b, the held-out test for memory and divide-by-zero, and the integer and leak exemplars — 2026-11-16 01:14 AEDT

Written before any model has been scored on J4 or J4b, and before Qwen3.8-27B has written any memory, integer or leak trace.
Addendum 3a required J4 to be fixed and re-matched under a further addendum before those rounds; this is that addendum.
The texts are cleaned per addendum 3g (written alongside).

## What was wrong with J4 (scripts/imp_build_juliet4.py)
1. Leaks never verified: ASAN_OPTIONS=detect_leaks=0, and the report pattern lacked "ERROR: LeakSanitizer" (0/60).
2. Integer bugs never fired: stdin was empty and the input-driven variants need a number (CWE-190 8/60, CWE-191 7/60).
3. Divide-by-zero was never loaded: "CWE369_Divide_By_Zero" does not match Juliet's "CWE369_Divide_by_Zero" (0 files).
4. Memory: only 60 candidate files per CWE, so per-CWE length matching kept only CWE-121 (24/24).
5. (Found under 3g) the texts kept Juliet's FLAW/FIX comments, CWE numbers and bad/good identifiers.

## J4b (scripts/imp_build_juliet4b.py, scripts/imp_finish_j4b.py)
- Flow variants _02-_22/_31-_45, single-file .c. Exemplar files are excluded. Labels come from execution only: the bad
  program fires a sanitizer, and the good program does not on the SAME stdin. Run in docker gcc:13 with no network, capped,
  non-root, ASan+UBSan.
- Memory: 200 candidate files per CWE (121, 122, 124, 126, 127, 415, 416, 476, 590).
- Leak (401): LeakSanitizer on for these files only, and its report counts.
- Integer: only signed int/int64 variants with a constant or stdin source. CWE-190 (add/multiply/square/inc) gets INT_MAX-type
  input; CWE-191 (sub/multiply/dec) gets INT_MIN-type input; CWE-369 (int divide/modulo) gets 0. Unsigned wrap and float
  division are not undefined behaviour, so they are excluded; rand and socket sources are excluded as nondeterministic or
  needing a network.
- Smoke run (4 files per CWE): leaks 3/4, overflow 4/4, underflow 4/4, divide-by-zero 3/4; no good program fired.
- Full build: 2,414 files, 2,044 verified pairs, and no good program fired anywhere. Verified per CWE: 121 164, 122 137,
  124 152, 126 137, 127 150, 190 196, 191 191, 369 146, 401 158, 415 147, 416 98, 476 171, 590 197.
- Per-CWE length matching exactly as 2c (chars AND tokens in [0.45, 0.55], at least 20 per class), on the cleaned texts:
  - KEPT, memory (358 vulnerable / 358 safe; category length-only 0.494): CWE-121 71/71, CWE-122 63/63, CWE-124 64/64,
    CWE-126 59/59, CWE-127 60/60, CWE-590 41/41.
  - KEPT, integer: divide-by-zero, CWE-369 28/28 (length-only 0.464).
  - NOT kept: CWE-190 (20/20 but length-only 0.39), CWE-191 (18/class), CWE-401 (6), CWE-415 (3), CWE-416 (11), CWE-476 (12).
    Juliet's good text for these holds two or three good functions against one bad one, so the classes cannot be
    length-matched. Integer overflow, underflow and leak still have no primary test, and no claim is made for them.
- results/j4_heldout_matched_cases.json: 772 functions, sha256 a977fb0b16810083…, pinned in the data manifest. It supersedes
  the 48-function J4 set (kept as results/j4_heldout_matched_cases.before_3e.json; never scored).

## Exemplars (rule of addendum 3b §2)
- Memory: no extra exemplars; the quick set already shows a VULNERABLE and a SAFE memory trace.
- Integer, from `CWE190_Integer_Overflow__int_max_add_01.c`, an _01 file in no pool and no test:
  - E11 VULNERABLE: INT_MAX + 1.
  - E12 SAFE: data = 2 in one function and a data < INT_MAX check in the other, both marked sufficient.
  - results/imp_fewshot_exemplars_st_integer.json, sha256 01769fc1b905bfca88541170b94d7070bc2c621e214346409112c9ce5b5e6f07.
- Leak, from `CWE401_Memory_Leak__char_malloc_01.c` (every CWE-401 _01 file is in pool J, so this pair leaves the leak pool,
  65 to 64):
  - E13 VULNERABLE: malloc, never freed.
  - E14 SAFE: a stack buffer (ALLOCA) and a freed heap buffer.
  - results/imp_fewshot_exemplars_st_leak.json, sha256 90b487aca2324e33d87b7c448b2f653d803e517f437b775c7f5d716f12278b86.
- The validator does not move: a VULNERABLE trace without a witness, and a SAFE trace with an unguarded sink, are rejected
  on each.
