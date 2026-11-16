# J5F build notes — sub-300 outcome (per brief_j5f.txt fallback)

## Result
- **240 verified pairs** (480 items) in `results/imp_juliet5f_items_all.json`.
- This is below the check's `MIN_PAIRS = 300`. Per the brief's explicit fallback
  ("If fewer than 300 pairs truly verify, do not weaken anything: finish, and report
  the real count and the rejection reasons"), nothing was weakened, truncated or
  padded. `acceptance/improve/check_j5f.py` passes every rule except the count line:
  `FAIL >= 300 verified pairs (got 240)`.
- All other checks PASS: ids, labels, feeds, parts (>=2), juliet_cwe, verification
  booleans, exactly one V + one S per pair, V/S text differs, no text > 4000 chars,
  `leak_hits` empty on every item, disjoint from all 406 CWE-134 stems used elsewhere
  (0 clashes).

## Why 240 is the true ceiling (rejection reasons)
Candidates: lettered multi-file cases (`_<NN><letter>.c/.cpp`) under
`data/juliet_dl/x/C/testcases/CWE134_Uncontrolled_Format_String/**`, console /
environment / file feeds only, grouped by case stem:

| stage | count | reason |
|---|---|---|
| lettered groups found | 600 | flows 22, 51-54, 61-68, 72-74, 81-84 (x 5 dirs x 3 feeds x 5 sinks x 2 char-types / sink mix) |
| rejected: `single_part` | 120 | flows 81-84 have only ONE lettered file (`_81a.cpp`); their other parts (`_81_bad.cpp`, `_81_goodG2B.cpp`, `_81_goodB2G.cpp`) carry no part letter, so they are not candidates under the brief's rule, and items must list >= 2 parts |
| candidates compiled + verified | 480 | 240 char + 240 wchar_t multi-file cases |
| rejected: `not_compiled` | 20 | all wchar_t `.cpp` groups (g++ -fpermissive still rejects them) |
| rejected: `bad_not_fired` | 220 | all remaining wchar_t groups |

**Every `char` multi-file case verifies (240/240). No `wchar_t` case can fire**, and
this is a property of the unchanged J3 recipe, not a builder defect: the Juliet
`main()` (built with `-DINCLUDEMAIN`) calls `printLine(...)` (narrow `fprintf`) before
the vulnerable sink, so stdout is byte-oriented; glibc then makes every subsequent
`fwprintf(stdout, data)` fail silently (mixed byte/wide orientation). The payload
never reaches a wide-format interpreter, `judge_fmt` sees no `T0x...` pointer output,
and the pair is correctly rejected as `bad_not_fired`. Confirmed with a minimal
reproducer in the sandbox (`fgetws` reads the payload fine; `fwprintf` after `fprintf`
prints nothing).

Cross-check: the J3 single-file build (same shim, same payload, same judge, accepted
by its own checks) also produced **zero** wchar_t CWE134 items
(`results/imp_train_juliet3_items.json`) — the oracle rejects them there too.

`stats` in the output JSON records the full rejection table:
`{"single_part": 120, "disjoint": 0, "not_compiled": 20, "bad_not_fired": 220,
"fired_on_benign": 0, "fired_on_empty": 0, "good_fired": 0, "error": 0, "too_long": 0, "leak": 0}`.
Verified pairs split evenly: 80 console / 80 environment / 80 file; 15 per flow across
flows 22, 51-54, 61-68, 72-74.

## What was NOT done (deliberately)
- wchar_t cases were not special-cased, recompiled with a custom main, or judged
  differently — that would deviate from the J3 model the brief mandates unchanged.
- Flows 81-84 (`_81a` + `_bad/_goodG2B/_goodB2G`) were not pulled in: their companion
  files carry no part letter, so they fail the brief's candidate rule.
- No existing file under `results/`, `scripts/`, or `src/` was modified; the only new
  files are `scripts/imp_build_juliet5f.py` and `results/imp_juliet5f_items_all.json`
  (plus this note).
