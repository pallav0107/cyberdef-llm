# Addendum 3f: format string exemplars, written before its round — 2026-11-16 00:44 AEDT

Written before Qwen3.8-27B has written any format-string trace. Follows the rule in addendum 3b §2. Nothing else changes.

## Exemplars
- The quick set has no format-string exemplar. The round adds one VULNERABLE and one SAFE exemplar, templated by
  scripts/imp_build_st_exemplars.py from `CWE134_Uncontrolled_Format_String__char_console_printf_02.c`. This is a J3 TRAINING
  file, in no held-out test. The pool builder drops it from training: format string goes from 177 to 176 pairs.
  - E9 VULNERABLE: the stdin line is printf's format. The length check is shown as an insufficient guard. Witness
    `CANARY%p.%p.%p.%p` on stdin, the oracle's reference form.
  - E10 SAFE: four sinks. Two print stdin through the constant format `"%s\n"` (the guard is the call itself). Two print the
    constant `"fixedstringtest"` (the guard is the strcpy of that constant). All four are marked sufficient; witness null.
- File results/imp_fewshot_exemplars_st_format_string.json, 5 exemplars (3 quick + E9 + E10), sha256
  0b42fe25483342a4879df4adfa853cdccf320e6b33daa52393fb1672d519295e, pinned in the data manifest.
  ci_exemplar_leak.py passes against every test set.
- The validator does not move. A VULNERABLE witness without CANARY, a SAFE trace with one printf(data) sink marked
  insufficient, and a SAFE trace with a payload witness are each rejected. The other categories' exemplar files are
  byte-identical after this change.

## No claim for this category
Format string has no primary held-out test: Juliet format-string fixes are always longer, so per-CWE length matching fails
(J3 matched dropped CWE-134). A round may train, and its CASTLE and PrimeVul-300 results are reported, but no
format-string claim is made from it.
