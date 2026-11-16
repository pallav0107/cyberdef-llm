# Addendum 3h: self-training rounds skip the C pass — 2026-11-16 03:42 AEDT

Written while command-injection round 1 is still generating, and before any later round starts.

- imp_trace_bank.py runs a second pass after the original traces: for each function with a V+P trace, three length edits,
  each re-scored greedily, to compute the C tag (verdict unchanged under length edits). In round 1 this pass is 470 extra
  generations (157 functions x 3), about 65 minutes against about 80 minutes for the 1,008 original traces.
- Addendum 3a selects items on V, P, K, O and X_strict, and never on C. Every later round therefore runs imp_trace_bank.py
  with --skip-c, which skips that pass. Nothing that selects, trains or tests changes. The default (C pass on) is unchanged
  for every other bank build, CI included.
- Command-injection round 1 keeps its C pass (it was already running); its C tags are reported but not used.
- Also: imp_trace_bank.py now writes the original traces to <out>.orig.partial before any second pass, so a crash late in a
  run cannot lose them.
