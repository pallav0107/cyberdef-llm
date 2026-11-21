# What `scripts/imp_dev_gate2.py --selftest` must cover (acceptance C8)

Owner: the implementer of scripts/imp_dev_gate2.py. This note is the contract for the selftest; the checker for C8 is
the selftest itself, run as `.venv/bin/python scripts/imp_dev_gate2.py --selftest` (exit 0 = every case behaved).
Source of the rules: CURRENT_PLAN.md (cycle-2 gate, Amendment 1 "Gate v2 threshold"). imp_dev_gate.py stays pinned and
untouched; imp_verdict.py is pinned and read-only (import from it, never edit it).

## Rule under test (fixed in code, never a run-time knob)

Eligible iff ALL of:
- comparisons.base.delta > 0 (pooled delta > 0; exactly 0 is NOT eligible),
- pair_veto.delta >= 0.035 (a constant; 0.034 is not eligible, 0.035 is),
- B-stratum wins(adapter) >= B-stratum wins(base) - 2 (three below is not eligible, two below is).
Winner: the eligible config with the highest pair_veto.delta, except K4a wins when it is eligible and within 0.02 of
the best (a gap of exactly 0.02 counts as within; 0.0201 does not). None eligible: NO-GO, exit 3, nothing scored on
VSP-T. Exit codes as gate v1: 0 winner, 2 refused input or usage error, 3 NO-GO.

## Screens (read from the train log before any dev2 score is looked at)

A config failing any screen is ineligible regardless of its dev2 numbers, and the reason is named in the output:
1. Per-domain sampler: in the train log sampler record, inside linux and inside non-linux the A and B slot counts
   differ by at most 1 in every epoch, and no pair appears more than twice in an epoch.
2. last200.pair < 0.679 (the train-loss pair term at the end of training; 0.679 fails, just below passes).
3. K4b only: the number of pair terms logged equals the number of pair-steps (the verdict_slot trap: a two-line
   target silently switches the pair term off).
Each screen needs a passing case and a failing case; a missing or null log field is a refusal (exit 2), not a pass.

## Cases the selftest must include (each asserts the exact decision and exit code)

1. pair_veto.delta +0.034, everything else good: NO-GO (exit 3).
2. pair_veto.delta +0.035, B wins three below base: NO-GO. Same with B wins two below base: eligible.
3. comparisons.base.delta exactly 0 with pair_veto.delta +0.10: NO-GO. Negative base delta: NO-GO.
4. Two eligible configs, K4a within 0.02 of K4b (K4b higher): K4a wins. K4b higher by more than 0.02: K4b wins.
   K4a not eligible, K4b eligible: K4b wins (the tie rule never promotes an ineligible config).
5. Screens: one passing and one failing case per screen above; a screen failure beats a good dev2 delta.
6. Refusals (exit 2, nothing written): n not equal to 2 x the dev2 pair count (a round scored on the wrong set);
   null or missing pair_veto.delta, comparisons.base.delta or B-win fields; unreadable file; dev2 cases that are not
   whole pairs.
7. A round file scored on the linux held-out set (results/vsp_probe_cases.json, n = 600) is refused even though its
   n is well formed: the gate must recognise the probe set by case content or path, because the probe is descriptive
   only unless the owner signs off in writing.
8. A round file scored on the cycle-1 dev set (n = 632) is refused.
9. Determinism: the same inputs give byte-identical output twice, and input order of --round arguments does not
   change the winner.
10. The selftest also proves it can fail: it mutates the rule constants in a temporary copy (0.035 to 0.03, wins - 2
    to wins - 3, tie 0.02 to 0.03) and confirms the cases above then report a mismatch.

Boundary values are the point: every threshold is tested one step on each side of its constant.
