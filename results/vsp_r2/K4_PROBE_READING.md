# K4 probe P1 reading (descriptive; linux held-out probe, NOT project-disjoint)

Recorded 2026-11-24 02:31 AEDT before any K4 pilot was trained or any dev2 score existed.

Inputs (Spark, CI runs 45182772418 base and 45182795945 vsp_pilot_k2, commit e80a9a3):
- results/ci_ev_qwen3.8-27b_vspprobe.json  sha256 b99585fa5caed3f2619f62382b1c823558a327b05cd2c65c033bb0c838637c39
- results/ci_ev_vsp_pilot_k2_vspprobe.json sha256 e0dfa2c15315d9206811faac234c00567b1ec071d930c7696ff5e031adec74d9
AUROC base 0.5596, K2 0.5708 (600 cases, 300 pairs).

Within-pair win rate (V scored above F; ties 0.5), strata by code_chars (A = fix longer, B = V longer), 95% paired
bootstrap (4000, seed 0):
- linux A n=150: base 0.713, K2 0.667, K2-base -0.047 [-0.130, +0.040]
- linux B n=150: base 0.597, K2 0.633, K2-base +0.037 [-0.053, +0.130]

Pre-stated readings (CURRENT_PLAN.md, Pre-pilot probe P1): (i)/(iii) need B >= base+0.08 (K4a live); (ii) needs B
within 0.03 of base (K4a dead, only K4b). +0.037 matches none: the rule has a gap in (+0.03, +0.08).
Decision: the reading is recorded as UNDEFINED (gap), not as (ii). A two-role consult (debugger, integration-tester;
model-family agreement only) answered NO to treating it as (ii). Both pre-budgeted pilots (K4a, K4b) are therefore
run; the cycle-2 gate is unchanged and every claim reports all configs screened. The pass estimate is not raised.
