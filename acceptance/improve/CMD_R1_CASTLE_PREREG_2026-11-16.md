# Pre-registration: command injection round 1 on CASTLE — 2026-11-16 09:29 AEDT

Written before the Qwen3.8-27B CoT base, the selective base or the round-1 twin has been scored on CASTLE.

## Why
Addendum 3i found no fair Juliet test for command injection: the J3-matched number is descriptive, because function count
alone scores 0.975. CASTLE (198 runnable programs, 99/99) has no structural tell (function-count and static-count AUROC
exactly 0.500; length-only 0.539) and was already one of the test sets addendum 3a lists for every round adapter. It is
the only fair held-out test for this round.

## Disclosed
At about 09:30 the round-1 CoT adapter (out/imp_st_cmd_injection_r1) scored CASTLE AUROC 0.770 (per_case; Hanley-McNeil SE
0.033); per class, injection 0.923 (n=31). Neither comparator below had been scored when this was written.

## Test
- H: self-training on the filtered command-injection traces Qwen3.8 wrote itself improves Qwen3.8 on CASTLE beyond (a) the
  untrained model with the same CoT scorer and (b) the verdict-only twin trained on the identical rows.
- Primary: CASTLE overall (n=198). Paired stratified bootstrap (10,000 resamples, seed 0) of CoT minus CoT-base and of CoT
  minus twin.
- Bar: BOTH differences > 2 x their paired SE, and the CoT adapter beats length-only by > 2 SE.
- Reported next to it: the unpaired Hanley-McNeil SE of each difference, the selective base, PrimeVul-300, J4s and J3s.
- The CASTLE injection class (n=31) is descriptive only.
- If either difference fails, H is not supported for round 1. That is reported as a null, with every number.
- Any claim also needs an experiment-auditor pass.
