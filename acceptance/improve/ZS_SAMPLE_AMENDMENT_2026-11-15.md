# Amendment: zero-shot reading probes (P18) run on a 300-case sample first — 2026-11-15

Written before any result on the sample exists. It changes how much compute the zero-shot arm (#5) gets,
not what counts as a success: the bar (AUROC >= 0.60 on the length-matched PrimeVul set) is unchanged.

## Why
Each zero-shot probe takes ~60 s per case (about 18 h for the 1,074-case set; four models is about 3 days of Spark).
Every reading arm so far is near chance. The owner re-prioritised Spark to the CoT and execution work (2026-11-15).

## The sample
`results/lenmatched_eval_cases_300.json` (sha256 f74c0690fb72f8ea…), drawn from `results/lenmatched_eval_cases.json`:
20 token-count quantile bins over all 1,074 cases; in each bin an equal number of VULNERABLE and SAFE cases drawn with
`random.Random(0)`, allocated by largest remainder to 150 per class. Length-only AUROC on the sample: chars 0.5043,
tokens 0.5001, lines 0.5021 (inside the [0.45, 0.55] length-matched band). 95 projects.

The plain "first 300 cases" cut was rejected because it is NOT length-matched (length-only AUROC 0.446 chars / 0.438 tokens).

## Decision rule (fixed now)
For each model, compute AUROC on the 300 cases and its Hanley–McNeil SE (n1 = n2 = 150).
- If AUROC_300 + 2·SE >= 0.60, the sample cannot rule out the bar: run that model on the full 1,074 cases.
  The 1,074 result is the reported number for that model.
- Otherwise the bar is ruled out for that model; report the 300-case AUROC with its 95% interval.
- No result on the sample counts as a crossing by itself.

## Bookkeeping
- `P18_zs_a_gptoss20b` (full 1,074) was stopped at about 200/1,074 by the operator. The scorer has no partial output, so
  nothing was produced; the job is recorded as SUPERSEDED, not failed (`queue/superseded/`).
- `P18_zs_b/c/d` are replaced by `P87_zs_*_pv300` (same command, sample file, outputs `results/imp_zs_<tag>_pv300.json`).
  The originals are kept in `queue/held/`.
- `P18_zs_e_best_extra` picks the best full-set result; it is held until a model qualifies for the full set.
