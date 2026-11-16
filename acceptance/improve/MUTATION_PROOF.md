# Mutation proofs (imp_ acceptance checks)
## 9c (2026-11-14T20:28:10+11:00)
- check_9c.py before the output existed: FAIL (output missing).
- Mutant 1 (published_7b @25% by_confidence AUROC overwritten with 0.9): check FAILS (auroc stored vs recomputed).
- Mutant 2 (one per_case row dropped from lenmatch_7b): check FAILS (per_case does not cover the matched cases).
- Real output: PASS.
## 6 (gradient reversal) 2026-11-14T20:47:55+11:00
- check_6.py grl before src/cyberdef/imp_adv.py existed: FAIL (ImportError). With the real GRL: PASS. With the broken identity-backward GRL (--broken): FAIL (G2, G3).
- check_6.py smoke before output existed: FAIL. First smoke run used lambda=2.0 / 120 steps and FAILED the pre-registered criterion (task loss rose 0.65->0.89 under reversal); it was a mis-parameterisation of the smoke
  (pre-registered training lambda is 1.0), re-run at lambda=1.0 / 240 steps: PASS (task 0.65->0.61, adversary MSE 1.68 vs 0.30 for the lambda=0 control). The criteria were not changed.
## 3/4/data17 2026-11-14T20:47:55+11:00
- check_3/check_4/check_data17 each FAILED before their builds existed (missing files). check_data17 --selftest: an injected test-set function is caught.
## 2 / 9a / bank / cotitems / train_slots (2026-11-14T21:55:58+11:00)
- check_2.py results: FAILED before any fuzz result existed; FAILS on the debug run (debug_limit set, n=2 != 198). check_2.py selftest controls C1-C4 pass (known-bad program confirmed, safe twin not, empty-seed direct run not, sanitizers-off (IMP_NOSAN=1) not confirmed).
  Two harness defects were found by looking at results, not by the check: UBSan text not counted as confirmed (18/99 vuln crashes mis-filed), and 4 programs lost to the container limit. Both fixed and logged as #2 amendment 1; the runs before the fix are kept in results/imp_superseded/ and not used. (A first re-run silently reused the OLD harness because the fix had not been pushed; it reproduced run 1 exactly and was also superseded.)
- check_9a.py baselines: FAILED before results/imp_9a_baselines.json existed; PASS after. Baselines: random 0.070/0.173 top1/top3, longest line 0.110/0.248 (line-length bias is real), regex sink 0.077/0.105, flawfinder 0.064/0.092.
- check_cotitems.py --selftest: a swapped twin label is caught. check_bank.py --selftest (always-pass validator) is implemented but has not been exercised: no bank exists yet (reported, not claimed).
- check_train_slots.py: first version failed because it assumed VULNERABLE is a single BPE token (it is " V"+"ULNERABLE"); the assumption in the TEST was wrong, the slot logic was right; test corrected, behavioural assertions (T2/T3/T4) unchanged.
## strict X / oracle spec (2026-11-14T22:50:58+11:00)
- check_strictx.py: FAILED before scripts/imp_bank_strictx.py existed (script not found); PASS with it (controls S1 long witness -> True, S2 short witness -> False, S3 empty-input crash -> False, S4 twin also crashes -> False, counts strict=1 loose=1, arm7 infeasible); the --broken mutant (empty-input condition dropped) is CAUGHT (S3 became True).
- check_2o.py selftest: FAILED before the harness existed (ModuleNotFoundError); PASS with controls L(leak) F(bad free) U(unsigned wrap, B only) T(TSan race) R(recursion) H(busy loop = cpu_hang) W(sleep = NOT confirmed) A(assert) S(safe, no variant counts); the --broken mutant (classifier returns nothing) is CAUGHT.
