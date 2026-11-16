"""Unit test: in pair_delta_counts a pair whose cluster is drawn twice must count twice."""
import sys
sys.path.insert(0, "scripts"); sys.path.insert(0, "src")
import imp_verdict as V
# two pairs, both stratum A; pair 0 adapter wins (V>S), base loses; pair 1 adapter loses, base wins; plus one B pair (tie-free, both win)
sa = [0.9, 0.1, 0.1, 0.9, 0.8, 0.2]   # cases: p0V p0S p1V p1S p2V p2S
sb = [0.1, 0.9, 0.9, 0.1, 0.8, 0.2]
iv, isf, strat, skip = [0, 2, 4], [1, 3, 5], ["A", "A", "B"], [False, False, False]
once = V.pair_delta_counts([1, 1, 1, 1, 1, 1], iv, isf, strat, skip, sa, sb)
twice0 = V.pair_delta_counts([2, 2, 1, 1, 1, 1], iv, isf, strat, skip, sa, sb)   # pair 0's cluster drawn twice
# once: A adapter mean (1+0)/2=0.5, base 0.5 -> delta 0. twice0: A adapter (1+1+0)/3=0.667, base (0+0+1)/3=0.333 -> delta +0.1667
ok = abs(once) < 1e-12 and abs(twice0 - (2 / 3 - 1 / 3) / 2) < 1e-12
print(f"once {once:+.4f} twice {twice0:+.4f} -> {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
