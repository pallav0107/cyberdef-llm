"""Stage H acceptance (written BEFORE scripts/reason_H_analyze.py). Usage (repo root): check_H.py controls | output <tag>
controls: `python scripts/reason_H_analyze.py --stubs [--broken]` prints JSON {stub: {"label": ...}} for the three stubs on a
synthetic probe set. Real probe must give length_stub=length-reader, oracle_stub=semantic-only, random_stub=neither;
the --broken probe (all deltas zeroed) must NOT reproduce that.
output: results/reason_H_<tag>_analysis.json must contain both axes with CIs, n counts and a verdict label."""
import json, os, subprocess, sys
fails = []
if sys.argv[1] == "controls":
    def st(*a):
        r = subprocess.run([sys.executable, "scripts/reason_H_analyze.py", "--stubs", *a], capture_output=True, text=True)
        return json.loads(r.stdout.strip().splitlines()[-1])
    try:
        real = st()
        want = {"length_stub": "length-reader", "oracle_stub": "semantic-only", "random_stub": "neither"}
        got = {k: real[k]["label"] for k in want}
        if got != want:
            fails.append(f"stubs not separated: {got}")
        bro = st("--broken")
        if {k: bro[k]["label"] for k in want} == want:
            fails.append("broken probe NOT caught")
    except Exception as e:
        fails.append(f"probe unavailable: {e}")
else:
    tag = sys.argv[2]
    try:
        d = json.load(open(f"results/reason_H_{tag}_analysis.json"))
        for k in ("length_axis", "semantic_axis", "label"):
            if k not in d:
                fails.append(f"{k} missing")
        la, sa = d.get("length_axis", {}), d.get("semantic_axis", {})
        for k in ("slope_per_1000_chars", "slope_ci95", "flip_rate", "n_base", "n_points"):
            if k not in la:
                fails.append(f"length_axis.{k} missing")
        for k in ("mean_delta", "mean_delta_ci95", "pairwise_acc", "pairwise_se", "pc_rate", "n_pairs"):
            if k not in sa:
                fails.append(f"semantic_axis.{k} missing")
    except Exception as e:
        fails.append(f"output missing: {e}")
print("PASS" if not fails else "FAIL: " + "; ".join(fails)); sys.exit(0 if not fails else 1)
