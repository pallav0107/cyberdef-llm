"""Aggregate the security-suite results into one scaling table. Reads
results/suite_<tag>_{base,tuned}.json (accuracy) and results/suite_sel_<tag>_{base,tuned}.json
(edge), prints a table sorted by model size. Every value comes from a recorded run."""
import json, glob, os, re

PARAMS = {"1.5b": 1.5, "3b": 3, "7b": 7, "14b": 14, "32b": 32, "72b": 72}


def load(f):
    return json.load(open(f)) if os.path.exists(f) else None


def main():
    tags = set()
    for f in glob.glob("results/suite_sel_*_tuned.json"):
        m = re.search(r"suite_sel_(.+)_tuned\.json$", f.replace("\\", "/"))
        if m:
            tags.add(m.group(1))
    rows = []
    for t in tags:
        ab, at = load(f"results/suite_{t}_base.json"), load(f"results/suite_{t}_tuned.json")
        sb, stt = load(f"results/suite_sel_{t}_base.json"), load(f"results/suite_sel_{t}_tuned.json")
        if not (sb and stt):
            continue
        rows.append((PARAMS.get(t, 99), t,
                     ab["score"] if ab else None, at["score"] if at else None,
                     sb["auroc"], stt["auroc"],
                     stt["risk_coverage"]["0.25"]["accuracy"], stt["ece"]))
    rows.sort()
    print(f"{'model':6s} {'base_acc':>8s} {'tuned_acc':>9s} {'dAcc':>7s} "
          f"{'base_AUROC':>10s} {'tuned_AUROC':>11s} {'tuned@25%':>9s} {'tuned_ECE':>9s}")
    for p, t, ba, ta, bau, tau, a25, ece in rows:
        da = f"{(ta - ba):+.3f}" if (ba is not None and ta is not None) else "  n/a"
        print(f"{t:6s} {(ba or 0):8.3f} {(ta or 0):9.3f} {da:>7s} "
              f"{bau:10.3f} {tau:11.3f} {a25:9.3f} {ece:9.3f}")
    if not rows:
        print("(no suite results yet)")


if __name__ == "__main__":
    main()
