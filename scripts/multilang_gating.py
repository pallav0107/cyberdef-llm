"""Apply the pre-registered activation bar (EXPERIMENT_PLAN_MULTILANG.md + stricter amendment) EXACTLY.
Per language ENABLED iff ALL of:
  (1) tuned AUROC - base AUROC > 2 * SE(difference)
  (2) tuned AUROC >= 0.65
  (3) tuned AUROC > length-only baseline AUROC on the same test cases
SE method: Hanley-McNeil (1982) SE for each AUROC, combined as sqrt(se_base^2 + se_tuned^2). This
ignores the positive correlation between the two paired AUROCs (same cases), so the SE is larger
than a paired (DeLong) SE and the test is conservative. AUROCs are recomputed from per_case
p_vuln, not read from the summary. OWASP is reported separately and never enables a language.
Usage: multilang_gating.py RESULTS_DIR OUT.json"""
import json
import sys
from pathlib import Path
sys.path.insert(0, "scripts")
from length_baseline import auroc, hanley_mcneil_se

R, OUT = Path(sys.argv[1]), sys.argv[2]


def recompute(f):
    pc = json.loads(Path(f).read_text())["per_case"]
    lab = [1 if p["label"] == "VULNERABLE" else 0 for p in pc]
    return auroc([p["p_vuln"] for p in pc], lab), sum(lab), len(lab) - sum(lab)


def row(tag, enable_allowed):
    ab, n1, n0 = recompute(R / f"{tag}_base.json")
    at, n1t, n0t = recompute(R / f"{tag}_tuned.json")
    assert (n1, n0) == (n1t, n0t), "base/tuned case sets differ"
    lb = json.loads((R / f"{tag}_length.json").read_text())
    sd = (hanley_mcneil_se(ab, n1, n0) ** 2 + hanley_mcneil_se(at, n1, n0) ** 2) ** 0.5
    diff = at - ab
    c1, c2, c3 = diff > 2 * sd, at >= 0.65, at > lb["auroc"]
    return {"n_vuln": n1, "n_safe": n0, "auroc_base": round(ab, 4), "auroc_tuned": round(at, 4),
            "diff": round(diff, 4), "se_diff": round(sd, 4), "two_se": round(2 * sd, 4),
            "length_baseline_auroc": lb["auroc"],
            "c1_beats_base_by_2se": bool(c1), "c2_tuned_ge_0.65": bool(c2), "c3_tuned_gt_length": bool(c3),
            "enabled": bool(c1 and c2 and c3) if enable_allowed else False}


res = {"bar": "enabled iff (tuned-base) > 2*SE(diff) AND tuned >= 0.65 AND tuned > length-only AUROC; "
              "OWASP reported separately, never enables a language",
       "se_method": "Hanley-McNeil per AUROC, combined sqrt(se_base^2+se_tuned^2); ignores paired "
                    "correlation so it is conservative (larger than a DeLong paired SE)",
       "languages": {}, "owasp_java_independent": None}
for lang in ("java", "python", "js"):
    res["languages"][lang] = row(f"ml_sel_{lang}", True)
o = row("owasp_sel", False)
o["note"] = "independent distribution-shifted set; reported only, does not enable"
o.pop("enabled")
res["owasp_java_independent"] = o
Path(OUT).write_text(json.dumps(res, indent=2))
for k, v in res["languages"].items():
    print(f"[gating] {k}: base={v['auroc_base']} tuned={v['auroc_tuned']} diff={v['diff']} 2se={v['two_se']} "
          f"len={v['length_baseline_auroc']} -> {'ENABLED' if v['enabled'] else 'disabled'}")
print(f"[gating] owasp: base={o['auroc_base']} tuned={o['auroc_tuned']} len={o['length_baseline_auroc']}")
