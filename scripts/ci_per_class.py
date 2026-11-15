#!/usr/bin/env python3
"""Per-class AUROC table for a result on CASTLE (classes = bug families from the CASTLE id's CWE) or on the J3 held-out set
(classes = CWE). Markdown to stdout, for the run summary. Each row: class, n, AUROC with Hanley-McNeil SE, and for J3 the
length-only AUROC of that class (length alone scores 0.62 on J3 held-out overall, so it is the number to beat there).
  python3 scripts/ci_per_class.py results/ci_ev_<tag>_castle.json [cases-file]"""
import json, math, re, sys

FAMILY = {78: "injection", 89: "injection", 22: "injection", 23: "injection", 36: "injection", 134: "injection",
          190: "integer", 191: "integer", 369: "integer", 680: "integer", 401: "leak", 362: "race", 366: "race", 367: "race",
          400: "resource", 770: "resource", 835: "resource", 674: "resource"}
MEMORY = {119, 120, 121, 122, 124, 125, 126, 127, 131, 193, 415, 416, 476, 590, 761, 787, 805, 822, 843}


def auroc(s, y):
    pos = [a for a, b in zip(s, y) if b]; neg = [a for a, b in zip(s, y) if not b]
    if not pos or not neg:
        return None, None
    a = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))
    n1, n2 = len(pos), len(neg); q1, q2 = a / (2 - a), 2 * a * a / (1 + a)
    se = math.sqrt(max(0.0, (a * (1 - a) + (n1 - 1) * (q1 - a * a) + (n2 - 1) * (q2 - a * a)) / (n1 * n2)))
    return a, se


def main():
    res = json.load(open(sys.argv[1]))
    per = {p["id"]: p for p in res.get("per_case", []) if "p_vuln" in p}
    key = sys.argv[1].rsplit("_", 1)[-1].replace(".json", "")
    cases_file = sys.argv[2] if len(sys.argv) > 2 else {"castle": "results/xdata_castle_cases.json", "j3h": "results/j3_heldout_cases.json", "j3m": "results/j3_heldout_matched_cases.json", "qh": "results/q_heldout_cases.json", "j4m": "results/j4_heldout_matched_cases.json"}.get(key)
    if not cases_file:
        return
    d = json.load(open(cases_file)); cases = d["cases"] if isinstance(d, dict) else d
    groups = {}
    for c in cases:
        if c["id"] not in per:
            continue
        if key == "castle":
            m = re.search(r"CASTLE-(\d+)-", c["id"]); cwe = int(m.group(1)) if m else -1
            cls = FAMILY.get(cwe, "memory" if cwe in MEMORY else "other")
        else:
            cls = c.get("cwe", "?")
        groups.setdefault(cls, []).append(c)
    print(f"\n#### Per class on {key} (`{sys.argv[1].split('/')[-1]}`)\n")
    head = "| class | n | AUROC ± SE |" + (" length-only |" if key in ("j3h", "j3m", "qh", "j4m") else "")
    print(head)
    print("|---|---|---|" + ("---|" if key in ("j3h", "j3m", "qh", "j4m") else ""))
    for cls, cs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        y = [c["label"] == "VULNERABLE" for c in cs]
        a, se = auroc([per[c["id"]]["p_vuln"] for c in cs], y)
        row = f"| {cls} | {len(cs)} | " + (f"{a:.3f} ± {se:.3f}" if a is not None else "n/a") + " |"
        if key in ("j3h", "j3m", "qh", "j4m"):
            la, _ = auroc([c["code_chars"] for c in cs], y)
            row += f" {max(la, 1 - la):.3f} |" if la is not None else " n/a |"
        print(row)
    print("\nPer-class numbers are hints unless n is large; CASTLE has 6-9 programs per CWE.")


if __name__ == "__main__":
    main()
