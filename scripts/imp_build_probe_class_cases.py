"""Class-probe case set: CLEANED Juliet (pools J, J2) VULNERABLE functions with their monitor class (train side) + CASTLE vulnerable programs (held-out test side, class from the CASTLE id CWE).
Monitor class = pipeline CWE_ORACLE of the true CWE (asan / integer / lsan / tsan / resource / cmd_injection / path_traversal / sqli / format_string / none); CWE 23/36 are folded to 22.
Writes results/imp_probe_class_cases.json.  python3 scripts/imp_build_probe_class_cases.py"""
import json, sys
sys.path.insert(0, "src")
from cyberdef.cwe_oracle import CWE_ORACLE

cases = []
for f, src in (("imp_train_juliet_items.json", "juliet"), ("imp_train_juliet2_items.json", "juliet2")):
    for it in json.load(open("results/" + f))["items"]:
        if it["label"] != "VULNERABLE":
            continue
        cw = int(it["cwe"].replace("CWE", ""))
        cw = {23: 22, 36: 22}.get(cw, cw)
        if cw in CWE_ORACLE:
            cases.append({"id": it["id"], "label": "VULNERABLE", "code": it["code"], "code_chars": it["code_chars"], "cwe": cw, "oracle_class": CWE_ORACLE[cw], "source": src, "group": it["pair"]})
for c in json.load(open("results/xdata_castle_cases.json"))["cases"]:
    if c["label"] != "VULNERABLE":
        continue
    cw = int(c["id"].split("-")[1])
    if cw in CWE_ORACLE:
        cases.append({"id": c["id"], "label": "VULNERABLE", "code": c["code"], "code_chars": c["code_chars"], "cwe": cw, "oracle_class": CWE_ORACLE[cw], "source": "castle", "group": "castle-%d" % cw})
json.dump({"cases": cases, "note": "Juliet = train side of the class probe, CASTLE = held-out test (never trained on)"}, open("results/imp_probe_class_cases.json", "w"))
import collections
print(len(cases), collections.Counter((c["source"], c["oracle_class"]) for c in cases))
