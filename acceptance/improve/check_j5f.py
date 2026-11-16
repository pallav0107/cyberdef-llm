"""Acceptance check for scripts/imp_build_juliet5f.py -> results/imp_juliet5f_items_all.json: verified multi-file Juliet
CWE-134 pairs (console / environment / file input), disjoint from every CWE-134 case used anywhere else, label text
removed. Exit 0 = every check passed.   python3 acceptance/improve/check_j5f.py"""
import collections
import glob
import json
import os
import re
import sys

sys.path.insert(0, "src")
from cyberdef.imp_clean import leak_hits  # noqa: E402

OUT = "results/imp_juliet5f_items_all.json"
MIN_PAIRS = 300
FAILS = []


def ok(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


def stem(k):
    """case stem: file name without extension and without a multi-file part letter"""
    k = re.sub(r"\.(c|cpp)$", "", os.path.basename(k))
    return re.sub(r"(_\d+)[a-z]$", r"\1", k)


def used_stems():
    out = set()
    for p in glob.glob("results/*.json") + glob.glob("results/before_3m/*.json"):
        if "juliet5f" in p or "j5f" in p:
            continue
        try:
            d = json.load(open(p))
        except Exception:
            continue
        rows = (d.get("items") or d.get("cases") or d.get("pairs") or []) if isinstance(d, dict) else d
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict):
                for f in ("id", "pair"):
                    for m in re.finditer(r"CWE134_[A-Za-z0-9_]+?_\d+[a-z]?(?=\.c|\.cpp|:|$|\b)", str(r.get(f, ""))):
                        out.add(stem(m.group(0)))
    return out


if not os.path.exists(OUT):
    print("FAIL output missing: " + OUT)
    sys.exit(1)
d = json.load(open(OUT))
items = d.get("items", [])
ok("items and stats present", bool(items) and isinstance(d.get("stats"), dict))
idre = re.compile(r"^juliet5:(CWE134_[A-Za-z0-9_]+_\d+):(V|S)$")
ok("ids are juliet5:<case stem>:V|S", all(idre.match(str(i.get("id", ""))) for i in items))
ok("label matches id", all((i["label"] == "VULNERABLE") == i["id"].endswith(":V") for i in items))
ok("feeds console/environment/file only", all(i.get("feed") in ("console", "environment", "file") for i in items))
ok("multi-file parts listed (>= 2 each)", all(isinstance(i.get("parts"), list) and len(i["parts"]) >= 2 for i in items))
ok("juliet_cwe CWE134", all(i.get("juliet_cwe") == "CWE134" for i in items))
ver = ("bad_payload", "bad_benign", "bad_empty", "good_payload")
ok("verification recorded and correct (payload fires bad; benign, empty and good+payload do not)",
   all(i.get("bad_payload") is True and i.get("bad_benign") is False and i.get("bad_empty") is False and i.get("good_payload") is False for i in items))
by = collections.defaultdict(dict)
for i in items:
    by[i["pair"]][i["label"]] = i
ok("every pair has exactly one V and one S", all(set(v) == {"VULNERABLE", "SAFE"} for v in by.values()) and len(items) == 2 * len(by))
ok("V and S texts differ", all(v["VULNERABLE"]["code"] != v["SAFE"]["code"] for v in by.values() if len(v) == 2))
ok("no text over 4000 chars (dropped, not truncated)", all(len(i["code"]) <= 4000 for i in items))
ok("no label text (imp_clean.leak_hits)", all(not leak_hits(i["code"]) for i in items))
us = used_stems()
clash = sorted({stem(i["pair"]) for i in items} & us)
ok(f"disjoint from every CWE-134 case used elsewhere ({len(us)} stems; clashes {clash[:3]})", not clash)
ok(f">= {MIN_PAIRS} verified pairs (got {len(by)})", len(by) >= MIN_PAIRS)
print(f"{len(FAILS)} failed" if FAILS else "ALL PASS")
sys.exit(1 if FAILS else 0)
