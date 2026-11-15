#!/usr/bin/env python3
"""Standing fail-first control for the guided-decoding grammar of the SC-CoT schema (the v2.1/v2.2 bug fixed in v2.3).

Compiles the LIVE schema with xgrammar (the vLLM structured-output default) and checks, model-free:
  real    : witness.values accepts a concrete witness ({"stdin": "x; echo CANARY"}, {"copy_bytes": 40, ...}) and still
            rejects malformed ones (values not an object, missing how_to_feed); the Stage C witness accepts a concrete one.
  mutant  : the same schema with the v2.3 fix stripped (no additionalProperties on values) must REJECT concrete witnesses,
            proving this control can detect the bug and is not passing vacuously.
Exit 1 if any expectation fails. Run inside cyberdef-train:aarch64 from the repo root:  python3 scripts/ci_schema_control.py"""
import copy, json, sys
sys.path.insert(0, "src")
import xgrammar as xgr
from transformers import AutoTokenizer
from cyberdef import schemas_cot as S
from cyberdef.imp_sc_schema import SCHEMA, SCHEMA_SHA

compiler = xgr.GrammarCompiler(xgr.TokenizerInfo.from_huggingface(AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")))


def witness_obj(schema):
    hits = []

    def walk(n):
        if isinstance(n, dict):
            p = n.get("properties")
            if isinstance(p, dict) and "witness" in p:
                hits.append(p["witness"])
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)
    walk(schema)
    for w in hits:
        for c in w.get("anyOf", [w]):
            if isinstance(c, dict) and c.get("type") == "object":
                return c
    raise SystemExit("witness object not found in schema")


def acc(schema, inst):
    return bool(xgr.GrammarMatcher(compiler.compile_json_schema(json.dumps(schema))).accept_string(json.dumps(inst)))


CONCRETE = [{"values": {"stdin": "x; echo CANARY"}, "state": [], "how_to_feed": "stdin"},
            {"values": {"copy_bytes": 40, "buffer_bytes": 10}, "state": [{"line": 3, "note": "n"}], "how_to_feed": "argv"}]
MALFORMED = [{"values": "x", "state": [], "how_to_feed": "stdin"}, {"values": {"a": 1}, "state": []}]

live = witness_obj(SCHEMA)
mutant = copy.deepcopy(live)
mutant["properties"]["values"].pop("additionalProperties", None)
stage_c = witness_obj(S.WITNESS)

checks = [
    ("live schema accepts concrete witnesses", all(acc(live, i) for i in CONCRETE)),
    ("live schema rejects malformed witnesses", not any(acc(live, i) for i in MALFORMED)),
    ("mutant (fix stripped) REJECTS concrete witnesses - the control can fail", not any(acc(mutant, i) for i in CONCRETE)),
    ("Stage C witness schema accepts a concrete witness", acc(stage_c, {"values": {"stdin": "AAAA"}, "how_to_feed": "stdin"})),
]
print("SC-CoT schema hash:", SCHEMA_SHA, "| values node:", json.dumps(live["properties"]["values"]))
for name, ok in checks:
    print(("OK   " if ok else "FAIL ") + name)
sys.exit(0 if all(ok for _, ok in checks) else 1)
