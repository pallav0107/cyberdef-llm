"""Schema v2.2 format-consistency acceptance (written BEFORE the schema change). Needs jsonschema (sast venv). Run from repo root: PYTHONPATH=src ~/venvs/sast/bin/python check_schema.py
The SC-CoT schema must make the format self-consistent: static_evidence non-null ONLY when oracle == none (then witness null); otherwise witness object and static_evidence null.
 pass-cases: valid non-none trace; valid none trace.   reject-cases (schema level): non-none + static_evidence object; none + witness object; none without static_evidence;
 non-none with witness null.  No content criterion lives in the schema, so a wrong class / wrong oracle for its class still PASSES the schema (the validator catches it)."""
import copy, json, sys
sys.path.insert(0, "src")
import jsonschema
from cyberdef.schemas_cot import SCHEMAS
from cyberdef import sc_cot as S
sch = SCHEMAS["sc"]
good = copy.deepcopy(S.GOOD); none = copy.deepcopy(S.NONE)
def ok(d):
    try:
        jsonschema.validate(d, sch); return True
    except jsonschema.ValidationError:
        return False
r = {"valid_nonnone_passes": ok(good), "valid_none_passes": ok(none)}
b = copy.deepcopy(good); b["static_evidence"] = {"line": 1, "snippet": "x"}; r["nonnone_with_static_evidence_rejected"] = not ok(b)
b = copy.deepcopy(none); b["witness"] = {"values": {"a": 1}, "state": [], "how_to_feed": "stdin"}; r["none_with_witness_rejected"] = not ok(b)
b = copy.deepcopy(none); b["static_evidence"] = None; r["none_without_static_evidence_rejected"] = not ok(b)
b = copy.deepcopy(good); b["witness"] = None; r["nonnone_without_witness_rejected"] = not ok(b)
b = copy.deepcopy(good); b["vuln_class"] = {"cwe": 22, "owasp": "A01 Broken Access Control"}; r["wrong_class_still_passes_schema_content_not_in_schema"] = ok(b)
bad = [k for k, v in r.items() if v is not True]
print(json.dumps(r)); print("PASS" if not bad else "FAIL: " + str(bad)); sys.exit(0 if not bad else 1)
