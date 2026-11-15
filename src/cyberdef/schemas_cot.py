"""JSON schemas for guided (structured-output) decoding. WITNESS = the Stage C witness prompt schema; SC = Secure-Code CoT."""
import hashlib, json
from cyberdef.cwe_oracle import ALLOWED_CWES, OWASP, ORACLES

_int = {"type": "integer"}
_str = {"type": "string"}
_wit = {"anyOf": [{"type": "object"}, {"type": "null"}]}
WITNESS = {"type": "object", "additionalProperties": False,
           "properties": {"inputs": {"type": "array", "items": _str},
                          "sinks": {"type": "array", "items": {"type": "object", "properties": {"line": _int, "op": _str}, "required": ["line", "op"]}},
                          "guards": {"type": "array", "items": {"type": "object", "properties": {"line": _int, "condition": _str}, "required": ["line", "condition"]}},
                          "trace": {"type": "array", "items": {"type": "object", "properties": {"line": _int, "state": _str}, "required": ["line", "state"]}},
                          "witness": _wit,
                          "verdict": {"enum": ["VULNERABLE", "SAFE"]},
                          "confidence": {"type": "number"}},
           "required": ["inputs", "sinks", "guards", "trace", "witness", "verdict", "confidence"]}
# schema v2.3 (BUG FIX, 2026-11-15): witness.values is an object with no declared properties. Once v2.1 added maxProperties,
# xgrammar strict mode (the vLLM structured-output default) treated its missing additionalProperties as false, so guided decoding
# could only ever emit "values": {} and every VULNERABLE trace failed the concrete-witness check. Stating additionalProperties
# explicitly (the JSON Schema default the author intended) restores it. No validator criterion changes.
# Proof (fail-first, model-free): scripts/ci_schema_control.py
SC = {"type": "object", "additionalProperties": False,
      "properties": {"contract": {"type": "object", "properties": {"summary": _str}, "required": ["summary"]},
                     "trust_boundary": {"type": "object", "properties": {"attacker_controlled": {"type": "array", "items": _str},
                                                                           "trusted": {"type": "array", "items": _str},
                                                                           "assumptions": {"type": "array", "items": _str}},
                                        "required": ["attacker_controlled", "trusted", "assumptions"]},
                     "sinks": {"type": "array", "items": {"type": "object", "properties": {"id": _str, "line": _int, "op": _str, "cwe": _str},
                                                          "required": ["id", "line", "op", "cwe"]}},
                     "dataflow": {"type": "array", "items": {"type": "object", "properties": {"sink": _str, "lines": {"type": "array", "items": _int}, "transforms": _str},
                                                             "required": ["sink", "lines", "transforms"]}},
                     "guard_audit": {"type": "array", "items": {"type": "object", "properties": {"sink": _str, "guards": {"type": "array", "items": {
                         "type": "object", "properties": {"line": _int, "condition": _str, "sufficient": {"type": "boolean"}, "issues": {"type": "array", "items": _str}},
                         "required": ["line", "condition", "sufficient", "issues"]}}}, "required": ["sink", "guards"]}},
                     "vuln_class": {"type": "object", "properties": {"cwe": {"enum": ALLOWED_CWES}, "owasp": {"enum": OWASP}}, "required": ["cwe", "owasp"]},
                     "oracle": {"enum": ORACLES},
                     "paths": {"type": "array", "items": {"type": "object", "properties": {"description": _str, "lines": {"type": "array", "items": _int}},
                                                          "required": ["description", "lines"]}},
                     "witness": {"anyOf": [{"type": "object", "properties": {"values": {"type": "object", "additionalProperties": True}, "state": {"type": "array", "items": {
                         "type": "object", "properties": {"line": _int, "note": _str}, "required": ["line", "note"]}}, "how_to_feed": _str},
                                            "required": ["values", "state", "how_to_feed"]}, {"type": "null"}]},
                     "static_evidence": {"anyOf": [{"type": "object", "properties": {"line": _int, "snippet": _str}, "required": ["line", "snippet"]}, {"type": "null"}]},
                     "refutation": {"type": "object", "properties": {"attempts": {"type": "array", "items": _str}, "assumptions": {"type": "array", "items": _str}},
                                    "required": ["attempts", "assumptions"]},
                     "verdict": {"enum": ["VULNERABLE", "SAFE", "UNCERTAIN"]}, "cwe": _str, "confidence": {"type": "number"},
                     "length_independence": _str,
                     "fix": {"type": "object", "properties": {"patch": _str, "why": _str}}},
      "required": ["contract", "trust_boundary", "sinks", "dataflow", "guard_audit", "vuln_class", "oracle", "paths", "witness", "static_evidence",
                   "refutation", "verdict", "cwe", "confidence", "length_independence"]}


def _bound(node, key=None):
    """schema v2.1: bound free-text strings (maxLength) and arrays (maxItems) / objects (maxProperties) so a degenerate generation cannot run away.
    Applied to the SC-CoT schema ONLY; the Stage C witness schema is unchanged."""
    if isinstance(node, dict):
        out = {k: _bound(v, k) for k, v in node.items()}
        if node.get("type") == "string":
            out["maxLength"] = 800 if key == "patch" else 240
        if node.get("type") == "array":
            out["maxItems"] = 12
        if key == "values" and node.get("type") == "object":
            out["maxProperties"] = 8
        return out
    if isinstance(node, list):
        return [_bound(x) for x in node]
    return node


# schema v2.2 (format-consistency BUG FIX): static_evidence/witness are CONDITIONAL on the oracle, expressed as two branches, so guided decoding can no longer
# fill static_evidence when oracle != none. No content criterion is in the schema (class/oracle correctness, lines, sinks stay validator checks).
_wit_obj = SC["properties"]["witness"]["anyOf"][0]
_se_obj = SC["properties"]["static_evidence"]["anyOf"][0]


def _branch(none):
    props = dict(SC["properties"])
    if none:
        props["oracle"] = {"enum": ["none"]}
        props["witness"] = {"type": "null"}
        props["static_evidence"] = _se_obj
    else:
        props["oracle"] = {"enum": [o for o in ORACLES if o != "none"]}
        props["witness"] = _wit_obj
        props["static_evidence"] = {"type": "null"}
    return {"type": "object", "additionalProperties": False, "properties": props, "required": SC["required"]}


SC = {"anyOf": [_branch(False), _branch(True)]}
SC = _bound(SC)
SCHEMAS = {"witness": WITNESS, "sc": SC}


def schema_hash(s):
    return hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()[:16]
