"""Smoke test for guided JSON decoding (both schemas) on 6 matched cases: output must parse and contain the schema's required keys."""
import json, sys
sys.path.insert(0, "scripts"); sys.path.insert(0, "src")
from cyberdef import vllm_gen
from cyberdef.schemas_cot import SCHEMAS
from reason_C_witness import SYSTEM as SYS_C, numbered, subset
from cyberdef import sc_cot
cases = subset()[:6]
B = "Qwen/Qwen2.5-7B-Instruct"
ok = True
for name, system, sch in (("witness", SYS_C, SCHEMAS["witness"]), ("sc", sc_cot.SYSTEM, SCHEMAS["sc"])):
    outs = vllm_gen.generate_all(B, None, system, [numbered(c["code"]) for c in cases], 4096, schema=sch)
    parsed = 0
    for t, nt, fin in outs:
        try:
            d = json.loads(t); req = sch.get("required") or sch["anyOf"][0]["required"]; parsed += all(k in d for k in req)
        except Exception:
            pass
    print(f"[smoke {name}] parsed+required {parsed}/{len(outs)} tokens {[o[1] for o in outs]} finish {[o[2] for o in outs]}", flush=True)
    print(vllm_gen.decode_config(sch, 4096), flush=True)
    ok &= parsed == len(outs)
sys.exit(0 if ok else 1)
