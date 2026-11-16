"""Acceptance for imp_train.py verdict-slot logic (CPU, tokenizer only). Run from repo root with CUDA_VISIBLE_DEVICES="" .venv/bin/python.
 T1 verdict-only target: the slot token decodes to something containing VULN (for VULNERABLE) / SAFE; alternatives are the other class
 T2 JSON trace target: same property, and the token at label index vdiv in the built example IS that slot token
 T3 a target with no verdict gives vdiv == -1 (no ranking, no crash)
 T4 the slot index shifts correctly when the trace body before the verdict changes length"""
import importlib.util, json, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from transformers import AutoTokenizer

spec = importlib.util.spec_from_file_location("imp_train", "scripts/imp_train.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")
fails = []
for lab in ("VULNERABLE", "SAFE"):
    vd, tv, ts = m.verdict_slot(tok, "VERDICT: " + lab)
    dv, ds_ = tok.decode([tv]), tok.decode([ts])
    if vd < 0 or not "VULNERABLE".startswith(dv.strip().upper()) or not dv.strip() or not "SAFE".startswith(ds_.strip().upper()) or not ds_.strip():   # BPE may split VULNERABLE as ' V'+'ULNERABLE'
        fails.append(f"T1 {lab}: slot {vd} {dv!r} {ds_!r}")
    if False:
        fails.append(f"T1 {lab}: slot {vd} {dv!r} {ds_!r}")
short = json.dumps({"a": [1], "verdict": "SAFE", "cwe": ""}, indent=1)
longer = json.dumps({"a": [1] * 40, "verdict": "VULNERABLE", "cwe": "CWE-787"}, indent=1)
s1, s2 = m.verdict_slot(tok, short), m.verdict_slot(tok, longer)
if s1[0] < 0 or s2[0] <= s1[0]:
    fails.append(f"T4 slots {s1} {s2}")
items = [{"code": "int x;", "label": "SAFE", "target": short}, {"code": "int y;", "label": "VULNERABLE", "target": longer}]
ds = m.build_examples(tok, items)
for k, row in enumerate(ds):
    first = next(i for i, x in enumerate(row["labels"]) if x != -100)
    tid = row["labels"][first + row["vdiv"]]
    want = row["tids"] if k == 0 else row["tidv"]
    if tid != want:
        fails.append(f"T2 item {k}: label token at slot {tid} != expected {want}")
if m.verdict_slot(tok, "no verdict here")[0] != -1:
    fails.append("T3 no-verdict target not -1")
# T5 (regression for BUG A): print_balance must survive an EMPTY quintile / empty class (category-balanced CoT items)
try:
    items5 = [{"code_chars": 100, "toks": 30, "label": "SAFE", "project": "p"} for _ in range(10)] + [{"code_chars": 100, "toks": 30, "label": "VULNERABLE", "project": "p"} for _ in range(2)]
    m.print_balance(items5)
    m.print_balance([{"code_chars": 100, "toks": 30, "label": "SAFE", "project": "p"} for _ in range(6)])      # no VULNERABLE at all
except Exception as e:
    fails.append(f"T5 print_balance crashed on empty quintile/class: {e!r}")
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS: verdict slot logic")
