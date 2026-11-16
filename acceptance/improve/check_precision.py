"""Fail-first test (568f808 note): imp_eval_cot.py must store p_vuln so that the stored AUROC equals the per_case recompute,
even when probabilities differ only beyond the 6th decimal. A fake vLLM returns verdict-token logprobs with
P(SAFE) ~ 1e-8: unrounded they separate the labels perfectly; rounded to 6 dp they all tie at 1.0."""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, "src")
from cyberdef.imp_common import auroc  # noqa: E402

T = tempfile.mkdtemp(prefix="prec_")
os.makedirs(f"{T}/fake/vllm/lora", exist_ok=True)
open(f"{T}/fake/vllm/__init__.py", "w").write(chr(10).join([
    '__version__ = "fake"',
    "import json, os, re",
    "class SamplingParams:",
    "    def __init__(self, **k): pass",
    "class _LP:",
    "    def __init__(self, t, l): self.decoded_token, self.logprob = t, l",
    "class _G:",
    "    def __init__(self, ls):",
    "        head = chr(123) + chr(34) + 'verdict' + chr(34) + ': ' + chr(34)",
    "        tail = chr(34) + chr(125)",
    "        self.text = head + 'VULNERABLE' + tail",
    "        self.token_ids = [1, 2, 3]",
    "        self.logprobs = [{1: _LP(head, -0.01)}, {2: _LP('VULNERABLE', 0.0), 4: _LP('SAFE', ls)}, {3: _LP(tail, -0.01)}]",
    "        self.finish_reason = 'stop'",
    "class _O:",
    "    def __init__(self, ls): self.outputs = [_G(ls)]",
    "class LLM:",
    "    def __init__(self, *a, **k): pass",
    "    def generate(self, prompts, sp=None, lora_request=None):",
    "        m = json.load(open(os.environ['LS_MAP']))",
    "        return [_O(m[re.search('CASE([0-9]+)X', p).group(1)]) for p in prompts]",
    ""]))
open(f"{T}/fake/vllm/lora/__init__.py", "w").write("")
open(f"{T}/fake/vllm/lora/request.py", "w").write("class LoRARequest:\n    def __init__(self, *a): pass\n")
open(f"{T}/fake/vllm/sampling_params.py", "w").write(chr(10).join(["class _D:", "    def __init__(self, *a, **k): pass", "def __getattr__(name):", "    return _D", ""]))
open(f"{T}/fake/transformers.py", "w").write(chr(10).join([
    "class PreTrainedTokenizerBase:",
    "    def apply_chat_template(self, msgs, **k): return chr(10).join(m['content'] for m in msgs)",
    "class _Tok(PreTrainedTokenizerBase):",
    "    pass",
    "class AutoTokenizer:",
    "    @staticmethod",
    "    def from_pretrained(m): return _Tok()",
    "def __getattr__(name):",
    "    return type(name, (), {})",
    ""]))
cases, lsmap = [], {}
for i in range(40):
    lab = "VULNERABLE" if i < 20 else "SAFE"
    cases.append({"id": f"c{i}", "code": f"int f(void) {{ return {i}; }} /* CASE{i}X */", "label": lab})
    lsmap[str(i)] = (-18.5 - 0.001 * i) if lab == "VULNERABLE" else (-18.0 - 0.001 * i)   # p(V) > p(S), both ~1 - 1e-8
json.dump({"cases": cases, "split": "t"}, open(f"{T}/cases.json", "w"))
json.dump(lsmap, open(f"{T}/ls.json", "w"))
env = dict(os.environ, PYTHONPATH=f"{T}/fake:src:scripts", LS_MAP=f"{T}/ls.json")
r = subprocess.run([sys.executable, "scripts/imp_eval_cot.py", "--model", "fake/none", "--cases-file", f"{T}/cases.json", "--out", f"{T}/out.json"],
                   capture_output=True, text=True, env=env)
if r.returncode:
    print("FAIL scorer did not run:", r.stderr[-800:])
    sys.exit(1)
d = json.load(open(f"{T}/out.json"))
pc = d["per_case"]
rec = auroc([p["p_vuln"] for p in pc], [1 if p["label"] == "VULNERABLE" else 0 for p in pc])
ok = abs(rec - d["auroc"]) < 1e-9 and abs(rec - 1.0) < 1e-9
print(f"stored auroc {d['auroc']}, per_case recompute {rec:.4f} -> {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
