"""Fail-first test for imp_eval_cot.py --shuffle-seed: fake vLLM/transformers; each output echoes its prompt's case marker.
Checks: generation order is shuffled for seed>0 and identity for seed 0; per_case stays in file order with the right output."""
import json, os, re, subprocess, sys, tempfile, types
T = tempfile.mkdtemp(prefix="shuf_")
os.makedirs(f"{T}/fake/vllm/lora", exist_ok=True)
open(f"{T}/fake/vllm/__init__.py", "w").write('''
__version__ = "fake"
import json, os
class SamplingParams:
    def __init__(self, **k): self.k = k
class _G:
    def __init__(self, t): self.text, self.token_ids, self.finish_reason, self.logprobs = t, [1], "stop", None
class _O:
    def __init__(self, t): self.outputs = [_G(t)]
class LLM:
    def __init__(self, *a, **k): pass
    def generate(self, prompts, sp=None, lora_request=None):
        import re
        marks = [re.search("CASE([0-9]+)X", p).group(1) for p in prompts]
        open(os.environ["GEN_ORDER"], "w").write(json.dumps(marks))
        return [_O("MARK" + m) for m in marks]
''')
open(f"{T}/fake/vllm/lora/__init__.py", "w").write("")
open(f"{T}/fake/vllm/sampling_params.py", "w").write(chr(10).join(["class _D:", "    def __init__(self, *a, **k): pass", "def __getattr__(name):", "    return _D", ""]))
open(f"{T}/fake/vllm/lora/request.py", "w").write("class LoRARequest:\n    def __init__(self, *a): pass\n")
open(f"{T}/fake/transformers.py", "w").write('''
class PreTrainedTokenizerBase:
    def apply_chat_template(self, msgs, **k): return chr(10).join(m["content"] for m in msgs)
class _Tok:
    def apply_chat_template(self, msgs, **k): return chr(10).join(m["content"] for m in msgs)
class AutoTokenizer:
    @staticmethod
    def from_pretrained(m): return _Tok()
def __getattr__(name):
    return type(name, (), {})
class AutoConfig:
    @staticmethod
    def from_pretrained(m, **k): return type("C", (), {})()
''')
cases = [{"id": f"c{i}", "code": f"int f(void) {{ return {i}; }} /* CASE{i}X */", "label": "VULNERABLE" if i % 2 else "SAFE"} for i in range(20)]
json.dump({"cases": cases, "split": "t"}, open(f"{T}/cases.json", "w"))
ok = True
for seed in (0, 3):
    env = dict(os.environ, PYTHONPATH=f"{T}/fake:src:scripts", GEN_ORDER=f"{T}/order{seed}.json")
    r = subprocess.run([sys.executable, "scripts/imp_eval_cot.py", "--model", "fake/none", "--cases-file", f"{T}/cases.json",
                        "--out", f"{T}/out{seed}.json"] + (["--shuffle-seed", str(seed)] if seed else []), capture_output=True, text=True, env=env)
    if r.returncode:
        print("run failed", seed, r.stderr[-1500:]); ok = False; continue
    order = json.load(open(f"{T}/order{seed}.json"))
    d = json.load(open(f"{T}/out{seed}.json"))
    same_order = order == [str(i) for i in range(20)]
    mapped = all(p["id"] == f"c{i}" and p["raw"] == f"MARK{i}" for i, p in enumerate(d["per_case"]))
    want_shuffled = seed > 0
    res = mapped and (same_order != want_shuffled) and d.get("shuffle_seed") == seed
    print(f"seed {seed}: generation order {'shuffled' if not same_order else 'file'}; per_case mapped back {mapped}; recorded {d.get('shuffle_seed')} -> {'PASS' if res else 'FAIL'}")
    ok &= res
print("ALL PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
