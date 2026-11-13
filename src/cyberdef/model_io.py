"""Model loading + generation. HF transformers (student) and an optional Ollama backend."""
from __future__ import annotations
import json
import urllib.request
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


def load_hf(model_id: str, quant4: bool = False, adapter: str | None = None):
    tok = AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    kw = dict(dtype=torch.bfloat16, device_map="auto")
    if quant4:
        from transformers import BitsAndBytesConfig
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(model_id, **kw)
    if adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter)
    model.eval()
    return model, tok


def chat_prompt(tok, system: str, user: str, tensors: bool = False):
    """Build the prompt robustly across model families. Qwen supports a system role;
    Mistral's template rejects it; a base model may have no chat template at all. Try
    system+user, fall back to a merged single user turn, then to plain text. Returns a
    list[int] (tensors=False) or a pt BatchEncoding dict (tensors=True)."""
    def enc(msgs):
        if tensors:
            return tok.apply_chat_template(msgs, add_generation_prompt=True,
                                           return_tensors="pt", return_dict=True)
        x = tok.apply_chat_template(msgs, add_generation_prompt=True, return_dict=False)
        return x["input_ids"] if hasattr(x, "keys") else x
    if getattr(tok, "chat_template", None):
        try:
            return enc([{"role": "system", "content": system},
                        {"role": "user", "content": user}])
        except Exception:
            try:
                return enc([{"role": "user", "content": system + "\n\n" + user}])
            except Exception:
                pass
    text = f"{system}\n\n{user}\n"
    return tok(text, return_tensors="pt") if tensors else tok(text)["input_ids"]


@torch.no_grad()
def generate(model, tok, system: str, user: str, max_new_tokens: int = 96) -> str:
    enc = chat_prompt(tok, system, user, tensors=True)
    enc = {k: v.to(model.device) for k, v in enc.items()}
    out = model.generate(**enc, max_new_tokens=max_new_tokens, do_sample=False,
                         pad_token_id=tok.pad_token_id)
    in_len = enc["input_ids"].shape[1]
    return tok.decode(out[0, in_len:], skip_special_tokens=True)


def ollama_chat(base_url: str, model: str, system: str, user: str, max_new_tokens: int = 96) -> str:
    body = {"model": model, "stream": False, "think": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"num_predict": max_new_tokens, "temperature": 0}}
    req = urllib.request.Request(base_url.rstrip("/") + "/api/chat",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read())["message"]["content"]
