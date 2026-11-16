"""Batched greedy generation with vLLM (bf16, temperature 0, optional LoRA adapter). One engine for ALL generation arms
(Stage C, C-SC, CASTLE witnesses) so the engine is constant across comparisons. Returns [(text, n_tokens, finish_reason)]."""
import vllm
from vllm import LLM, SamplingParams
from vllm.lora.request import LoRARequest
from transformers import AutoTokenizer

ENGINE = f"vllm {vllm.__version__} bf16 temp=0 enable_lora max_model_len=8192"


def generate_all(model, adapter, system, users, max_tokens, gpu_util=None, schema=None):
    import os
    if gpu_util is None:    # cap our footprint: MEM_GB / total unified memory (default 28 GB), never vLLM's 0.9 default
        tot = [int(l.split()[1]) for l in open("/proc/meminfo") if l.startswith("MemTotal")][0] / 1048576
        gpu_util = round(min(0.5, float(os.environ.get("VLLM_MEM_GB", 28)) / tot), 3)
    tok = AutoTokenizer.from_pretrained(model)
    prompts = [tok.apply_chat_template([{"role": "system", "content": system}, {"role": "user", "content": u}],
                                       add_generation_prompt=True, tokenize=False) for u in users]
    llm = LLM(model, dtype="bfloat16", enable_lora=adapter is not None, max_lora_rank=16, max_model_len=8192,
              gpu_memory_utilization=gpu_util, enforce_eager=True)
    lr = LoRARequest("a", 1, adapter) if adapter else None
    kw = {}
    if schema is not None:      # guided JSON decoding against the exact output schema
        from vllm.sampling_params import StructuredOutputsParams
        kw["structured_outputs"] = StructuredOutputsParams(json=schema)
    outs = llm.generate(prompts, SamplingParams(temperature=0, max_tokens=max_tokens, **kw), lora_request=lr)
    return [(o.outputs[0].text, len(o.outputs[0].token_ids), o.outputs[0].finish_reason) for o in outs]


def decode_config(schema, max_tokens):
    """recorded in every cache row"""
    from cyberdef.schemas_cot import schema_hash
    return {"engine": ENGINE, "guided": "json" if schema is not None else "none",
            "schema_hash": schema_hash(schema) if schema is not None else None, "max_tokens": max_tokens, "temperature": 0}
