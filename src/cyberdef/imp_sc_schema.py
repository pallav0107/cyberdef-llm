"""Thin wrapper: the SC-CoT JSON schema and its hash come from the pipeline's src/cyberdef/schemas_cot.py (imported read-only, so bank traces, C2 and C-SC share one schema),
and the guided path is the same vLLM StructuredOutputsParams(json=...) used by vllm_gen.generate_all, but with caller-supplied sampling params (bank: T=0.7, top_p, n=K)."""
from __future__ import annotations
from cyberdef.schemas_cot import SC as SCHEMA, schema_hash

SCHEMA_SHA = schema_hash(SCHEMA)
MAX_NEW_TOKENS = 4096


def sampling_params(vllm, guided=True, **kw):
    from vllm import SamplingParams
    if not guided:
        return SamplingParams(**kw)
    from vllm.sampling_params import StructuredOutputsParams       # raises if unavailable: never silently decode free-form while recording guided=json
    return SamplingParams(structured_outputs=StructuredOutputsParams(json=SCHEMA), **kw)


def config_row(guided, max_tokens, temperature, top_p, engine, generator):
    """same keys as vllm_gen.decode_config (+ top_p, generator)"""
    return {"engine": engine, "guided": "json" if guided else "none", "schema_hash": SCHEMA_SHA if guided else None, "max_tokens": max_tokens,
            "temperature": temperature, "top_p": top_p, "generator": generator}
