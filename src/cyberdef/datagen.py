"""Teacher data generation (LATER increments).

HARD RULE: the teacher must be an OPEN-WEIGHT, distillation-permitted model
(e.g. Qwen2.5-72B-Instruct, Apache-2.0) run from its weights — on the Spark or an
open-weight cloud host. NEVER use outputs of a CLOSED commercial API
(OpenAI / Anthropic / Claude / Kimi / Gemini / qwen-max|plus|turbo DashScope tiers)
as training data: their terms forbid training competing models and it would taint the
evidence. Apache-2.0 open weights carry no such restriction wherever they run.

Increment 1 needs no teacher: the vuln_detect dataset is ground-truth-by-construction.
"""
from __future__ import annotations


def generate_from_teacher(*_args, **_kwargs):
    raise NotImplementedError(
        "Teacher distillation not wired yet. Use an OPEN-WEIGHT teacher only "
        "(Qwen2.5-72B-Instruct / Apache-2.0). Increment 1 trains teacher-free on "
        "ground-truth-by-construction data."
    )
