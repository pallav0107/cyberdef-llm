"""Every cyberdef prompt is built WITHOUT the model's thinking mode.

Thinking-capable chat templates (Qwen3.x, including Qwen3.8) open a `<think>` block at the end of the generation prompt
unless `enable_thinking=False` is passed. That would silently corrupt three things this pipeline depends on:
  - verdict-token scoring (imp_selective reads the verdict probability at the first generated position),
  - guided-JSON trace generation and SC-CoT evaluation (the JSON would start inside an open think block),
  - training text (the supervised target would follow a think marker the scorer never sees).

Importing `cyberdef` makes `enable_thinking=False` the default of `apply_chat_template` for every tokenizer. A caller can
still pass it explicitly. Templates that never read the variable (Qwen2.5 and earlier) render byte-identically; this is
checked for the Qwen2.5 tokenizers before the change is used.
"""
from __future__ import annotations

try:
    from transformers import PreTrainedTokenizerBase
except ImportError:          # cyberdef modules that do not need transformers still import cleanly
    PreTrainedTokenizerBase = None

if PreTrainedTokenizerBase is not None and not getattr(PreTrainedTokenizerBase.apply_chat_template, "_cyberdef_no_think", False):
    _original = PreTrainedTokenizerBase.apply_chat_template

    def _apply_chat_template_no_think(self, *args, **kwargs):
        kwargs.setdefault("enable_thinking", False)
        return _original(self, *args, **kwargs)

    _apply_chat_template_no_think._cyberdef_no_think = True
    _apply_chat_template_no_think.__doc__ = (_original.__doc__ or "") + "\n\n[cyberdef] enable_thinking defaults to False."
    PreTrainedTokenizerBase.apply_chat_template = _apply_chat_template_no_think
