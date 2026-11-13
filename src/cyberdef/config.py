"""Central config. No secrets here."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Student = the model we fine-tune (Apache-2.0, distillation-permitted).
STUDENT_DEFAULT = "Qwen/Qwen2.5-7B-Instruct"
# Teacher (LATER increment, on the Spark): Qwen2.5-72B-Instruct (Apache-2.0).
# HARD RULE: teachers must be open-weight & distillation-permitted. Never use
# outputs of a commercial API (OpenAI/Anthropic/Claude/Kimi/Gemini) as training data.
TEACHER_DEFAULT = "Qwen/Qwen2.5-72B-Instruct"

SEED = 0


@dataclass
class Config:
    student: str = STUDENT_DEFAULT
    teacher: str = TEACHER_DEFAULT
    seed: int = SEED
    results_dir: Path = field(default_factory=lambda: ROOT / "results")
    out_dir: Path = field(default_factory=lambda: ROOT / "out")

    def ensure_dirs(self) -> None:
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
