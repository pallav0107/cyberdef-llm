"""QLoRA SFT of the student on the vuln_detect TRAIN split (disjoint from the test
benchmark). Teacher-free for this increment: the training targets are the ground-truth
labels of the synthetic-by-construction dataset. Open-weight student only."""
from __future__ import annotations
import argparse
import torch
from transformers import (AutoModelForCausalLM, AutoTokenizer, TrainingArguments,
                          Trainer, DataCollatorForSeq2Seq)
from datasets import Dataset
from .config import STUDENT_DEFAULT, SEED
from .data import build_dataset
from .evaluate import SYSTEM, make_user


def target(label: str, cwe: str) -> str:
    return f"VERDICT: {label}" + (f"\nCWE: {cwe}" if label == "VULNERABLE" else "")


def _ids(x):  # transformers 5.x may return a BatchEncoding; coerce to list[int]
    return x["input_ids"] if hasattr(x, "keys") else x


def build_examples(tok, items):
    feats = []
    for it in items:
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": make_user(it["code"])}]
        prompt_ids = _ids(tok.apply_chat_template(msgs, add_generation_prompt=True, return_dict=False))
        full = msgs + [{"role": "assistant", "content": target(it["label"], it["cwe"])}]
        full_ids = _ids(tok.apply_chat_template(full, add_generation_prompt=False, return_dict=False))
        labels = [-100] * len(prompt_ids) + full_ids[len(prompt_ids):]
        feats.append({"input_ids": full_ids, "attention_mask": [1] * len(full_ids),
                      "labels": labels})
    return Dataset.from_list(feats)


def load_model(model_id):
    try:
        from transformers import BitsAndBytesConfig
        from peft import prepare_model_for_kbit_training
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                 bnb_4bit_compute_dtype=torch.bfloat16,
                                 bnb_4bit_use_double_quant=True)
        m = AutoModelForCausalLM.from_pretrained(model_id, quantization_config=bnb,
                                                 device_map="auto", dtype=torch.bfloat16)
        m = prepare_model_for_kbit_training(m)
        return m, "4bit"
    except Exception as e:  # Blackwell bnb issues -> fall back to bf16 LoRA
        print(f"[train] 4-bit unavailable ({e}); using bf16 LoRA")
        m = AutoModelForCausalLM.from_pretrained(model_id, device_map="auto",
                                                 dtype=torch.bfloat16)
        return m, "bf16"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=STUDENT_DEFAULT)
    ap.add_argument("--out", required=True)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--epochs", type=float, default=3.0)
    a = ap.parse_args()
    torch.manual_seed(SEED)

    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    train = build_dataset(SEED)["train"]
    if a.smoke:
        train = train[:16]
    ds = build_examples(tok, train)

    model, mode = load_model(a.base)
    from peft import LoraConfig, get_peft_model
    lc = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
                    task_type="CAUSAL_LM",
                    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                    "gate_proj", "up_proj", "down_proj"])
    model = get_peft_model(model, lc)
    model.print_trainable_parameters()

    args = TrainingArguments(
        output_dir=a.out + "_ckpt",
        per_device_train_batch_size=1, gradient_accumulation_steps=8,
        num_train_epochs=(1 if a.smoke else a.epochs),
        max_steps=(2 if a.smoke else -1),
        learning_rate=2e-4, bf16=True, logging_steps=5, save_strategy="no",
        report_to=[], seed=SEED,
        optim=("paged_adamw_8bit" if mode == "4bit" else "adamw_torch"))
    coll = DataCollatorForSeq2Seq(tok, label_pad_token_id=-100)
    tr = Trainer(model=model, args=args, train_dataset=ds, data_collator=coll)
    tr.train()
    model.save_pretrained(a.out)
    tok.save_pretrained(a.out)
    print(f"[train] saved adapter -> {a.out} (mode={mode}, n_train={len(train)}, smoke={a.smoke})")


if __name__ == "__main__":
    main()
