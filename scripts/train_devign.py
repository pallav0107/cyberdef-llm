"""QLoRA fine-tune on a registered benchmark's TRAIN split (Devign or PrimeVul via --dataset),
leakage-deduped vs val/test. Teacher-free: targets are the dataset's ground-truth labels.
Lower LR + weight decay + modest epochs so real (non-separable) data does not collapse to a
memorised ~1e-5 loss. Trains + prints an in-process validation sanity; the headline
baseline-vs-tuned comparison is run separately by extbench.py / selective_eval.py on TEST."""
from __future__ import annotations
import argparse
import torch
from transformers import AutoTokenizer, TrainingArguments, Trainer, DataCollatorForSeq2Seq
from datasets import Dataset
import sys
sys.path.insert(0, "src")
from cyberdef.evaluate import SYSTEM, make_user, parse_pred
from cyberdef.train import load_model, _ids
from cyberdef import model_io, benchdata


def target(label: str) -> str:
    return f"VERDICT: {label}"


def build_examples(tok, items):
    feats = []
    for it in items:
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": make_user(it["code"])}]
        prompt_ids = _ids(tok.apply_chat_template(msgs, add_generation_prompt=True, return_dict=False))
        full = msgs + [{"role": "assistant", "content": target(it["label"])}]
        full_ids = _ids(tok.apply_chat_template(full, add_generation_prompt=False, return_dict=False))
        labels = [-100] * len(prompt_ids) + full_ids[len(prompt_ids):]
        feats.append({"input_ids": full_ids, "attention_mask": [1] * len(full_ids), "labels": labels})
    return Dataset.from_list(feats)


def val_sanity(model, tok, dataset, n_per_class, seed, max_chars):
    cases, _ = benchdata.balanced_sample(dataset, "validation", n_per_class, seed, max_chars)
    model.eval()
    correct = 0
    for c in cases:
        raw = model_io.generate(model, tok, SYSTEM, make_user(c["code"]))
        correct += int(parse_pred(raw) == c["label"])
    print(f"[val-sanity] {dataset} tuned val acc={round(correct/len(cases),4)} (n={len(cases)})", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--out", required=True)
    ap.add_argument("--dataset", default="devign", choices=list(benchdata.BENCHES))
    ap.add_argument("--n-per-class", type=int, default=1000)
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-chars", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--val-per-class", type=int, default=100)
    a = ap.parse_args()
    torch.manual_seed(a.seed)

    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    items, stats = benchdata.train_items(a.dataset, a.n_per_class, a.seed, a.max_chars)
    print(f"[data] dataset={a.dataset} items={len(items)} {stats}", flush=True)
    ds = build_examples(tok, items)

    model, mode = load_model(a.base)
    from peft import LoraConfig, get_peft_model
    lc = LoraConfig(r=a.lora_r, lora_alpha=a.lora_alpha, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
                    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                    "gate_proj", "up_proj", "down_proj"])
    model = get_peft_model(model, lc)
    model.print_trainable_parameters()

    args = TrainingArguments(
        output_dir=a.out + "_ckpt",
        per_device_train_batch_size=1, gradient_accumulation_steps=8,
        num_train_epochs=a.epochs, learning_rate=a.lr, weight_decay=0.01,
        lr_scheduler_type="cosine", warmup_steps=15,
        bf16=True, logging_steps=10, save_strategy="no", report_to=[], seed=a.seed,
        optim=("paged_adamw_8bit" if mode == "4bit" else "adamw_torch"))
    coll = DataCollatorForSeq2Seq(tok, label_pad_token_id=-100)
    tr = Trainer(model=model, args=args, train_dataset=ds, data_collator=coll)
    tr.train()
    model.save_pretrained(a.out)
    tok.save_pretrained(a.out)
    print(f"[train] saved adapter -> {a.out} (dataset={a.dataset}, mode={mode}, "
          f"n_train={len(items)}, epochs={a.epochs}, lr={a.lr})", flush=True)
    val_sanity(model, tok, a.dataset, a.val_per_class, a.seed, a.max_chars)


if __name__ == "__main__":
    main()
