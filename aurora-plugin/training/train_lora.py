"""
train_lora.py — fine-tuning LoRA di LLaMA 3.1 per lo scorer BitM (v7.0).

Consuma i file prodotti da build_dataset.py (train.jsonl + val.jsonl in formato
"messages" ChatML) e addestra un adapter LoRA sul base model scelto.

Dipendenze (non incluse in requirements.txt del runtime):
  pip install "transformers>=4.44" "peft>=0.12" "trl>=0.10" \\
              "datasets>=2.20" "accelerate>=0.33" "bitsandbytes>=0.43"

Uso tipico (GPU singola, 8B in 4bit):
  python train_lora.py \\
      --dataset-dir ./dataset \\
      --base-model meta-llama/Meta-Llama-3.1-8B-Instruct \\
      --output-dir ./lora-bitm-v7 \\
      --epochs 3 \\
      --batch-size 2 \\
      --grad-accum 8

Uso CPU / smoke test (modello minuscolo, nessuna quantizzazione):
  python train_lora.py \\
      --dataset-dir ./dataset \\
      --base-model sshleifer/tiny-gpt2 \\
      --output-dir ./smoke \\
      --no-4bit --epochs 1 --batch-size 1 --grad-accum 1
"""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", required=True,
                    help="cartella con train.jsonl e val.jsonl")
    ap.add_argument("--base-model", required=True,
                    help="es. meta-llama/Meta-Llama-3.1-8B-Instruct")
    ap.add_argument("--output-dir", required=True)

    # Hyperparams
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--batch-size", type=int, default=2)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max-seq-len", type=int, default=2048)
    ap.add_argument("--warmup-ratio", type=float, default=0.03)
    ap.add_argument("--weight-decay", type=float, default=0.0)

    # LoRA
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--lora-dropout", type=float, default=0.05)

    # Quantizzazione
    ap.add_argument("--no-4bit", action="store_true",
                    help="disabilita la quantizzazione 4bit (CPU/debug)")

    ap.add_argument("--seed", type=int, default=42)
    return ap.parse_args()


def main() -> None:
    args = parse_args()

    # Import "lazy": se l'utente non ha le librerie installate l'errore arriva
    # solo all'esecuzione effettiva, non al semplice --help dello script.
    import torch
    from datasets import load_dataset
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )
    from peft import LoraConfig, prepare_model_for_kbit_training
    from trl import SFTConfig, SFTTrainer

    ds_dir = Path(args.dataset_dir)
    train_file = ds_dir / "train.jsonl"
    val_file   = ds_dir / "val.jsonl"
    if not train_file.exists():
        raise SystemExit(f"train.jsonl non trovato: {train_file}")

    data_files = {"train": str(train_file)}
    if val_file.exists() and val_file.stat().st_size > 0:
        data_files["validation"] = str(val_file)
    dataset = load_dataset("json", data_files=data_files)

    # ── Tokenizer ────────────────────────────────────────────────────────────
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=True)
    if tokenizer.pad_token is None:
        # LLaMA non ha pad token nativo: riusiamo eos per consentire il padding.
        tokenizer.pad_token = tokenizer.eos_token

    # ── Model ────────────────────────────────────────────────────────────────
    model_kwargs: dict = {"torch_dtype": torch.bfloat16}
    use_4bit = (not args.no_4bit) and torch.cuda.is_available()
    if use_4bit:
        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        model_kwargs["device_map"] = "auto"

    model = AutoModelForCausalLM.from_pretrained(args.base_model, **model_kwargs)
    if use_4bit:
        model = prepare_model_for_kbit_training(model)
    model.config.use_cache = False  # richiesto quando si usa gradient_checkpointing

    # ── LoRA ─────────────────────────────────────────────────────────────────
    # Target modules validi per l'architettura LLaMA; trl.SFTTrainer accetta
    # peft_config e applica get_peft_model() internamente.
    peft_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )

    # ── Trainer ──────────────────────────────────────────────────────────────
    sft_config = SFTConfig(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        warmup_ratio=args.warmup_ratio,
        weight_decay=args.weight_decay,
        lr_scheduler_type="cosine",
        max_seq_length=args.max_seq_len,
        packing=False,
        gradient_checkpointing=True,
        bf16=torch.cuda.is_available(),
        logging_steps=10,
        save_strategy="epoch",
        eval_strategy="epoch" if "validation" in dataset else "no",
        report_to="none",
        seed=args.seed,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=sft_config,
        train_dataset=dataset["train"],
        eval_dataset=dataset.get("validation"),
        peft_config=peft_config,
    )

    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    print(f"[train_lora] Adapter salvato in: {args.output_dir}")


if __name__ == "__main__":
    main()
