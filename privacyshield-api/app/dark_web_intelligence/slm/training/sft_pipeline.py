"""
sft_pipeline.py — Supervised Fine-Tuning (SFT) with QLoRA.

Trains Llama-3-8B-Instruct on the security/privacy dataset produced by
data_collector.py.  Uses 4-bit quantisation (bitsandbytes) + LoRA (peft)
so it runs on a single A100-40GB, A10, or 3×RTX 3090.

Run:
    python -m app.dark_web_intelligence.slm.training.sft_pipeline

After completion, adapter weights are saved to ./models/aletheos-dwi-sft/
Feed this into dpo_pipeline.py for the second alignment stage.
"""

import json
import os
from pathlib import Path
from typing import List, Dict

import torch
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, DataCollatorForCompletionOnlyLM

from app.dark_web_intelligence.slm.config import intel_config

cfg_m   = intel_config.model
cfg_l   = intel_config.lora
cfg_sft = intel_config.sft


# ─────────────────────────────────────────────────────────────────────────────
# Tokeniser
# ─────────────────────────────────────────────────────────────────────────────

def load_tokenizer():
    tokenizer = AutoTokenizer.from_pretrained(
        cfg_m.base_model_id,
        token=cfg_m.hf_token or os.environ.get("HF_TOKEN"),
        trust_remote_code=True,
    )
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"  # required for SFT
    return tokenizer


# ─────────────────────────────────────────────────────────────────────────────
# Model (4-bit QLoRA)
# ─────────────────────────────────────────────────────────────────────────────

def load_model(tokenizer):
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
    )

    model = AutoModelForCausalLM.from_pretrained(
        cfg_m.base_model_id,
        quantization_config=bnb_config,
        device_map="auto",
        token=cfg_m.hf_token or os.environ.get("HF_TOKEN"),
        trust_remote_code=True,
    )
    model.config.use_cache = False
    model.config.pretraining_tp = 1

    # Prepare for k-bit training (adds gradient checkpointing, casts LN layers)
    model = prepare_model_for_kbit_training(model)

    lora_config = LoraConfig(
        r=cfg_l.r,
        lora_alpha=cfg_l.lora_alpha,
        lora_dropout=cfg_l.lora_dropout,
        bias=cfg_l.bias,
        task_type=cfg_l.task_type,
        target_modules=cfg_l.target_modules,
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    return model


# ─────────────────────────────────────────────────────────────────────────────
# Dataset
# ─────────────────────────────────────────────────────────────────────────────

def load_jsonl(path: str) -> List[Dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def messages_to_text(example: Dict, tokenizer) -> Dict:
    """
    Apply the model's chat template to convert the 'messages' list into
    a single string that SFTTrainer expects.
    """
    text = tokenizer.apply_chat_template(
        example["messages"],
        tokenize=False,
        add_generation_prompt=False,
    )
    return {"text": text}


def build_datasets(tokenizer):
    train_raw = load_jsonl(cfg_sft.train_data_path)
    eval_raw  = load_jsonl(cfg_sft.eval_data_path)

    train_ds = Dataset.from_list(train_raw)
    eval_ds  = Dataset.from_list(eval_raw)

    # Apply chat template
    train_ds = train_ds.map(lambda x: messages_to_text(x, tokenizer), batched=False)
    eval_ds  = eval_ds.map(lambda x: messages_to_text(x, tokenizer), batched=False)

    return train_ds, eval_ds


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def train():
    print("[sft_pipeline] Loading tokeniser …")
    tokenizer = load_tokenizer()

    print("[sft_pipeline] Loading model (4-bit QLoRA) …")
    model = load_model(tokenizer)

    print("[sft_pipeline] Building datasets …")
    train_ds, eval_ds = build_datasets(tokenizer)
    print(f"  Train: {len(train_ds):,} | Eval: {len(eval_ds):,}")

    training_args = TrainingArguments(
        output_dir=cfg_sft.output_dir,
        num_train_epochs=cfg_sft.num_train_epochs,
        per_device_train_batch_size=cfg_sft.per_device_train_batch_size,
        gradient_accumulation_steps=cfg_sft.gradient_accumulation_steps,
        learning_rate=cfg_sft.learning_rate,
        warmup_ratio=cfg_sft.warmup_ratio,
        lr_scheduler_type=cfg_sft.lr_scheduler_type,
        fp16=cfg_sft.fp16,
        logging_steps=cfg_sft.logging_steps,
        save_steps=cfg_sft.save_steps,
        eval_steps=cfg_sft.eval_steps,
        evaluation_strategy="steps",
        save_total_limit=cfg_sft.save_total_limit,
        load_best_model_at_end=True,
        report_to=cfg_sft.report_to,
        gradient_checkpointing=True,
        optim="paged_adamw_32bit",       # memory-efficient optimiser
        group_by_length=True,            # speeds up training
        dataloader_pin_memory=False,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        dataset_text_field="text",
        max_seq_length=cfg_sft.max_seq_length,
        packing=False,
    )

    print("[sft_pipeline] Starting SFT training …")
    trainer.train()

    print(f"[sft_pipeline] Saving adapter to {cfg_sft.output_dir} …")
    trainer.save_model(cfg_sft.output_dir)
    tokenizer.save_pretrained(cfg_sft.output_dir)

    print("[sft_pipeline] ✅ SFT complete.")
    print(f"  Next step → run dpo_pipeline.py using adapter at {cfg_sft.output_dir}")


# ─────────────────────────────────────────────────────────────────────────────
# Quick inference test (validates the saved adapter)
# ─────────────────────────────────────────────────────────────────────────────

def test_inference(prompt: str = "What should I do if my email is found on the dark web?"):
    """
    Loads the saved SFT adapter and generates a response.
    Use after training to sanity-check the model.
    """
    from peft import PeftModel

    print("[sft_pipeline] Loading saved adapter for inference test …")
    tokenizer = AutoTokenizer.from_pretrained(cfg_sft.output_dir)
    base_model = AutoModelForCausalLM.from_pretrained(
        cfg_m.base_model_id,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        token=cfg_m.hf_token or os.environ.get("HF_TOKEN"),
    )
    model = PeftModel.from_pretrained(base_model, cfg_sft.output_dir)
    model.eval()

    messages = [
        {"role": "system", "content": "You are Aletheos Intelligence, a privacy and cybersecurity assistant."},
        {"role": "user",   "content": prompt},
    ]
    input_ids = tokenizer.apply_chat_template(
        messages,
        return_tensors="pt",
        add_generation_prompt=True,
    ).to(model.device)

    with torch.no_grad():
        output = model.generate(
            input_ids,
            max_new_tokens=512,
            temperature=0.7,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id,
        )

    response = tokenizer.decode(output[0][input_ids.shape[1]:], skip_special_tokens=True)
    print(f"\n[TEST] Prompt: {prompt}")
    print(f"[TEST] Response:\n{response}\n")
    return response


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        test_inference()
    else:
        train()
