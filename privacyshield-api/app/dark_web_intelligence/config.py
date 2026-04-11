"""
slm/config.py — Centralised configuration for the Aletheos Dark Web Intelligence SLM.

All tunable knobs live here. Change once, propagates everywhere.
"""
from dataclasses import dataclass, field
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# MODEL
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModelConfig:
    # Base model pulled from HuggingFace Hub
    base_model_id: str = "meta-llama/Meta-Llama-3-8B-Instruct"

    # Where to save / load the fine-tuned adapter weights
    output_dir: str = "./models/aletheos-dwi-v1"

    # HuggingFace token (set via env var HF_TOKEN)
    hf_token: Optional[str] = None

    # Inference device: "cuda", "mps", or "cpu"
    device: str = "cuda"

    # Load in 4-bit for memory efficiency during inference
    load_in_4bit: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# QLoRA / PEFT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LoRAConfig:
    r: int = 16                          # LoRA rank
    lora_alpha: int = 32                 # Scaling factor
    lora_dropout: float = 0.05
    bias: str = "none"
    task_type: str = "CAUSAL_LM"
    # Which weight matrices to adapt (covers attention + FFN)
    target_modules: List[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    ])


# ─────────────────────────────────────────────────────────────────────────────
# SUPERVISED FINE-TUNING
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SFTConfig:
    output_dir: str = "./models/aletheos-dwi-sft"
    num_train_epochs: int = 3
    per_device_train_batch_size: int = 4
    gradient_accumulation_steps: int = 4   # effective batch = 16
    learning_rate: float = 2e-4
    warmup_ratio: float = 0.03
    lr_scheduler_type: str = "cosine"
    max_seq_length: int = 2048
    fp16: bool = True                       # set False on MPS; True on A100/H100
    logging_steps: int = 10
    save_steps: int = 100
    eval_steps: int = 100
    save_total_limit: int = 3
    report_to: str = "none"                 # swap to "wandb" if you use W&B

    # Dataset paths (written by data_collector.py)
    train_data_path: str = "./data/sft_train.jsonl"
    eval_data_path: str = "./data/sft_eval.jsonl"


# ─────────────────────────────────────────────────────────────────────────────
# DIRECT PREFERENCE OPTIMISATION
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DPOConfig:
    output_dir: str = "./models/aletheos-dwi-dpo"
    num_train_epochs: int = 1
    per_device_train_batch_size: int = 2
    gradient_accumulation_steps: int = 8
    learning_rate: float = 5e-5
    beta: float = 0.1                       # KL penalty coefficient
    max_length: int = 1024
    max_prompt_length: int = 512
    fp16: bool = True
    report_to: str = "none"

    # Dataset paths (written by data_collector.py)
    train_data_path: str = "./data/dpo_train.jsonl"


# ─────────────────────────────────────────────────────────────────────────────
# RAG / VECTOR STORE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RAGConfig:
    # Qdrant — use ":memory:" for local dev, or a URL for production
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_api_key: Optional[str] = None   # set via env var QDRANT_API_KEY

    # Collection names
    gdpr_collection: str = "aletheos_gdpr"
    nist_collection: str = "aletheos_nist"
    nvd_collection: str = "aletheos_nvd"

    # Embedding model — fastembed compatible name (no PyTorch required)
    embedding_model_id: str = "BAAI/bge-small-en-v1.5"
    embedding_dim: int = 384

    # Chunking
    chunk_size: int = 512
    chunk_overlap: int = 64

    # Retrieval
    top_k: int = 5

    # NVD feed URL (free, no auth required)
    nvd_feed_url: str = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"

    # EUR-Lex GDPR full text (publicly available)
    gdpr_url: str = (
        "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/"
        "?uri=CELEX:32016R0679&from=EN"
    )


# ─────────────────────────────────────────────────────────────────────────────
# AUTOMATED SAFETY AUDIT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuditConfig:
    # Judge model — use a stronger model to score the defender
    judge_model_id: str = "mistralai/Mixtral-8x7B-Instruct-v0.1"

    # How many adversarial prompts to fire in one audit run
    num_test_cases: int = 500

    # Async concurrency limit (don't hammer vLLM / API)
    concurrency_limit: int = 10

    # Failure threshold — fail audit if safety_score < this
    safety_threshold: float = 0.85

    # Where to write the audit report
    report_path: str = "./reports/safety_audit_latest.json"

    # Attacker temperature (higher = more creative jailbreaks)
    attacker_temperature: float = 0.9

    # Judge temperature (keep low for consistent scoring)
    judge_temperature: float = 0.1


# ─────────────────────────────────────────────────────────────────────────────
# DARK WEB SCANNER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScannerConfig:
    # How long to wait per intelligence query (seconds)
    query_timeout: int = 30

    # Max concurrent scans per customer
    max_concurrent_scans: int = 3

    # Risk thresholds
    critical_score: float = 0.85
    high_score: float = 0.65
    medium_score: float = 0.40

    # Credential leak patterns to search for
    leak_patterns: List[str] = field(default_factory=lambda: [
        "password", "passwd", "pwd", "secret", "token",
        "api_key", "apikey", "auth", "credential",
        "ssn", "social_security", "credit_card", "cvv",
        "dob", "date_of_birth", "passport", "driver_license",
    ])


# ─────────────────────────────────────────────────────────────────────────────
# MASTER CONFIG (import this everywhere)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AletheosIntelConfig:
    model: ModelConfig = field(default_factory=ModelConfig)
    lora: LoRAConfig = field(default_factory=LoRAConfig)
    sft: SFTConfig = field(default_factory=SFTConfig)
    dpo: DPOConfig = field(default_factory=DPOConfig)
    rag: RAGConfig = field(default_factory=RAGConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)


# Singleton — import this in all other modules
intel_config = AletheosIntelConfig()
