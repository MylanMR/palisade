"""Palisade: a policy-enforced local LLM stack with a tamper-evident audit trail."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml

__version__ = "0.1.0"

ROOT = Path(os.environ.get("PALISADE_ROOT", Path(__file__).resolve().parent.parent))
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
BIN_DIR = DATA_DIR / "bin"
MODELS_DIR = DATA_DIR / "models"
LOCK_PATH = DATA_DIR / "manifest.lock"


def load_yaml(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_settings() -> dict[str, Any]:
    return load_yaml(CONFIG_DIR / "settings.yaml")


def load_models() -> dict[str, Any]:
    return load_yaml(CONFIG_DIR / "models.yaml")


def policy_path() -> Path:
    """Prefer a local, untracked policy override if present, else the tracked example.

    This lets the public repo ship a generic policy.yaml while an operator keeps their
    real taxonomy in policy.local.yaml, which .gitignore excludes.
    """
    local = CONFIG_DIR / "policy.local.yaml"
    return local if local.exists() else CONFIG_DIR / "policy.yaml"


def load_policy() -> dict[str, Any]:
    return load_yaml(policy_path())


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON for hashing: sorted keys, no whitespace variance."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def read_lock() -> dict[str, Any]:
    if not LOCK_PATH.exists():
        return {}
    with open(LOCK_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def write_lock(lock: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOCK_PATH, "w", encoding="utf-8") as f:
        json.dump(lock, f, indent=2, sort_keys=True)


def manifest_hash(lock: dict[str, Any]) -> str:
    """A single hash summarizing binaries, models, and config in force."""
    return sha256_text(canonical_json(lock))
