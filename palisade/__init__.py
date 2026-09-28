"""Palisade: a policy-enforced local LLM stack with a tamper-evident audit trail."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml

__version__ = "0.2.0"

ROOT = Path(os.environ.get("PALISADE_ROOT", Path(__file__).resolve().parent.parent))
CONFIG_DIR = ROOT / "config"
# Data layout. In desktop mode everything lives under ROOT/data. In service mode
# (scripts/service/*) the installer sets PALISADE_DATA so that code and config stay
# root-owned and read-only to the service account, and only the writable state
# directories (audit, logs, state, eval, compliance) belong to the service.
DATA_DIR = Path(os.environ.get("PALISADE_DATA", ROOT / "data"))
BIN_DIR = DATA_DIR / "bin"
MODELS_DIR = DATA_DIR / "models"
LOCK_PATH = Path(os.environ.get("PALISADE_LOCK", DATA_DIR / "manifest.lock"))
AUDIT_DIR = DATA_DIR / "audit"
LOGS_DIR = DATA_DIR / "logs"
STATE_DIR = DATA_DIR / "state"

# POSIX permission defaults for anything Palisade writes that holds audit or state data.
# Owner (the service account) reads and writes; the audit group reads; others get nothing.
FILE_MODE = 0o640
DIR_MODE = 0o2750          # setgid so new files inherit the audit group on Linux
POSIX = os.name == "posix"


def audit_dir(settings: dict) -> Path:
    """Resolve the audit directory: the default follows PALISADE_DATA; a custom
    relative path is taken from ROOT; an absolute path is used as given."""
    d = str(settings.get("audit", {}).get("directory", "data/audit")).rstrip("/")
    if d == "data/audit":
        return AUDIT_DIR
    return Path(d) if Path(d).is_absolute() else ROOT / d


def secure_mkdir(path: Path, mode: int = DIR_MODE) -> Path:
    """Create a directory (and parents) and apply restrictive permissions on POSIX."""
    path.mkdir(parents=True, exist_ok=True)
    if POSIX:
        try:
            os.chmod(path, mode)
        except PermissionError:
            pass  # directory owned by another account (e.g. root-provisioned); leave as is
    return path


def secure_write_text(path: Path, text: str, mode: int = FILE_MODE) -> Path:
    """Write a file so it is never readable by other accounts, even briefly.

    Only the file's own mode is set. The parent directory is created with a secure
    mode if it does not exist, but an existing directory is never altered: callers
    may write reports into their own folders, and changing those would be a bug."""
    if not path.parent.exists():
        secure_mkdir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    if POSIX:
        os.chmod(path, mode)
    return path


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
