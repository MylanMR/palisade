"""Palisade: a policy-enforced local LLM stack with a tamper-evident audit trail."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml

__version__ = "0.3.0"

ROOT = Path(os.environ.get("PALISADE_ROOT", Path(__file__).resolve().parent.parent))
POSIX = os.name == "posix"


def _read_install_info(root: Path) -> dict[str, Any]:
    """Installers write install.json at the package root. A source checkout has none."""
    try:
        return json.loads((root / "install.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


INSTALL_INFO = _read_install_info(ROOT)
PACKAGED = bool(INSTALL_INFO)


def _read_mode() -> str:
    """Which layout this process uses.

      source   a git checkout: config and data live in the checkout (the original layout)
      desktop  an installed copy run by a person: config and data in that person's folders
      service  an installed copy run by the system service: config and data in system folders

    PALISADE_MODE wins. An installer records the machine's chosen mode in install-mode,
    so administrators running `palisade ...` in a terminal see the service's files.
    """
    env = os.environ.get("PALISADE_MODE", "").strip().lower()
    if env:
        return env
    try:
        recorded = (ROOT / "install-mode").read_text(encoding="utf-8").strip().lower()
        if recorded in ("desktop", "service"):
            return recorded
    except OSError:
        pass
    return "desktop" if PACKAGED else "source"


MODE = _read_mode()


def default_dirs(mode: str, platform: str | None = None, env: dict | None = None,
                 home: Path | None = None) -> tuple[Path, Path]:
    """(config_dir, data_dir) for a mode on a platform. Pure, so it can be tested anywhere."""
    import sys as _sys
    platform = platform or _sys.platform
    env = os.environ if env is None else env
    home = home or Path.home()
    if mode == "source":
        return ROOT / "config", ROOT / "data"
    if platform.startswith("win"):
        if mode == "service":
            base = Path(env.get("ProgramData", r"C:\ProgramData")) / "Palisade"
        else:
            base = Path(env.get("LOCALAPPDATA", home / "AppData" / "Local")) / "Palisade"
        return base / "config", base / "data"
    if platform == "darwin":
        base = (Path("/Library/Application Support/Palisade") if mode == "service"
                else home / "Library" / "Application Support" / "Palisade")
        return base / "config", base / "data"
    if mode == "service":
        return Path("/etc/palisade"), Path("/var/lib/palisade")
    cfg = Path(env.get("XDG_CONFIG_HOME") or home / ".config") / "palisade"
    data = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / "palisade"
    return cfg, data


_DEF_CONFIG, _DEF_DATA = default_dirs(MODE)
CONFIG_DIR = Path(os.environ.get("PALISADE_CONFIG", _DEF_CONFIG))
# Data layout. In service mode, code, models.yaml, and the bundled model server are
# owned by root (or SYSTEM) and read-only to the service account; only the writable
# state directories (audit, logs, state, eval, compliance) belong to the service.
DATA_DIR = Path(os.environ.get("PALISADE_DATA", _DEF_DATA))
BIN_DIR = DATA_DIR / "bin"
MODELS_DIR = DATA_DIR / "models"
LOCK_PATH = Path(os.environ.get("PALISADE_LOCK", DATA_DIR / "manifest.lock"))
SETUP_STATUS = DATA_DIR / "setup-status.json"
# Installers bundle a signed llama-server; a source checkout downloads one into BIN_DIR.
PACKAGED_BIN = (Path(os.environ["PALISADE_BIN"]) if os.environ.get("PALISADE_BIN")
                else (ROOT / INSTALL_INFO["bin"]) if INSTALL_INFO.get("bin") else None)
# models.yaml describes what this release installs, so installed copies read the
# package's copy rather than a per-user one; settings and policy are the operator's.
MODELS_FILE = Path(os.environ.get("PALISADE_MODELS_FILE",
                                  ROOT / "config" / "models.yaml" if PACKAGED else CONFIG_DIR / "models.yaml"))
AUDIT_DIR = DATA_DIR / "audit"
LOGS_DIR = DATA_DIR / "logs"
STATE_DIR = DATA_DIR / "state"

# POSIX permission defaults for anything Palisade writes that holds audit or state data.
# Owner (the service account) reads and writes; the audit group reads; others get nothing.
FILE_MODE = 0o640
DIR_MODE = 0o2750          # setgid so new files inherit the audit group on Linux


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
    return load_yaml(MODELS_FILE)


def server_dir(tag: str) -> Path:
    """Directory holding llama-server: the bundled copy, or the one downloaded for `tag`."""
    return PACKAGED_BIN if PACKAGED_BIN else BIN_DIR / tag


def config_file(name: str) -> Path:
    """Where a config file recorded in manifest.lock lives."""
    return MODELS_FILE if name == "models.yaml" else CONFIG_DIR / name


CONFIG_DEFAULTS = ("settings.yaml", "policy.yaml", "policy.example-blank.yaml", "policy.example-standard.yaml")


def ensure_config() -> list[str]:
    """Installed copies start each person's (or the service's) config from the package
    defaults. Existing files are never overwritten: they are the operator's."""
    if MODE == "source":
        return []
    created = []
    src = ROOT / "config"
    if not CONFIG_DIR.exists():      # an installer may have created it with its own owner and mode
        secure_mkdir(CONFIG_DIR, 0o750)
    for name in CONFIG_DEFAULTS:
        dest = CONFIG_DIR / name
        if not dest.exists() and (src / name).exists():
            secure_write_text(dest, (src / name).read_text(encoding="utf-8"), 0o640)
            created.append(name)
    return created


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
    """Replace the lock atomically, so a reader never sees a half-written file."""
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = LOCK_PATH.with_name(LOCK_PATH.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(lock, f, indent=2, sort_keys=True)
    os.replace(tmp, LOCK_PATH)


def manifest_hash(lock: dict[str, Any]) -> str:
    """A single hash summarizing binaries, models, and config in force."""
    return sha256_text(canonical_json(lock))
