"""First-run setup for installed copies of Palisade.

Installers ship a small package: code, a Python runtime, and a signed model server.
The models (about 10 GB) are downloaded on first run, by this module.

Who runs it:
  service mode   a root (macOS, Linux) or SYSTEM (Windows) job the installer registers.
                 The service account cannot write models or manifest.lock, so it cannot
                 fetch them itself; it shows setup progress while it waits.
  desktop mode   Palisade itself, as the person using it, who owns their own data.

Progress goes to setup-status.json, which the web page polls. The file is readable by
the audit group and never contains secrets.

Setup only fills in what is missing. A file that differs from its recorded or published
hash stops setup with an error; it is never re-trusted automatically.
"""
from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path
from typing import Any, Optional

from . import (MODE, PACKAGED_BIN, SETUP_STATUS, DATA_DIR, MODELS_DIR, __version__,
               ensure_config, load_settings, load_models, secure_mkdir)


class Status:
    """Writes setup-status.json atomically so a reader never sees half a file."""

    def __init__(self, path: Path = SETUP_STATUS):
        self.path = path
        self.data: dict[str, Any] = {"state": "running", "version": __version__, "steps": [],
                                     "started": _now(), "updated": _now()}
        self._last_write = 0.0

    def step(self, name: str, label: str) -> None:
        for s in self.data["steps"]:
            if s["state"] == "running":
                s["state"] = "done"
        self.data["steps"].append({"name": name, "label": label, "state": "running"})
        self.data.pop("download", None)
        self.write(force=True)

    def download(self, model: str, done: int, total: int) -> None:
        self.data["download"] = {"model": model, "done": done, "total": total}
        self.write()

    def finish(self, state: str, message: str = "", problems: Optional[list[str]] = None) -> None:
        for s in self.data["steps"]:
            if s["state"] == "running":
                s["state"] = "done" if state == "complete" else "failed"
        self.data.update({"state": state, "message": message, "problems": problems or []})
        self.data.pop("download", None)
        self.write(force=True)

    def write(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_write < 1.0:   # downloads report many times a second
            return
        self._last_write = now
        self.data["updated"] = _now()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)


def read_status(path: Path = SETUP_STATUS) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "pending", "steps": []}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def needs_setup(manifest: dict, tier: str) -> list[str]:
    """Cheap check, run at every boot by the service-mode setup job: what is missing?
    It never hashes the multi-gigabyte models; `palisade run` verifies those at start."""
    from . import read_lock, config_file, sha256_file, policy_path
    from .fetch import model_path
    lock = read_lock()
    reasons = []
    lc = lock.get("llama_cpp", {})
    if not lc or (PACKAGED_BIN and not lc.get("packaged")):
        reasons.append("model server not recorded")
    elif PACKAGED_BIN and lc.get("server_sha256") and (PACKAGED_BIN / "bin-manifest.json").exists():
        info = json.loads((PACKAGED_BIN / "bin-manifest.json").read_text(encoding="utf-8"))
        if info.get("files") != lc.get("files"):
            reasons.append("a new release bundled a different model server")
    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        if mid not in lock.get("models", {}) or not model_path(mid, manifest).exists():
            reasons.append(f"model {mid} not installed")
    cfg = lock.get("config", {})
    if not cfg or policy_path().name not in cfg:
        reasons.append("config fingerprints not recorded")
    elif cfg.get("models.yaml") != sha256_file(config_file("models.yaml")):
        reasons.append("a new release changed models.yaml")
    return reasons


def run_setup(status: Optional[Status] = None, tier_override: Optional[str] = None,
              only_if_needed: bool = False) -> int:
    """Bring an installed copy to a verified state. Returns 0 on success."""
    from .fetch import (HashMismatch, install_binaries, install_model, installation_problems,
                        record_config_hashes, register_packaged_binaries)
    from .hardware import detect, choose_tier

    status = status or Status()
    try:
        status.step("config", "Preparing settings and policy")
        ensure_config()
        # Create, but never re-mode, these folders: in service mode the installer set their
        # owner, group, and setgid bit, and changing them would lock the service out.
        for d, mode in ((DATA_DIR, 0o750), (MODELS_DIR, 0o2750)):
            if not d.exists():
                secure_mkdir(d, mode)
        settings, manifest = load_settings(), load_models()
        host = detect()
        tier = choose_tier(host, manifest["tiers"], tier_override or settings.get("tier", "auto"))
        t = manifest["tiers"][tier]
        status.data["tier"] = tier
        if only_if_needed:
            reasons = needs_setup(manifest, tier)
            if not reasons:
                status.finish("complete", "Nothing to set up.")
                return 0
            status.data["reasons"] = reasons

        status.step("binaries", "Checking the model server")
        if PACKAGED_BIN:
            register_packaged_binaries()
        else:
            install_binaries(host, manifest)

        for mid in (t["base"], t["guardian"]):
            m = manifest["models"][mid]
            status.step(f"model:{mid}", f"Downloading {mid} (about {m.get('approx_gb', '?')} GB)")
            install_model(mid, manifest, progress=lambda d, n, mid=mid: status.download(mid, d, n))

        status.step("lock", "Recording fingerprints")
        record_config_hashes(only_missing=True)

        problems = installation_problems(manifest, tier)
        if problems:
            status.finish("error", "Setup finished, but the installation does not verify.",
                          [p.message for p in problems])
            return 1
        status.finish("complete", "Setup complete.")
        return 0
    except HashMismatch as e:
        status.finish("error", "A downloaded or installed file failed verification. "
                               "Nothing was trusted. See the details below.", [str(e)])
        return 2
    except Exception as e:   # surface the reason on the setup page, not only in a log
        status.finish("error", f"Setup stopped: {e}", [traceback.format_exc(limit=3)])
        return 1


def import_existing(source: Path) -> list[str]:
    """Copy models (verified) and an audit chain from an earlier source-checkout install,
    so moving to an installed copy does not mean downloading 10 GB again or starting a
    new audit history. Models must match the published hashes; the audit chain is only
    copied into an empty audit folder, never merged."""
    import shutil
    from . import AUDIT_DIR
    from .fetch import install_model
    from .hardware import detect, choose_tier

    done = []
    settings, manifest = load_settings(), load_models()
    tier = choose_tier(detect(), manifest["tiers"], settings.get("tier", "auto"))
    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        src = source / "models" / mid / manifest["models"][mid]["file"]
        if src.exists():
            install_model(mid, manifest, url_override=src.as_uri())
            done.append(f"model {mid}")
    src_audit = source / "audit"
    if src_audit.is_dir() and any(src_audit.glob("audit-*.jsonl")):
        if AUDIT_DIR.exists() and any(AUDIT_DIR.glob("audit-*.jsonl")):
            done.append("audit chain NOT copied: this installation already has audit records")
        else:
            secure_mkdir(AUDIT_DIR)
            for f in sorted(src_audit.glob("audit-*.jsonl")):
                shutil.copy2(f, AUDIT_DIR / f.name)
            done.append(f"audit chain ({len(list(src_audit.glob('audit-*.jsonl')))} files)")
    return done
