"""Fetch pinned binaries and models, and maintain manifest.lock.

The lock file is the supply-chain record for this installation:
  - llama.cpp release tag and the SHA-256 of the llama-server binary in use
  - every model file with its SHA-256
  - SHA-256 of settings.yaml, models.yaml, and the active policy file
    (policy.local.yaml if present, else policy.yaml)
Every audit record carries a hash of this lock, so a decision can always be tied to
the exact binaries, weights, and policy in force when it was made.
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import httpx

from . import (
    BIN_DIR, CONFIG_DIR, MODELS_DIR, DATA_DIR,
    read_lock, write_lock, sha256_file, load_models,
)
from .hardware import Host


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with httpx.stream("GET", url, follow_redirects=True, timeout=None) as r:
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} fetching {url}")
        total = int(r.headers.get("content-length", 0))
        done = 0
        with open(tmp, "wb") as f:
            for chunk in r.iter_bytes(1 << 20):
                f.write(chunk)
                done += len(chunk)
                if total:
                    pct = done * 100 // total
                    sys.stdout.write(f"\r  {dest.name}: {pct}% ({done >> 20} MB)")
                    sys.stdout.flush()
        sys.stdout.write("\n")
    tmp.replace(dest)


def _extract(archive: Path, into: Path) -> None:
    into.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            z.extractall(into)
    else:
        with tarfile.open(archive) as t:
            t.extractall(into)


def _find_server(root: Path) -> Path:
    names = {"llama-server", "llama-server.exe"}
    for p in root.rglob("*"):
        if p.name in names and p.is_file():
            return p
    raise FileNotFoundError("llama-server not found in extracted archive")


def install_binaries(host: Host, manifest: dict) -> Path:
    cfg = manifest["llama_cpp"]
    tag = cfg["tag"]
    key = host.asset_key
    if key not in cfg["assets"]:
        raise RuntimeError(f"no llama.cpp asset for platform key '{key}'")

    target = BIN_DIR / tag
    server = target / ("llama-server.exe" if host.os == "windows" else "llama-server")
    if server.exists():
        print(f"llama.cpp {tag} already installed for {key}")
        return server

    stage = DATA_DIR / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    assets = [cfg["assets"][key]] + cfg.get("extra_assets", {}).get(key, "").split()
    for name in filter(None, assets):
        name = name.format(tag=tag)
        url = f"{cfg['base_url']}/{tag}/{name}"
        print(f"fetching {url}")
        arc = stage / name
        _download(url, arc)
        _extract(arc, stage / "x")

    found = _find_server(stage / "x")
    target.mkdir(parents=True, exist_ok=True)
    # Copy the server and every sibling shared library / DLL next to it.
    for p in found.parent.iterdir():
        if p.is_file():
            shutil.copy2(p, target / p.name)
    if host.os != "windows":
        server.chmod(server.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    shutil.rmtree(stage, ignore_errors=True)

    lock = read_lock()
    lock.setdefault("llama_cpp", {})
    lock["llama_cpp"] = {"tag": tag, "asset": cfg["assets"][key].format(tag=tag),
                         "server_sha256": sha256_file(server)}
    write_lock(lock)
    print(f"installed llama-server {tag} -> {server}")
    return server


def model_path(model_id: str, manifest: dict) -> Path:
    m = manifest["models"][model_id]
    return MODELS_DIR / model_id / m["file"]


def install_model(model_id: str, manifest: dict, url_override: str | None = None) -> Path:
    m = manifest["models"][model_id]
    dest = model_path(model_id, manifest)
    lock = read_lock()
    models_lock = lock.setdefault("models", {})

    if dest.exists():
        digest = sha256_file(dest)
        recorded = models_lock.get(model_id, {}).get("sha256")
        if recorded and recorded != digest:
            raise RuntimeError(
                f"{model_id}: file on disk does not match manifest.lock. "
                f"Refusing to use it. Delete {dest} and reinstall, or investigate.")
        if not recorded:
            models_lock[model_id] = {"file": m["file"], "repo": m["repo"], "sha256": digest}
            write_lock(lock)
        print(f"{model_id} present, sha256 {digest[:16]}...")
        return dest

    if url_override:
        url = url_override
    else:
        if m["repo"].startswith("VERIFY/"):
            raise RuntimeError(
                f"{model_id}: repo is marked VERIFY in config/models.yaml. "
                f"Set the real Hugging Face repo id (see docs/MODELS.md) or pass --model-url.")
        url = f"{manifest['hf_base_url']}/{m['repo']}/resolve/main/{m['file']}"

    print(f"fetching {model_id} ({m.get('approx_gb', '?')} GB) from {url}")
    _download(url, dest)
    digest = sha256_file(dest)
    models_lock[model_id] = {"file": m["file"], "repo": m["repo"], "source_url": url, "sha256": digest}
    write_lock(lock)
    print(f"{model_id} sha256 {digest}")
    return dest


def record_config_hashes() -> dict:
    from . import policy_path
    lock = read_lock()
    cfg = {name: sha256_file(CONFIG_DIR / name) for name in ("settings.yaml", "models.yaml")}
    active_policy = policy_path()
    cfg[active_policy.name] = sha256_file(active_policy)
    lock["config"] = cfg
    write_lock(lock)
    return lock


def verify_installation(manifest: dict, tier: str) -> list[str]:
    """Return a list of problems; empty means everything on disk matches the lock."""
    problems: list[str] = []
    lock = read_lock()
    if not lock:
        return ["manifest.lock missing; run: palisade install"]

    lc = lock.get("llama_cpp", {})
    server = None
    for cand in (BIN_DIR / lc.get("tag", "") / "llama-server",
                 BIN_DIR / lc.get("tag", "") / "llama-server.exe"):
        if cand.exists():
            server = cand
    if server is None:
        problems.append("llama-server binary missing")
    elif sha256_file(server) != lc.get("server_sha256"):
        problems.append("llama-server binary hash does not match manifest.lock")

    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        p = model_path(mid, manifest)
        rec = lock.get("models", {}).get(mid, {}).get("sha256")
        if not p.exists():
            problems.append(f"model file missing: {mid}")
        elif rec is None:
            problems.append(f"model {mid} has no hash in manifest.lock")
        elif sha256_file(p) != rec:
            problems.append(f"model {mid} hash does not match manifest.lock")

    for name, h in lock.get("config", {}).items():
        cfg_file = CONFIG_DIR / name
        if not cfg_file.exists():
            problems.append(f"config/{name} recorded in manifest.lock is missing (run `palisade install` to re-lock)")
        elif sha256_file(cfg_file) != h:
            problems.append(f"config/{name} changed since install (run `palisade install` to re-lock)")
    return problems
