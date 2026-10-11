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
    if url.startswith("file://"):
        from urllib.parse import urlparse, unquote
        from urllib.request import url2pathname
        src = Path(url2pathname(unquote(urlparse(url).path)))
        if not src.is_file():
            raise RuntimeError(f"local file not found: {src}")
        print(f"  copying {src}")
        shutil.copyfile(src, tmp)
        tmp.replace(dest)
        return
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


class HashMismatch(RuntimeError):
    pass


def _published_model_hash(m: dict) -> str | None:
    h = str(m.get("sha256", "") or "").strip().lower()
    return h or None


def _published_server_hash(cfg: dict, key: str) -> str | None:
    h = str((cfg.get("server_sha256") or {}).get(key, "") or "").strip().lower()
    return h or None


def _reject(path: Path, what: str, expected: str, actual: str) -> None:
    """Move a file that failed verification aside so it can never be recorded as trusted."""
    rejected = path.with_name(path.name + ".rejected")
    try:
        path.replace(rejected)
        where = f" Moved to {rejected} for inspection."
    except OSError:
        where = ""
    raise HashMismatch(
        f"{what} does not match the hash published in config/models.yaml.\n"
        f"  expected {expected}\n  got      {actual}\n"
        f"The file was not installed.{where} Do not use it until you know why it differs.")


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
        digest = sha256_file(server)
        published = _published_server_hash(cfg, key)
        if published and digest != published:
            raise HashMismatch(
                f"installed llama-server {tag} for {key} does not match the hash published in "
                f"config/models.yaml.\n  expected {published}\n  got      {digest}")
        lock = read_lock()
        lc = lock.setdefault("llama_cpp", {})
        if lc.get("platform") != key or lc.get("verified_against_published") != bool(published):
            lc.update({"platform": key, "verified_against_published": bool(published)})
            write_lock(lock)
        print(f"llama.cpp {tag} already installed for {key}"
              + (" (matches published hash)" if published else ""))
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

    digest = sha256_file(server)
    published = _published_server_hash(cfg, key)
    if published and digest != published:
        shutil.rmtree(target, ignore_errors=True)
        raise HashMismatch(
            f"llama-server {tag} for {key} does not match the hash published in config/models.yaml.\n"
            f"  expected {published}\n  got      {digest}\nThe binary was removed and not installed.")
    if not published:
        print(f"note: no published hash for llama-server on {key}; recording this download as trusted "
              f"(trust on first use). Compare it with a known-good install before relying on it.")

    lock = read_lock()
    lock.setdefault("llama_cpp", {})
    lock["llama_cpp"] = {"tag": tag, "asset": cfg["assets"][key].format(tag=tag),
                         "platform": key, "server_sha256": digest,
                         "verified_against_published": bool(published)}
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

    published = _published_model_hash(m)
    if dest.exists():
        digest = sha256_file(dest)
        if published and digest != published:
            _reject(dest, f"{model_id} ({dest.name})", published, digest)
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
    if published and digest != published:
        _reject(dest, f"{model_id} ({dest.name})", published, digest)
    if not published:
        print(f"note: no published hash for {model_id}; recording this download as trusted "
              f"(trust on first use). Compare it with the SHA256 shown on the Hugging Face file page.")
    models_lock[model_id] = {"file": m["file"], "repo": m["repo"], "source_url": url, "sha256": digest,
                             "verified_against_published": bool(published)}
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

    pub_srv = _published_server_hash(manifest["llama_cpp"], lc.get("platform", "")) if lc.get("platform") else None
    if pub_srv and lc.get("server_sha256") != pub_srv:
        problems.append("llama-server hash in manifest.lock differs from the hash published in models.yaml")

    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        p = model_path(mid, manifest)
        rec = lock.get("models", {}).get(mid, {}).get("sha256")
        pub = _published_model_hash(manifest["models"].get(mid, {}))
        if pub and rec and rec != pub:
            problems.append(f"model {mid}: manifest.lock differs from the hash published in models.yaml")
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


def manifest_components(manifest: dict, tier: str, full: bool = False) -> dict:
    """Per-component integrity status for the Runtime panel.

    quick (default): config files and the llama-server binary are re-hashed (small files);
                     models are checked for presence and size only.
    full:            every model file is re-hashed too. Several seconds for multi-GB models.
    """
    from . import policy_path
    lock = read_lock()
    comps: list[dict] = []

    def row(kind, name, path, recorded, rehash):
        exists = path is not None and Path(path).exists()
        if not exists:
            status = "missing"
        elif recorded is None:
            status = "unlocked"
        elif rehash:
            status = "match" if sha256_file(Path(path)) == recorded else "mismatch"
        else:
            status = "present"
        comps.append({"kind": kind, "name": name, "sha256": recorded or "",
                      "status": status, "rehashed": bool(rehash and exists)})

    lc = lock.get("llama_cpp", {})
    server = None
    for cand in ("llama-server", "llama-server.exe"):
        p = BIN_DIR / lc.get("tag", "") / cand
        if p.exists():
            server = p
    row("binary", f"llama-server {lc.get('tag', '?')}", server, lc.get("server_sha256"), True)

    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        row("model", mid, model_path(mid, manifest),
            lock.get("models", {}).get(mid, {}).get("sha256"), full)

    active_policy = policy_path().name
    for name, h in lock.get("config", {}).items():
        row("config", name, CONFIG_DIR / name, h, True)
    if active_policy not in lock.get("config", {}):
        comps.append({"kind": "config", "name": active_policy, "sha256": "",
                      "status": "unlocked", "rehashed": False})

    bad = [c for c in comps if c["status"] in ("missing", "mismatch", "unlocked")]
    return {"mode": "full" if full else "quick",
            "status": "match" if not bad else "drift",
            "problems": [f"{c['kind']} {c['name']}: {c['status']}" for c in bad],
            "components": comps,
            "llama_cpp_tag": lc.get("tag", "")}


def publish_hashes(models_yaml: str, lock: dict) -> tuple[str, list[str]]:
    """Write the fingerprints in manifest.lock into models.yaml as published values.

    Edits the text in place so comments and layout survive. Returns (new_text, changes).
    Model hashes go on a `sha256:` line inside each model's block; the llama-server hash
    goes under `llama_cpp.server_sha256.<platform>`.
    """
    import re
    text, changes = models_yaml, []

    for mid, rec in sorted((lock.get("models") or {}).items()):
        h = rec.get("sha256")
        if not h:
            continue
        block = re.search(rf"(?m)^  {re.escape(mid)}:\n((?:    .*\n|\s*\n)+)", text)
        if not block:
            continue
        body = block.group(1)
        if re.search(r"(?m)^    sha256:.*$", body):
            new_body = re.sub(r"(?m)^    sha256:.*$", f"    sha256: {h}", body, count=1)
        else:
            new_body = re.sub(r"(?m)^(    file:.*\n)", rf"\1    sha256: {h}\n", body, count=1)
        if new_body != body:
            text = text[:block.start(1)] + new_body + text[block.end(1):]
            changes.append(f"{mid}: sha256 {h[:16]}...")

    lc = lock.get("llama_cpp") or {}
    plat, h = lc.get("platform"), lc.get("server_sha256")
    if plat and h:
        sect = re.search(r"(?m)^llama_cpp:\n((?:  .*\n|\s*\n)+)", text)
        if sect:
            body = sect.group(1)
            if re.search(r"(?m)^  server_sha256:\s*$", body):
                if re.search(rf"(?m)^    {re.escape(plat)}:.*$", body):
                    new_body = re.sub(rf"(?m)^    {re.escape(plat)}:.*$", f"    {plat}: {h}", body, count=1)
                else:
                    new_body = re.sub(r"(?m)^(  server_sha256:\s*\n)", rf"\1    {plat}: {h}\n", body, count=1)
            else:
                entry = ("  # Published hashes of the extracted llama-server binary, per platform.\n"
                         f"  server_sha256:\n    {plat}: {h}\n")
                new_body = re.sub(r"(?m)^(  base_url:.*\n)", rf"\1{entry}", body, count=1)
            if new_body != body:
                text = text[:sect.start(1)] + new_body + text[sect.end(1):]
                changes.append(f"llama-server ({plat}): sha256 {h[:16]}...")
    return text, changes
