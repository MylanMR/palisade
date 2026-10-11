"""Fetch pinned binaries and models, and maintain manifest.lock.

The lock file is the supply-chain record for this installation:
  - llama.cpp release tag, and the SHA-256 of every file in the model-server directory
    (the server and the shared libraries it loads)
  - every model file with its SHA-256
  - SHA-256 of settings.yaml, models.yaml, and the active policy file
    (policy.local.yaml if present, else policy.yaml)
Every audit record carries a hash of this lock, so a decision can always be tied to
the exact binaries, weights, and policy in force when it was made.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import httpx

from . import (
    BIN_DIR, CONFIG_DIR, MODELS_DIR, DATA_DIR, PACKAGED, PACKAGED_BIN,
    read_lock, write_lock, sha256_file, load_models, server_dir, config_file,
)
from .hardware import Host

Progress = Callable[[int, int], None]   # (bytes done, bytes total; 0 if unknown)


# ---------------------------------------------------------------- downloads
def hf_token() -> Optional[str]:
    """A Hugging Face access token, if one is configured, for models that require one.

    The default models do not. Looked up in order: HF_TOKEN, then hf-token in Palisade's
    config folder (service mode: readable by root and the audit group only), then the
    token file the Hugging Face CLI writes for the person running Palisade (desktop mode).
    """
    if os.environ.get("HF_TOKEN"):
        return os.environ["HF_TOKEN"].strip()
    for p in (CONFIG_DIR / "hf-token", Path.home() / ".cache" / "huggingface" / "token"):
        try:
            tok = p.read_text(encoding="utf-8").strip()
            if tok:
                return tok
        except OSError:
            continue
    return None


def _download(url: str, dest: Path, progress: Optional[Progress] = None,
              headers: Optional[dict] = None) -> None:
    """Download to dest via dest.part, resuming a partial download when the server allows.

    Multi-gigabyte model downloads get interrupted; restarting from zero each time
    would make first-run setup on a slow link impractical. Integrity does not depend
    on the transfer: every file is hashed after download and checked against a
    published or recorded value before anything trusts it.
    """
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

    def report(done: int, total: int) -> None:
        if progress:
            progress(done, total)
        elif total:
            sys.stdout.write(f"\r  {dest.name}: {done * 100 // total}% ({done >> 20} MB)")
            sys.stdout.flush()

    for attempt in range(5):
        have = tmp.stat().st_size if tmp.exists() else 0
        req_headers = dict(headers or {})
        if have:
            req_headers["Range"] = f"bytes={have}-"
        try:
            # httpx drops the Authorization header when a redirect leaves the original host,
            # so a token sent to huggingface.co is not forwarded to its storage CDN.
            with httpx.stream("GET", url, follow_redirects=True, timeout=httpx.Timeout(60.0, read=300.0),
                              headers=req_headers) as r:
                if r.status_code == 416 and have:          # already complete
                    break
                if r.status_code == 206 and have:
                    mode, done = "ab", have
                    total = have + int(r.headers.get("content-length", 0) or 0)
                elif r.status_code == 200:
                    mode, done = "wb", 0
                    total = int(r.headers.get("content-length", 0) or 0)
                else:
                    raise RuntimeError(f"HTTP {r.status_code} fetching {url}")
                with open(tmp, mode) as f:
                    for chunk in r.iter_bytes(1 << 20):
                        f.write(chunk)
                        done += len(chunk)
                        report(done, total)
            break
        except (httpx.TransportError, httpx.RemoteProtocolError) as e:
            if attempt == 4:
                raise RuntimeError(f"download kept failing ({e}); rerun to resume from where it stopped")
            print(f"\n  connection interrupted ({e}); resuming")
    if not progress:
        sys.stdout.write("\n")
    tmp.replace(dest)


# ---------------------------------------------------------------- published hashes
class HashMismatch(RuntimeError):
    pass


def _published_model_hash(m: dict) -> str | None:
    h = str(m.get("sha256", "") or "").strip().lower()
    return h or None


def _published_server_hash(cfg: dict, key: str) -> str | None:
    h = str((cfg.get("server_sha256") or {}).get(key, "") or "").strip().lower()
    return h or None


def _published_archive_hash(cfg: dict, key: str) -> str | None:
    h = str((cfg.get("archive_sha256") or {}).get(key, "") or "").strip().lower()
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
        f"{what} does not match the hash published in models.yaml.\n"
        f"  expected {expected}\n  got      {actual}\n"
        f"The file was not installed.{where} Do not use it until you know why it differs.")


# ---------------------------------------------------------------- llama.cpp
def _safe_extract(archive: Path, into: Path) -> None:
    """Extract without letting an archive write outside `into` (absolute paths, '..', links)."""
    into.mkdir(parents=True, exist_ok=True)
    root = into.resolve()
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            for name in z.namelist():
                target = (into / name).resolve()
                if root not in target.parents and target != root:
                    raise RuntimeError(f"archive entry escapes the extraction folder: {name}")
            z.extractall(into)
    else:
        with tarfile.open(archive) as t:
            if hasattr(tarfile, "data_filter"):
                t.extractall(into, filter="data")
            else:   # Python builds without tarfile's "data" filter (for example 3.9.6)
                for m in t.getmembers():
                    target = (into / m.name).resolve()
                    escapes = root not in target.parents and target != root
                    if m.issym():
                        link = (target.parent / m.linkname).resolve()
                        escapes = escapes or root not in link.parents
                    elif m.islnk():
                        escapes = escapes or root not in (into / m.linkname).resolve().parents
                    elif not (m.isfile() or m.isdir()):
                        escapes = True   # devices, fifos: never expected in a release archive
                    if escapes:
                        raise RuntimeError(f"archive entry escapes the extraction folder: {m.name}")
                t.extractall(into)


def _find_server(root: Path) -> Path:
    names = {"llama-server", "llama-server.exe"}
    for p in root.rglob("*"):
        if p.name in names and p.is_file():
            return p
    raise FileNotFoundError("llama-server not found in extracted archive")


_LIB = re.compile(r"(\.dll|\.dylib|\.so(\.\d+)*)$", re.IGNORECASE)
_OTHER_TOOL_LIB = re.compile(r"llama-(?!server-)[a-z0-9-]+-impl", re.IGNORECASE)


def is_runtime_file(name: str) -> bool:
    """Files llama-server needs: itself, the shared libraries it loads, and licenses.

    The release archives also carry about twenty other tools (benchmarks, converters,
    a CLI). Leaving them out shrinks what has to be signed, hashed, and trusted.
    """
    n = name.lower()
    if n in ("llama-server", "llama-server.exe") or n.startswith("license"):
        return True
    return bool(_LIB.search(n)) and not _OTHER_TOOL_LIB.search(n)


def bin_digests(d: Path) -> dict[str, str]:
    """SHA-256 of every file in the model-server directory, keyed by file name."""
    return {p.name: sha256_file(p) for p in sorted(d.iterdir()) if p.is_file() and not p.is_symlink()} \
        | {p.name: "symlink:" + os.readlink(p) for p in sorted(d.iterdir()) if p.is_symlink()}


def _server_in(d: Path) -> Path | None:
    for cand in ("llama-server", "llama-server.exe"):
        if (d / cand).exists():
            return d / cand
    return None


def register_packaged_binaries() -> dict:
    """Record the installer's bundled llama-server in manifest.lock.

    The build writes bin-manifest.json beside the binaries after signing them, listing
    every file's hash. The installed directory is owned by root (or SYSTEM), and the
    operating system verifies the package; this check catches anything changed since.
    """
    d = PACKAGED_BIN
    info = json.loads((d / "bin-manifest.json").read_text(encoding="utf-8"))
    expected: dict[str, str] = info["files"]
    actual = {k: v for k, v in bin_digests(d).items() if k != "bin-manifest.json"}
    bad = sorted(k for k in expected if actual.get(k) != expected[k])
    extra = sorted(set(actual) - set(expected))
    if bad or extra:
        raise HashMismatch(
            "the bundled model server does not match the list it was built with: "
            + ", ".join([f"{k} changed or missing" for k in bad] + [f"{k} not expected" for k in extra]))
    server = _server_in(d)
    lock = read_lock()
    lock["llama_cpp"] = {"tag": info["tag"], "platform": info["platform"], "packaged": True,
                         "server_sha256": sha256_file(server), "files": expected,
                         "verified_against_published": True}
    write_lock(lock)
    return lock["llama_cpp"]


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
                f"models.yaml.\n  expected {published}\n  got      {digest}")
        lock = read_lock()
        lc = lock.setdefault("llama_cpp", {})
        changed = False
        if lc.get("platform") != key or lc.get("verified_against_published") != bool(published):
            lc.update({"platform": key, "verified_against_published": bool(published)})
            changed = True
        if "files" not in lc and lc.get("server_sha256") == digest:
            # Older installs recorded only the server; record the libraries it loads too.
            lc["files"] = bin_digests(target)
            changed = True
        if changed:
            write_lock(lock)
        print(f"llama.cpp {tag} already installed for {key}"
              + (" (matches published hash)" if published else ""))
        return server

    stage = DATA_DIR / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    assets = [cfg["assets"][key]] + cfg.get("extra_assets", {}).get(key, "").split()
    for i, name in enumerate(filter(None, assets)):
        name = name.format(tag=tag)
        url = f"{cfg['base_url']}/{tag}/{name}"
        print(f"fetching {url}")
        arc = stage / name
        _download(url, arc)
        pub_arc = _published_archive_hash(cfg, key) if i == 0 else None
        if pub_arc:
            got = sha256_file(arc)
            if got != pub_arc:
                shutil.rmtree(stage, ignore_errors=True)
                raise HashMismatch(f"{name} does not match the archive hash published in models.yaml.\n"
                                   f"  expected {pub_arc}\n  got      {got}\nNothing was extracted.")
        _safe_extract(arc, stage / "x")

    found = _find_server(stage / "x")
    target.mkdir(parents=True, exist_ok=True)
    for p in found.parent.iterdir():
        if p.is_file() and is_runtime_file(p.name):
            shutil.copy2(p, target / p.name, follow_symlinks=False)
    if host.os != "windows":
        server.chmod(server.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    shutil.rmtree(stage, ignore_errors=True)

    digest = sha256_file(server)
    published = _published_server_hash(cfg, key)
    if published and digest != published:
        shutil.rmtree(target, ignore_errors=True)
        raise HashMismatch(
            f"llama-server {tag} for {key} does not match the hash published in models.yaml.\n"
            f"  expected {published}\n  got      {digest}\nThe binary was removed and not installed.")
    if not published and not _published_archive_hash(cfg, key):
        print(f"note: no published hash for llama-server on {key}; recording this download as trusted "
              f"(trust on first use). Compare it with a known-good install before relying on it.")

    lock = read_lock()
    lock["llama_cpp"] = {"tag": tag, "asset": cfg["assets"][key].format(tag=tag),
                         "platform": key, "server_sha256": digest, "files": bin_digests(target),
                         "verified_against_published": bool(published or _published_archive_hash(cfg, key))}
    write_lock(lock)
    print(f"installed llama-server {tag} -> {server}")
    return server


# ---------------------------------------------------------------- models
def model_path(model_id: str, manifest: dict) -> Path:
    m = manifest["models"][model_id]
    return MODELS_DIR / model_id / m["file"]


def install_model(model_id: str, manifest: dict, url_override: str | None = None,
                  progress: Optional[Progress] = None) -> Path:
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
            models_lock[model_id] = {"file": m["file"], "repo": m["repo"], "sha256": digest,
                                     "verified_against_published": bool(published)}
            write_lock(lock)
        print(f"{model_id} present, sha256 {digest[:16]}...")
        return dest

    if url_override:
        url = url_override
    else:
        if m["repo"].startswith("VERIFY/"):
            raise RuntimeError(
                f"{model_id}: repo is marked VERIFY in models.yaml. "
                f"Set the real Hugging Face repo id (see docs/MODELS.md) or pass --model-url.")
        url = f"{manifest['hf_base_url']}/{m['repo']}/resolve/main/{m['file']}"

    print(f"fetching {model_id} ({m.get('approx_gb', '?')} GB) from {url}")
    headers = {}
    tok = hf_token()
    if tok and url.startswith(str(manifest.get("hf_base_url", "https://huggingface.co")).rstrip("/") + "/"):
        headers["Authorization"] = f"Bearer {tok}"
    _download(url, dest, progress, headers)
    digest = sha256_file(dest)
    if published and digest != published:
        _reject(dest, f"{model_id} ({dest.name})", published, digest)
    if not published:
        print(f"note: no published hash for {model_id}; recording this download as trusted "
              f"(trust on first use). Compare it with the SHA256 shown on the Hugging Face file page.")
    lock = read_lock()   # re-read: the download can take an hour, and other steps may have written
    lock.setdefault("models", {})[model_id] = {
        "file": m["file"], "repo": m["repo"], "source_url": url, "sha256": digest,
        "verified_against_published": bool(published)}
    write_lock(lock)
    print(f"{model_id} sha256 {digest}")
    return dest


# ---------------------------------------------------------------- config
def record_config_hashes(only_missing: bool = False) -> dict:
    """Record config fingerprints. With only_missing, settings and policy already in the
    lock keep their recorded value, so an unexplained change still shows up as drift;
    models.yaml always follows the installed release because the package owns it."""
    from . import policy_path
    lock = read_lock()
    old = lock.get("config", {})
    active_policy = policy_path()
    cfg = {"models.yaml": sha256_file(config_file("models.yaml"))}
    for path in (CONFIG_DIR / "settings.yaml", active_policy):
        if only_missing and path.name in old:
            cfg[path.name] = old[path.name]
        else:
            cfg[path.name] = sha256_file(path)
    lock["config"] = cfg
    write_lock(lock)
    return lock


# ---------------------------------------------------------------- verification
@dataclass
class Problem:
    kind: str        # "missing": setup has not finished; "mismatch": something changed
    message: str

    def __str__(self) -> str:
        return self.message


def installation_problems(manifest: dict, tier: str) -> list[Problem]:
    """What stands between this installation and a verified start.

    "missing" problems are what first-run setup fills in. "mismatch" problems mean a
    file differs from its recorded or published hash; nothing repairs those
    automatically, because quietly re-trusting a changed file would defeat the check.
    """
    problems: list[Problem] = []
    lock = read_lock()
    if not lock:
        return [Problem("missing", "manifest.lock missing; run: palisade install"
                        if not PACKAGED else "setup has not run yet")]

    lc = lock.get("llama_cpp", {})
    d = server_dir(lc.get("tag", ""))
    server = _server_in(d) if d.exists() else None
    if server is None:
        problems.append(Problem("missing", "llama-server binary missing"))
    elif sha256_file(server) != lc.get("server_sha256"):
        problems.append(Problem("mismatch", "llama-server binary hash does not match manifest.lock"))
    elif lc.get("files"):
        actual = bin_digests(d)
        actual.pop("bin-manifest.json", None)
        for name, h in lc["files"].items():
            if actual.get(name) != h:
                problems.append(Problem("mismatch", f"model-server file {name} changed or is missing"))
        for name in sorted(set(actual) - set(lc["files"])):
            problems.append(Problem("mismatch", f"unexpected file in the model-server folder: {name}"))
    if PACKAGED_BIN and server is not None and not lc.get("packaged"):
        problems.append(Problem("missing", "bundled model server not yet recorded"))

    pub_srv = _published_server_hash(manifest["llama_cpp"], lc.get("platform", "")) if lc.get("platform") else None
    if pub_srv and not lc.get("packaged") and lc.get("server_sha256") != pub_srv:
        problems.append(Problem("mismatch", "llama-server hash in manifest.lock differs from the hash published in models.yaml"))

    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        p = model_path(mid, manifest)
        rec = lock.get("models", {}).get(mid, {}).get("sha256")
        pub = _published_model_hash(manifest["models"].get(mid, {}))
        if pub and rec and rec != pub:
            problems.append(Problem("mismatch", f"model {mid}: manifest.lock differs from the hash published in models.yaml"))
        if not p.exists():
            problems.append(Problem("missing", f"model file missing: {mid}"))
        elif rec is None:
            problems.append(Problem("missing", f"model {mid} has no hash in manifest.lock"))
        elif sha256_file(p) != rec:
            problems.append(Problem("mismatch", f"model {mid} hash does not match manifest.lock"))

    from . import policy_path
    recorded = lock.get("config", {})
    if not recorded:
        problems.append(Problem("missing", "config fingerprints not yet recorded"))
    elif policy_path().name not in recorded:
        problems.append(Problem("mismatch", f"config/{policy_path().name} is in force but was never recorded "
                                            f"(run `palisade install` to re-lock)"))
    for name, h in recorded.items():
        cfg_file = config_file(name)
        if not cfg_file.exists():
            problems.append(Problem("mismatch", f"config/{name} recorded in manifest.lock is missing "
                                                f"(run `palisade install` to re-lock)"))
        elif sha256_file(cfg_file) != h:
            # A new release ships a new models.yaml; setup records it. Settings and
            # policy belong to the operator, so a change there is reported, not absorbed.
            kind = "missing" if (name == "models.yaml" and PACKAGED) else "mismatch"
            problems.append(Problem(kind, f"config/{name} changed since install (run `palisade install` to re-lock)"))
    return problems


def verify_installation(manifest: dict, tier: str) -> list[str]:
    """Return a list of problems; empty means everything on disk matches the lock."""
    return [p.message for p in installation_problems(manifest, tier)]


def manifest_components(manifest: dict, tier: str, full: bool = False) -> dict:
    """Per-component integrity status for the Runtime panel.

    quick (default): config files and the model-server files are re-hashed (small files);
                     models are checked for presence only.
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
    d = server_dir(lc.get("tag", ""))
    server = _server_in(d) if d.exists() else None
    label = f"llama-server {lc.get('tag', '?')}" + (" (bundled)" if lc.get("packaged") else "")
    row("binary", label, server, lc.get("server_sha256"), True)
    libs = {k: v for k, v in (lc.get("files") or {}).items() if k != (server.name if server else "")}
    if libs:
        actual = bin_digests(d) if d.exists() else {}
        bad = sorted(k for k, v in libs.items() if actual.get(k) != v)
        comps.append({"kind": "binary", "name": f"{len(libs)} model-server libraries",
                      "sha256": "", "status": "mismatch" if bad else "match", "rehashed": True})

    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        row("model", mid, model_path(mid, manifest),
            lock.get("models", {}).get(mid, {}).get("sha256"), full)

    active_policy = policy_path().name
    for name, h in lock.get("config", {}).items():
        row("config", name, config_file(name), h, True)
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
