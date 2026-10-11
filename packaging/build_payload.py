#!/usr/bin/env python3
"""Assemble the files every Palisade installer ships, for one platform.

  python packaging/build_payload.py --platform linux-x64 --out build/payload
  python packaging/build_payload.py --rehash-bin build/payload     (after code signing)

Run it on the platform being built (CI does), because Python packages with native code
are installed for the interpreter that runs them.

Payload layout (the installed "Palisade folder"):

  install.json              marks an installed copy; read by palisade/__init__.py
  runtime/                  Python, with Palisade's dependencies installed from requirements.lock
  palisade/ compliance/ eval/ config/
                            the application, and the default config copied on first run
  llama/                    llama-server and the libraries it loads, plus bin-manifest.json
  bin/                      launchers: `palisade` (POSIX) or palisade.cmd (Windows)
  LICENSE, THIRD_PARTY_NOTICES.txt, README.md, SECURITY.md, CHANGELOG.md

Every download is checked against a pinned SHA-256 before it is opened.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
PLATFORMS = ("macos-arm64", "macos-x64", "linux-x64", "windows-x64")
APP_DIRS = ("palisade", "compliance", "eval")
DOCS = ("LICENSE", "README.md", "SECURITY.md", "CHANGELOG.md")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, expected: str, cache: Path) -> Path:
    """Download once into the cache; verify the hash every time it is used."""
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / url.rsplit("/", 1)[-1].replace("%2B", "+")
    if not dest.exists():
        print(f"  downloading {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(url, timeout=300) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
        tmp.replace(dest)
    got = sha256(dest)
    if got != expected:
        dest.unlink()
        raise SystemExit(f"hash mismatch for {url}\n  expected {expected}\n  got      {got}\nRefusing to build.")
    return dest


def extract(archive: Path, into: Path) -> None:
    sys.path.insert(0, str(REPO))
    from palisade.fetch import _safe_extract   # the same path-traversal checks the app uses
    _safe_extract(archive, into)


def python_exe(runtime: Path, plat: str, windowed: bool = False) -> Path:
    if plat.startswith("windows"):
        return runtime / ("pythonw.exe" if windowed else "python.exe")
    return runtime / "bin" / "python3"


def site_packages(runtime: Path, plat: str) -> Path:
    if plat.startswith("windows"):
        return runtime / "Lib" / "site-packages"
    return next((runtime / "lib").glob("python3.*/site-packages"))


def build(plat: str, out: Path, cache: Path) -> None:
    inputs = yaml.safe_load((REPO / "packaging" / "inputs.yaml").read_text(encoding="utf-8"))
    models = yaml.safe_load((REPO / "config" / "models.yaml").read_text(encoding="utf-8"))
    version = _version()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    print(f"[1/6] Python {inputs['python']['version']} runtime")
    py = inputs["python"]["files"][plat]
    arc = fetch(f"{inputs['python']['base_url']}/{py['name'].replace('+', '%2B')}", py["sha256"], cache)
    stage = cache / f"stage-python-{plat}"
    shutil.rmtree(stage, ignore_errors=True)
    extract(arc, stage)
    shutil.move(str(stage / "python"), str(out / "runtime"))
    shutil.rmtree(stage, ignore_errors=True)
    runtime = out / "runtime"
    for junk in ("include", "share"):
        shutil.rmtree(runtime / junk, ignore_errors=True)

    print("[2/6] Dependencies from requirements.lock (exact versions, hash-verified, wheels only)")
    subprocess.run([str(python_exe(runtime, plat)), "-I", "-m", "pip", "install", "--disable-pip-version-check",
                    "--no-warn-script-location", "--root-user-action=ignore", "--require-hashes", "--only-binary", ":all:", "--no-compile",
                    "-r", str(REPO / "requirements.lock")], check=True)
    # pip itself is not needed at run time and is one more thing to patch; remove it.
    sp = site_packages(runtime, plat)
    for p in list(sp.glob("pip")) + list(sp.glob("pip-*.dist-info")):
        shutil.rmtree(p)
    for p in list((runtime / "bin").glob("pip*")) + list((runtime / "Scripts").glob("pip*")):
        p.unlink()
    # Make the payload root importable even under `python -I`: a relative .pth line is
    # resolved against site-packages, so the install folder can live anywhere.
    rel = os.path.relpath(out, sp)
    (sp / "palisade-root.pth").write_text(rel + "\n", encoding="utf-8")

    print("[3/6] Application")
    for d in APP_DIRS:
        shutil.copytree(REPO / d, out / d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (out / "config").mkdir()
    for name in ("models.yaml", "settings.yaml", "policy.yaml",
                 "policy.example-blank.yaml", "policy.example-standard.yaml"):
        shutil.copy2(REPO / "config" / name, out / "config" / name)
    for name in DOCS:
        shutil.copy2(REPO / name, out / name)

    print("[4/6] llama.cpp model server")
    key = inputs["llama"][plat]
    lc = models["llama_cpp"]
    asset = lc["assets"][key].format(tag=lc["tag"])
    arc = fetch(f"{lc['base_url']}/{lc['tag']}/{asset}", lc["archive_sha256"][key], cache)
    stage = cache / f"stage-llama-{plat}"
    shutil.rmtree(stage, ignore_errors=True)
    extract(arc, stage)
    from palisade.fetch import _find_server, is_runtime_file
    server = _find_server(stage)
    if sha256(server) != lc["server_sha256"][key]:
        raise SystemExit("llama-server inside the verified archive does not match server_sha256; refusing to build")
    llama = out / "llama"
    llama.mkdir()
    for p in server.parent.iterdir():
        if is_runtime_file(p.name) and (p.is_file() or p.is_symlink()):
            shutil.copy2(p, llama / p.name, follow_symlinks=False)
    shutil.rmtree(stage, ignore_errors=True)
    write_bin_manifest(out, tag=lc["tag"], platform=key)

    print("[5/6] Launchers, notices, install.json")
    (out / "bin").mkdir()
    if plat.startswith("windows"):
        (out / "bin" / "palisade.cmd").write_text(
            '@echo off\r\n"%~dp0..\\runtime\\python.exe" -I -m palisade %*\r\n', encoding="utf-8")
    else:
        launcher = out / "bin" / "palisade"
        launcher.write_text(POSIX_LAUNCHER, encoding="utf-8")
        launcher.chmod(0o755)
    write_notices(out, runtime, plat)
    info = {"version": version, "platform": plat, "bin": "llama", "llama_cpp": lc["tag"],
            "python": inputs["python"]["version"], "commit": _commit()}
    (out / "install.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")

    print("[6/6] Precompiling Python (the installed folder is read-only to Palisade)")
    subprocess.run([str(python_exe(runtime, plat)), "-I", "-m", "compileall", "-q",
                    "--invalidation-mode", "unchecked-hash", str(out / "palisade"), str(out / "compliance"),
                    str(runtime)], check=False)
    smoke(out, plat)
    print(f"payload ready: {out}")


POSIX_LAUNCHER = """#!/bin/sh
# Palisade launcher. Resolves its own location (it is usually reached through a symlink
# such as /usr/bin/palisade) and runs the bundled Python in isolated mode, so PYTHONPATH,
# PYTHONHOME, and per-user site-packages cannot change what code runs.
self="$0"
while [ -L "$self" ]; do
  link=$(readlink "$self")
  case "$link" in /*) self="$link" ;; *) self="$(dirname "$self")/$link" ;; esac
done
root=$(cd "$(dirname "$self")/.." && pwd -P)
exec "$root/runtime/bin/python3" -I -m palisade "$@"
"""


def write_bin_manifest(out: Path, tag: str | None = None, platform: str | None = None) -> None:
    """Record every model-server file's hash. Rerun after code signing changes the files."""
    llama = out / "llama"
    path = llama / "bin-manifest.json"
    old = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    files = {}
    for p in sorted(llama.iterdir()):
        if p.name == "bin-manifest.json":
            continue
        files[p.name] = ("symlink:" + os.readlink(p)) if p.is_symlink() else sha256(p)
    data = {"tag": tag or old["tag"], "platform": platform or old["platform"], "files": files}
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_notices(out: Path, runtime: Path, plat: str) -> None:
    parts = ["Palisade bundles the following third-party software. Each is distributed under",
             "its own license, reproduced below.\n"]

    def add(title: str, files) -> None:
        for f in files:
            if f.is_file():
                parts.append("=" * 78 + f"\n{title} ({f.name})\n" + "=" * 78)
                parts.append(f.read_text(encoding="utf-8", errors="replace"))

    add("CPython", [p for p in [runtime / "LICENSE.txt"] + list(runtime.glob("lib/python3.*/LICENSE.txt"))
                    if p.exists()])
    add("llama.cpp and bundled libraries", sorted((out / "llama").glob("LICENSE*")))
    sp = site_packages(runtime, plat)
    for dist in sorted(sp.glob("*.dist-info")):
        files = sorted(list(dist.glob("LICENSE*")) + list(dist.glob("COPYING*")) +
                       list(dist.glob("licenses/**/*")))
        add(dist.name.replace(".dist-info", ""), [f for f in files if f.is_file()])
    (out / "THIRD_PARTY_NOTICES.txt").write_text("\n".join(parts), encoding="utf-8")


def smoke(out: Path, plat: str) -> None:
    """Prove the payload runs before it is packaged: imports, mode detection, server binary."""
    host_os = {"darwin": "macos", "win32": "windows"}.get(sys.platform, "linux")
    if not plat.startswith(host_os):
        print("  (skipping smoke test: built for another platform)")
        return
    code = ("import palisade, palisade.server, palisade.setup, uvicorn, fastapi; "
            "assert palisade.PACKAGED and palisade.PACKAGED_BIN.name == 'llama', palisade.PACKAGED_BIN; "
            "print('  imports ok; mode', palisade.MODE, '; models file', palisade.MODELS_FILE)")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PALISADE_")}
    subprocess.run([str(python_exe(out / "runtime", plat)), "-I", "-c", code], check=True, env=env, cwd=str(out.parent))
    exe = out / "llama" / ("llama-server.exe" if plat.startswith("windows") else "llama-server")
    r = subprocess.run([str(exe), "--version"], capture_output=True, text=True)
    line = (r.stdout + r.stderr).strip().splitlines()
    print(f"  llama-server: {line[0] if line else 'no output'}")
    if r.returncode != 0:
        raise SystemExit("bundled llama-server does not run")


def _version() -> str:
    import re
    text = (REPO / "palisade" / "__init__.py").read_text(encoding="utf-8")
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def _commit() -> str:
    try:
        return subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:
        return "unknown"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--platform", choices=PLATFORMS)
    ap.add_argument("--out", type=Path, default=REPO / "build" / "payload")
    ap.add_argument("--cache", type=Path, default=REPO / "build" / "cache")
    ap.add_argument("--rehash-bin", type=Path, metavar="PAYLOAD",
                    help="rewrite llama/bin-manifest.json after signing changed the binaries")
    args = ap.parse_args(argv)
    if args.rehash_bin:
        write_bin_manifest(args.rehash_bin)
        print(f"rewrote {args.rehash_bin / 'llama' / 'bin-manifest.json'}")
        return 0
    if not args.platform:
        ap.error("--platform is required")
    build(args.platform, args.out.resolve(), args.cache.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
