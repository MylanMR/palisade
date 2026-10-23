"""Fetch the pinned llama-server build for the live harness tests, verified.

    python packaging/test_llama_server.py OUT_DIR [--platform linux-x64-cpu]

Downloads the release archive named in config/models.yaml, refuses it unless its SHA-256
matches archive_sha256, extracts it without letting it write outside OUT_DIR, checks the
server binary against server_sha256, and prints the binary's path. CI sets
PALISADE_TEST_LLAMA_SERVER to that path.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from palisade.fetch import _download, _safe_extract, _server_in  # noqa: E402


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--platform", default="linux-x64-cpu")
    a = ap.parse_args(argv)
    lc = yaml.safe_load((ROOT / "config" / "models.yaml").read_text(encoding="utf-8"))["llama_cpp"]
    name = lc["assets"][a.platform].format(tag=lc["tag"])
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    archive = out / name
    if not archive.exists():
        _download(f"{lc['base_url']}/{lc['tag']}/{name}", archive)
    got, want = sha256(archive), lc["archive_sha256"][a.platform]
    if got != want:
        archive.unlink()
        print(f"archive hash mismatch: expected {want}, got {got}", file=sys.stderr)
        return 1
    dest = out / "llama"
    _safe_extract(archive, dest)
    server = next((s for s in (_server_in(d) for d in [dest, *dest.rglob("*")] if d.is_dir()) if s), None)
    if server is None or sha256(server) != lc["server_sha256"][a.platform]:
        print("llama-server missing or does not match server_sha256", file=sys.stderr)
        return 1
    server.chmod(0o755)
    print(server)
    return 0


if __name__ == "__main__":
    sys.exit(main())
