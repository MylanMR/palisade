#!/usr/bin/env python3
"""Compare models.yaml against the SHA-256 that Hugging Face publishes for each model file.

Hugging Face stores model files in Git LFS and reports each file's SHA-256 through its API.
That is an independent source for the hashes in models.yaml, which may have been recorded
from someone's own download.

  python packaging/hf_hashes.py            report, exit 1 on any mismatch or missing hash
  python packaging/hf_hashes.py --write    also fill in missing hashes (never overwrites one)

Checks every model used by a tier. Needs network access to huggingface.co; uses only the
standard library, so it runs before any dependencies are installed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "config" / "models.yaml"


def hf_sha256(repo: str, file: str) -> str | None:
    url = f"https://huggingface.co/api/models/{repo}/tree/main"
    with urllib.request.urlopen(url, timeout=60) as r:
        for entry in json.load(r):
            if entry.get("path") == file:
                return (entry.get("lfs") or {}).get("oid")
    return None


def main(argv=None) -> int:
    import yaml  # PyYAML; present on GitHub runners and in Palisade's environment
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="fill in missing sha256 lines")
    args = ap.parse_args(argv)
    text = MODELS.read_text(encoding="utf-8")
    cfg = yaml.safe_load(text)
    used = sorted({mid for t in cfg["tiers"].values() for k, mid in t.items() if k in ("base", "guardian")})
    failed = False
    for mid in used:
        m = cfg["models"][mid]
        if m["repo"].startswith("VERIFY/"):
            print(f"FAIL  {mid}: repository is still marked VERIFY")
            failed = True
            continue
        try:
            remote = hf_sha256(m["repo"], m["file"])
        except Exception as e:
            print(f"FAIL  {mid}: could not query Hugging Face ({e})")
            failed = True
            continue
        local = str(m.get("sha256") or "").lower() or None
        if remote is None:
            print(f"FAIL  {mid}: {m['file']} not found in {m['repo']}")
            failed = True
        elif local == remote:
            print(f"OK    {mid}: {remote}")
        elif local:
            print(f"FAIL  {mid}: models.yaml has {local}\n            Hugging Face has {remote}")
            failed = True
        elif args.write:
            block = re.search(rf"(?m)^  {re.escape(mid)}:\n((?:    .*\n|\s*\n)+)", text)
            body = block.group(1)
            new_body = re.sub(r"(?m)^(    file:.*\n)", rf"\1    sha256: {remote}\n", body, count=1)
            text = text[:block.start(1)] + new_body + text[block.end(1):]
            print(f"ADDED {mid}: {remote}")
        else:
            print(f"FAIL  {mid}: no sha256 in models.yaml (Hugging Face has {remote}; rerun with --write)")
            failed = True
    if args.write:
        yaml.safe_load(text)
        MODELS.write_text(text, encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
