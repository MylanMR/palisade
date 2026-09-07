#!/usr/bin/env bash
# Palisade bootstrap for macOS and Linux.
# Creates a virtualenv, installs deps, downloads the pinned binary + models,
# then starts the stack. Re-running is safe; downloads are skipped if hashes match.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null; then echo "python3 not found on PATH"; exit 1; fi

if [ ! -d .venv ]; then
  echo "creating virtualenv"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

python -m palisade doctor || true
python -m palisade install "$@"
exec python -m palisade run
