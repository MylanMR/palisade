#!/bin/bash
# Build the Linux .deb and .rpm.   packaging/linux/build.sh [OUTPUT_DIR]
# Needs: Python 3.9+ with PyYAML (pip install --require-hashes -r requirements-dev.lock).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${1:-$repo/dist}"
cache="$repo/build/cache"
payload="$repo/build/payload-linux-x64"
mkdir -p "$out" "$cache"

python3 "$repo/packaging/build_payload.py" --platform linux-x64 --out "$payload" --cache "$cache"

# nfpm, pinned and verified (packaging/inputs.yaml)
read -r nfpm_url nfpm_sha < <(python3 -c '
import yaml,sys; d=yaml.safe_load(open(sys.argv[1]))["nfpm"]; print(d["url"], d["sha256"])' "$repo/packaging/inputs.yaml")
tgz="$cache/$(basename "$nfpm_url")"
[ -f "$tgz" ] || curl -sSLf -o "$tgz" "$nfpm_url"
echo "$nfpm_sha  $tgz" | sha256sum -c --quiet || { rm -f "$tgz"; echo "nfpm hash mismatch" >&2; exit 1; }
mkdir -p "$cache/nfpm" && tar -xzf "$tgz" -C "$cache/nfpm" nfpm

version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$payload/install.json")
cd "$here"
# nfpm does not expand variables in content paths, so render the config first.
cfg="$repo/build/nfpm.rendered.yaml"
PALISADE_PAYLOAD="$payload" PALISADE_VERSION="$version" python3 -c '
import os,sys; t=open(sys.argv[1]).read()
for k in ("PALISADE_PAYLOAD","PALISADE_VERSION"): t=t.replace("${"+k+"}", os.environ[k])
open(sys.argv[2],"w").write(t)' nfpm.yaml "$cfg"
for fmt in deb rpm; do
  "$cache/nfpm/nfpm" package --config "$cfg" --packager "$fmt" --target "$out/"
done
ls -l "$out"
