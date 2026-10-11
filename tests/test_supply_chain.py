"""Supply-chain and exposure controls: hash-locked dependencies, published model and
binary hashes, and the startup refusal to bind to a network address."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from palisade.exposure import check_exposure, is_loopback

ROOT = Path(__file__).resolve().parents[1]


# ---------- dependency locks ----------
def _lock_entries(path):
    text = (ROOT / path).read_text()
    entries = {}
    for block in re.split(r"\n(?=[a-z0-9])", text):
        m = re.match(r"([a-z0-9][a-z0-9._-]*)==([^\s;\\]+)", block, re.I)
        if m:
            entries.setdefault(m.group(1).lower().replace("_", "-"), []).append(
                (m.group(2), len(re.findall(r"--hash=sha256:[0-9a-f]{64}", block))))
    return entries


def _requirement_names(path):
    names = []
    for line in (ROOT / path).read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            names.append(re.split(r"[<>=\[; ]", line)[0].lower().replace("_", "-"))
    return names


@pytest.mark.parametrize("lock,sources", [
    ("requirements.lock", ["requirements.txt"]),
    ("requirements-dev.lock", ["requirements.txt", "requirements-dev.txt"]),
])
def test_locks_pin_every_requirement_with_hashes(lock, sources):
    entries = _lock_entries(lock)
    for src in sources:
        for name in _requirement_names(src):
            assert name in entries, f"{name} from {src} is missing from {lock}"
    for name, versions in entries.items():
        for version, nhashes in versions:
            assert nhashes >= 1, f"{name}=={version} in {lock} has no hash"


def test_every_installer_uses_hash_verified_lock():
    for script in ["scripts/bootstrap.sh", "scripts/bootstrap.ps1",
                   "scripts/service/macos/install.sh", "scripts/service/linux/install.sh",
                   ".github/workflows/ci.yml"]:
        text = (ROOT / script).read_text()
        installs = [l for l in text.splitlines() if "pip install" in l and not l.strip().startswith("#")]
        assert installs, f"{script} installs nothing?"
        for line in installs:
            assert "--require-hashes" in line and ".lock" in line, f"unverified install in {script}: {line}"


def test_ci_actions_pinned_to_commit_shas():
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), f"not pinned to a full SHA: {u}"
    assert re.search(r"(?m)^permissions:\s*\n\s+contents:\s*read", text)


# ---------- exposure guard ----------
@pytest.mark.parametrize("host,extra,refused,warned", [
    ("127.0.0.1", {}, False, False),
    ("::1", {}, False, False),
    ("localhost", {}, False, False),
    ("0.0.0.0", {}, True, False),
    ("192.168.1.20", {}, True, False),
    ("mini.local", {}, True, False),
    ("0.0.0.0", {"allow_remote": True}, False, True),
    ("0.0.0.0", {"allow_remote": "yes"}, True, False),
    ("0.0.0.0", {"allow_remote": True, "require_token": False}, True, False),
    ("127.0.0.1", {"require_token": False}, False, True),
])
def test_exposure_rules(host, extra, refused, warned):
    errors, warnings = check_exposure({"server": {"host": host, **extra}})
    assert bool(errors) == refused
    assert bool(warnings) == warned


def test_shipped_settings_are_local_only():
    import yaml
    settings = yaml.safe_load((ROOT / "config/settings.yaml").read_text())
    assert is_loopback(settings["server"]["host"])
    assert settings["server"].get("require_token", True) is True
    assert settings["server"].get("allow_remote", False) is False
    assert check_exposure(settings) == ([], [])


# ---------- published hashes (isolated data directory) ----------
SCRIPT = r'''
import hashlib, json, os, sys
from pathlib import Path
from palisade import load_models, read_lock, BIN_DIR
from palisade.fetch import install_model, install_binaries, HashMismatch, verify_installation, model_path
from palisade.hardware import Host
out = {}
src = Path(os.environ["SRC"]); src.write_bytes(b"genuine weights")
good = hashlib.sha256(b"genuine weights").hexdigest()
m = load_models(); mid = "gemma4-12b"

def attempt(name, published, pre_existing=None):
    mm = json.loads(json.dumps(m)); mm["models"][mid]["sha256"] = published
    dest = model_path(mid, mm)
    for p in (dest, dest.with_name(dest.name + ".rejected")):
        if p.exists(): p.unlink()
    lk = read_lock(); lk.get("models", {}).pop(mid, None)
    from palisade import write_lock; write_lock(lk)
    if pre_existing is not None:
        dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(pre_existing)
    try:
        install_model(mid, mm, None if pre_existing is not None else src.as_uri())
        r = "installed"
    except HashMismatch:
        r = "rejected"
    rec = read_lock().get("models", {}).get(mid)
    out[name] = {"result": r, "recorded": bool(rec), "verified": (rec or {}).get("verified_against_published"),
                 "file_left_in_place": dest.exists(),
                 "quarantined": dest.with_name(dest.name + ".rejected").exists()}

attempt("no_published_hash", "")
attempt("correct_published_hash", good)
attempt("wrong_published_hash", "0" * 64)
attempt("hand_placed_tampered_file", good, pre_existing=b"tampered weights")

# lock disagrees with published -> verify_installation reports it
mm = json.loads(json.dumps(m)); mm["models"][mid]["sha256"] = good
install_model(mid, mm, src.as_uri())
mm["models"][mid]["sha256"] = "f" * 64
out["verify_flags_lock_vs_published"] = any("differs from the hash published" in p
                                            for p in verify_installation(mm, "standard"))

# installed binary checked against its published hash even when already present
host = Host("macos", "arm64", 48, 12, "apple", 33, "metal", "macos-arm64")
tag = m["llama_cpp"]["tag"]; (BIN_DIR / tag).mkdir(parents=True, exist_ok=True)
(BIN_DIR / tag / "llama-server").write_bytes(b"server")
cfg = json.loads(json.dumps(m))
cfg["llama_cpp"]["server_sha256"] = {"macos-arm64": hashlib.sha256(b"server").hexdigest()}
install_binaries(host, cfg)
out["binary_matching_accepted"] = read_lock()["llama_cpp"]["verified_against_published"]
cfg["llama_cpp"]["server_sha256"] = {"macos-arm64": "0" * 64}
try:
    install_binaries(host, cfg); out["binary_mismatch"] = "accepted"
except HashMismatch:
    out["binary_mismatch"] = "rejected"
print(json.dumps(out))
'''


def test_published_hashes_enforced(tmp_path):
    env = dict(os.environ, PALISADE_DATA=str(tmp_path / "data"), PYTHONPATH=str(ROOT),
               SRC=str(tmp_path / "weights.gguf"))
    res = subprocess.run([sys.executable, "-c", SCRIPT], env=env, cwd=ROOT, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout.strip().splitlines()[-1])
    assert out["no_published_hash"] == {"result": "installed", "recorded": True, "verified": False,
                                        "file_left_in_place": True, "quarantined": False}
    assert out["correct_published_hash"]["result"] == "installed" and out["correct_published_hash"]["verified"] is True
    for case in ("wrong_published_hash", "hand_placed_tampered_file"):
        assert out[case] == {"result": "rejected", "recorded": False, "verified": None,
                             "file_left_in_place": False, "quarantined": True}, case
    assert out["verify_flags_lock_vs_published"] is True
    assert out["binary_matching_accepted"] is True
    assert out["binary_mismatch"] == "rejected"
