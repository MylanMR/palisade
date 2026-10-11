"""Installed-copy behavior: layout by mode and platform, first-run setup, resumable and
verified downloads, safe archive extraction, the setup page, and the pinned build inputs."""
import hashlib
import http.server
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


# ---------- layout ----------
@pytest.mark.parametrize("mode,platform,env,expected", [
    ("service", "linux", {}, ("/etc/palisade", "/var/lib/palisade")),
    ("desktop", "linux", {}, ("/home/u/.config/palisade", "/home/u/.local/share/palisade")),
    ("desktop", "linux", {"XDG_CONFIG_HOME": "/x/c", "XDG_DATA_HOME": "/x/d"}, ("/x/c/palisade", "/x/d/palisade")),
    ("service", "darwin", {}, ("/Library/Application Support/Palisade/config",
                               "/Library/Application Support/Palisade/data")),
    ("desktop", "darwin", {}, ("/home/u/Library/Application Support/Palisade/config",
                               "/home/u/Library/Application Support/Palisade/data")),
    ("service", "win32", {"ProgramData": "C:/ProgramData"}, ("C:/ProgramData/Palisade/config", "C:/ProgramData/Palisade/data")),
    ("desktop", "win32", {"LOCALAPPDATA": "C:/Users/u/AppData/Local"},
     ("C:/Users/u/AppData/Local/Palisade/config", "C:/Users/u/AppData/Local/Palisade/data")),
])
def test_default_dirs(mode, platform, env, expected):
    from palisade import default_dirs
    cfg, data = default_dirs(mode, platform=platform, env=env, home=Path("/home/u"))
    assert (cfg.as_posix(), data.as_posix()) == expected


def test_source_checkout_layout_unchanged():
    import palisade
    assert palisade.MODE == "source" and not palisade.PACKAGED
    assert palisade.CONFIG_DIR == ROOT / "config"
    assert palisade.MODELS_FILE == ROOT / "config" / "models.yaml"


# ---------- release-archive filtering and extraction ----------
@pytest.mark.parametrize("name,keep", [
    ("llama-server", True), ("llama-server.exe", True), ("libllama-server-impl.so", True),
    ("llama-server-impl.dll", True), ("libggml-vulkan.so", True), ("libggml.0.23.0.dylib", True),
    ("libllama.so.0.4.0", True), ("libomp.dll", True), ("LICENSE-LLVM-OpenMP", True),
    ("llama-cli", False), ("llama-bench-impl.dll", False), ("libllama-bench-impl.so", False),
    ("ggml-rpc-server", False), ("ggml-metal-tuning", False),
])
def test_runtime_file_filter(name, keep):
    from palisade.fetch import is_runtime_file
    assert is_runtime_file(name) is keep


def _tar(path, members):
    with tarfile.open(path, "w:gz") as t:
        for name, data, link in members:
            ti = tarfile.TarInfo(name)
            if link is None:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            else:
                ti.type, ti.linkname = tarfile.SYMTYPE, link
                t.addfile(ti)
    return path


@pytest.mark.parametrize("without_filter", [False, True])
def test_safe_extract(tmp_path, monkeypatch, without_filter):
    from palisade.fetch import _safe_extract
    if without_filter:   # behave like Python builds that lack tarfile's data filter (3.9.6)
        monkeypatch.delattr(tarfile, "data_filter", raising=False)
    good = _tar(tmp_path / "good.tgz", [("x/libggml.0.dylib", b"lib", None), ("x/libggml.dylib", b"", "libggml.0.dylib")])
    _safe_extract(good, tmp_path / "ok")
    assert (tmp_path / "ok/x/libggml.dylib").is_symlink()
    for i, members in enumerate([[("../escape", b"x", None)], [("x/l", b"", "/etc/passwd")],
                                 [("x/l", b"", "../../outside")]]):
        with pytest.raises(Exception):
            _safe_extract(_tar(tmp_path / f"bad{i}.tgz", members), tmp_path / f"o{i}")
    z = tmp_path / "slip.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../slip", "x")
    with pytest.raises(RuntimeError):
        _safe_extract(z, tmp_path / "oz")
    assert not (tmp_path / "escape").exists() and not (tmp_path.parent / "slip").exists()


# ---------- a local "Hugging Face" with Range support that drops one connection ----------
class _Server:
    def __init__(self, files: dict[str, bytes]):
        self.files, self.dropped, self.requests = files, set(), []
        srv = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                data = srv.files.get(self.path)
                srv.requests.append((self.path, self.headers.get("Range")))
                if data is None:
                    self.send_error(404)
                    return
                m = re.match(r"bytes=(\d+)-", self.headers.get("Range", ""))
                start = int(m.group(1)) if m else 0
                self.send_response(206 if m else 200)
                if m:
                    self.send_header("Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}")
                self.send_header("Content-Length", str(len(data) - start))
                self.end_headers()
                body = data[start:]
                if self.path not in srv.dropped:          # first request: cut it off halfway
                    srv.dropped.add(self.path)
                    self.wfile.write(body[: len(body) // 2])
                    self.wfile.flush()
                    self.connection.shutdown(2)
                    return
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def test_download_resumes_after_interruption(tmp_path):
    from palisade.fetch import _download
    data = os.urandom(3_000_000)
    srv = _Server({"/f.bin": data})
    try:
        seen = []
        _download(f"{srv.url}/f.bin", tmp_path / "f.bin", progress=lambda d, n: seen.append((d, n)))
    finally:
        srv.close()
    assert (tmp_path / "f.bin").read_bytes() == data
    assert srv.requests[0][1] is None and srv.requests[1][1].startswith("bytes=")   # second request resumed
    assert seen[-1] == (len(data), len(data))


# ---------- first-run setup of an installed copy, end to end ----------
SETUP_SCRIPT = r'''
import json, os, sys
from pathlib import Path
import palisade
from palisade import setup, fetch, load_models, load_settings
from palisade.hardware import detect, choose_tier
assert palisade.PACKAGED and palisade.MODE == "desktop", (palisade.PACKAGED, palisade.MODE)
out = {}
out["ensure_config"] = sorted(palisade.ensure_config())
m = load_models(); tier = choose_tier(detect(), m["tiers"], "small")
out["needs_before"] = len(setup.needs_setup(m, tier)) > 0
out["rc"] = setup.run_setup(tier_override="small")
status = setup.read_status()
out["state"] = status["state"]
out["problems_after"] = [p.message for p in fetch.installation_problems(m, tier)]
out["needs_after"] = setup.needs_setup(m, tier)
lc = palisade.read_lock()["llama_cpp"]
out["packaged_recorded"] = lc.get("packaged") and sorted(lc["files"]) == ["libggml.so", "llama-server"]
# a second run at "boot" exits immediately
out["rc_again"] = setup.run_setup(tier_override="small", only_if_needed=True)
out["again_message"] = setup.read_status()["message"]
# tamper with a bundled library: reported as a mismatch, and setup does not re-trust it
(palisade.PACKAGED_BIN / "libggml.so").write_bytes(b"evil")
probs = fetch.installation_problems(m, tier)
out["tamper_kinds"] = sorted({p.kind for p in probs})
out["rc_tampered"] = setup.run_setup(tier_override="small")
print(json.dumps(out))
'''


def test_installed_copy_first_run_setup(tmp_path):
    guardian, base = os.urandom(900_000), os.urandom(1_200_000)
    models = yaml.safe_load((ROOT / "config/models.yaml").read_text())
    small = models["tiers"]["small"]
    mb, mg = models["models"][small["base"]], models["models"][small["guardian"]]
    srv = _Server({f"/{mb['repo']}/resolve/main/{mb['file']}": base,
                   f"/{mg['repo']}/resolve/main/{mg['file']}": guardian})
    try:
        pkg = tmp_path / "pkg"
        (pkg / "config").mkdir(parents=True)
        for name in ("settings.yaml", "policy.yaml", "policy.example-blank.yaml", "policy.example-standard.yaml"):
            (pkg / "config" / name).write_text((ROOT / "config" / name).read_text())
        models["hf_base_url"] = srv.url
        mb["sha256"] = hashlib.sha256(base).hexdigest()
        mg["sha256"] = hashlib.sha256(guardian).hexdigest()
        (pkg / "config/models.yaml").write_text(yaml.safe_dump(models))
        llama = pkg / "llama"
        llama.mkdir()
        (llama / "llama-server").write_bytes(b"server")
        (llama / "libggml.so").write_bytes(b"lib")
        files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in llama.iterdir()}
        (llama / "bin-manifest.json").write_text(json.dumps({"tag": "b10830", "platform": "linux-x64-vulkan", "files": files}))
        (pkg / "install.json").write_text(json.dumps({"version": "test", "bin": "llama"}))
        env = {k: v for k, v in os.environ.items() if not k.startswith("PALISADE_")}
        env.update(PALISADE_ROOT=str(pkg), HOME=str(tmp_path / "home"), PYTHONPATH=str(ROOT),
                   XDG_CONFIG_HOME=str(tmp_path / "home/.config"), XDG_DATA_HOME=str(tmp_path / "home/.local/share"),
                   LOCALAPPDATA=str(tmp_path / "home/AppData"))
        res = subprocess.run([sys.executable, "-c", SETUP_SCRIPT], env=env, cwd=tmp_path, capture_output=True, text=True)
    finally:
        srv.close()
    assert res.returncode == 0, res.stderr[-3000:]
    out = json.loads(res.stdout.strip().splitlines()[-1])
    assert "settings.yaml" in out["ensure_config"] and "policy.yaml" in out["ensure_config"]
    assert out["needs_before"] is True
    assert out["rc"] == 0 and out["state"] == "complete", out
    assert out["problems_after"] == [] and out["needs_after"] == []
    assert out["packaged_recorded"] is True
    assert out["rc_again"] == 0 and out["again_message"] == "Nothing to set up."
    assert out["tamper_kinds"] == ["mismatch"]
    assert out["rc_tampered"] != 0


# ---------- setup page ----------
def test_setup_app(tmp_path):
    from fastapi.testclient import TestClient
    from palisade import load_settings
    from palisade.fetch import Problem
    from palisade.server import build_setup_app
    status = tmp_path / "setup-status.json"
    status.write_text(json.dumps({"state": "running", "steps": [], "download": {"model": "m", "done": 5, "total": 10}}))
    problems = [Problem("missing", "model file missing: m")]
    c = TestClient(build_setup_app(load_settings(), lambda: problems, status))
    assert c.get("/api/setup/status").status_code == 401
    page = c.get("/")
    assert page.status_code == 200 and "Setting up Palisade" in page.text
    r = c.get("/api/setup/status").json()
    assert r["ready"] is False and r["setup"]["download"]["done"] == 5
    assert r["problems"] == [{"kind": "missing", "message": "model file missing: m"}]
    for method in ("get", "post"):
        assert getattr(c, method)("/api/chat").status_code == 503
    assert c.get("/static/setup.html").status_code == 404


# ---------- pinned build inputs and workflows ----------
def test_build_inputs_are_pinned():
    inputs = yaml.safe_load((ROOT / "packaging/inputs.yaml").read_text())
    models = yaml.safe_load((ROOT / "config/models.yaml").read_text())
    hexsha = re.compile(r"[0-9a-f]{64}")
    assert set(inputs["python"]["files"]) == {"macos-arm64", "macos-x64", "linux-x64", "windows-x64"}
    for f in inputs["python"]["files"].values():
        assert hexsha.fullmatch(f["sha256"]) and inputs["python"]["version"] in f["name"]
    for plat, key in inputs["llama"].items():
        assert hexsha.fullmatch(models["llama_cpp"]["archive_sha256"][key]), key
        assert hexsha.fullmatch(models["llama_cpp"]["server_sha256"][key]), key
    for tool in ("winsw", "nfpm"):
        assert hexsha.fullmatch(inputs[tool]["sha256"]) and inputs[tool]["version"] in inputs[tool]["url"]


def test_default_models_publish_hashes_or_say_so():
    models = yaml.safe_load((ROOT / "config/models.yaml").read_text())
    std = models["tiers"]["standard"]
    for mid in (std["base"], std["guardian"]):
        assert re.fullmatch(r"[0-9a-f]{64}", str(models["models"][mid].get("sha256", ""))), mid
    for t in models["tiers"].values():
        for k in ("base", "guardian"):
            assert not models["models"][t[k]]["repo"].startswith("VERIFY/"), t[k]


@pytest.mark.parametrize("wf", sorted((ROOT / ".github/workflows").glob("*.yml")), ids=lambda p: p.name)
def test_workflow_actions_pinned_and_token_read_only(wf):
    text = wf.read_text()
    for u in re.findall(r"uses:\s*(\S+)", text):
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), f"{wf.name}: not pinned to a full SHA: {u}"
    assert re.search(r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$", text), f"{wf.name}: default token must be read-only"


@pytest.mark.skipif(os.name == "nt", reason="bash syntax check")
def test_installers_and_scripts_parse():
    for sh in ["packaging/linux/palisade-mode", "packaging/linux/build.sh", "packaging/macos/palisade-mode",
               "packaging/macos/build.sh", "packaging/macos/uninstall.sh"] + \
              [str(p.relative_to(ROOT)) for p in (ROOT / "packaging").glob("*/scripts/**/*") if p.is_file()]:
        r = subprocess.run(["bash", "-n", str(ROOT / sh)], capture_output=True, text=True)
        assert r.returncode == 0, f"{sh}: {r.stderr}"
    import xml.etree.ElementTree as ET
    for x in ["packaging/windows/Palisade.wxs", "packaging/windows/Bundle.wxs",
              "packaging/macos/distribution.xml.in", "packaging/macos/desktop-mode.plist"]:
        ET.parse(ROOT / x)


def test_hf_token_sent_only_to_huggingface_host(tmp_path, monkeypatch):
    """A configured token goes to the model host but never follows a redirect to another host."""
    import httpx
    seen = {}

    class CDN(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen["cdn"] = self.headers.get("Authorization")
            self.send_response(200)
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"abc")

    cdn = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CDN)

    class HF(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen["hf"] = self.headers.get("Authorization")
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{cdn.server_address[1]}/blob")
            self.end_headers()

    hf = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HF)
    for s in (cdn, hf):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        from palisade.fetch import install_model
        import palisade.fetch as f
        monkeypatch.setenv("HF_TOKEN", "hf_secret")
        monkeypatch.setattr(f, "MODELS_DIR", tmp_path / "models")
        monkeypatch.setattr(f, "read_lock", lambda: {})
        monkeypatch.setattr(f, "write_lock", lambda lock: None)
        manifest = {"hf_base_url": f"http://127.0.0.1:{hf.server_address[1]}",
                    "models": {"m": {"repo": "o/r", "file": "m.gguf", "sha256": hashlib.sha256(b"abc").hexdigest()}}}
        install_model("m", manifest)
    finally:
        cdn.shutdown(); hf.shutdown()
    assert seen == {"hf": "Bearer hf_secret", "cdn": None}
