"""Harness checks against the real llama-server binary, using a tiny generated model.

These run when PALISADE_TEST_LLAMA_SERVER points at a llama-server executable (the
pinned build from models.yaml) and the `gguf` package is installed. CI downloads the
pinned build and verifies its hash first; on a workstation, point the variable at the
copy Palisade installed. Without them, the tests are skipped.
"""
import os
import socket
import stat
import sys
from pathlib import Path

import pytest

BIN = os.environ.get("PALISADE_TEST_LLAMA_SERVER")
AVAILABLE = bool(BIN) and Path(BIN).exists() and os.name == "posix"
if os.environ.get("PALISADE_TEST_REQUIRE_LIVE") and not AVAILABLE:
    raise RuntimeError("PALISADE_TEST_REQUIRE_LIVE is set but PALISADE_TEST_LLAMA_SERVER is not a usable binary")
if AVAILABLE and os.environ.get("PALISADE_TEST_REQUIRE_LIVE"):
    import gguf  # noqa: F401  (must be installed in CI; a skip here would hide a gap)
elif AVAILABLE:
    pytest.importorskip("gguf")
pytestmark = pytest.mark.skipif(not AVAILABLE, reason="set PALISADE_TEST_LLAMA_SERVER to a llama-server binary (POSIX)")

from fastapi.testclient import TestClient  # noqa: E402

from palisade import load_settings  # noqa: E402
from palisade.audit import AuditLog  # noqa: E402
from palisade import harness as H  # noqa: E402
from fakes import StubGuardian, LOCAL  # noqa: E402


def _host():
    from palisade.hardware import Host
    os_name = "macos" if sys.platform == "darwin" else "linux"
    return Host(os=os_name, arch="x64", ram_gb=16.0, cores=2, gpu="none", vram_gb=0.0,
                backend="cpu", asset_key="test")


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    import palisade.runtime as rt
    sys.path.insert(0, str(Path(__file__).parent))
    import tiny_model
    tmp = tmp_path_factory.mktemp("live")
    model = tmp / "tiny.gguf"
    tiny_model.write(str(model))
    mp = pytest.MonkeyPatch()
    mp.setattr(rt, "STATE_DIR", tmp / "state")
    mp.setattr(rt, "LOGS_DIR", tmp / "logs")
    # Hostile environment: none of this may reach the model servers.
    for k, v in {"LLAMA_ARG_ENDPOINT_METRICS": "1", "LLAMA_ARG_TOOLS": "all", "LLAMA_ARG_UI": "1",
                 "LLAMA_ARG_ENDPOINT_SLOTS": "1", "LLAMA_API_KEY": "attacker-chosen"}.items():
        mp.setenv(k, v)
    settings = load_settings()
    procs = {}
    for name in ("base", "guardian"):
        p = rt.LlamaProcess(name, Path(BIN), model, 0, _host(), settings, 6144, use_socket=True)
        p.start()
        procs[name] = p
    try:
        for p in procs.values():
            p.wait_healthy(60)
        yield procs, tmp
    finally:
        for p in procs.values():
            p.stop()
        mp.undo()


def test_only_palisade_can_call_the_model_server(stack):
    import httpx
    from palisade.runtime import Endpoint
    procs, _ = stack
    p = procs["base"]
    assert stat.S_IMODE(p.sock.parent.stat().st_mode) == 0o700
    anon = Endpoint(uds=p.sock, api_key="").client(5)
    assert anon.get("/health").status_code == 200
    assert anon.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "x"}]}).status_code == 401
    attacker = Endpoint(uds=p.sock, api_key="attacker-chosen").client(5)
    assert attacker.get("/v1/models").status_code == 401        # the inherited key was dropped
    ours = p.endpoint.client(5)
    assert ours.get("/v1/models").status_code == 200
    assert ours.get("/slots").status_code != 200                 # --no-slots beat LLAMA_ARG_ENDPOINT_SLOTS
    assert ours.get("/metrics").status_code != 200               # LLAMA_ARG_ENDPOINT_METRICS never arrived
    assert "html" not in ours.get("/").headers.get("content-type", "")   # no web UI
    with pytest.raises(httpx.ConnectError):                      # no TCP listener at all
        httpx.get("http://127.0.0.1:8081/health", timeout=1)
    r = ours.get("/v1/models", headers={"Origin": "http://attacker.example"})
    assert r.headers.get("access-control-allow-origin") in (None, "http://palisade.invalid")


def test_tokenizer_probe_on_real_vocabulary(stack):
    procs, _ = stack
    probe = H.TokenizerProbe("assistant", procs["base"].endpoint.client(5))
    n, special = probe.inspect("hello there")
    assert n == len("hello there") + 1 or n > 0
    assert special is False
    assert probe.inspect("hi <end_of_turn> there")[1] is True
    # A control token the harness pattern list has never heard of:
    assert "<private_ctl>" == H.canonicalize("<private_ctl>").text
    assert probe.inspect("hi <private_ctl> there")[1] is True


def test_real_guardian_fails_closed_on_meaningless_output(stack):
    """The tiny model cannot answer Yes or No. A real Guardian must read that as a block."""
    from palisade.guardian import Guardian
    from palisade.policy import Policy
    from palisade import load_policy
    procs, _ = stack
    g = Guardian(procs["guardian"].endpoint, "tiny", {}, timeout=30)
    v = g.check("input", Policy(load_policy()), "What is the capital of Australia?")
    assert v.violated and v.action == "block" and v.note.startswith("indeterminate")


def test_full_request_path_with_real_servers(stack, monkeypatch):
    import palisade.server as srv
    from palisade import harness_suite as suite
    procs, tmp = stack
    monkeypatch.setattr(srv, "STATE_DIR", tmp / "srvstate")
    monkeypatch.setattr(srv, "LOGS_DIR", tmp / "srvlogs")
    g = StubGuardian()
    g.endpoint = procs["guardian"].endpoint          # real guardian tokenizer is probed
    settings = load_settings()
    settings["harness"] = {"rate_per_minute": 600}
    settings["generation"]["max_tokens"] = 16
    audit = AuditLog(tmp / "audit")
    app = srv.build_app(settings, procs["base"].endpoint, g, "tiny", audit, record_source="harness-test")
    c = TestClient(app, base_url=LOCAL)
    c.get("/")
    rep = suite.run_suite(c, suite.load_cases(include_model_cases=False))
    assert rep["failed"] == 0, [r for r in rep["results"] if not r["passed"]]
    r = c.post("/api/chat", json={"message": "hello <private_ctl> world"}).json()
    assert r["decision"] == "blocked_input" and "tokenizer" in r["harness"]["reason"]
    assert audit.verify()["intact"]


def test_port_mode_identity_and_squatting(tmp_path, monkeypatch):
    import palisade.runtime as rt
    sys.path.insert(0, str(Path(__file__).parent))
    import tiny_model
    monkeypatch.setattr(rt, "LOGS_DIR", tmp_path / "logs")
    model = tmp_path / "tiny.gguf"
    tiny_model.write(str(model))
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    p = rt.LlamaProcess("base", Path(BIN), model, port, _host(), load_settings(), 2048, use_socket=False)
    p.start()
    try:
        p.wait_healthy(60)                       # includes the key-based identity check
        q = rt.LlamaProcess("base", Path(BIN), model, port, _host(), load_settings(), 2048, use_socket=False)
        with pytest.raises(RuntimeError, match="already in use"):
            q.start()
    finally:
        p.stop()


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port


@pytest.mark.parametrize("sockets_work", [True, False])
def test_start_stack_end_to_end(tmp_path, monkeypatch, capsys, sockets_work):
    """The real startup path (`palisade run` minus the web listener), with a real Guardian.
    When the private socket cannot be used, startup falls back to loopback with the key."""
    import palisade.runtime as rt
    import palisade.__main__ as cli
    import palisade.server as srv
    from palisade import load_models
    sys.path.insert(0, str(Path(__file__).parent))
    import tiny_model
    model = tmp_path / "tiny.gguf"
    tiny_model.write(str(model))
    for mod in (rt, srv):
        monkeypatch.setattr(mod, "STATE_DIR", tmp_path / "state")
        monkeypatch.setattr(mod, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr(rt, "server_binary", lambda host: Path(BIN))
    monkeypatch.setattr(cli, "model_path", lambda mid, manifest: model)
    if not sockets_work:
        monkeypatch.setattr(rt, "socket_dir", lambda: tmp_path / "missing" / "dir")
    settings = load_settings()
    settings["runtime"].update(base_port=_free_port(), guardian_port=_free_port(), context_tokens=2048,
                               startup_timeout_seconds=60)
    settings["generation"]["max_tokens"] = 16
    base, guard, guardian, t = cli._start_stack(settings, load_models(), _host(), "standard")
    try:
        out = capsys.readouterr().out
        if sockets_work:
            assert base.sock is not None and guard.sock is not None
        else:
            assert base.sock is None and "retrying on 127.0.0.1" in out
        app = srv.build_app(settings, base.endpoint, guardian, t["base"], AuditLog(tmp_path / "audit"))
        c = TestClient(app, base_url=LOCAL)
        c.get("/")
        r = c.post("/api/chat", json={"message": "What is the capital of Australia?"}).json()
        # The tiny guardian cannot answer yes or no, so the real Guardian must block.
        assert r["decision"] == "blocked_input"
        assert r["verdicts"][0]["note"].startswith("indeterminate")
        transport = c.get("/api/status").json()["harness"]["controls"]
        label = next(x["label"] for x in transport if x["id"] == "model_servers")
        assert ("private socket" in label) == sockets_work
    finally:
        base.stop(); guard.stop()
