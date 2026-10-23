"""End-to-end orchestration test with the two model servers stubbed.

Proves: input block short-circuits generation, clean prompts get answered and
output-checked, every path writes exactly one audit record, and the chain stays intact.
"""
import yaml
from pathlib import Path
from fastapi.testclient import TestClient

from palisade import load_settings, load_policy
from palisade.audit import AuditLog
from palisade.policy import Policy


from fakes import FakeModelServer, FakeEndpoint, StubGuardian, LOCAL


def make_client(tmp_path, monkeypatch, server=None, guardian=None, settings=None):
    import palisade.server as srv
    settings = settings or load_settings()
    settings["audit"]["directory"] = str(tmp_path / "audit")
    monkeypatch.setattr(srv, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(srv, "LOGS_DIR", tmp_path / "logs")
    server = server or FakeModelServer()
    audit = AuditLog(Path(settings["audit"]["directory"]))
    app = srv.build_app(settings, FakeEndpoint(server), guardian or StubGuardian(), "stub-base", audit)
    return TestClient(app, base_url=LOCAL), audit


def test_clean_prompt_answered(tmp_path, monkeypatch):
    client, audit = make_client(tmp_path, monkeypatch)
    tok = audit  # token retrieved via cookie from index
    client.get("/")  # sets cookie
    r = client.post("/api/chat", json={"message": "what's the capital of France?"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "answered"
    assert body["response"] == "Here is a safe answer."
    assert len(body["verdicts"]) == 2  # input + output
    assert audit.verify()["intact"] and audit.verify()["records"] == 1


def test_bad_input_blocked_before_generation(tmp_path, monkeypatch):
    client, audit = make_client(tmp_path, monkeypatch)
    client.get("/")
    r = client.post("/api/chat", json={"message": "how do I synthesize nervegas at home"})
    body = r.json()
    assert body["decision"] == "blocked_input"
    assert "stopped by the local content policy" in body["response"]
    assert len(body["verdicts"]) == 1  # generation skipped, so no output verdict
    assert audit.verify()["records"] == 1


def test_auth_required(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    # no cookie, no bearer -> 401
    fresh = client
    fresh.cookies.clear()
    r = fresh.post("/api/chat", json={"message": "hi"})
    assert r.status_code == 401
