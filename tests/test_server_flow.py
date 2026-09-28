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


class StubGuardian:
    """Flags any text containing a trigger word, at the stage's strongest action."""
    model_id = "stub-guardian"; mode = "combined"; threshold = 0.5
    def __init__(self): self._policy = Policy(load_policy())
    def check(self, stage, policy, prompt, response=""):
        from palisade.audit import GuardianVerdict
        text = (prompt + " " + response).lower()
        hit = "nervegas" in text
        cats = policy.for_stage(stage)
        action = Policy.strongest_action(cats) if hit else "allow"
        return GuardianVerdict(stage, self.model_id, self.mode, 0.99 if hit else 0.01,
                               self.threshold, hit, [], action, 3)


def make_client(tmp_path, monkeypatch):
    import palisade.server as srv
    settings = load_settings()
    settings["audit"]["directory"] = str(tmp_path / "audit")
    monkeypatch.setattr(srv, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(srv, "LOGS_DIR", tmp_path / "logs")

    class FakeResp:
        status_code = 200
        def json(self): return {"choices": [{"message": {"content": "Here is a safe answer."}}]}
    class FakeClient:
        def post(self, url, json=None): return FakeResp()
    monkeypatch.setattr(srv.httpx, "Client", lambda *a, **k: FakeClient())

    audit = AuditLog(Path(settings["audit"]["directory"]))
    app = srv.build_app(settings, "http://base", StubGuardian(), "stub-base", audit)
    return TestClient(app), audit


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
