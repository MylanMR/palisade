"""Tests for the reviewable audit log, anchors, permissions, and the review API."""
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from palisade import secure_write_text, load_settings, load_models
from palisade.audit import AuditLog, AuditRecord, GENESIS
from palisade import review
from palisade.describe import label_of, quant_of

POSIX = os.name == "posix"
ROOT = Path(__file__).resolve().parents[1]


def _rec(decision="answered", p_in=0.02, cats=()):
    return AuditRecord(seq=0, ts="2026-09-28T00:00:00Z", request_id="r", manifest_hash="m",
                       policy_version="1.0.0", base_model="b", guardian_model="g", decision=decision,
                       prompt_sha256="p", response_sha256="s",
                       verdicts=[{"stage": "input", "p_violation": p_in, "categories": list(cats)}],
                       latency_ms=1)


def _log(tmp_path, decisions=("answered", "flagged", "blocked_input", "answered", "blocked_output")):
    log = AuditLog(tmp_path / "audit")
    for d in decisions:
        log.append(_rec(d, 0.95 if d.startswith("blocked") else 0.02))
    return log


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


# ---------- permissions ----------
@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_new_audit_files_are_group_read_only(tmp_path):
    log = _log(tmp_path, ("answered",))
    f = next((tmp_path / "audit").glob("audit-*.jsonl"))
    assert _mode(f) == 0o640
    assert _mode(tmp_path / "audit") == 0o2750


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_secure_write_never_changes_an_existing_parent(tmp_path):
    """Regression: writing a report into a user's folder must not alter that folder."""
    folder = tmp_path / "users-folder"
    folder.mkdir()
    os.chmod(folder, 0o755)
    out = secure_write_text(folder / "report.log", "x")
    assert _mode(folder) == 0o755
    assert _mode(out) == 0o640


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_apply_permissions_repairs_loose_files(tmp_path):
    log = _log(tmp_path, ("answered",))
    f = next((tmp_path / "audit").glob("audit-*.jsonl"))
    os.chmod(f, 0o666)
    assert log.apply_permissions() == []
    assert _mode(f) == 0o640


def test_empty_log_creates_no_file_until_first_append(tmp_path):
    log = AuditLog(tmp_path / "audit")
    assert list((tmp_path / "audit").glob("*.jsonl")) == []
    log.append(_rec())
    assert len(list((tmp_path / "audit").glob("*.jsonl"))) == 1


# ---------- text review log ----------
def test_report_contents_and_self_hash(tmp_path):
    log = _log(tmp_path)
    text = review.render_report(log, manifest_hash="abc")
    assert "Chain status:   INTACT (5 records verified)" in text
    assert "BLOCKED-INPUT" in text and "FLAGGED" in text
    assert "Records listed: 5" in text
    assert review.check_report(text)["valid"]
    assert not review.check_report(text.replace("FLAGGED ", "answered", 1))["valid"]


def test_report_filter_blocked(tmp_path):
    text = review.render_report(_log(tmp_path), decision="blocked")
    assert "Records listed: 2" in text and "answered " not in text.split("=" * 118)[1]


def test_report_flags_broken_chain(tmp_path):
    log = _log(tmp_path)
    f = next((tmp_path / "audit").glob("audit-*.jsonl"))
    lines = f.read_text().splitlines()
    lines[2] = lines[2].replace('"blocked_input"', '"answered"')
    f.write_text("\n".join(lines) + "\n")
    text = review.render_report(AuditLog(tmp_path / "audit"))
    assert "BROKEN at record #3" in text and "UNTRUSTED" in text


# ---------- anchors ----------
def test_anchor_detects_every_tamper_pattern(tmp_path):
    log = _log(tmp_path)
    a = review.anchor(log)
    assert review.check_anchor(log, a)["valid"]
    f = next((tmp_path / "audit").glob("audit-*.jsonl"))
    pristine = f.read_text()

    # 1. content edit, stored hashes left alone
    f.write_text(pristine.replace('"decision":"blocked_input"', '"decision":"answered"'))
    assert not review.check_anchor(AuditLog(tmp_path / "audit"), a)["valid"]

    # 2. full rewrite with every hash recomputed: internal verify passes, anchor does not
    recs = [json.loads(l) for l in pristine.splitlines()]
    recs[2]["decision"] = "answered"
    prev = GENESIS
    for r in recs:
        r["prev_hash"] = prev
        r["hash"] = AuditLog.compute_hash(prev, r)
        prev = r["hash"]
    f.write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in recs))
    rewritten = AuditLog(tmp_path / "audit")
    assert rewritten.verify()["intact"]
    assert not review.check_anchor(rewritten, a)["valid"]

    # 3. truncation
    f.write_text("\n".join(pristine.splitlines()[:2]) + "\n")
    res = review.check_anchor(AuditLog(tmp_path / "audit"), a)
    assert not res["valid"] and "removed" in res["reason"]


# ---------- labels ----------
@pytest.mark.parametrize("fname,label,quant", [
    ("gemma-4-12B-it-Q4_K_M.gguf", "Gemma 4 12B", "Q4_K_M"),
    ("shieldgemma-2b.Q8_0.gguf", "ShieldGemma 2B", "Q8_0"),
    ("granite-guardian-3.3-8b-Q4_K_M.gguf", "Granite Guardian 3.3 8B", "Q4_K_M"),
])
def test_model_labels(fname, label, quant):
    assert label_of("x", {"file": fname}) == label
    assert quant_of(fname) == quant


# ---------- review API ----------
from fakes import FakeModelServer, FakeEndpoint, StubGuardian, LOCAL


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    import palisade.server as srv
    monkeypatch.setattr(srv, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(srv, "LOGS_DIR", tmp_path / "logs")
    settings = load_settings()
    audit = AuditLog(tmp_path / "audit")
    g = StubGuardian()
    g.model_id = "shieldgemma-2b"
    app = srv.build_app(settings, FakeEndpoint(FakeModelServer("ok")), g, "gemma4-12b", audit,
                        models_cfg=load_models(), tier="standard", backend="metal")
    c = TestClient(app, base_url=LOCAL)
    c.get("/")
    token = (tmp_path / "state" / "reviewer.token").read_text().strip()
    return c, token, tmp_path


def test_review_requires_reviewer_token(app_client):
    c, token, _ = app_client
    c.post("/api/chat", json={"message": "hello"})
    assert c.get("/api/review/records").status_code == 403
    assert c.get("/api/audit/tail").status_code == 403
    assert c.post("/api/review/login", json={"token": "wrong"}).status_code == 403
    assert c.post("/api/review/login", json={"token": token}).status_code == 200
    recs = c.get("/api/review/records").json()
    assert len(recs) == 1 and recs[0]["decision"] == "answered"


def test_review_requires_session_token_too(app_client):
    c, token, _ = app_client
    c.cookies.clear()
    assert c.post("/api/review/login", json={"token": token}).status_code == 401


def test_review_filter_and_report_export(app_client):
    c, token, tmp = app_client
    for m in ("hello", "nervegas please", "thanks"):
        c.post("/api/chat", json={"message": m})
    c.post("/api/review/login", json={"token": token})
    blocked = c.get("/api/review/records?decision=blocked").json()
    assert [r["decision"] for r in blocked] == ["blocked_input"]
    assert c.get("/api/review/records?decision=bogus").status_code == 400
    r = c.post("/api/review/report", json={"decision": None, "include_content": False})
    assert r.status_code == 200 and review.check_report(r.text)["valid"]
    saved = Path(r.headers["x-palisade-saved-to"])
    assert saved.exists()
    if POSIX:
        assert _mode(saved) == 0o640
    log = (tmp / "logs" / "review-access.log").read_text()
    assert '"event": "login"' in log and '"event": "report_export"' in log


def test_review_login_rate_limited(app_client):
    c, token, _ = app_client
    for _ in range(10):
        c.post("/api/review/login", json={"token": "wrong"})
    assert c.post("/api/review/login", json={"token": token}).status_code == 429


def test_status_reports_runtime_details(app_client):
    c, _, _ = app_client
    s = c.get("/api/status").json()
    assert s["assistant"]["label"] == "Gemma 4 12B" and s["assistant"]["backend_label"] == "Metal GPU"
    assert s["assistant"]["healthy"] is True           # the fake model server answers /health
    assert {c["id"] for c in s["harness"]["controls"]} >= {"probe", "history", "canary", "fail_closed"}
    assert s["guardian"]["check_input"] and s["guardian"]["check_output"]
    assert s["policy"]["counts"]["block"] >= 1 and s["policy"]["categories"]
    c.post("/api/chat", json={"message": "hello"})
    h = c.get("/api/health").json()
    assert h["session"]["counts"]["messages"] == 1 and h["session"]["last"]["input"]["p"] == 0.01


def test_static_route_is_allowlisted(app_client):
    c, _, _ = app_client
    assert c.get("/static/shared.css").status_code == 200
    assert c.get("/static/server.py").status_code == 404
    assert c.get("/static/..%2F__init__.py").status_code == 404


# ---------- manifest components (isolated data dir via subprocess) ----------
def test_manifest_quick_and_full_detect_model_tampering(tmp_path):
    script = r'''
import json, sys
from palisade import BIN_DIR, MODELS_DIR, write_lock, sha256_file, load_models
from palisade.fetch import record_config_hashes, manifest_components, model_path
m = load_models(); t = m["tiers"]["standard"]
(BIN_DIR / "b10830").mkdir(parents=True); (BIN_DIR / "b10830" / "llama-server").write_bytes(b"bin")
lock = {"llama_cpp": {"tag": "b10830", "server_sha256": sha256_file(BIN_DIR / "b10830" / "llama-server")}, "models": {}}
for mid in (t["base"], t["guardian"]):
    p = model_path(mid, m); p.parent.mkdir(parents=True); p.write_bytes(b"weights")
    lock["models"][mid] = {"sha256": sha256_file(p)}
write_lock(lock); record_config_hashes()
out = {"clean_quick": manifest_components(m, "standard")["status"]}
model_path(t["base"], m).write_bytes(b"tampered")
out["tampered_quick"] = manifest_components(m, "standard")["status"]
out["tampered_full"] = manifest_components(m, "standard", full=True)["status"]
print(json.dumps(out))
'''
    env = dict(os.environ, PALISADE_DATA=str(tmp_path / "data"), PYTHONPATH=str(ROOT))
    res = subprocess.run([sys.executable, "-c", script], env=env, cwd=ROOT, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout.strip().splitlines()[-1])
    # quick mode checks model presence only; full mode re-hashes and catches the swap
    assert out == {"clean_quick": "match", "tampered_quick": "match", "tampered_full": "drift"}
