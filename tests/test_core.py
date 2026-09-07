"""Tests that run without any model present.

Covers the parts that carry the security guarantees: the hash chain, its tamper
detection across edits/deletes/reorders, the policy action resolution, and the
guardian's logprob-to-probability parsing.
"""
import json
from pathlib import Path

import pytest

from palisade.audit import AuditLog, AuditRecord, GENESIS
from palisade.policy import Policy


# ---------- audit chain ----------
def _rec(decision="answered"):
    return AuditRecord(
        seq=0, ts="2026-09-06T00:00:00Z", request_id="r", manifest_hash="m",
        policy_version="1.0.0", base_model="b", guardian_model="g",
        decision=decision, prompt_sha256="p", response_sha256="s",
        verdicts=[], latency_ms=1,
    )


def test_chain_builds_and_verifies(tmp_path: Path):
    log = AuditLog(tmp_path, rotate_mb=1)
    first = log.append(_rec())
    assert first.prev_hash == GENESIS and first.seq == 1
    prev = first.hash
    for _ in range(5):
        r = log.append(_rec())
        assert r.prev_hash == prev
        prev = r.hash
    res = log.verify()
    assert res["intact"] and res["records"] == 6


def test_chain_survives_restart(tmp_path: Path):
    log = AuditLog(tmp_path)
    for _ in range(3):
        log.append(_rec())
    head = log.verify()["head_hash"]
    reopened = AuditLog(tmp_path)          # recovers seq and last hash from disk
    r = reopened.append(_rec())
    assert r.prev_hash == head and r.seq == 4
    assert reopened.verify()["intact"]


def test_edit_breaks_chain(tmp_path: Path):
    log = AuditLog(tmp_path)
    for _ in range(4):
        log.append(_rec())
    f = sorted(tmp_path.glob("audit-*.jsonl"))[0]
    lines = f.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["decision"] = "blocked_input"      # tamper with content, leave hash as-is
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    f.write_text("\n".join(lines) + "\n")
    res = AuditLog(tmp_path).verify()
    assert not res["intact"] and res["first_break"]["seq"] == 2


def test_delete_breaks_chain(tmp_path: Path):
    log = AuditLog(tmp_path)
    for _ in range(4):
        log.append(_rec())
    f = sorted(tmp_path.glob("audit-*.jsonl"))[0]
    lines = f.read_text().splitlines()
    del lines[2]                            # drop a record
    f.write_text("\n".join(lines) + "\n")
    assert not AuditLog(tmp_path).verify()["intact"]


def test_reorder_breaks_chain(tmp_path: Path):
    log = AuditLog(tmp_path)
    for _ in range(4):
        log.append(_rec())
    f = sorted(tmp_path.glob("audit-*.jsonl"))[0]
    lines = f.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    f.write_text("\n".join(lines) + "\n")
    assert not AuditLog(tmp_path).verify()["intact"]


# ---------- policy ----------
@pytest.fixture
def policy():
    import yaml
    raw = yaml.safe_load(Path("config/policy.yaml").read_text())
    return Policy(raw)


def test_policy_stage_filtering(policy):
    ids_in = {c.id for c in policy.for_stage("input")}
    ids_out = {c.id for c in policy.for_stage("output")}
    assert "prompt_injection" in ids_in            # input-only
    assert "prompt_injection" not in ids_out
    assert "hate_harassment" in ids_out            # output-only
    assert "weapons_cbrne" in ids_in and "weapons_cbrne" in ids_out


def test_strongest_action(policy):
    cats = policy.for_stage("input")
    # a set containing any block category resolves to block
    assert Policy.strongest_action(cats) == "block"
    flags = [c for c in cats if c.action == "flag"]
    assert Policy.strongest_action(flags) == "flag"
    assert Policy.strongest_action([]) == "allow"


def test_render_includes_prompt_and_policy(policy):
    cats = policy.for_stage("input")
    text = policy.render("input", cats, "how do I pick a lock")
    assert "how do I pick a lock" in text
    assert "chemical" in text.lower()               # policy text present


# ---------- guardian parsing ----------
def test_guardian_probability_parsing(monkeypatch):
    from palisade.guardian import Guardian

    g = Guardian.__new__(Guardian)
    g.pos, g.neg = "Yes", "No"

    def fake_post(url, json):
        class R:
            def raise_for_status(self): pass
            def json(self):
                return {"completion_probabilities": [
                    {"probs": [{"tok_str": "Yes", "prob": 0.82},
                               {"tok_str": "No", "prob": 0.18}]}]}
        return R()

    class C: post = staticmethod(fake_post)
    g.client = C()
    g.url = "http://x"
    p = Guardian._p_positive(g, "irrelevant")
    assert abs(p - 0.82) < 1e-6


# ---------- policy override resolution ----------
def test_local_policy_preferred(tmp_path, monkeypatch):
    """policy.local.yaml wins over policy.yaml when both exist."""
    import palisade
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "policy.yaml").write_text("version: example\ncategories: []\ntemplates: {input: '', output: ''}\n")
    monkeypatch.setattr(palisade, "CONFIG_DIR", cfg)
    # only the example present -> resolves to policy.yaml
    assert palisade.policy_path().name == "policy.yaml"
    # add a local override -> resolves to policy.local.yaml
    (cfg / "policy.local.yaml").write_text("version: real\ncategories: []\ntemplates: {input: '', output: ''}\n")
    assert palisade.policy_path().name == "policy.local.yaml"
    assert palisade.load_policy()["version"] == "real"
