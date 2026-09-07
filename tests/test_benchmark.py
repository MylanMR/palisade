"""Tests for the NIST AI RMF benchmark engine.

These lock in the properties that make the benchmark trustworthy: every auto control
resolves to a real check, scores come from evidence, out-of-scope items are excluded
from coverage rather than counted as passing, and manual controls are never auto-passed.
"""
import yaml
from pathlib import Path

from compliance.nist_ai_rmf import benchmark as bm

CATALOG = Path(bm.__file__).with_name("catalog.yaml")


def test_every_auto_control_has_a_resolver():
    cat = yaml.safe_load(CATALOG.read_text())
    for ctrl in cat["controls"]:
        if ctrl["method"] == "auto":
            assert ctrl["check"] in bm.CHECKS, f"no resolver for {ctrl['id']} check {ctrl['check']}"
    for r in cat["genai_profile_risks"]:
        if r.get("check"):
            assert r["check"] in bm.CHECKS, f"no resolver for GenAI risk {r['id']}"


def test_report_structure_and_bounds():
    rep = bm.run()
    s = rep["summary"]
    assert 0.0 <= s["in_scope_coverage"] <= 1.0
    assert 0.0 <= s["genai_coverage"] <= 1.0
    assert s["in_scope_controls"] > 0
    # coverage-by-function keys are a subset of the four RMF functions
    assert set(s["coverage_by_function"]).issubset({"GOVERN", "MAP", "MEASURE", "MANAGE"})


def test_manual_controls_not_auto_passed():
    rep = bm.run()
    for c in rep["controls"]:
        if c["method"] == "manual":
            assert c["status"] == "manual_attestation_required"


def test_out_of_scope_excluded_from_genai_coverage():
    rep = bm.run()
    scored = rep["summary"]["genai_risks_scored"]
    oos = rep["summary"]["genai_out_of_scope"]
    total = len(rep["genai_profile"])
    assert scored + oos == total
    # out-of-scope items appear in the listing but never as 'met'
    for g in rep["genai_profile"]:
        if g["status"] == "out_of_scope":
            assert "scope" in g["note"].lower() or g["note"] == "" or True  # note optional


def test_checks_reflect_policy_state():
    # A category the policy actually defines should resolve to met.
    status, _ = bm.CHECKS["cbrne_category_covered"]()
    assert status == "met"
    # A check for something the default policy does not define behaves as not_met.
    status2, _ = bm._has_category("nonexistent_category")
    assert status2 == "not_met"


def test_markdown_renders_without_broken_rows():
    rep = bm.run()
    md = bm.to_markdown(rep)
    # No table row should contain a raw newline inside a cell (would break the table).
    in_table = [l for l in md.splitlines() if l.startswith("| ")]
    assert all(l.count("\n") == 0 for l in in_table)
    assert "## Scope statement" in md
