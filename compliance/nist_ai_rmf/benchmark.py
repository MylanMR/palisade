"""NIST AI RMF benchmark for Palisade.

Resolves each catalog `check` against the actual repository, configuration, and (when
running) the live audit log, then scores coverage. Auto checks inspect real artifacts;
manual controls are recorded as attestations, never auto-passed.

    python -m compliance.nist_ai_rmf.benchmark            # score, print, write report
    python -m compliance.nist_ai_rmf.benchmark --md out.md # also write a Markdown report

Honesty rules baked in:
  - Organizational controls a desktop tool cannot satisfy are `out_of_scope`, not `met`.
  - An auto check returns met/partial/not_met from evidence, and the evidence string is
    recorded so a reviewer can audit the score itself.
  - Overall coverage is reported over in-scope controls, with out-of-scope counted separately.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable

import yaml

ROOT = Path(__file__).resolve().parents[2]
CATALOG = Path(__file__).with_name("catalog.yaml")
CONFIG = ROOT / "config"
import sys as _sys
_sys.path.insert(0, str(ROOT))
from palisade import DATA_DIR as DATA, LOCK_PATH  # honors PALISADE_DATA / PALISADE_LOCK


# ---- evidence helpers -------------------------------------------------------
def _load_yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}


def _policy() -> dict:
    # Score the policy actually in force: local override if present, else the example.
    local = CONFIG / "policy.local.yaml"
    return _load_yaml(local if local.exists() else CONFIG / "policy.yaml")


def _models() -> dict:
    return _load_yaml(CONFIG / "models.yaml")


def _category_ids() -> set[str]:
    return {c["id"] for c in _policy().get("categories", [])}


def _lock() -> dict:
    p = LOCK_PATH
    return json.loads(p.read_text()) if p.exists() else {}


Result = tuple[str, str]  # (status, evidence)


def _has_category(cid: str) -> Result:
    present = cid in _category_ids()
    return ("met" if present else "not_met",
            f"policy category '{cid}' {'present' if present else 'absent'}")


# ---- check registry ---------------------------------------------------------
CHECKS: dict[str, Callable[[], Result]] = {}


def check(name: str):
    def deco(fn: Callable[[], Result]) -> Callable[[], Result]:
        CHECKS[name] = fn
        return fn
    return deco


@check("policy_file_present")
def _c_policy_present() -> Result:
    local = CONFIG / "policy.local.yaml"
    active = local if local.exists() else CONFIG / "policy.yaml"
    ok = active.exists() and bool(_policy().get("categories"))
    return ("met" if ok else "not_met", f"{active.name} with categories" if ok else "policy missing")


@check("policy_versioned")
def _c_policy_versioned() -> Result:
    v = str(_policy().get("version", ""))
    return ("met" if v else "not_met", f"policy version {v or 'unset'}")


@check("audit_present")
def _c_audit_present() -> Result:
    # The capability exists in code; presence of records is runtime state.
    files = list((DATA / "audit").glob("audit-*.jsonl")) if (DATA / "audit").exists() else []
    if files:
        return ("met", f"{len(files)} audit file(s) on disk")
    return ("partial", "audit subsystem implemented; no records yet (run the server to generate)")


@check("audit_chain_intact")
def _c_audit_chain() -> Result:
    d = DATA / "audit"
    if not d.exists() or not list(d.glob("audit-*.jsonl")):
        return ("partial", "no audit records yet to verify; chain verified in unit tests")
    import sys
    sys.path.insert(0, str(ROOT))
    from palisade.audit import AuditLog
    res = AuditLog(d).verify()
    if res["intact"]:
        return ("met", f"chain intact over {res['records']} records")
    return ("not_met", f"chain broken at seq {res['first_break']}")


@check("audit_records_attributable")
def _c_attributable() -> Result:
    # Attribution is structural: records carry model, policy_version, manifest_hash by schema.
    from dataclasses import fields
    import sys
    sys.path.insert(0, str(ROOT))
    from palisade.audit import AuditRecord
    names = {f.name for f in fields(AuditRecord)}
    need = {"base_model", "guardian_model", "policy_version", "manifest_hash"}
    ok = need <= names
    return ("met" if ok else "not_met", f"record carries {sorted(need & names)}")


@check("audit_full_retention_option")
def _c_full_retention() -> Result:
    s = _load_yaml(CONFIG / "settings.yaml")
    mode = s.get("audit", {}).get("retain_content")
    ok = mode in ("hashes", "full")
    return ("met" if ok else "not_met", f"retain_content={mode} (full available for incident review)")


@check("manifest_lock_complete")
def _c_lock_complete() -> Result:
    lock = _lock()
    if not lock:
        return ("partial", "manifest.lock not yet written (created by `palisade install`); schema defined")
    have = {k for k in ("llama_cpp", "models", "config") if lock.get(k)}
    return ("met" if len(have) == 3 else "partial", f"manifest.lock sections present: {sorted(have)}")


@check("model_provenance_documented")
def _c_provenance() -> Result:
    ms = _models().get("models", {})
    if not ms:
        return ("not_met", "no models defined")
    complete = [m for m in ms.values() if m.get("lab") and m.get("license") and m.get("repo")]
    ok = len(complete) == len(ms)
    return ("met" if ok else "partial", f"{len(complete)}/{len(ms)} models document lab+license+repo")


@check("architecture_documented")
def _c_arch() -> Result:
    p = ROOT / "docs" / "ARCHITECTURE.md"
    ok = p.exists() and p.stat().st_size > 1000
    return ("met" if ok else "not_met", "docs/ARCHITECTURE.md present" if ok else "architecture doc missing")


@check("eval_harness_present")
def _c_eval_harness() -> Result:
    cases = ROOT / "eval" / "cases.jsonl"
    has_cmd = (ROOT / "palisade" / "__main__.py").read_text().find("cmd_eval") >= 0
    ok = cases.exists() and has_cmd
    n = len(cases.read_text().splitlines()) if cases.exists() else 0
    return ("met" if ok else "not_met", f"eval command present; {n} labeled cases")


@check("eval_report_exists")
def _c_eval_report() -> Result:
    reports = list((DATA / "eval").glob("eval-*.json")) if (DATA / "eval").exists() else []
    if reports:
        return ("met", f"{len(reports)} eval report(s) retained")
    return ("partial", "eval harness present; no report yet (run `palisade eval`)")


@check("guardian_enabled")
def _c_guardian() -> Result:
    s = _load_yaml(CONFIG / "settings.yaml").get("guardian", {})
    ok = s.get("check_input") and s.get("check_output")
    return ("met" if ok else "partial", f"input={s.get('check_input')} output={s.get('check_output')}")


@check("output_check_enabled")
def _c_output() -> Result:
    ok = _load_yaml(CONFIG / "settings.yaml").get("guardian", {}).get("check_output")
    return ("met" if ok else "not_met", f"check_output={ok}")


@check("prompt_injection_covered")
def _c_injection() -> Result:
    return _has_category("prompt_injection")


@check("adversarial_harness")
def _c_harness() -> Result:
    """MEASURE-2.7: resilience to adversarial input is built in and has been tested."""
    cases = ROOT / "eval" / "harness_cases.yaml"
    if not (ROOT / "palisade" / "harness.py").exists() or not cases.exists():
        return ("not_met", "no harness or harness test cases")
    if "prompt_injection" not in _category_ids():
        return ("partial", "harness present; policy has no prompt_injection category")
    n = len((_load_yaml(cases) or {}).get("cases", []))
    reports = sorted((DATA / "eval").glob("harness-*.json")) if (DATA / "eval").exists() else []
    if not reports:
        return ("partial", f"harness present with {n} attack cases; not yet run (`palisade harness test`)")
    rep = json.loads(reports[-1].read_text())
    if rep.get("failed", 1):
        return ("partial", f"latest harness test {reports[-1].name}: {rep.get('failed')} of {rep.get('cases')} failed")
    return ("met", f"latest harness test {reports[-1].name}: {rep.get('passed')} of {rep.get('cases')} passed")


@check("block_action_enforced")
def _c_block() -> Result:
    actions = {c.get("action") for c in _policy().get("categories", [])}
    ok = "block" in actions
    return ("met" if ok else "not_met", f"actions in policy: {sorted(a for a in actions if a)}")


@check("cbrne_category_covered")
def _c_cbrne() -> Result:
    return _has_category("weapons_cbrne")


@check("cyber_category_covered")
def _c_cyber() -> Result:
    return _has_category("cyber_offense")


@check("child_safety_covered")
def _c_child() -> Result:
    return _has_category("child_safety")


@check("hate_category_covered")
def _c_hate() -> Result:
    return _has_category("hate_harassment")


@check("privacy_category_covered")
def _c_privacy() -> Result:
    return _has_category("privacy_pii")


@check("violence_hate_covered")
def _c_vh() -> Result:
    s1, _ = _has_category("violent_extremism")
    s2, _ = _has_category("hate_harassment")
    both = s1 == "met" and s2 == "met"
    return ("met" if both else "partial", f"violent_extremism={s1}, hate_harassment={s2}")


@check("violence_hate_covered_genai")
def _c_vh2() -> Result:
    return _c_vh()


# ---- scoring ----------------------------------------------------------------
SCORE = {"met": 1.0, "partial": 0.5, "not_met": 0.0}


def run() -> dict[str, Any]:
    cat = _load_yaml(CATALOG)
    cat["framework"] = {k: str(v) for k, v in cat["framework"].items()}
    controls_out = []
    in_scope_score = 0.0
    in_scope_n = 0
    oos = 0

    for ctrl in cat["controls"]:
        cid, method = ctrl["id"], ctrl["method"]
        applies = ctrl.get("applies", "yes")
        if method == "manual":
            status, evidence = "manual_attestation_required", ctrl.get("palisade", "")
            row_scope = "manual"
        else:
            chk = ctrl.get("check")
            if chk not in CHECKS:
                status, evidence, row_scope = "not_met", f"no resolver for check '{chk}'", "in_scope"
            else:
                status, evidence = CHECKS[chk]()
                row_scope = "in_scope"
        if applies == "partial" and status == "met":
            status = "partial"  # control only partially borne by the tool
        if row_scope == "in_scope":
            in_scope_score += SCORE.get(status, 0.0)
            in_scope_n += 1
        controls_out.append({"id": cid, "function": cid.split("-")[0], "method": method,
                             "status": status, "evidence": evidence, "intent": ctrl["intent"]})

    genai_out = []
    g_score = 0.0
    g_n = 0
    for r in cat["genai_profile_risks"]:
        mit = r["mitigation"]
        if mit == "out_of_scope":
            oos += 1
            status = "out_of_scope"
        else:
            if r.get("check") in CHECKS:
                status, _ = CHECKS[r["check"]]()
                # clamp to the catalog's stated mitigation ceiling
                if r["mitigation"] == "partial" and status == "met":
                    status = "partial"
            else:
                status = mit
            g_score += SCORE.get(status, 0.0)
            g_n += 1
        genai_out.append({"id": r["id"], "name": r["name"], "status": status,
                          "note": r.get("note", "")})

    coverage = round(in_scope_score / in_scope_n, 3) if in_scope_n else 0.0
    g_cov = round(g_score / g_n, 3) if g_n else 0.0
    by_fn: dict[str, list[float]] = {}
    for c in controls_out:
        if c["method"] == "auto":
            by_fn.setdefault(c["function"], []).append(SCORE.get(c["status"], 0.0))
    fn_cov = {k: round(sum(v) / len(v), 3) for k, v in by_fn.items()}

    return {
        "framework": cat["framework"],
        "catalog_version": cat["catalog_version"],
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "in_scope_controls": in_scope_n,
            "in_scope_coverage": coverage,
            "coverage_by_function": fn_cov,
            "manual_controls": sum(1 for c in controls_out if c["method"] == "manual"),
            "genai_risks_scored": g_n,
            "genai_coverage": g_cov,
            "genai_out_of_scope": oos,
        },
        "controls": controls_out,
        "genai_profile": genai_out,
    }


def to_markdown(rep: dict[str, Any]) -> str:
    s = rep["summary"]
    fw = rep["framework"]
    lines = [
        f"# NIST AI RMF Benchmark: Palisade",
        "",
        f"Framework: {fw['core']} with {fw['profile']}  ",
        f"Verified against {fw['verified_against']} on {fw['verified_on']}  ",
        f"Catalog version {rep['catalog_version']}, generated {rep['generated']}",
        "",
        "## Summary",
        "",
        f"- In-scope controls scored: **{s['in_scope_controls']}**",
        f"- In-scope coverage: **{s['in_scope_coverage']*100:.0f}%**",
        f"- Coverage by function: " + ", ".join(f"{k} {v*100:.0f}%" for k, v in s["coverage_by_function"].items()),
        f"- Manual attestations required: **{s['manual_controls']}**",
        f"- GenAI-profile risks scored: **{s['genai_risks_scored']}** at **{s['genai_coverage']*100:.0f}%** "
        f"({s['genai_out_of_scope']} out of scope)",
        "",
        "Coverage is computed only over controls a single desktop runtime control can bear on. "
        "Organizational controls are listed as manual attestations, not counted as met.",
        "",
        "## Controls",
        "",
        "| Control | Fn | Method | Status | Evidence |",
        "|---------|----|--------|--------|----------|",
    ]
    def cell(x: str) -> str:
        return " ".join(str(x).split()).replace("|", "\\|")
    for c in rep["controls"]:
        lines.append(f"| {c['id']} | {c['function']} | {c['method']} | {c['status']} | {cell(c['evidence'])} |")
    lines += ["", "## GenAI Profile risks (NIST.AI.600-1)", "",
              "| Risk | Status | Note |", "|------|--------|------|"]
    for g in rep["genai_profile"]:
        lines.append(f"| {g['id']} {g['name']} | {g['status']} | {cell(g['note'])} |")
    lines += ["", "## Scope statement", "",
              "This benchmark scores Palisade as a runtime control. A `met` status means the "
              "system provides the mechanism the subcategory calls for, evidenced by the artifact "
              "named. It is not an authorization or a certification; an accrediting authority owns "
              "that decision. Manual controls require human attestation with evidence."]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nist-benchmark")
    ap.add_argument("--json", default=str(DATA / "compliance" / "nist_ai_rmf_benchmark.json"))
    ap.add_argument("--md", default=str(ROOT / "compliance" / "nist_ai_rmf" / "REPORT.md"))
    args = ap.parse_args(argv)

    rep = run()
    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(rep, indent=2), encoding="utf-8")
    Path(args.md).write_text(to_markdown(rep), encoding="utf-8")

    s = rep["summary"]
    print(f"NIST AI RMF benchmark: {s['in_scope_coverage']*100:.0f}% in-scope coverage "
          f"over {s['in_scope_controls']} controls")
    for k, v in s["coverage_by_function"].items():
        print(f"  {k}: {v*100:.0f}%")
    print(f"  GenAI risks: {s['genai_coverage']*100:.0f}% over {s['genai_risks_scored']} scored "
          f"({s['genai_out_of_scope']} out of scope)")
    print(f"  manual attestations required: {s['manual_controls']}")
    print(f"report: {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
