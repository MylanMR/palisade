"""Palisade command line.

  python -m palisade install [--tier small|standard] [--model-url ID=URL ...]
  python -m palisade run
  python -m palisade doctor
  python -m palisade verify
  python -m palisade eval [--cases eval/cases.jsonl]
  python -m palisade benchmark
  python -m palisade audit report [--decision D] [--include-content] [--out FILE]
  python -m palisade audit anchor [--out FILE]
  python -m palisade audit check-anchor FILE
  python -m palisade audit check-report FILE
  python -m palisade audit permissions
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

import os

from . import (ROOT, DATA_DIR, STATE_DIR, POSIX, __version__, load_settings, load_models,
               read_lock, manifest_hash, audit_dir, secure_write_text)
from .audit import AuditLog
from .fetch import (install_binaries, install_model, model_path,
                    record_config_hashes, verify_installation)
from .hardware import detect, choose_tier


def _tier(settings, manifest, override=None):
    host = detect()
    return host, choose_tier(host, manifest["tiers"], override or settings.get("tier", "auto"))


def cmd_doctor(args):
    settings, manifest = load_settings(), load_models()
    host, tier = _tier(settings, manifest)
    print(f"palisade {__version__}")
    print(json.dumps(host.as_dict(), indent=2))
    print(f"tier: {tier} -> base={manifest['tiers'][tier]['base']} guardian={manifest['tiers'][tier]['guardian']}")
    problems = verify_installation(manifest, tier)
    if problems:
        print("problems:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("installation matches manifest.lock")
    print(f"manifest hash: {manifest_hash(read_lock())}")
    return 0


def cmd_install(args):
    settings, manifest = load_settings(), load_models()
    host, tier = _tier(settings, manifest, args.tier)
    print(f"host: {host.os}/{host.arch} ram={host.ram_gb:.0f}GB gpu={host.gpu} backend={host.backend}")
    print(f"tier: {tier}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    install_binaries(host, manifest)
    overrides = dict(kv.split("=", 1) for kv in (args.model_url or []))
    t = manifest["tiers"][tier]
    for mid in (t["base"], t["guardian"]):
        install_model(mid, manifest, overrides.get(mid))
    lock = record_config_hashes()
    print(f"manifest.lock written; manifest hash {manifest_hash(lock)}")
    return 0


def cmd_verify(args):
    settings = load_settings()
    log = AuditLog(audit_dir(settings), settings["audit"].get("rotate_mb", 64))
    res = log.verify()
    print(json.dumps(res, indent=2))
    return 0 if res["intact"] else 2


def _start_stack(settings, manifest, host, tier):
    from .runtime import LlamaProcess, server_binary
    from .guardian import Guardian

    t = manifest["tiers"][tier]
    binary = server_binary(host)
    ctx = settings["runtime"]["context_tokens"]
    base = LlamaProcess("base", binary, model_path(t["base"], manifest),
                        settings["runtime"]["base_port"], host, settings, ctx)
    guard = LlamaProcess("guardian", binary, model_path(t["guardian"], manifest),
                         settings["runtime"]["guardian_port"], host, settings, min(ctx, 4096))
    for p in (base, guard):
        print(f"starting {p.name}: {' '.join(p.cmd[1:5])} ...")
        p.start()
    timeout = settings["runtime"]["startup_timeout_seconds"]
    for p in (base, guard):
        p.wait_healthy(timeout)
        print(f"{p.name} ready on {p.url}")

    gcfg = settings["guardian"]
    guardian = Guardian(guard.url, t["guardian"], manifest["models"][t["guardian"]],
                        mode=gcfg.get("mode", "combined"), threshold=float(gcfg.get("threshold", 0.5)))
    return base, guard, guardian, t


def cmd_run(args):
    import uvicorn
    from .server import build_app

    settings, manifest = load_settings(), load_models()
    host, tier = _tier(settings, manifest)
    problems = verify_installation(manifest, tier)
    if problems:
        print("refusing to start; installation does not match manifest.lock:")
        for p in problems:
            print(f"  - {p}")
        return 1

    if POSIX:
        os.umask(0o027)  # anything Palisade creates: no access for other accounts
    base, guard, guardian, t = _start_stack(settings, manifest, host, tier)
    audit = AuditLog(audit_dir(settings), settings["audit"].get("rotate_mb", 64))
    app = build_app(settings, base.url, guardian, t["base"], audit,
                    models_cfg=manifest, tier=tier, backend=host.backend)

    def _stop(*_):
        print("\nstopping llama-server processes")
        base.stop(); guard.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    s = settings["server"]
    print(f"\nPalisade ready: http://{s['host']}:{s['port']}/")
    print(f"API token (for non-browser clients): {app.state.palisade['token']}")
    print(f"Audit review:  http://{s['host']}:{s['port']}/review")
    print(f"Reviewer token file (audit group readable): {STATE_DIR / 'reviewer.token'}\n")
    try:
        uvicorn.run(app, host=s["host"], port=int(s["port"]), log_level="warning")
    finally:
        base.stop(); guard.stop()
    return 0


def cmd_eval(args):
    """Run the guardian alone against labeled cases and report precision/recall."""
    from .policy import Policy
    from . import load_policy

    settings, manifest = load_settings(), load_models()
    host, tier = _tier(settings, manifest)
    problems = verify_installation(manifest, tier)
    if problems:
        print("installation does not match manifest.lock; run `palisade doctor`")
        return 1
    base, guard, guardian, t = _start_stack(settings, manifest, host, tier)
    policy = Policy(load_policy())
    cases = [json.loads(l) for l in Path(args.cases).read_text(encoding="utf-8").splitlines() if l.strip()]

    tp = fp = tn = fn = 0
    rows = []
    try:
        for c in cases:
            v = guardian.check(c.get("stage", "input"), policy, c["prompt"], c.get("response", ""))
            pred, truth = v.violated, bool(c["unsafe"])
            if pred and truth: tp += 1
            elif pred and not truth: fp += 1
            elif not pred and truth: fn += 1
            else: tn += 1
            rows.append({"id": c.get("id"), "truth": truth, "pred": pred, "p": v.p_violation,
                         "expected": c.get("category"), "attributed": v.categories})
            print(f"{'OK ' if pred == truth else 'MISS'} {c.get('id','?'):24} p={v.p_violation:.3f} truth={truth}")
    finally:
        base.stop(); guard.stop()

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    out = {"cases": len(cases), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
           "precision": round(prec, 3), "recall": round(rec, 3),
           "threshold": guardian.threshold, "mode": guardian.mode,
           "guardian": guardian.model_id, "policy_version": policy.version,
           "manifest_hash": manifest_hash(read_lock()), "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "rows": rows}
    dest = DATA_DIR / "eval" / f"eval-{int(time.time())}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nprecision={prec:.3f} recall={rec:.3f}  (tp={tp} fp={fp} tn={tn} fn={fn})")
    print(f"report: {dest}")
    return 0


def cmd_benchmark(args):
    """Score the installation against the NIST AI RMF catalog."""
    from compliance.nist_ai_rmf import benchmark as bm
    return bm.main([])


def _audit_log():
    settings = load_settings()
    return AuditLog(audit_dir(settings), settings["audit"].get("rotate_mb", 64))


def cmd_audit(args):
    """Review-side audit commands. Read-only against the chain, except `permissions`."""
    from . import review
    mhash = manifest_hash(read_lock()) if read_lock() else ""
    if args.action == "report":
        log = _audit_log()
        text = review.render_report(log, decision=args.decision,
                                    include_content=args.include_content, manifest_hash=mhash)
        if args.out == "-":
            sys.stdout.write(text)
        else:
            out = Path(args.out or f"audit-review-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.log")
            secure_write_text(out, text)
            print(f"review log written: {out.resolve()} (mode 0640)")
        return 0 if log.verify()["intact"] else 2
    if args.action == "anchor":
        a = review.anchor(_audit_log(), mhash)
        text = review.anchor_text(a)
        if args.out:
            secure_write_text(Path(args.out), text)
            print(f"anchor written: {Path(args.out).resolve()}")
        else:
            sys.stdout.write(text)
        print("Store this anchor off the machine (another system, removable media, or print).",
              file=sys.stderr)
        return 0
    if args.action == "check-anchor":
        a = json.loads(Path(args.file).read_text(encoding="utf-8"))
        res = review.check_anchor(_audit_log(), a)
        print(json.dumps(res, indent=2))
        return 0 if res["valid"] else 2
    if args.action == "check-report":
        res = review.check_report(Path(args.file).read_text(encoding="utf-8"))
        print(json.dumps(res, indent=2))
        return 0 if res["valid"] else 2
    if args.action == "verify":
        return cmd_verify(args)
    if args.action == "permissions":
        log = _audit_log()
        failed = log.apply_permissions()
        print(f"audit directory: {log.dir}")
        if failed:
            print("could not change (owned by another account; run as the owner or with sudo):")
            for f in failed:
                print(f"  - {f}")
            return 1
        print("directory set to 2750, files set to 0640")
        return 0
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="palisade")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("install"); p.add_argument("--tier"); p.add_argument("--model-url", action="append")
    sub.add_parser("run"); sub.add_parser("doctor"); sub.add_parser("verify")
    e = sub.add_parser("eval"); e.add_argument("--cases", default=str(ROOT / "eval" / "cases.jsonl"))
    sub.add_parser("benchmark")
    a = sub.add_parser("audit", help="review-side audit commands")
    asub = a.add_subparsers(dest="action", required=True)
    r = asub.add_parser("report", help="write a plain-text review log from the chain")
    r.add_argument("--decision", choices=["answered", "flagged", "blocked", "blocked_input", "blocked_output"])
    r.add_argument("--include-content", action="store_true",
                   help="include prompt/response text where retain_content is full")
    r.add_argument("--out", help="output file (default: ./audit-review-<time>.log, '-' for stdout)")
    an = asub.add_parser("anchor", help="export the current head hash for off-box storage")
    an.add_argument("--out")
    ca = asub.add_parser("check-anchor", help="confirm the chain still passes through an anchor")
    ca.add_argument("file")
    cr = asub.add_parser("check-report", help="confirm a saved review log was not edited")
    cr.add_argument("file")
    asub.add_parser("permissions", help="apply 2750/0640 to the audit directory and files")
    asub.add_parser("verify", help="recompute the hash chain (same as `palisade verify`)")
    args = ap.parse_args(argv)
    return {"install": cmd_install, "run": cmd_run, "doctor": cmd_doctor,
            "verify": cmd_verify, "eval": cmd_eval, "benchmark": cmd_benchmark,
            "audit": cmd_audit}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
