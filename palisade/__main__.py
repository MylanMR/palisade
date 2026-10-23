"""Palisade command line.

  python -m palisade install [--tier small|standard] [--model-url ID=URL ...]
  python -m palisade run
  python -m palisade doctor
  python -m palisade verify
  python -m palisade eval [--cases eval/cases.jsonl]
  python -m palisade benchmark
  python -m palisade harness show | test [--no-model-cases]
  python -m palisade audit report [--decision D] [--include-content] [--out FILE]
  python -m palisade audit anchor [--out FILE]
  python -m palisade audit check-anchor FILE
  python -m palisade audit check-report FILE
  python -m palisade audit permissions
  python -m palisade setup [--if-needed]          (installed copies: first-run downloads)
  python -m palisade open [--no-browser]          (installed copies: start if needed, open the page)
  python -m palisade import FOLDER                (reuse models and audit chain from a source checkout)
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

import os

from . import (ROOT, DATA_DIR, STATE_DIR, LOGS_DIR, POSIX, MODE, PACKAGED, SETUP_STATUS, __version__,
               load_settings, load_models, read_lock, manifest_hash, audit_dir, secure_write_text,
               secure_mkdir, ensure_config, load_yaml, CONFIG_DIR)
from .audit import AuditLog
from .fetch import (install_binaries, install_model, model_path, installation_problems,
                    record_config_hashes, verify_installation)
from .hardware import detect, choose_tier


def _settings_for_startup() -> dict:
    """Settings for deciding how to start. A service can start before its setup job has
    written the config folder; until then it uses the package defaults, which only
    matter for the setup page (address, port, token)."""
    if MODE == "desktop":
        ensure_config()
    if (CONFIG_DIR / "settings.yaml").exists():
        return load_settings()
    return load_yaml(ROOT / "config" / "settings.yaml")


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
    if PACKAGED:
        # Installed copies: models come from first-run setup. Running `install` by hand is
        # the explicit way to record intended changes to settings or policy.
        from .setup import run_setup, Status
        rc = run_setup(Status(), tier_override=args.tier)
        if rc == 0:
            lock = record_config_hashes()
            print(f"recorded current settings and policy; manifest hash {manifest_hash(lock)}")
        else:
            print(f"setup did not complete; see {SETUP_STATUS}")
        return rc
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
    # The guardian reads the policy text plus a whole message and a whole answer. Size its
    # window so that always fits; a truncated prompt would leave text unscreened.
    guard = LlamaProcess("guardian", binary, model_path(t["guardian"], manifest),
                         settings["runtime"]["guardian_port"], host, settings, min(ctx + 2048, 8192))
    for p in (base, guard):
        print(f"starting {p.name} model server ({p.endpoint.transport}) ...")
        p.start()
    timeout = settings["runtime"]["startup_timeout_seconds"]
    procs = {"base": base, "guardian": guard}
    for name, p in list(procs.items()):
        try:
            p.wait_healthy(timeout)
        except RuntimeError as e:
            if p.sock is None or "exited early" not in str(e):
                raise
            # A server that cannot listen on its private socket gets one retry on loopback,
            # still behind its per-launch key and the port-ownership check. Said out loud,
            # and shown on the Runtime panel, because it is a weaker arrangement.
            print(f"{name} model server could not use its private socket ({e}); retrying on 127.0.0.1")
            p.stop()
            p = LlamaProcess(name, binary, p.model, p.port, host, settings,
                             int(p.cmd[p.cmd.index("--ctx-size") + 1]), use_socket=False)
            p.start()
            p.wait_healthy(timeout)
            procs[name] = p
    base, guard = procs["base"], procs["guardian"]
    for p in (base, guard):
        print(f"{p.name} ready" + (f" on 127.0.0.1:{p.port}" if p.sock is None else ""))

    gcfg = settings["guardian"]
    from .harness import harness_config
    hcfg, _ = harness_config(settings)
    guardian = Guardian(guard.endpoint, t["guardian"], manifest["models"][t["guardian"]],
                        mode=gcfg.get("mode", "combined"), threshold=float(gcfg.get("threshold", 0.5)),
                        timeout=float(hcfg["guardian_timeout_seconds"]))
    return base, guard, guardian, t


def cmd_run(args):
    import uvicorn
    from .server import build_app

    settings, manifest = _settings_for_startup(), load_models()
    from .exposure import check_exposure
    errors, warnings = check_exposure(settings)
    if errors:
        print("refusing to start; network exposure check failed:")
        for e in errors:
            print(f"  - {e}")
        return 1
    for w in warnings:
        print(w + "\n")
    if POSIX:
        os.umask(0o027)  # anything Palisade creates: no access for other accounts
    host, tier = _tier(settings, manifest)
    problems = installation_problems(manifest, tier) if (CONFIG_DIR / "settings.yaml").exists() else ["config"]
    if problems:
        if MODE == "source":
            print("refusing to start; installation does not match manifest.lock:")
            for p in problems:
                print(f"  - {p}")
            return 1
        if _wait_for_setup(settings) != 0:
            return 1
        settings, manifest = load_settings(), load_models()
        host, tier = _tier(settings, manifest)

    from .harness import harness_config
    for note in harness_config(settings)[1]:
        print(f"harness: {note}")
    base, guard, guardian, t = _start_stack(settings, manifest, host, tier)
    audit = AuditLog(audit_dir(settings), settings["audit"].get("rotate_mb", 64))
    app = build_app(settings, base.endpoint, guardian, t["base"], audit,
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


def _wait_for_setup(settings) -> int:
    """Serve the setup page until the installation verifies, then return so `run`
    continues into a normal start. In desktop mode Palisade runs setup itself; in
    service mode a separate root/SYSTEM job does, because the service account cannot
    write models or manifest.lock."""
    import subprocess
    import threading
    import uvicorn
    from .server import build_setup_app
    from .fetch import Problem

    def problems():
        try:
            if not (CONFIG_DIR / "settings.yaml").exists():
                return [Problem("missing", "settings not yet created")]
            st, mf = load_settings(), load_models()
            return installation_problems(mf, _tier(st, mf)[1])
        except Exception as e:      # half-written config during setup: keep waiting
            return [Problem("missing", f"waiting for setup ({e})")]

    initial = problems()
    child = None
    if MODE == "desktop" and not any(p.kind == "mismatch" for p in initial):
        secure_mkdir(LOGS_DIR)
        log = open(LOGS_DIR / "setup.log", "ab")
        child = subprocess.Popen([sys.executable, "-m", "palisade", "setup"], stdout=log, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, **_no_window())

    app = build_setup_app(settings, problems, SETUP_STATUS)
    s = settings["server"]
    server = uvicorn.Server(uvicorn.Config(app, host=s["host"], port=int(s["port"]), log_level="warning"))
    print(f"Palisade is not set up yet; progress at http://{s['host']}:{s['port']}/")
    for p in initial:
        print(f"  - {p}")

    def watch():
        while not server.should_exit:
            time.sleep(3)
            if not problems():
                time.sleep(2)            # let the page show "Ready" before the switch
                server.should_exit = True
    threading.Thread(target=watch, daemon=True).start()
    server.run()
    if child is not None and child.poll() is None:
        child.wait()
    if problems():
        return 1                         # stopped by a signal, not by setup finishing
    print("setup complete; starting")
    return 0


def _no_window() -> dict:
    """Keyword arguments that keep a child process from opening a console window on Windows."""
    if os.name == "nt":
        return {"creationflags": 0x08000000}   # CREATE_NO_WINDOW
    return {}


def cmd_setup(args):
    from .setup import run_setup, Status
    if MODE == "source":
        print("setup is for installed copies; in a source checkout use `palisade install`")
        return 1
    if POSIX:
        os.umask(0o027)
    rc = run_setup(Status(), tier_override=args.tier, only_if_needed=args.if_needed)
    from .setup import read_status
    st = read_status()
    print(f"setup: {st.get('state')} {st.get('message', '')}")
    for p in st.get("problems", []):
        print(f"  - {p}")
    return rc


def cmd_import(args):
    from .setup import import_existing
    src = Path(args.folder).expanduser()
    if not (src / "models").is_dir() and not (src / "audit").is_dir():
        print(f"{src} has no models/ or audit/ folder; point at the data folder of a source checkout")
        return 1
    ensure_config()          # no-op in a source checkout
    for line in import_existing(src):
        print(f"  - {line}")
    return 0


def cmd_open(args):
    """Open Palisade in the browser, starting it first in desktop mode if it is not running."""
    import subprocess
    import webbrowser
    import httpx
    settings = _settings_for_startup()
    s = settings["server"]
    url = f"http://{s['host']}:{s['port']}/"

    def up() -> bool:
        try:
            return httpx.get(url, timeout=2).status_code == 200
        except httpx.HTTPError:
            return False

    if not up():
        if MODE == "service":
            print(f"Palisade is not answering at {url}. The service may still be starting; "
                  f"check it with your system's service manager.")
        else:
            secure_mkdir(LOGS_DIR)
            log = open(LOGS_DIR / "palisade.log", "ab")
            exe = sys.executable
            if os.name == "nt" and exe.lower().endswith("python.exe"):
                exe = exe[:-10] + "pythonw.exe"
            kw = _no_window() if os.name == "nt" else {"start_new_session": True}
            if os.name == "nt":
                kw["creationflags"] = kw.get("creationflags", 0) | 0x00000200 | 0x00000008  # NEW_GROUP, DETACHED
            subprocess.Popen([exe, "-m", "palisade", "run"], stdout=log, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, close_fds=True, **kw)
            for _ in range(60):
                if up():
                    break
                time.sleep(1)
    if not args.no_browser:
        webbrowser.open(url)
    return 0 if up() else 1


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


def cmd_publish_hashes(args):
    """Publish the verified fingerprints from manifest.lock into config/models.yaml."""
    from .fetch import publish_hashes
    from . import CONFIG_DIR
    settings, manifest = load_settings(), load_models()
    host, tier = _tier(settings, manifest)
    problems = [p for p in verify_installation(manifest, tier) if "config/" not in p]
    if problems:
        print("refusing: files on disk do not match manifest.lock, so their hashes cannot be published:")
        for p in problems:
            print(f"  - {p}")
        return 1
    path = CONFIG_DIR / "models.yaml"
    new, changes = publish_hashes(path.read_text(encoding="utf-8"), read_lock())
    if not changes:
        print("models.yaml already carries the published hashes; nothing to change.")
        return 0
    import yaml
    yaml.safe_load(new)  # never write a file that no longer parses
    if args.dry_run:
        print(new)
        return 0
    path.write_text(new, encoding="utf-8")
    print("Published into config/models.yaml:")
    for c in changes:
        print(f"  - {c}")
    print("\nBefore committing, compare each model hash with the SHA256 shown on its Hugging Face file page.")
    print("Then run `python -m palisade install` to record the updated models.yaml in manifest.lock.")
    return 0


def cmd_harness(args):
    """`show`: the harness controls and effective limits. `test`: start the models and
    run eval/harness_cases.yaml through the full request path."""
    from .harness import harness_config, describe
    settings = load_settings()
    cfg, notes = harness_config(settings)
    if args.action == "show":
        d = describe(cfg, notes, "private socket" if POSIX else "loopback with key")
        for c in d["controls"]:
            state = "on" if c.get("always_on") or c.get("enabled") else "off"
            print(f"  [{state:>3}] {c['label']}")
        print("limits:")
        for k, v in cfg.items():
            print(f"  {k}: {v}")
        for n in notes:
            print(f"note: {n}")
        return 0

    from fastapi.testclient import TestClient
    from .server import build_app
    from . import harness_suite as suite
    manifest = load_models()
    host, tier = _tier(settings, manifest)
    problems = verify_installation(manifest, tier)
    if problems:
        print("installation does not match manifest.lock; run `palisade doctor`")
        return 1
    # The suite sends many requests quickly; lift only the rate limit for this run.
    test_settings = json.loads(json.dumps(settings))
    test_settings.setdefault("harness", {})["rate_per_minute"] = 600
    base, guard, guardian, t = _start_stack(settings, manifest, host, tier)
    try:
        audit = AuditLog(audit_dir(settings), settings["audit"].get("rotate_mb", 64))
        app = build_app(test_settings, base.endpoint, guardian, t["base"], audit, models_cfg=manifest,
                        tier=tier, backend=host.backend, record_source="harness-test")
        client = TestClient(app, base_url=suite.LOCAL)
        client.get("/")
        rep = suite.run_suite(client, suite.load_cases(include_model_cases=not args.no_model_cases))
    finally:
        base.stop(); guard.stop()
    for r in rep["results"]:
        print(f"{'PASS' if r['passed'] else 'FAIL'} {r['id']:24} {r['layer']:13} "
              f"{r['status']} {r['decision'] or '-'}" + (f"  ({'; '.join(r['failures'])})" if r["failures"] else ""))
    print(f"\n{rep['passed']} of {rep['cases']} passed")
    out = suite.write_report(rep, DATA_DIR / "eval", {
        "type": "palisade-harness-test", "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "palisade_version": __version__, "manifest_hash": manifest_hash(read_lock()),
        "base_model": t["base"], "guardian_model": t["guardian"], "limits": cfg,
        "note": "rate_per_minute raised to 600 for this run only; audit records are tagged source=harness-test"})
    print(f"report: {out}")
    return 0 if rep["failed"] == 0 else 2


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
    sp = sub.add_parser("setup", help="installed copies: download models and record fingerprints")
    sp.add_argument("--tier"); sp.add_argument("--if-needed", action="store_true",
                                               help="exit quickly when nothing is missing (boot-time job)")
    op = sub.add_parser("open", help="installed copies: start Palisade if needed and open it in a browser")
    op.add_argument("--no-browser", action="store_true")
    ip = sub.add_parser("import", help="reuse models and the audit chain from a source checkout's data folder")
    ip.add_argument("folder")
    e = sub.add_parser("eval"); e.add_argument("--cases", default=str(ROOT / "eval" / "cases.jsonl"))
    sub.add_parser("benchmark")
    hp = sub.add_parser("harness", help="show the harness controls, or test them against the running models")
    hsub = hp.add_subparsers(dest="action", required=True)
    hsub.add_parser("show", help="list the controls and effective limits")
    ht = hsub.add_parser("test", help="start the models and run eval/harness_cases.yaml through the full path")
    ht.add_argument("--no-model-cases", action="store_true", help="skip cases whose outcome depends on model judgment")
    ph = sub.add_parser("publish-hashes", help="write verified fingerprints from manifest.lock into models.yaml")
    ph.add_argument("--dry-run", action="store_true", help="print the result instead of writing it")
    a = sub.add_parser("audit", help="review-side audit commands")
    asub = a.add_subparsers(dest="action", required=True)
    r = asub.add_parser("report", help="write a plain-text review log from the chain")
    r.add_argument("--decision", choices=["answered", "flagged", "blocked", "blocked_input", "blocked_output",
                                         "rejected", "error"])
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
    if MODE == "desktop":
        ensure_config()      # a person's first command creates their config from the defaults
    return {"install": cmd_install, "run": cmd_run, "doctor": cmd_doctor,
            "verify": cmd_verify, "eval": cmd_eval, "benchmark": cmd_benchmark, "harness": cmd_harness,
            "audit": cmd_audit, "publish-hashes": cmd_publish_hashes,
            "setup": cmd_setup, "open": cmd_open, "import": cmd_import}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
