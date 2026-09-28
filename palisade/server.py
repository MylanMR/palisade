"""HTTP orchestrator. Request path:

    client -> [token check] -> guardian(input) -> base model -> guardian(output) -> client
                                    |                                 |
                                    +------------ audit log ----------+

Binds to 127.0.0.1 only. Streaming is deliberately off: the output check needs the
complete response before anything reaches the user.

Every decision is made here, on the server. The browser pages are display-only: they
render what these endpoints return and cannot change a threshold, a policy, or a verdict.

Two credentials:
  - the session token (cookie from "/" or Bearer header) gates every /api route;
  - the reviewer token additionally gates /api/review/*. It is stored in
    <data>/state/reviewer.token with mode 0640, so on a service install only the
    service account and members of the audit group can read it. Reading the audit
    trail through the web UI therefore requires the same group membership as reading
    the files on disk.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from . import (sha256_text, sha256_file, manifest_hash, read_lock, load_policy, policy_path,
               STATE_DIR, LOGS_DIR, AUDIT_DIR, secure_mkdir, secure_write_text, __version__)
from .audit import AuditLog, AuditRecord, new_request_id, utc_now
from .describe import label_of, quant_of, mode_text, BACKEND_LABEL
from .guardian import Guardian
from .policy import Policy
from . import review as review_mod

WEB_DIR = Path(__file__).parent / "web"


class ChatIn(BaseModel):
    message: str
    history: list[dict[str, str]] = []


class ReviewLogin(BaseModel):
    token: str


class ReportIn(BaseModel):
    decision: Optional[str] = None   # Optional[] keeps Python 3.9 compatible
    include_content: bool = False


def _load_reviewer_token() -> str:
    """Create the reviewer token once; reuse it across restarts. Delete the file to rotate."""
    p = STATE_DIR / "reviewer.token"
    secure_mkdir(STATE_DIR)
    if p.exists():
        tok = p.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(32)
    secure_write_text(p, tok + "\n")
    return tok


def _review_log(event: str, **fields: Any) -> None:
    """Append reviewer activity (logins, exports) to a restricted access log."""
    secure_mkdir(LOGS_DIR)
    p = LOGS_DIR / "review-access.log"
    line = json.dumps({"ts": utc_now(), "event": event, **fields}, sort_keys=True)
    import os
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def build_app(settings: dict[str, Any], base_url: str, guardian: Guardian,
              base_model_id: str, audit: AuditLog, *,
              models_cfg: dict | None = None, tier: str | None = None,
              backend: str = "unknown") -> FastAPI:
    app = FastAPI(title="Palisade", docs_url=None, redoc_url=None)
    policy = Policy(load_policy())
    lock = read_lock()
    mhash = manifest_hash(lock)
    token = secrets.token_urlsafe(32)
    reviewer_token = _load_reviewer_token()
    require_token = settings["server"].get("require_token", True)
    gen = settings["generation"]
    gcfg = settings.get("guardian", {})
    retain_full = settings["audit"].get("retain_content", "hashes") == "full"
    client = httpx.Client(timeout=600.0)
    health_client = httpx.Client(timeout=3.0)
    models_cfg = models_cfg or {}
    started = utc_now()

    lock_mutex = threading.Lock()
    session: Counter = Counter()
    last: dict[str, dict | None] = {"input": None, "output": None}
    review_failures: deque = deque(maxlen=50)

    state = {"token": token}

    # ---- auth ----
    def _authed(req: Request) -> None:
        if not require_token:
            return
        hdr = req.headers.get("authorization", "")
        if hdr.startswith("Bearer ") and secrets.compare_digest(hdr[7:], token):
            return
        if secrets.compare_digest(req.cookies.get("palisade_token", ""), token):
            return
        raise HTTPException(401, "missing or invalid token")

    def _reviewer(req: Request) -> None:
        _authed(req)
        supplied = req.headers.get("x-palisade-reviewer", "") or req.cookies.get("palisade_reviewer", "")
        if not supplied or not secrets.compare_digest(supplied, reviewer_token):
            raise HTTPException(403, "reviewer access required")

    def _page(name: str) -> HTMLResponse:
        html = (WEB_DIR / name).read_text(encoding="utf-8")
        resp = HTMLResponse(html)
        resp.set_cookie("palisade_token", token, httponly=True, samesite="strict")
        return resp

    # ---- descriptive helpers (read-only) ----
    def _model_info(mid: str) -> dict:
        meta = models_cfg.get("models", {}).get(mid, {})
        rec = lock.get("models", {}).get(mid, {})
        return {
            "id": mid,
            "label": label_of(mid, meta) if meta else mid,
            "quant": quant_of(meta.get("file", "")) if meta else "unknown",
            "lab": meta.get("lab", ""),
            "license": meta.get("license", ""),
            "file": meta.get("file", ""),
            "repo": meta.get("repo", ""),
            "sha256": rec.get("sha256", ""),
        }

    def _healthy(url: str) -> bool:
        try:
            return health_client.get(f"{url}/health").status_code == 200
        except Exception:
            return False

    def _guardian_healthy() -> bool:
        fn = getattr(guardian, "healthy", None)
        try:
            return bool(fn()) if fn else False
        except Exception:
            return False

    def _policy_info() -> dict:
        path = policy_path()
        counts = Counter(c.action for c in policy.categories)
        recorded = lock.get("config", {}).get(path.name)
        try:
            matches = recorded is not None and sha256_file(path) == recorded
        except OSError:
            matches = False
        return {
            "source": path.name,
            "version": policy.version,
            "is_example": "example" in policy.version.lower(),
            "counts": {k: counts.get(k, 0) for k in ("block", "flag", "allow")},
            "categories": [{"id": c.id, "action": c.action, "applies_to": c.applies_to}
                           for c in policy.categories],
            "matches_lock": matches,
            "locked": recorded is not None,
        }

    def _session() -> dict:
        with lock_mutex:
            return {"started": started, "counts": dict(session),
                    "last": {k: (dict(v) if v else None) for k, v in last.items()}}

    # ---- pages ----
    @app.get("/", response_class=HTMLResponse)
    def index():
        return _page("index.html")

    @app.get("/review", response_class=HTMLResponse)
    def review_page():
        return _page("review.html")

    STATIC = {"shared.css": "text/css", "shared.js": "application/javascript"}

    @app.get("/static/{name}")
    def static(name: str):
        if name not in STATIC:  # fixed allowlist: no path traversal, no directory listing
            raise HTTPException(404, "not found")
        return Response((WEB_DIR / name).read_text(encoding="utf-8"), media_type=STATIC[name],
                        headers={"Cache-Control": "no-cache"})

    # ---- runtime status ----
    @app.get("/api/status")
    def status(req: Request):
        _authed(req)
        a = _model_info(base_model_id)
        a.update({"backend": backend, "backend_label": BACKEND_LABEL.get(backend, backend),
                  "healthy": _healthy(base_url)})
        g = _model_info(guardian.model_id)
        g.update({
            "mode": guardian.mode, "mode_text": mode_text(guardian.mode),
            "threshold": guardian.threshold,
            "check_input": bool(gcfg.get("check_input", True)),
            "check_output": bool(gcfg.get("check_output", True)),
            "healthy": _guardian_healthy(),
        })
        return {
            "version": __version__,
            "assistant": a,
            "guardian": g,
            "policy": _policy_info(),
            "manifest": {"hash": mhash, "tier": tier,
                         "llama_cpp_tag": lock.get("llama_cpp", {}).get("tag", "")},
            "audit": audit.verify(),
            "session": _session(),
            "retain_content": "full" if retain_full else "hashes",
            # legacy flat fields kept for older clients
            "base_model": base_model_id, "guardian_model": guardian.model_id,
            "guardian_mode": guardian.mode, "threshold": guardian.threshold,
            "policy_version": policy.version, "manifest_hash": mhash,
        }

    @app.get("/api/health")
    def health(req: Request):
        _authed(req)
        return {"assistant": _healthy(base_url), "guardian": _guardian_healthy(),
                "session": _session()}

    @app.get("/api/manifest")
    def manifest(req: Request, full: bool = False):
        _authed(req)
        if not models_cfg or not tier:
            raise HTTPException(503, "manifest details unavailable in this mode")
        from .fetch import manifest_components
        res = manifest_components(models_cfg, tier, full=full)
        res["hash"] = mhash
        res["checked_at"] = utc_now()
        return res

    @app.get("/api/manifest/export")
    def manifest_export(req: Request):
        _authed(req)
        body = {"type": "palisade-manifest-export", "generated": utc_now(),
                "palisade_version": __version__, "manifest_hash": mhash, "lock": lock}
        return Response(json.dumps(body, indent=2), media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="palisade-manifest-{mhash[:12]}.json"'})

    @app.get("/api/audit/tail")
    def audit_tail(req: Request, n: int = 30):
        _reviewer(req)
        return audit.tail(min(max(n, 1), 500))

    @app.get("/api/audit/verify")
    def audit_verify(req: Request):
        _authed(req)
        res = audit.verify()
        res["checked_at"] = utc_now()
        return res

    # ---- review (reviewer token required) ----
    @app.post("/api/review/login")
    def review_login(body: ReviewLogin, req: Request):
        _authed(req)
        now = time.time()
        recent = [t for t in review_failures if now - t < 600]
        if len(recent) >= 10:
            raise HTTPException(429, "too many failed attempts; wait 10 minutes")
        if not secrets.compare_digest(body.token.strip(), reviewer_token):
            review_failures.append(now)
            _review_log("login_failed")
            raise HTTPException(403, "invalid reviewer token")
        _review_log("login")
        resp = JSONResponse({"ok": True})
        resp.set_cookie("palisade_reviewer", reviewer_token, httponly=True, samesite="strict")
        return resp

    @app.post("/api/review/logout")
    def review_logout(req: Request):
        _authed(req)
        resp = JSONResponse({"ok": True})
        resp.delete_cookie("palisade_reviewer")
        return resp

    @app.get("/api/review/session")
    def review_session(req: Request):
        _authed(req)
        supplied = req.cookies.get("palisade_reviewer", "")
        return {"reviewer": bool(supplied) and secrets.compare_digest(supplied, reviewer_token),
                "token_file": str(STATE_DIR / "reviewer.token")}

    @app.get("/api/review/summary")
    def review_summary(req: Request):
        _reviewer(req)
        counts = Counter(r.get("decision") for r in audit.all_records())
        v = audit.verify()
        v["checked_at"] = utc_now()
        return {"verify": v, "counts": dict(counts), "retain_content": "full" if retain_full else "hashes",
                "manifest_hash": mhash}

    @app.get("/api/review/records")
    def review_records(req: Request, decision: Optional[str] = None, limit: int = 100,
                       before: Optional[int] = None):
        _reviewer(req)
        allowed = {None, "", "answered", "flagged", "blocked", "blocked_input", "blocked_output"}
        if decision not in allowed:
            raise HTTPException(400, "unknown decision filter")
        return audit.records(decision or None, min(max(limit, 1), 500), before)

    @app.post("/api/review/report")
    def review_report(body: ReportIn, req: Request):
        _reviewer(req)
        text = review_mod.render_report(audit, decision=body.decision or None,
                                        include_content=body.include_content and retain_full,
                                        manifest_hash=mhash, generated_by="web reviewer")
        name = f"audit-review-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.log"
        saved = secure_write_text(audit.dir / "reports" / name, text)
        _review_log("report_export", file=name, decision=body.decision or "all",
                    include_content=bool(body.include_content and retain_full))
        return PlainTextResponse(text, headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Palisade-Saved-To": str(saved)})

    @app.get("/api/review/anchor")
    def review_anchor(req: Request):
        _reviewer(req)
        a = review_mod.anchor(audit, mhash)
        _review_log("anchor_export", records=a["records"], head_hash=a["head_hash"])
        return Response(review_mod.anchor_text(a), media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="palisade-anchor-{a["records"]}.json"'})

    # ---- chat (enforcement path, unchanged in behavior) ----
    @app.post("/api/chat")
    def chat(body: ChatIn, req: Request):
        _authed(req)
        t0 = time.time()
        rid = new_request_id()
        prompt = body.message.strip()
        if not prompt:
            raise HTTPException(400, "empty message")

        verdicts = []
        decision = "answered"
        response_text = ""

        # 1. input check
        if settings["guardian"].get("check_input", True):
            v_in = guardian.check("input", policy, prompt)
            verdicts.append(v_in)
            if v_in.violated and v_in.action == "block":
                decision = "blocked_input"
                response_text = policy.block_message
            elif v_in.violated and v_in.action == "flag":
                decision = "flagged"

        # 2. generation
        if decision != "blocked_input":
            msgs = [{"role": "system", "content": gen["system_prompt"].strip()}]
            msgs += [m for m in body.history if m.get("role") in ("user", "assistant")][-20:]
            msgs.append({"role": "user", "content": prompt})
            r = client.post(f"{base_url}/v1/chat/completions", json={
                "messages": msgs,
                "temperature": gen.get("temperature", 0.4),
                "max_tokens": gen.get("max_tokens", 1024),
                "stream": False,
            })
            if r.status_code != 200:
                raise HTTPException(502, f"base model error: {r.text[:200]}")
            response_text = r.json()["choices"][0]["message"]["content"]

            # 3. output check
            if settings["guardian"].get("check_output", True):
                v_out = guardian.check("output", policy, prompt, response_text)
                verdicts.append(v_out)
                if v_out.violated and v_out.action == "block":
                    decision = "blocked_output"
                    response_text = policy.block_message
                elif v_out.violated and v_out.action == "flag" and decision == "answered":
                    decision = "flagged"

        # 4. audit
        rec = audit.append(AuditRecord(
            seq=0, ts=utc_now(), request_id=rid, manifest_hash=mhash,
            policy_version=policy.version, base_model=base_model_id,
            guardian_model=guardian.model_id, decision=decision,
            prompt_sha256=sha256_text(prompt), response_sha256=sha256_text(response_text),
            verdicts=[v.__dict__ for v in verdicts],
            latency_ms=int((time.time() - t0) * 1000),
            prompt=prompt if retain_full else None,
            response=response_text if retain_full else None,
        ))

        with lock_mutex:
            session["messages"] += 1
            session[decision] += 1
            for v in verdicts:
                last[v.stage] = {"p": v.p_violation, "violated": v.violated, "action": v.action,
                                 "categories": list(v.categories), "seq": rec.seq}

        return {
            "request_id": rid,
            "decision": decision,
            "response": response_text,
            "verdicts": [v.__dict__ for v in verdicts],
            "audit": {"seq": rec.seq, "hash": rec.hash, "prev_hash": rec.prev_hash},
            "latency_ms": rec.latency_ms,
        }

    @app.exception_handler(HTTPException)
    def _http_err(_, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    app.state.palisade = state
    return app
