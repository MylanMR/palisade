"""HTTP orchestrator. Request path:

    client -> admission -> [token check] -> harness clean-up and probe -> guardian(input)
           -> base model -> harness output checks -> guardian(output) -> client
                                    |                                 |
                                    +------------ audit log ----------+

The harness (harness.py) is the fixed-rule layer around every model call; the guardian
is the model-based layer. Either can stop a request; neither can be skipped.

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
from .guardian import Guardian, GuardianUnavailable
from .policy import Policy
from . import review as review_mod
from . import harness as H
from .runtime import as_endpoint

WEB_DIR = Path(__file__).parent / "web"


class ChatIn(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    # Refused when non-empty: history is held by the server so it cannot be forged.
    history: Optional[list[Any]] = None


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


def _admission(app: FastAPI, settings: dict[str, Any], max_body_kb: int) -> None:
    app.add_middleware(H.AdmissionMiddleware, hosts=H.allowed_hosts(settings["server"]),
                       max_body=max_body_kb * 1024)


def build_app(settings: dict[str, Any], base: Any, guardian: Guardian,
              base_model_id: str, audit: AuditLog, *,
              models_cfg: dict | None = None, tier: str | None = None,
              backend: str = "unknown", record_source: Optional[str] = None) -> FastAPI:
    """`base` is the assistant model server's Endpoint (runtime.py). `record_source`
    tags every audit record this app writes, for example "harness-test"; it is set by
    the program that builds the app, never by a client."""
    app = FastAPI(title="Palisade", docs_url=None, redoc_url=None)
    hcfg, hnotes = H.harness_config(settings)
    _admission(app, settings, hcfg["max_body_kb"])
    policy = Policy(load_policy())
    lock = read_lock()
    mhash = manifest_hash(lock)
    token = secrets.token_urlsafe(32)
    reviewer_token = _load_reviewer_token()
    require_token = settings["server"].get("require_token", True)
    gen = settings["generation"]
    gcfg = settings.get("guardian", {})
    retain_full = settings["audit"].get("retain_content", "hashes") == "full"
    base_ep = as_endpoint(base)
    base_url = base_ep.url
    client = base_ep.client(float(hcfg["generation_timeout_seconds"]))
    health_client = base_ep.client(3.0)
    probes = [H.TokenizerProbe("assistant", base_ep.client(30.0))]
    if getattr(guardian, "endpoint", None) is not None:
        probes.append(H.TokenizerProbe("guardian", guardian.endpoint.client(30.0)))
    canary = H.Canary(gen["system_prompt"])
    conversations = H.Conversations(hcfg["conversation_idle_minutes"], hcfg["max_conversations"],
                                    hcfg["max_blocks_per_conversation"])
    limiter = H.RateLimiter(hcfg["rate_per_minute"])
    gate = H.Gate(hcfg["queue_depth"], hcfg["queue_wait_seconds"])
    ctx_tokens = int(settings["runtime"].get("context_tokens", 4096))
    max_new = int(gen.get("max_tokens", 1024))
    budget_cache: dict[str, int] = {}
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

    def _healthy(_url: str = "") -> bool:
        try:
            return health_client.get("/health").status_code == 200
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
            "harness": _harness_status(),
            # legacy flat fields kept for older clients
            "base_model": base_model_id, "guardian_model": guardian.model_id,
            "guardian_mode": guardian.mode, "threshold": guardian.threshold,
            "policy_version": policy.version, "manifest_hash": mhash,
        }

    @app.get("/api/health")
    def health(req: Request):
        _authed(req)
        return {"assistant": _healthy(base_url), "guardian": _guardian_healthy(),
                "session": _session(), "harness_live": _harness_status()["live"]}

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
        allowed = {None, "", "answered", "flagged", "blocked", "blocked_input", "blocked_output",
                   "rejected", "error"}
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

    # ---- harness helpers ----
    def _harness_status() -> dict:
        d = H.describe(hcfg, hnotes, base_ep.transport)
        with lock_mutex:
            d["live"] = {"conversations": conversations.count(), "waiting": gate.waiting,
                         "rate_limited": session.get("rate_limited", 0),
                         "busy_refused": session.get("busy_refused", 0)}
        return d

    def _budgets() -> tuple[int, int]:
        """(largest message in tokens, tokens left for message plus history). Counted once
        with the assistant's own tokenizer, on first use."""
        if "context" not in budget_cache:
            sys_tokens, special = probes[0].inspect(canary.system_prompt)
            if special:
                raise H.HarnessStop("error", "the configured system prompt contains a control token",
                                    H.ERROR_MESSAGE, 503)
            context = ctx_tokens - max_new - H.RESERVE_TOKENS - sys_tokens - H.TEMPLATE_OVERHEAD_TOKENS
            if context < 64:
                raise H.HarnessStop("error", "context window too small for the system prompt and answer length",
                                    H.ERROR_MESSAGE, 503)
            budget_cache["context"] = context
            budget_cache["message"] = min(hcfg["max_message_tokens"], context - H.TEMPLATE_OVERHEAD_TOKENS)
        return budget_cache["message"], budget_cache["context"]

    def _inspect(text: str, stage: str) -> int:
        """Probe every model's tokenizer. Returns the assistant token count."""
        count = 0
        for p in probes:
            n, special = p.inspect(text)
            if p.name == "assistant":
                count = n
            if special:
                if stage == "input":
                    raise H.HarnessStop("blocked_input", f"control token survived clean-up ({p.name} tokenizer)",
                                        policy.block_message)
                raise H.HarnessStop("blocked_output", f"answer contained a control token ({p.name} tokenizer)",
                                    policy.block_message)
        return count

    def _json(status: int, body: dict, headers: Optional[dict] = None) -> JSONResponse:
        return JSONResponse(body, status_code=status, headers=headers or {})

    # ---- chat (enforcement path) ----
    @app.post("/api/chat")
    def chat(body: ChatIn, req: Request):
        _authed(req)
        try:
            limiter.take()
        except H.Busy as e:
            with lock_mutex:
                session["rate_limited"] += 1
            return _json(429, {"error": str(e), "code": "rate_limited"}, {"Retry-After": str(e.retry_after)})
        if not body.message.strip():
            raise HTTPException(400, "empty message")

        t0 = time.time()
        rid = new_request_id()
        info: dict[str, Any] = {"source": record_source} if record_source else {}
        verdicts: list = []
        raw_prompt = body.message
        prompt = raw_prompt.strip()
        response_text = ""
        decision = "answered"
        status_code = 200
        conv = None

        try:
            if body.history:
                raise H.HarnessStop("rejected", "client sent conversation history; the server holds history",
                                    H.REJECT_MESSAGE.format(reason="conversation history is kept by Palisade, "
                                                            "so send conversation_id instead of past turns"), 400)
            try:
                conv = conversations.open(body.conversation_id)
            except H.ConversationError as e:
                return _json(e.status, {"error": e.message, "code": e.code})
            info["conversation"] = conv.ref
            info["turn"] = sum(1 for t in conv.turns if t.role == "user") + 1

            with conversations.hold(conv), gate.slot():
                cleaned = H.canonicalize(raw_prompt)
                prompt = cleaned.text.strip()
                if cleaned.changed:
                    info["input_cleaned"] = cleaned.summary()
                    info["raw_prompt_sha256"] = sha256_text(raw_prompt)
                    if retain_full:
                        info["raw_prompt"] = raw_prompt
                if not prompt:
                    raise H.HarnessStop("rejected", "message was empty after removing hidden characters "
                                        "and control tokens",
                                        H.REJECT_MESSAGE.format(reason="nothing was left after removing hidden "
                                                                "characters and control tokens"), 400)

                msg_limit, context_budget = _budgets()
                n_tokens = _inspect(prompt, "input")
                info["input_tokens"] = n_tokens
                if n_tokens > msg_limit:
                    raise H.HarnessStop("rejected", f"message is {n_tokens} tokens; limit is {msg_limit}",
                                        H.REJECT_MESSAGE.format(reason=f"it is {n_tokens} tokens long and the "
                                                                f"limit is {msg_limit}"), 413)

                # 1. input screening: the message, then the recent conversation together
                if gcfg.get("check_input", True):
                    v_in = guardian.check("input", policy, prompt)
                    verdicts.append(v_in)
                    if v_in.violated and v_in.action == "block":
                        decision = "blocked_input"
                    elif v_in.violated and v_in.action == "flag":
                        decision = "flagged"
                    prior = conv.user_turns(hcfg["conversation_window"])
                    if (decision != "blocked_input" and hcfg["check_conversation"] and prior):
                        joined = "\n\n".join(prior + [prompt])
                        v_conv = guardian.check("input", policy, joined)
                        v_conv.note = (v_conv.note + "; " if v_conv.note else "") + \
                            f"conversation: last {len(prior) + 1} messages together"
                        verdicts.append(v_conv)
                        if v_conv.violated and v_conv.action == "block":
                            decision = "blocked_input"
                            info["reason"] = "the conversation as a whole violates policy"
                        elif v_conv.violated and v_conv.action == "flag" and decision == "answered":
                            decision = "flagged"
                if cleaned.suspicious and decision == "answered":
                    decision = "flagged"
                    info.setdefault("reason", "hidden characters or control tokens were removed from the message")

                # 2. generation, with server-held history trimmed to the token budget
                if decision != "blocked_input":
                    history = H.build_context(conv, context_budget - n_tokens - H.TEMPLATE_OVERHEAD_TOKENS,
                                              hcfg["max_history_turns"])
                    info["context_turns"] = len(history)
                    msgs = [{"role": "system", "content": canary.system_prompt}]
                    msgs += [{"role": t.role, "content": t.content} for t in history]
                    msgs.append({"role": "user", "content": prompt})
                    try:
                        r = client.post("/v1/chat/completions", json={
                            "messages": msgs,
                            "temperature": gen.get("temperature", 0.4),
                            "max_tokens": max_new,
                            "stream": False,
                        })
                    except Exception as e:
                        raise H.HarnessStop("error", f"assistant model unreachable: {type(e).__name__}",
                                            H.ERROR_MESSAGE, 502) from e
                    if r.status_code != 200:
                        raise H.HarnessStop("error", f"assistant model returned HTTP {r.status_code}",
                                            H.ERROR_MESSAGE, 502)
                    try:
                        choice = r.json()["choices"][0]
                        raw_answer = choice["message"].get("content") or ""
                    except (ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
                        raise H.HarnessStop("error", "assistant model returned an unreadable answer",
                                            H.ERROR_MESSAGE, 502) from e
                    info["finish_reason"] = choice.get("finish_reason")

                    # 3. output: clean-up, probe, leak check, then the guardian
                    out = H.canonicalize(raw_answer, nfkc=False)
                    response_text = out.text
                    if out.changed:
                        info["output_cleaned"] = out.summary()
                        info["raw_response_sha256"] = sha256_text(raw_answer)
                    out_tokens = _inspect(response_text, "output") if response_text else 0
                    leak = canary.leaked(response_text)
                    if leak:
                        raise H.HarnessStop("blocked_output", f"answer disclosed the {leak.replace('_', ' ')}",
                                            policy.block_message)
                    if gcfg.get("check_output", True):
                        v_out = guardian.check("output", policy, prompt, H.screening_text(response_text))
                        verdicts.append(v_out)
                        if v_out.violated and v_out.action == "block":
                            decision = "blocked_output"
                        elif v_out.violated and v_out.action == "flag" and decision == "answered":
                            decision = "flagged"

                    if decision in ("answered", "flagged"):
                        conv.turns.append(H.Turn("user", prompt, n_tokens))
                        conv.turns.append(H.Turn("assistant", response_text, out_tokens))
                if decision.startswith("blocked") or cleaned.suspicious:
                    conversations.record_block(conv)
                if decision.startswith("blocked"):
                    response_text = policy.block_message

        except H.Busy as e:
            with lock_mutex:
                session["busy_refused"] += 1
            return _json(429, {"error": str(e), "code": "busy"}, {"Retry-After": str(e.retry_after)})
        except H.ConversationError as e:
            return _json(e.status, {"error": e.message, "code": e.code})
        except H.HarnessStop as e:
            decision, response_text, status_code = e.decision, e.public, e.status
            info["reason"] = e.reason
            if decision.startswith("blocked") and conv is not None:
                conversations.record_block(conv)
        except (GuardianUnavailable, H.ProbeError) as e:
            decision, response_text, status_code = "error", H.ERROR_MESSAGE, 503
            info["reason"] = str(e)
        except Exception as e:   # anything unexpected: fail closed, and record it
            decision, response_text, status_code = "error", H.ERROR_MESSAGE, 500
            info["reason"] = f"internal error: {type(e).__name__}"

        if conv is not None:
            info["conversation_closed"] = conv.closed

        # 4. audit: every processed request, whatever the outcome
        rec = audit.append(AuditRecord(
            seq=0, ts=utc_now(), request_id=rid, manifest_hash=mhash,
            policy_version=policy.version, base_model=base_model_id,
            guardian_model=guardian.model_id, decision=decision,
            prompt_sha256=sha256_text(prompt), response_sha256=sha256_text(response_text),
            verdicts=[v.__dict__ for v in verdicts],
            latency_ms=int((time.time() - t0) * 1000),
            prompt=prompt if retain_full else None,
            response=response_text if retain_full else None,
            harness=info or None,
        ))

        with lock_mutex:
            session["messages"] += 1
            session[decision] += 1
            for v in verdicts:
                last[v.stage] = {"p": v.p_violation, "violated": v.violated, "action": v.action,
                                 "categories": list(v.categories), "seq": rec.seq}

        public_info = {k: info[k] for k in ("reason", "input_cleaned", "output_cleaned", "context_turns",
                                            "turn", "conversation_closed", "finish_reason") if k in info}
        return _json(status_code, {
            "request_id": rid,
            "decision": decision,
            "response": response_text,
            "verdicts": [v.__dict__ for v in verdicts],
            "conversation_id": conv.id if conv is not None and not conv.closed else None,
            "harness": public_info,
            "audit": {"seq": rec.seq, "hash": rec.hash, "prev_hash": rec.prev_hash},
            "latency_ms": rec.latency_ms,
        })

    @app.exception_handler(HTTPException)
    def _http_err(_, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    app.state.palisade = state
    return app


def build_setup_app(settings: dict[str, Any], problems_fn, status_path: Path) -> FastAPI:
    """Served while an installed copy is not ready: first-run downloads in progress, or a
    verification failure an administrator needs to see. It runs no models and exposes no
    audit data; it reports setup progress and the problems found, behind the same
    session-token rules as the main app. `problems_fn` returns the current problem list."""
    from .setup import read_status
    from . import MODE

    app = FastAPI(title="Palisade setup", docs_url=None, redoc_url=None)
    _admission(app, settings, 16)
    token = secrets.token_urlsafe(32)
    require_token = settings["server"].get("require_token", True)
    cache: dict[str, Any] = {"at": 0.0, "problems": []}

    def _authed(req: Request) -> None:
        if not require_token:
            return
        hdr = req.headers.get("authorization", "")
        if hdr.startswith("Bearer ") and secrets.compare_digest(hdr[7:], token):
            return
        if secrets.compare_digest(req.cookies.get("palisade_token", ""), token):
            return
        raise HTTPException(401, "missing or invalid token")

    @app.get("/", response_class=HTMLResponse)
    @app.get("/review", response_class=HTMLResponse)
    def page():
        resp = HTMLResponse((WEB_DIR / "setup.html").read_text(encoding="utf-8"))
        resp.set_cookie("palisade_token", token, httponly=True, samesite="strict")
        return resp

    STATIC = {"shared.css": "text/css", "shared.js": "application/javascript"}

    @app.get("/static/{name}")
    def static(name: str):
        if name not in STATIC:
            raise HTTPException(404, "not found")
        return Response((WEB_DIR / name).read_text(encoding="utf-8"), media_type=STATIC[name],
                        headers={"Cache-Control": "no-cache"})

    @app.get("/api/setup/status")
    def setup_status(req: Request):
        _authed(req)
        # Problem checks hash files, so refresh them at most every few seconds.
        if time.time() - cache["at"] > 5:
            cache["problems"] = [{"kind": p.kind, "message": p.message} for p in problems_fn()]
            cache["at"] = time.time()
        return {"mode": MODE, "setup": read_status(status_path), "problems": cache["problems"],
                "ready": not cache["problems"]}

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def not_ready(rest: str, req: Request):
        _authed(req)
        raise HTTPException(503, "Palisade is still being set up")

    @app.exception_handler(HTTPException)
    def _http_err(_, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    app.state.palisade = {"token": token}
    return app
