"""HTTP orchestrator. Request path:

    client -> [token check] -> guardian(input) -> base model -> guardian(output) -> client
                                    |                                 |
                                    +------------ audit log ----------+

Binds to 127.0.0.1 only. Streaming is deliberately off: the output check needs the
complete response before anything reaches the user.
"""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import sha256_text, manifest_hash, read_lock, load_policy
from .audit import AuditLog, AuditRecord, new_request_id, utc_now
from .guardian import Guardian
from .policy import Policy

WEB = Path(__file__).parent / "web" / "index.html"


class ChatIn(BaseModel):
    message: str
    history: list[dict[str, str]] = []


def build_app(settings: dict[str, Any], base_url: str, guardian: Guardian,
              base_model_id: str, audit: AuditLog) -> FastAPI:
    app = FastAPI(title="Palisade", docs_url=None, redoc_url=None)
    policy = Policy(load_policy())
    mhash = manifest_hash(read_lock())
    token = secrets.token_urlsafe(32)
    require_token = settings["server"].get("require_token", True)
    gen = settings["generation"]
    retain_full = settings["audit"].get("retain_content", "hashes") == "full"
    client = httpx.Client(timeout=600.0)

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

    # ---- routes ----
    @app.get("/", response_class=HTMLResponse)
    def index(response: Response):
        html = WEB.read_text(encoding="utf-8")
        response.set_cookie("palisade_token", token, httponly=True, samesite="strict")
        return HTMLResponse(html, headers=response.headers)

    @app.get("/api/status")
    def status(req: Request):
        _authed(req)
        return {
            "base_model": base_model_id,
            "guardian_model": guardian.model_id,
            "guardian_mode": guardian.mode,
            "threshold": guardian.threshold,
            "policy_version": policy.version,
            "manifest_hash": mhash,
            "audit": audit.verify(),
        }

    @app.get("/api/audit/tail")
    def audit_tail(req: Request, n: int = 30):
        _authed(req)
        return audit.tail(min(max(n, 1), 500))

    @app.get("/api/audit/verify")
    def audit_verify(req: Request):
        _authed(req)
        return audit.verify()

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
