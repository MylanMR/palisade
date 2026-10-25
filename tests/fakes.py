"""Test doubles for the model servers.

FakeModelServer answers the llama-server endpoints Palisade uses (/health, /tokenize,
/v1/chat/completions, /v1/models) without a model. Its tokenizer is one token per
character, except that strings in `specials` become a single control token when
parse_special is true, which is how the real tokenizer behaves.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

SPECIALS = ["<start_of_turn>", "<end_of_turn>", "<bos>", "<eos>",
            "[[CTRL]]"]   # [[CTRL]] stands in for a token the harness pattern list does not know


class Resp:
    def __init__(self, status: int, body: Any):
        self.status_code, self._body = status, body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body

    @property
    def text(self):
        return str(self._body)


class FakeModelServer:
    def __init__(self, answer: Callable[[list[dict]], str] | str = "Here is a safe answer.",
                 specials: Optional[list[str]] = None):
        self.answer = answer
        self.specials = SPECIALS if specials is None else specials
        self.requests: list[dict] = []
        self.fail_chat: Optional[Exception | int] = None
        self.fail_tokenize: Optional[Exception | int] = None

    def tokenize(self, text: str, parse_special: bool) -> list[int]:
        ids, i = [], 0
        while i < len(text):
            hit = next((s for s in self.specials if parse_special and text.startswith(s, i)), None)
            if hit:
                ids.append(100000 + self.specials.index(hit))
                i += len(hit)
            else:
                ids.append(ord(text[i]))
                i += 1
        return ids

    def handle(self, method: str, path: str, json: Optional[dict]) -> Resp:
        if path == "/health":
            return Resp(200, {"status": "ok"})
        if path == "/v1/models":
            return Resp(200, {"data": []})
        if path == "/tokenize":
            if isinstance(self.fail_tokenize, Exception):
                raise self.fail_tokenize
            if isinstance(self.fail_tokenize, int):
                return Resp(self.fail_tokenize, {"error": "x"})
            return Resp(200, {"tokens": self.tokenize(json["content"], json.get("parse_special", True))})
        if path == "/v1/chat/completions":
            self.requests.append(json)
            if isinstance(self.fail_chat, Exception):
                raise self.fail_chat
            if isinstance(self.fail_chat, int):
                return Resp(self.fail_chat, {"error": "x"})
            text = self.answer(json["messages"]) if callable(self.answer) else self.answer
            return Resp(200, {"choices": [{"message": {"content": text}, "finish_reason": "stop"}]})
        return Resp(404, {"error": "not found"})


class FakeClient:
    def __init__(self, server: FakeModelServer):
        self.server = server

    def post(self, path: str, json: Optional[dict] = None, **_: Any) -> Resp:
        return self.server.handle("POST", path, json)

    def get(self, path: str, **_: Any) -> Resp:
        return self.server.handle("GET", path, None)


class FakeEndpoint:
    url = "http://model"
    transport = "test double"

    def __init__(self, server: FakeModelServer):
        self.server = server

    def client(self, timeout: float = 0) -> FakeClient:
        return FakeClient(self.server)


class StubGuardian:
    """Flags any text containing a trigger word, at the stage's strongest action. With a
    `server`, it also exposes an endpoint so the harness probes its tokenizer."""

    model_id = "stub-guardian"
    mode = "combined"
    threshold = 0.5

    def __init__(self, server: Optional[FakeModelServer] = None, trigger: str = "nervegas"):
        self.trigger = trigger
        self.calls: list[tuple[str, str, str]] = []
        self.fail: Optional[Exception] = None
        if server is not None:
            self.endpoint = FakeEndpoint(server)

    def healthy(self) -> bool:
        return True

    def check(self, stage, policy, prompt, response="", mode=None):
        from palisade.audit import GuardianVerdict
        from palisade.policy import Policy
        self.calls.append((stage, prompt, response))
        if self.fail:
            raise self.fail
        hit = self.trigger in (prompt + " " + response).lower()
        action = Policy.strongest_action(policy.for_stage(stage)) if hit else "allow"
        return GuardianVerdict(stage, self.model_id, self.mode, 0.99 if hit else 0.01,
                               self.threshold, hit, [], action, 3)


LOCAL = "http://127.0.0.1:8080"
