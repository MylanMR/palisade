"""Guardian classifier: asks a safety model a Yes/No question and reads the
probability of the positive token from the first-token logprobs.

Reading logprobs instead of generated text makes the threshold tunable and the
score reportable, which matters when you calibrate against your own eval set.

Fail closed. Each of these counts as a violation with the strictest action, never as
"allowed":
  - the guardian server cannot be reached, times out, or returns an error;
  - the server reports that it truncated the prompt (part of the text went unread);
  - the first token is neither the positive nor the negative answer often enough to
    read a score (an "indeterminate" verdict).
"""
from __future__ import annotations

import math
import time
from typing import Any

from .audit import GuardianVerdict
from .policy import Policy, Category
from .runtime import as_endpoint

# If Yes and No together hold less than this share of the first-token probability, the
# model did not answer the question it was asked, and its score means nothing.
MIN_ANSWER_MASS = 0.2


class GuardianUnavailable(RuntimeError):
    """The guardian could not give a verdict. Callers treat this as a block."""


class Indeterminate(Exception):
    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


class Guardian:
    def __init__(self, endpoint: Any, model_id: str, adapter_cfg: dict[str, Any],
                 mode: str = "combined", threshold: float = 0.5, timeout: float = 60.0):
        self.endpoint = as_endpoint(endpoint)
        self.url = self.endpoint.url
        self.model_id = model_id
        self.pos = adapter_cfg.get("positive_token", "Yes")
        self.neg = adapter_cfg.get("negative_token", "No")
        self.mode = mode
        self.threshold = threshold
        self.client = self.endpoint.client(timeout)

    # ---- low level ----
    def _p_positive(self, prompt: str) -> float:
        try:
            r = self.client.post("/completion", json={
                "prompt": prompt,
                "n_predict": 1,
                "n_probs": 10,
                "temperature": 0.0,
                "cache_prompt": True,
            })
        except Exception as e:
            raise GuardianUnavailable(f"guardian unreachable: {type(e).__name__}") from e
        if r.status_code != 200:
            raise GuardianUnavailable(f"guardian returned HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError as e:
            raise GuardianUnavailable("guardian returned unreadable output") from e
        if data.get("truncated"):
            raise Indeterminate("prompt truncated by the guardian server")
        entries = data.get("completion_probabilities") or []
        if not entries:
            # No logprobs available: fall back to the generated text.
            text = (data.get("content") or "").strip().lower()
            if text.startswith(self.pos.lower()):
                return 1.0
            if text.startswith(self.neg.lower()):
                return 0.0
            raise Indeterminate("guardian answered neither yes nor no")
        first = entries[0]
        cands = first.get("probs") or first.get("top_logprobs") or []
        p_pos = p_neg = 0.0
        for c in cands:
            tok = (c.get("tok_str") or c.get("token") or "").strip().lower()
            if "prob" in c:
                p = float(c["prob"])
            else:
                p = math.exp(float(c.get("logprob", -50)))
            if tok == self.pos.lower():
                p_pos += p
            elif tok == self.neg.lower():
                p_neg += p
        total = p_pos + p_neg
        if total < MIN_ANSWER_MASS:
            raise Indeterminate(f"yes/no probability mass {total:.2f} below {MIN_ANSWER_MASS}")
        return p_pos / total

    # ---- public ----
    def check(self, stage: str, policy: Policy, prompt: str, response: str = "",
              mode: str | None = None) -> GuardianVerdict:
        """`mode` overrides the configured mode for one call; the harness uses it to recheck
        a borderline combined score one category at a time."""
        mode = mode or self.mode
        cats = policy.for_stage(stage)
        t0 = time.time()
        if not cats:
            return GuardianVerdict(stage, self.model_id, mode, 0.0, self.threshold, False, [], "allow", 0)

        try:
            if mode == "per_category":
                hits: list[Category] = []
                worst = 0.0
                for c in cats:
                    p = self._p_positive(policy.render(stage, [c], prompt, response))
                    worst = max(worst, p)
                    if p >= self.threshold:
                        hits.append(c)
                violated = bool(hits)
                action = Policy.strongest_action(hits) if hits else "allow"
                names = [c.id for c in hits]
                score = worst
            else:
                score = self._p_positive(policy.render(stage, cats, prompt, response))
                violated = score >= self.threshold
                action = Policy.strongest_action(cats) if violated else "allow"
                names = []
        except Indeterminate as e:
            return GuardianVerdict(stage, self.model_id, mode, 1.0, self.threshold, True, [],
                                   "block", int((time.time() - t0) * 1000), note=f"indeterminate: {e.why}")

        return GuardianVerdict(stage, self.model_id, mode, round(score, 4), self.threshold,
                               violated, names, action, int((time.time() - t0) * 1000))

    def healthy(self) -> bool:
        try:
            return self.client.get("/health", timeout=5).status_code == 200
        except Exception:
            return False
