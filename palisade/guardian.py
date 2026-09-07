"""Guardian classifier: asks a safety model a Yes/No question and reads the
probability of the positive token from the first-token logprobs.

Reading logprobs instead of generated text makes the threshold tunable and the
score reportable, which matters when you calibrate against your own eval set.
"""
from __future__ import annotations

import math
import time
from typing import Any

import httpx

from .audit import GuardianVerdict
from .policy import Policy, Category


class Guardian:
    def __init__(self, base_url: str, model_id: str, adapter_cfg: dict[str, Any],
                 mode: str = "combined", threshold: float = 0.5):
        self.url = base_url.rstrip("/")
        self.model_id = model_id
        self.pos = adapter_cfg.get("positive_token", "Yes")
        self.neg = adapter_cfg.get("negative_token", "No")
        self.mode = mode
        self.threshold = threshold
        self.client = httpx.Client(timeout=120.0)

    # ---- low level ----
    def _p_positive(self, prompt: str) -> float:
        r = self.client.post(f"{self.url}/completion", json={
            "prompt": prompt,
            "n_predict": 1,
            "n_probs": 10,
            "temperature": 0.0,
            "cache_prompt": True,
        })
        r.raise_for_status()
        data = r.json()
        entries = data.get("completion_probabilities") or []
        if not entries:
            # No logprobs available: fall back to the generated text.
            return 1.0 if data.get("content", "").strip().lower().startswith(self.pos.lower()) else 0.0
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
        if total <= 0:
            return 0.0
        return p_pos / total

    # ---- public ----
    def check(self, stage: str, policy: Policy, prompt: str, response: str = "") -> GuardianVerdict:
        cats = policy.for_stage(stage)
        t0 = time.time()
        if not cats:
            return GuardianVerdict(stage, self.model_id, self.mode, 0.0, self.threshold, False, [], "allow", 0)

        if self.mode == "per_category":
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

        return GuardianVerdict(stage, self.model_id, self.mode, round(score, 4), self.threshold,
                               violated, names, action, int((time.time() - t0) * 1000))

    def healthy(self) -> bool:
        try:
            return self.client.get(f"{self.url}/health", timeout=5).status_code == 200
        except Exception:
            return False
