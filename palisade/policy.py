"""Turn policy.yaml into guardian prompts and map verdicts to actions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITY = {"block": 2, "flag": 1, "allow": 0}


@dataclass
class Category:
    id: str
    action: str
    applies_to: list[str]
    guardian_text: str


class Policy:
    def __init__(self, raw: dict[str, Any]):
        self.version: str = str(raw.get("version", "0"))
        self.block_message: str = raw.get("block_message", "Blocked by policy.").strip()
        self.templates: dict[str, str] = raw["templates"]
        self.categories: list[Category] = [
            Category(c["id"], c["action"], list(c["applies_to"]), c["guardian_text"].strip())
            for c in raw["categories"]
        ]
        for c in self.categories:
            if c.action not in SEVERITY:
                raise ValueError(f"category {c.id}: unknown action {c.action}")

    def for_stage(self, stage: str) -> list[Category]:
        return [c for c in self.categories if stage in c.applies_to]

    def policy_text(self, cats: list[Category]) -> str:
        return "\n\n".join(f"* {c.guardian_text}" for c in cats)

    def render(self, stage: str, cats: list[Category], prompt: str, response: str = "") -> str:
        tpl = self.templates[stage]
        return tpl.format(policy_text=self.policy_text(cats), prompt=prompt, response=response)

    @staticmethod
    def strongest_action(cats: list[Category]) -> str:
        """In combined mode we cannot attribute a hit to one category, so the
        decision takes the most severe action among the categories checked."""
        return max((c.action for c in cats), key=lambda a: SEVERITY[a], default="allow")
