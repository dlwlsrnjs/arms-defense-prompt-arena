from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DefensePrompt:
    condition: str
    author: str
    text: str

    def __post_init__(self) -> None:
        if self.condition not in {"no_defense", "human", "agent"}:
            raise ValueError("condition must be no_defense, human, or agent")
        if self.condition == "no_defense" and self.text.strip():
            raise ValueError("no_defense must not install a system prompt")
        if self.condition != "no_defense" and not self.text.strip():
            raise ValueError(f"{self.condition} requires a non-empty defense system prompt")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    @property
    def installed_text(self) -> str:
        return self.text.strip()


class SystemPromptTarget:
    """Target client wrapper that installs one authored prompt at system priority."""

    def __init__(self, target: Any, system_prompt: str):
        self.target = target
        self.system_prompt = system_prompt.strip()

    def chat(self, messages: list[dict], **overrides: Any) -> str:
        if not self.system_prompt:
            return self.target.chat(messages, **overrides)
        if any(message.get("role") == "system" for message in messages):
            raise ValueError("target messages already contain a system prompt; refusing ambiguous precedence")
        installed = [{"role": "system", "content": self.system_prompt}, *messages]
        return self.target.chat(installed, **overrides)
