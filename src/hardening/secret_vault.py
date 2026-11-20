"""Secrets-out-of-context: the vault holds the secrets; they NEVER enter the model's prompt.

Threat model shift. The lab's Red/Blue embed the secret in the system prompt, so every defense
is a filter trying to stop the model from repeating something it can see. This module removes the
premise: the model is never given the secret. Only an authorized tool call, behind the egress
policy, can read a value — and tool output is itself filtered before it could ever reach a reply.
A prompt, in any language or encoding, cannot extract what the model does not hold.
"""
from __future__ import annotations

import json
from pathlib import Path


class SecretVault:
    def __init__(self, path: str | None = None):
        p = Path(path) if path else Path(__file__).resolve().parents[2] / "data" / "protected" / "vinbank_secrets.json"
        self._secrets = json.loads(p.read_text(encoding="utf-8")).get("secrets", {})
        self.access_log: list[dict] = []

    def available_names(self) -> list[str]:
        """Names only — never values. Safe to show the model so it knows what CAN be fetched."""
        return list(self._secrets.keys())

    def get(self, name: str, *, authorized: bool, purpose: str = "") -> str | None:
        """Return a value ONLY to an authorized tool context. Every access is logged.
        The model layer must never call this; only the tool/egress layer may, after its own policy."""
        self.access_log.append({"name": name, "authorized": bool(authorized), "purpose": purpose})
        if not authorized:
            return None
        return self._secrets.get(name)
