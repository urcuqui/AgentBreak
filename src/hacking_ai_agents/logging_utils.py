"""Logging helpers: secret redaction and an in-memory audit trail.

The audit trail is purely local. Nothing here writes to the network.
"""

from __future__ import annotations

import re
from typing import Any

from .models import AuditEvent

SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "secret",
        "client_secret",
        "credential",
        "credentials",
        "authorization",
    }
)

# Match obvious secret-looking values for redaction even when the key is unknown.
_SECRET_VALUE_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{4,}|AKIA[0-9A-Z]{8,}|ghp_[A-Za-z0-9]{8,})\b"
)


def redact_value(value: str) -> str:
    """Redact a single string value, keeping the first/last chars for context."""

    if not isinstance(value, str):
        return value
    if len(value) <= 6:
        return "***"
    return f"{value[:6]}****{value[-6:]}"


def _redact_string(text: str) -> str:
    return _SECRET_VALUE_RE.sub(lambda m: redact_value(m.group(0)), text)


def redact(obj: Any) -> Any:
    """Recursively redact sensitive fields in ``obj`` for safe logging."""

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS:
                if isinstance(v, str):
                    out[k] = redact_value(v)
                else:
                    out[k] = "***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact(v) for v in obj)
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj


class AuditLog:
    """A simple list-backed audit log used by both agents and tests."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        # Make sure no secret slips into the recorded payload.
        if event.arguments_redacted is not None:
            event = event.model_copy(
                update={"arguments_redacted": redact(event.arguments_redacted)}
            )
        self._events.append(event)

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def find(self, event_type: str) -> list[AuditEvent]:
        return [e for e in self._events if e.event_type == event_type]

    def clear(self) -> None:
        self._events.clear()
