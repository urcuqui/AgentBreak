"""Security controls applied independently of the model.

This module implements the *defense* layer of the demo:

* ``authorize_tool``         - allowlist enforcement by task.
* ``validate_arguments``     - sensitive-field detection (recursive).
* ``check_egress``           - block secrets being sent out by ``send_report``.
* ``detect_suspicious_content`` - explainable signal for prompt injection.

These controls are intentionally simple, deterministic, and explainable.
They do not rely on the language model behaving well.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .models import SecurityDecision, SuspiciousFinding
from .policies import (
    ALLOWED_TOOLS_BY_TASK,
    EGRESS_TOOLS,
    SENSITIVE_ARGUMENT_KEYS,
    is_tool_allowed,
)


class SecurityViolation(Exception):
    """Raised when a security policy blocks an action."""

    def __init__(self, decision: SecurityDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


# ---------------------------------------------------------------------------
# 1. Tool authorization
# ---------------------------------------------------------------------------

def authorize_tool(task: str, tool_name: str) -> SecurityDecision:
    """Authorize ``tool_name`` for ``task`` against the static allowlist."""

    if task not in ALLOWED_TOOLS_BY_TASK:
        return SecurityDecision(
            allowed=False,
            reason=f"Unknown task '{task}'. Deny by default.",
            policy_name="tool_allowlist",
            risk_level="high",
        )
    if is_tool_allowed(task, tool_name):
        return SecurityDecision(
            allowed=True,
            reason=f"Tool '{tool_name}' is allowed for task '{task}'.",
            policy_name="tool_allowlist",
            risk_level="info",
        )
    return SecurityDecision(
        allowed=False,
        reason=f"Tool '{tool_name}' is not allowed for task '{task}'.",
        policy_name="tool_allowlist",
        risk_level="high",
    )


# ---------------------------------------------------------------------------
# 2. Argument validation (recursive)
# ---------------------------------------------------------------------------

def _iter_keys(obj: Any) -> Iterable[str]:
    """Yield every dict key encountered anywhere inside ``obj``."""

    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _iter_keys(v)
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            yield from _iter_keys(item)


def find_sensitive_fields(arguments: Any) -> list[str]:
    """Return a sorted list of sensitive field names found in ``arguments``."""

    hits: set[str] = set()
    for key in _iter_keys(arguments):
        if key.lower() in SENSITIVE_ARGUMENT_KEYS:
            hits.add(key)
    return sorted(hits)


def validate_arguments(tool_name: str, arguments: Any) -> SecurityDecision:
    """Reject tool calls whose arguments contain sensitive fields."""

    hits = find_sensitive_fields(arguments)
    if hits:
        return SecurityDecision(
            allowed=False,
            reason=(
                f"Sensitive field(s) {hits} present in arguments for tool "
                f"'{tool_name}'."
            ),
            policy_name="argument_validation",
            risk_level="critical",
        )
    return SecurityDecision(
        allowed=True,
        reason="No sensitive fields detected in arguments.",
        policy_name="argument_validation",
        risk_level="info",
    )


# ---------------------------------------------------------------------------
# 3. Egress control for outbound tools
# ---------------------------------------------------------------------------

_SECRET_VALUE_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{4,}|AKIA[0-9A-Z]{8,}|ghp_[A-Za-z0-9]{8,})\b"
)


def _contains_secret_value(obj: Any) -> bool:
    if isinstance(obj, str):
        return bool(_SECRET_VALUE_RE.search(obj))
    if isinstance(obj, dict):
        return any(_contains_secret_value(v) for v in obj.values())
    if isinstance(obj, (list, tuple, set)):
        return any(_contains_secret_value(v) for v in obj)
    return False


def check_egress(tool_name: str, arguments: Any) -> SecurityDecision:
    """Block secrets / sensitive fields from leaving via egress tools."""

    if tool_name not in EGRESS_TOOLS:
        return SecurityDecision(
            allowed=True,
            reason=f"Tool '{tool_name}' is not an egress tool.",
            policy_name="egress_control",
            risk_level="info",
        )
    sensitive = find_sensitive_fields(arguments)
    if sensitive:
        return SecurityDecision(
            allowed=False,
            reason=(
                f"Egress blocked: sensitive field(s) {sensitive} in payload "
                f"for '{tool_name}'."
            ),
            policy_name="egress_control",
            risk_level="critical",
        )
    if _contains_secret_value(arguments):
        return SecurityDecision(
            allowed=False,
            reason=f"Egress blocked: secret-looking value in payload for '{tool_name}'.",
            policy_name="egress_control",
            risk_level="critical",
        )
    return SecurityDecision(
        allowed=True,
        reason=f"No sensitive data detected in egress payload for '{tool_name}'.",
        policy_name="egress_control",
        risk_level="low",
    )


# ---------------------------------------------------------------------------
# 4. Suspicious-content detection (signal only, not a guarantee)
# ---------------------------------------------------------------------------

SUSPICIOUS_PATTERNS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "system update",
    "send the api key",
    "send the api_key",
    "retrieve the customer record",
    "call the tool",
    "reveal the secret",
    "bypass policy",
    "do not mention this",
)


def detect_suspicious_content(text: str) -> list[SuspiciousFinding]:
    """Return findings for explainable suspicious phrases in ``text``.

    This is *only* a signal of risk. It must not be presented or relied upon
    as the primary defense; deterministic tool authorization is.
    """

    lowered = text.lower()
    findings: list[SuspiciousFinding] = []
    for pattern in SUSPICIOUS_PATTERNS:
        idx = lowered.find(pattern)
        if idx == -1:
            continue
        start = max(0, idx - 20)
        end = min(len(text), idx + len(pattern) + 20)
        findings.append(SuspiciousFinding(pattern=pattern, snippet=text[start:end].strip()))
    return findings
