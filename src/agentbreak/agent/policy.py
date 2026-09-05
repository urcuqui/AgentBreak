"""Deterministic security controls, evaluated independently of the model.

The rule this module exists to enforce: *the agent may propose an action, but
these functions decide whether it is allowed to happen.* Every control here is
pure, synchronous, and explainable -- none of it depends on the model
behaving well, and none of it is the model's job to run.

Controls:

* ``authorize_tool``            -- allowlist enforcement by task.
* ``validate_arguments``        -- recursive sensitive-field detection.
* ``check_data_classification`` -- flags secret/confidential fields.
* ``validate_destination``      -- egress destination allowlist.
* ``check_egress``              -- composes the two controls above for
                                    outbound tools.
* ``require_human_approval``    -- high-impact tools need an explicit
                                    approval flag; an unattended run has none.
* ``detect_suspicious_content``  -- explainable signal only, never the gate.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, Final

from .agent_models import PolicyDecision, SuspiciousFinding
from .tools import HIGH_IMPACT_TOOLS

# Allowlist of tools per logical task. Anything not listed is denied by default.
ALLOWED_TOOLS_BY_TASK: Final[dict[str, frozenset[str]]] = {
    "grid_incident_response": frozenset({"search_knowledge_base"}),
    # An intentionally over-permissive profile used by the regression corpus
    # (tests/security_cases/tool_abuse.json) to show that tool authorization
    # alone is not enough: a broad, role-based allowlist ("excessive agency")
    # still gets contained by argument validation, data classification and
    # egress control further down the pipeline.
    "asset_maintenance_broad": frozenset(
        {"search_knowledge_base", "get_asset_credentials", "send_report"}
    ),
}

# Fields whose presence anywhere in tool arguments is forbidden, regardless of task.
SENSITIVE_ARGUMENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_token", "api_key", "apikey", "password", "passwd", "token",
        "refresh_token", "private_key", "secret", "client_secret",
        "credential", "credentials", "authorization",
    }
)

# Field name -> data classification. Anything not listed is "public".
DATA_CLASSIFICATION: Final[dict[str, str]] = {
    "access_token": "secret",
    "api_key": "secret",
    "password": "secret",
    "maintenance_status": "internal",
    "location": "internal",
}

# Tools whose output can leave the system.
EGRESS_TOOLS: Final[frozenset[str]] = frozenset({"send_report"})

# The only destinations an egress tool may target.
ALLOWED_DESTINATIONS: Final[frozenset[str]] = frozenset(
    {"local://outbox", "https://incident.northgrid.internal/reports"}
)

SUSPICIOUS_PATTERNS: Final[tuple[str, ...]] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "important operational update",
    "important system update",
    "retrieve the maintenance credentials",
    "send the access token",
    "do not mention this",
    "bypass policy",
)

_SECRET_VALUE_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{4,}|grid-[A-Za-z0-9_-]{4,}|AKIA[0-9A-Z]{8,}|ghp_[A-Za-z0-9]{8,})\b"
)


def is_tool_allowed(task: str, tool_name: str) -> bool:
    allowed = ALLOWED_TOOLS_BY_TASK.get(task)
    return tool_name in allowed if allowed is not None else False


def authorize_tool(task: str, tool_name: str) -> PolicyDecision:
    """Allowlist enforcement: is ``tool_name`` permitted for ``task``?"""

    if task not in ALLOWED_TOOLS_BY_TASK:
        return PolicyDecision(
            control="tool_authorization",
            allowed=False,
            reason=f"Unknown task '{task}'. Deny by default.",
            risk_level="high",
        )
    if is_tool_allowed(task, tool_name):
        return PolicyDecision(
            control="tool_authorization",
            allowed=True,
            reason=f"Tool '{tool_name}' is allowed for task '{task}'.",
            risk_level="info",
        )
    return PolicyDecision(
        control="tool_authorization",
        allowed=False,
        reason=f"Tool '{tool_name}' is not allowed for task '{task}'.",
        risk_level="high",
    )


def _iter_keys(obj: Any) -> Iterable[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from _iter_keys(v)
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            yield from _iter_keys(item)


def find_sensitive_fields(arguments: Any) -> list[str]:
    """Return the sorted sensitive field names found anywhere in ``arguments``."""

    return sorted({k for k in _iter_keys(arguments) if k.lower() in SENSITIVE_ARGUMENT_KEYS})


def validate_arguments(tool_name: str, arguments: Any) -> PolicyDecision:
    """Reject tool calls whose own arguments name a sensitive field."""

    hits = find_sensitive_fields(arguments)
    if hits:
        return PolicyDecision(
            control="argument_validation",
            allowed=False,
            reason=f"Sensitive field(s) {hits} present in arguments for '{tool_name}'.",
            risk_level="critical",
        )
    return PolicyDecision(
        control="argument_validation",
        allowed=True,
        reason="No sensitive fields detected in arguments.",
        risk_level="info",
    )


def _classify(obj: Any) -> set[str]:
    labels: set[str] = set()
    for key in _iter_keys(obj):
        labels.add(DATA_CLASSIFICATION.get(key.lower(), "public"))
    return labels


def check_data_classification(tool_name: str, arguments: Any) -> PolicyDecision:
    """Flag arguments carrying secret- or confidential-classified data."""

    labels = _classify(arguments)
    if "secret" in labels:
        return PolicyDecision(
            control="data_classification",
            allowed=False,
            reason=f"Payload for '{tool_name}' contains secret-classified data.",
            risk_level="critical",
        )
    if "confidential" in labels:
        return PolicyDecision(
            control="data_classification",
            allowed=False,
            reason=f"Payload for '{tool_name}' contains confidential-classified data.",
            risk_level="high",
        )
    return PolicyDecision(
        control="data_classification",
        allowed=True,
        reason="No secret- or confidential-classified data in payload.",
        risk_level="info",
    )


def _contains_secret_value(obj: Any) -> bool:
    if isinstance(obj, str):
        return bool(_SECRET_VALUE_RE.search(obj))
    if isinstance(obj, dict):
        return any(_contains_secret_value(v) for v in obj.values())
    if isinstance(obj, (list, tuple, set)):
        return any(_contains_secret_value(v) for v in obj)
    return False


def validate_destination(tool_name: str, destination: str | None) -> PolicyDecision:
    """Egress tools may only target an explicitly allowed destination."""

    if tool_name not in EGRESS_TOOLS:
        return PolicyDecision(
            control="egress_validation",
            allowed=True,
            reason=f"Tool '{tool_name}' does not perform egress.",
            risk_level="info",
        )
    if destination in ALLOWED_DESTINATIONS:
        return PolicyDecision(
            control="egress_validation",
            allowed=True,
            reason=f"Destination '{destination}' is authorized.",
            risk_level="info",
        )
    return PolicyDecision(
        control="egress_validation",
        allowed=False,
        reason=f"Destination '{destination}' is not authorized.",
        risk_level="critical",
    )


def check_egress(
    tool_name: str, arguments: Any, destination: str | None = None
) -> PolicyDecision:
    """Composite egress check: destination allowlist + classification + secret values."""

    if tool_name not in EGRESS_TOOLS:
        return PolicyDecision(
            control="egress_control",
            allowed=True,
            reason=f"Tool '{tool_name}' is not an egress tool.",
            risk_level="info",
        )
    dest_decision = validate_destination(tool_name, destination)
    if not dest_decision.allowed:
        return PolicyDecision(
            control="egress_control",
            allowed=False,
            reason=dest_decision.reason,
            risk_level="critical",
        )
    sensitive = find_sensitive_fields(arguments)
    if sensitive:
        return PolicyDecision(
            control="egress_control",
            allowed=False,
            reason=f"Egress blocked: sensitive field(s) {sensitive} in payload for '{tool_name}'.",
            risk_level="critical",
        )
    if _contains_secret_value(arguments):
        return PolicyDecision(
            control="egress_control",
            allowed=False,
            reason=f"Egress blocked: secret-looking value in payload for '{tool_name}'.",
            risk_level="critical",
        )
    return PolicyDecision(
        control="egress_control",
        allowed=True,
        reason=f"No sensitive data detected in egress payload for '{tool_name}'.",
        risk_level="low",
    )


def require_human_approval(tool_name: str, approved: bool = False) -> PolicyDecision:
    """High-impact tools require an explicit human approval flag to run."""

    if tool_name not in HIGH_IMPACT_TOOLS:
        return PolicyDecision(
            control="approval_gate",
            allowed=True,
            reason=f"Tool '{tool_name}' does not require human approval.",
            risk_level="info",
        )
    if approved:
        return PolicyDecision(
            control="approval_gate",
            allowed=True,
            reason=f"Tool '{tool_name}' was explicitly approved by a human operator.",
            risk_level="info",
        )
    return PolicyDecision(
        control="approval_gate",
        allowed=False,
        reason=f"Tool '{tool_name}' is high-impact and has no human approval on record.",
        risk_level="high",
    )


def detect_suspicious_content(text: str) -> list[SuspiciousFinding]:
    """Explainable phrase-matching signal for prompt injection.

    This is *only* a signal of risk, logged as telemetry. It must never be
    the thing standing between an attacker and a privileged action -- the
    controls above are.
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


def evaluate(
    task: str,
    tool_name: str,
    arguments: dict[str, Any],
    destination: str | None = None,
    *,
    approved: bool = False,
) -> list[PolicyDecision]:
    """Run every applicable control for one proposed tool call.

    All controls are evaluated (not short-circuited) so the full pipeline is
    visible in telemetry, even once one control has already denied the call.
    ``approved`` is a control-plane signal (was a human asked and did they say
    yes?) and is passed separately from ``arguments`` on purpose -- mixing it
    into the tool's own payload would blur the same data/control separation
    this module exists to enforce.
    """

    decisions = [
        authorize_tool(task, tool_name),
        validate_arguments(tool_name, arguments),
        check_data_classification(tool_name, arguments),
        require_human_approval(tool_name, approved=approved),
    ]
    if tool_name in EGRESS_TOOLS:
        decisions.append(check_egress(tool_name, arguments, destination))
    return decisions
