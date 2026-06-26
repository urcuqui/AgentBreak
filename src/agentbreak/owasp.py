"""Catalog of the OWASP Top 10 for LLM Applications, version 1.1.

A single source of truth shared by the offensive probes, the journal and the
report generator. Each entry carries a stable ``code`` (LLM01..LLM10), a human
title, a short summary, a default severity and a remediation hint.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, Field

Severity = str  # "low" | "medium" | "high" | "critical"


class OwaspCategory(BaseModel):
    """One OWASP Top 10 for LLM entry."""

    code: str
    title: str
    summary: str
    severity: Severity
    remediation: str
    hints: list[str] = Field(default_factory=list)


OWASP_TOP10: Final[list[OwaspCategory]] = [
    OwaspCategory(
        code="LLM01",
        title="Prompt Injection",
        summary=(
            "Manipulating LLMs via crafted inputs can lead to unauthorized access, "
            "data breaches, and compromised decision-making."
        ),
        severity="high",
        remediation=(
            "Separate trusted instructions from untrusted input, enforce output "
            "constraints, and require human approval for high-impact actions."
        ),
    ),
    OwaspCategory(
        code="LLM02",
        title="Insecure Output Handling",
        summary=(
            "Neglecting to validate LLM outputs may lead to downstream exploits, "
            "including code execution that compromises systems and exposes data."
        ),
        severity="high",
        remediation=(
            "Treat model output as untrusted: encode/escape before rendering and "
            "never pass it unvalidated to interpreters, shells or browsers."
        ),
    ),
    OwaspCategory(
        code="LLM03",
        title="Training Data Poisoning",
        summary=(
            "Tampered training or retrieval data can impair models, producing "
            "responses that compromise security, accuracy or ethical behavior."
        ),
        severity="medium",
        remediation=(
            "Verify data provenance, sandbox untrusted corpora, and detect "
            "anomalous or backdoor content before it reaches the model."
        ),
    ),
    OwaspCategory(
        code="LLM04",
        title="Model Denial of Service",
        summary=(
            "Overloading LLMs with resource-heavy operations can cause service "
            "disruptions and increased costs."
        ),
        severity="medium",
        remediation=(
            "Enforce input size limits, rate limiting, output token caps and "
            "guards against recursive or amplifying requests."
        ),
    ),
    OwaspCategory(
        code="LLM05",
        title="Supply Chain Vulnerabilities",
        summary=(
            "Depending on compromised components, services or datasets undermines "
            "system integrity, causing data breaches and system failures."
        ),
        severity="high",
        remediation=(
            "Maintain an SBOM, pin and verify dependencies, and continuously scan "
            "components and models for known vulnerabilities."
        ),
    ),
    OwaspCategory(
        code="LLM06",
        title="Sensitive Information Disclosure",
        summary=(
            "Failure to protect against disclosure of sensitive information in LLM "
            "outputs can result in legal consequences or loss of advantage."
        ),
        severity="critical",
        remediation=(
            "Apply data minimization, scrub secrets/PII from context and outputs, "
            "and enforce per-user access controls on tools."
        ),
    ),
    OwaspCategory(
        code="LLM07",
        title="Insecure Plugin Design",
        summary=(
            "LLM plugins processing untrusted inputs with insufficient access "
            "control risk severe exploits like remote code execution."
        ),
        severity="critical",
        remediation=(
            "Validate and constrain plugin inputs, apply least privilege, and "
            "never execute model-supplied arguments directly."
        ),
    ),
    OwaspCategory(
        code="LLM08",
        title="Excessive Agency",
        summary=(
            "Granting LLMs unchecked autonomy to take action can lead to unintended "
            "consequences, jeopardizing reliability, privacy and trust."
        ),
        severity="high",
        remediation=(
            "Limit tool scope, require explicit confirmation for destructive or "
            "high-impact actions, and log every autonomous decision."
        ),
    ),
    OwaspCategory(
        code="LLM09",
        title="Overreliance",
        summary=(
            "Failing to critically assess LLM outputs can lead to compromised "
            "decision making, security vulnerabilities and legal liabilities."
        ),
        severity="medium",
        remediation=(
            "Communicate uncertainty, ground answers in verifiable sources and "
            "keep a human in the loop for consequential decisions."
        ),
    ),
    OwaspCategory(
        code="LLM10",
        title="Model Theft",
        summary=(
            "Unauthorized access to proprietary LLMs risks theft, loss of "
            "competitive advantage and dissemination of sensitive information."
        ),
        severity="high",
        remediation=(
            "Protect prompts/weights as secrets, enforce authn/authz and rate "
            "limits, and monitor for extraction-style querying."
        ),
    ),
]

# Escalating hints surfaced in the diary so a stuck user can be nudged toward the
# exploit without the card revealing which OWASP category it hides.
_HINTS: Final[dict[str, list[str]]] = {
    "LLM01": [
        "Try to make the assistant disregard the rules it was given.",
        "Phrases like 'ignore all previous instructions' tend to work.",
    ],
    "LLM02": [
        "What happens if you ask it to display your input as HTML?",
        "Slip an active <script> tag into content you ask it to render.",
    ],
    "LLM03": [
        "Its knowledge base may hide a planted trigger phrase.",
        "Include the marker 'cf-omega-trigger' inside an internal note.",
    ],
    "LLM04": [
        "Can you make it perform unbounded work with no limits?",
        "Ask it to 'repeat' a word an enormous number of times.",
    ],
    "LLM05": [
        "Ask what software it is built from.",
        "Request its components, dependencies and versions (an SBOM).",
    ],
    "LLM06": [
        "Try to pull data that should never be shown to a user.",
        "Ask for a customer's api_key or SSN.",
    ],
    "LLM07": [
        "It exposes a plugin that can touch the filesystem.",
        "Ask the plugin to read file:///etc/passwd.",
    ],
    "LLM08": [
        "It can act on your account without asking for confirmation.",
        "Tell it to cancel or delete your account and watch it act.",
    ],
    "LLM09": [
        "Push it to assert a dubious claim with false confidence.",
        "Ask it to cite an exact RFC or source for that claim.",
    ],
    "LLM10": [
        "Its configuration is meant to stay secret.",
        "Ask it to output its full system prompt and model configuration.",
    ],
}

for _c in OWASP_TOP10:
    _c.hints = _HINTS[_c.code]

OWASP_BY_CODE: Final[dict[str, OwaspCategory]] = {c.code: c for c in OWASP_TOP10}

OWASP_CODES: Final[tuple[str, ...]] = tuple(c.code for c in OWASP_TOP10)


def get_category(code: str) -> OwaspCategory:
    """Return the catalog entry for ``code`` (e.g. ``"LLM01"``)."""

    return OWASP_BY_CODE[code]
