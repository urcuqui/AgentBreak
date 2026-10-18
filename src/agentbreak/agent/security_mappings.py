"""Structured security mappings for the flagship ``indirect-injection`` scenario.

The machine-readable counterpart of ``docs/security-mappings.md``, which stays
the human-readable explanation. Deliberately limited to the categories the
scenario exercises end to end -- not all ten OWASP LLM categories, which are
explored one by one in the separate OWASP lab. Only ATLAS IDs cited with
confidence in that document appear here; never add a guessed ID.
"""

from __future__ import annotations

from typing import Any, Final

from ..owasp import get_category

MAPPINGS_DOC: Final = "docs/security-mappings.md"

# OWASP code -> why it applies. Titles come from the owasp.py catalog.
OWASP_LLM: Final[tuple[tuple[str, str], ...]] = (
    ("LLM01", "Injected instructions in a retrieved document steer the agent."),
    ("LLM06", "The successful attack path retrieves and exfiltrates a credential."),
    ("LLM07", "send_report executes against an untrusted destination when unchecked."),
    ("LLM08", "The agent requests privileged tools the task never needed."),
)

MITRE_ATLAS: Final[tuple[tuple[str, str], ...]] = (
    ("AML.T0051", "LLM Prompt Injection"),
    ("AML.T0051.001", "LLM Prompt Injection: Indirect"),
)


def related_mappings() -> dict[str, Any]:
    """The flagship scenario's related mappings, ready to serialize."""

    return {
        "source": MAPPINGS_DOC,
        "owasp_llm": [
            {"code": code, "title": get_category(code).title, "why": why}
            for code, why in OWASP_LLM
        ],
        "mitre_atlas": [{"id": id_, "title": title} for id_, title in MITRE_ATLAS],
    }
