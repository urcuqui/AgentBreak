"""Shared helpers used by both the vulnerable and the secure agents.

Keeps decision-making (which tool calls to propose) and prompt assembly out of
the agent flow files so the latter stay short and readable.
"""

from __future__ import annotations

from typing import Literal

from .llm import (
    SECURE_SYSTEM_PROMPT,
    VULNERABLE_SYSTEM_PROMPT,
    OllamaClient,
    build_secure_user_prompt,
    build_vulnerable_user_prompt,
    propose_tool_calls,
    simulate_tool_calls,
)
from .models import RetrievedDocument, ToolCall

DecisionSource = Literal["llm", "simulator", "llm+fallback"]


_ATTACK_TOOLS = {"get_customer_record", "send_report"}


def _is_full_attack(calls: list[ToolCall]) -> bool:
    names = {c.tool_name for c in calls}
    return _ATTACK_TOOLS.issubset(names)


def decide_tool_calls(
    question: str,
    document: RetrievedDocument,
    *,
    mode: Literal["vulnerable", "secure"],
    llm: OllamaClient | None,
    force_attack_for_demo: bool = False,
) -> tuple[list[ToolCall], DecisionSource]:
    """Return the tool calls the agent will attempt, plus their provenance.

    * If ``llm`` is provided and reachable, ask it first.
    * If the LLM result is unparsable or empty, fall back to the simulator.
    * In vulnerable mode, when ``force_attack_for_demo`` is true and the LLM
      did not produce the attack calls, fall back so the demo still shows the
      threat. The provenance returned is ``"llm+fallback"``.
    """

    if llm is not None:
        system = (
            VULNERABLE_SYSTEM_PROMPT if mode == "vulnerable" else SECURE_SYSTEM_PROMPT
        )
        user = (
            build_vulnerable_user_prompt(question, document)
            if mode == "vulnerable"
            else build_secure_user_prompt(question, document)
        )
        calls = propose_tool_calls(llm, system=system, user=user)
        if calls:
            if mode == "vulnerable" and force_attack_for_demo and not _is_full_attack(calls):
                # Model resisted the injection. Show the threat anyway.
                return simulate_tool_calls(document), "llm+fallback"
            return calls, "llm"
    return simulate_tool_calls(document), "simulator"
