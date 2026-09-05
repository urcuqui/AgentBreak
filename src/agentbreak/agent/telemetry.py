"""Structured + human-readable telemetry for the flagship scenario.

Every decision the agent and the policy layer make is recorded as a
:class:`ScenarioEvent` (machine-readable) and, unless the console is
suppressed, printed as one of the ``[RETRIEVAL]`` / ``[AGENT]`` / ``[POLICY]``
/ ``[ATTACK]`` / ``[RESULT]`` blocks a live audience can follow.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console

from .agent_models import PolicyDecision, RetrievedDocument, ScenarioEvent


class TelemetryLog:
    """Collects :class:`ScenarioEvent` rows and prints the console blocks."""

    def __init__(self, scenario: str, console: Console | None = None, *, quiet: bool = False) -> None:
        self.scenario = scenario
        self.console = console or Console()
        self.quiet = quiet
        self.events: list[ScenarioEvent] = []

    def _emit(self, event: ScenarioEvent) -> None:
        self.events.append(event)

    def _print(self, *lines: str) -> None:
        if self.quiet:
            return
        for line in lines:
            self.console.print(line)
        self.console.print()

    def retrieval(self, document: RetrievedDocument) -> None:
        self._emit(
            ScenarioEvent(
                scenario=self.scenario,
                context_source=document.source,
                context_trust_level=document.trust_level,
                agent_action="retrieve",
                final_action="context_retrieved",
            )
        )
        self._print(
            "[bold]\\[RETRIEVAL][/bold]",
            f"source={document.source}",
            f"trust=[yellow]{document.trust_level.upper()}[/yellow]",
        )

    def agent_requested(self, tool_name: str, arguments: dict[str, Any]) -> None:
        self._emit(
            ScenarioEvent(
                scenario=self.scenario,
                agent_action="propose_tool_call",
                requested_tool=tool_name,
                tool_arguments=arguments,
                final_action="tool_call_proposed",
            )
        )
        self._print("[bold]\\[AGENT][/bold]", f"requested_tool={tool_name}")

    def policy(self, tool_name: str, decision: PolicyDecision) -> None:
        self._emit(
            ScenarioEvent(
                scenario=self.scenario,
                agent_action="policy_check",
                requested_tool=tool_name,
                policy_decision=decision.status,
                policy_reason=decision.reason,
                security_control=decision.control,
                final_action=f"policy_{decision.status.lower()}",
            )
        )
        color = "green" if decision.allowed else "red"
        self._print(
            "[bold]\\[POLICY][/bold]",
            f"control={decision.control}",
            f"decision=[{color}]{decision.status}[/{color}]",
            f"reason={decision.reason}",
        )

    def attack(self, detected: bool, same_payload: bool = False) -> None:
        self._emit(
            ScenarioEvent(
                scenario=self.scenario,
                agent_action="attack_signal",
                attack_detected=detected,
                final_action="attack_signal_recorded",
            )
        )
        if same_payload:
            self._print("[bold]\\[ATTACK][/bold]", "same_payload=true")
        else:
            mark = "DETECTED" if detected else "not detected"
            self._print("[bold]\\[ATTACK][/bold]", f"indirect_prompt_injection={mark}")

    def result(self, status: str) -> None:
        self._emit(
            ScenarioEvent(
                scenario=self.scenario,
                agent_action="final_result",
                final_action=status,
            )
        )
        color = "red" if status == "ATTACK_SUCCESS" else "green"
        self._print("[bold]\\[RESULT][/bold]", f"[{color}]{status}[/{color}]")
