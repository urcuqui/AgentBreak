"""Pydantic models for the retrieval -> agent -> policy -> tool pipeline.

These types separate *what the agent receives* (untrusted retrieved content)
from *what the agent decides to do* (tool calls) and *what the policy layer
decided* (allow/block decisions) -- the same separation the trust boundary
depends on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TrustLevel = Literal["trusted", "untrusted"]
RiskLevel = Literal["info", "low", "medium", "high", "critical"]
ScenarioMode = Literal["normal", "attack", "secure"]
FinalStatus = Literal[
    "ATTACK_SUCCESS", "ATTACK_BLOCKED", "PARTIALLY_MITIGATED", "NO_ATTACK"
]


def utcnow() -> datetime:
    return datetime.now(UTC)


class RetrievedDocument(BaseModel):
    """A document returned by the RAG layer. Always untrusted data, never instructions."""

    document_id: str
    title: str
    content: str
    source: str
    trust_level: TrustLevel = "untrusted"
    retrieval_score: float = 0.0


class ToolCall(BaseModel):
    """A tool invocation proposed by the agent, before authorization."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class ToolResult(BaseModel):
    """The outcome of executing a tool."""

    tool_name: str
    ok: bool
    output: Any | None = None
    error: str | None = None


class PolicyDecision(BaseModel):
    """Output of one deterministic control evaluated against one tool call."""

    model_config = ConfigDict(frozen=True)

    control: str
    allowed: bool
    reason: str
    risk_level: RiskLevel = "info"

    @property
    def status(self) -> str:
        return "ALLOW" if self.allowed else "BLOCK"


class SuspiciousFinding(BaseModel):
    """A single hit from the explainable suspicious-content signal."""

    pattern: str
    snippet: str


class ScenarioEvent(BaseModel):
    """One structured telemetry row, matching the AgentBreak security schema."""

    timestamp: datetime = Field(default_factory=utcnow)
    scenario: str
    context_source: str | None = None
    context_trust_level: TrustLevel | None = None
    agent_action: str
    requested_tool: str | None = None
    tool_arguments: dict[str, Any] | None = None
    policy_decision: str | None = None
    policy_reason: str | None = None
    security_control: str | None = None
    attack_detected: bool = False
    final_action: str


class ScenarioRun(BaseModel):
    """The full result of one normal/attack/secure run."""

    scenario: str
    mode: ScenarioMode
    events: list[ScenarioEvent] = Field(default_factory=list)
    document: RetrievedDocument | None = None
    proposed_calls: list[ToolCall] = Field(default_factory=list)
    executed_calls: list[str] = Field(default_factory=list)
    blocked_calls: list[str] = Field(default_factory=list)
    sensitive_accessed: bool = False
    data_exfiltrated: bool = False
    suspicious_findings: list[SuspiciousFinding] = Field(default_factory=list)
    final_status: FinalStatus = "NO_ATTACK"
