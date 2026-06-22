"""Pydantic models shared by the demo components.

These types deliberately separate *what the agent receives* (untrusted context)
from *what the agent decides to do* (tool calls) and *what security policy
enforcement produced* (decisions and audit events).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TrustLevel = Literal["trusted", "untrusted"]
RiskLevel = Literal["info", "low", "medium", "high", "critical"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class UserRequest(BaseModel):
    """A request issued by an end user to the support agent."""

    model_config = ConfigDict(frozen=True)

    question: str = Field(..., min_length=1)
    task: str = Field(..., description="Logical task type, e.g. 'refund_policy'.")
    user_id: str = Field(default="anonymous")


class RetrievedDocument(BaseModel):
    """A document returned by the RAG layer."""

    document_id: str
    title: str
    content: str
    source: str
    trust_level: TrustLevel = "untrusted"
    retrieval_score: float = 0.0


class ToolCall(BaseModel):
    """A request to invoke a tool, before authorization."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class ToolResult(BaseModel):
    """The outcome of executing a tool."""

    tool_name: str
    ok: bool
    output: Any | None = None
    error: str | None = None


class CustomerRecord(BaseModel):
    """A fictional customer record."""

    customer_id: str
    name: str
    email: str
    tier: str = "standard"
    api_key: str = Field(..., description="Fictional credential, demo-only.")


class SecurityDecision(BaseModel):
    """Output of a policy evaluation for a single tool call."""

    allowed: bool
    reason: str
    policy_name: str
    risk_level: RiskLevel = "info"

    @property
    def status(self) -> str:
        return "ALLOW" if self.allowed else "BLOCK"


class AuditEvent(BaseModel):
    """A structured audit record for a single agent decision or action."""

    timestamp: datetime = Field(default_factory=_utcnow)
    actor: str = "agent"
    event_type: str
    task: str | None = None
    tool_name: str | None = None
    arguments_redacted: dict[str, Any] | None = None
    decision: SecurityDecision | None = None
    message: str = ""

    def to_log_dict(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        return data


class SuspiciousFinding(BaseModel):
    """A single hit from the suspicious-content detector."""

    pattern: str
    snippet: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.pattern!r} -> {self.snippet!r}"
