"""Pydantic models shared across AgentBreak components."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class ChatResponse(BaseModel):
    """The structured output of a single chatbot turn.

    ``text`` is what an end user would see. ``meta`` carries machine-readable
    evidence used by the offensive probes to detect a vulnerability, mirroring
    the kind of side effects a real agent would expose (tool calls, raw output
    passed downstream, leaked data, etc.).
    """

    text: str
    backend: str = "simulator"
    actions: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class ProbeResult(BaseModel):
    """Outcome of running one offensive probe against the chatbot."""

    code: str
    name: str
    discovered: bool
    severity: str
    payload: str
    evidence: str
    response_excerpt: str
    timestamp: datetime = Field(default_factory=utcnow)


class JournalEntry(BaseModel):
    """A single page of the diary, locked until its vulnerability is found."""

    code: str
    title: str
    summary: str
    severity: str
    remediation: str
    hints: list[str] = Field(default_factory=list)
    unlocked: bool = False
    discovered_at: datetime | None = None
    evidence: str = ""
    payload: str = ""

    def locked_blurb(self) -> str:
        return (
            f"??? — Page sealed. Discover the {self.code} vulnerability in the "
            "chatbot to unlock this entry of the journal."
        )


class JournalState(BaseModel):
    """Persistable diary state: which OWASP pages have been unlocked."""

    entries: dict[str, JournalEntry] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utcnow)

    @property
    def unlocked_count(self) -> int:
        return sum(1 for e in self.entries.values() if e.unlocked)

    @property
    def total(self) -> int:
        return len(self.entries)
