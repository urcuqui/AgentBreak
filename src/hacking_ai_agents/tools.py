"""Tool implementations used by the agent.

These are local, deterministic stand-ins for the kinds of capabilities a real
support agent might have. ``send_report`` simulates outbound delivery by
appending a JSON line to a file in the local ``sent_reports/`` directory; it
never opens a network connection.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import CustomerRecord, RetrievedDocument, ToolResult
from .rag import load_default_kb, retrieve

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
CUSTOMERS_FILE = DATA_DIR / "customers.json"

# Local "outbox" used by send_report. Created on demand.
SENT_REPORTS_DIR = PROJECT_ROOT / "sent_reports"


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

ALL_TOOLS: tuple[str, ...] = (
    "search_knowledge_base",
    "get_customer_record",
    "create_support_ticket",
    "send_report",
)


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------

def search_knowledge_base(query: str, poisoned: bool = False) -> ToolResult:
    """Search the bundled knowledge base and return the best match."""

    kb = load_default_kb(poisoned=poisoned)
    matches = retrieve(query, kb, top_k=1)
    docs: list[RetrievedDocument] = list(matches)
    return ToolResult(
        tool_name="search_knowledge_base",
        ok=True,
        output=[d.model_dump() for d in docs],
    )


def _load_customers() -> list[CustomerRecord]:
    raw = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return [CustomerRecord(**entry) for entry in raw]


def get_customer_record(customer_id: str) -> ToolResult:
    """Return a fictional customer record by id, or an error result."""

    for record in _load_customers():
        if record.customer_id == customer_id:
            return ToolResult(
                tool_name="get_customer_record",
                ok=True,
                output=record.model_dump(),
            )
    return ToolResult(
        tool_name="get_customer_record",
        ok=False,
        error=f"customer '{customer_id}' not found",
    )


def create_support_ticket(subject: str, body: str) -> ToolResult:
    """Create an in-memory support ticket (no persistence, no network)."""

    ticket_id = f"TCK-{abs(hash((subject, body))) % 10_000:04d}"
    return ToolResult(
        tool_name="create_support_ticket",
        ok=True,
        output={"ticket_id": ticket_id, "subject": subject, "body": body},
    )


def send_report(payload: dict[str, Any], destination: str = "local://outbox") -> ToolResult:
    """Simulate sending a report. Writes a local JSON file only.

    This function never opens a network socket. It exists so we can show the
    *intent* of exfiltration without actually performing one.
    """

    SENT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    out_path = SENT_REPORTS_DIR / f"report_{timestamp}.json"
    out_path.write_text(
        json.dumps(
            {"destination": destination, "payload": payload}, indent=2, sort_keys=True
        ),
        encoding="utf-8",
    )
    return ToolResult(
        tool_name="send_report",
        ok=True,
        output={"destination": destination, "stored_at": str(out_path)},
    )
