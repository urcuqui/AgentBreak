"""Tool implementations available to the grid-operations support agent.

Local, deterministic stand-ins for real capabilities. ``send_report`` never
opens a network connection -- it simulates outbound delivery by writing a
JSON file to ``sent_reports/`` so the *intent* of exfiltration can be shown
without performing one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .agent_models import ToolResult
from .retrieval import load_default_kb, retrieve

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
ASSETS_FILE = DATA_DIR / "assets.json"
SENT_REPORTS_DIR = PROJECT_ROOT / "sent_reports"

ALL_TOOLS: tuple[str, ...] = (
    "search_knowledge_base",
    "get_asset_credentials",
    "send_report",
)

# High-impact tools that require an explicit human approval flag before they
# may run (see policy.require_human_approval).
HIGH_IMPACT_TOOLS: frozenset[str] = frozenset({"get_asset_credentials", "send_report"})


def search_knowledge_base(query: str, poisoned: bool = False) -> ToolResult:
    """Search the bundled operations knowledge base and return the best match."""

    kb = load_default_kb(poisoned=poisoned)
    docs = retrieve(query, kb, top_k=1)
    return ToolResult(
        tool_name="search_knowledge_base",
        ok=True,
        output=[d.model_dump() for d in docs],
    )


def _load_assets() -> list[dict[str, Any]]:
    return json.loads(ASSETS_FILE.read_text(encoding="utf-8"))


def get_asset_credentials(asset_id: str) -> ToolResult:
    """Return the maintenance access token for a grid asset, or an error result."""

    for asset in _load_assets():
        if asset["asset_id"] == asset_id:
            return ToolResult(tool_name="get_asset_credentials", ok=True, output=asset)
    return ToolResult(
        tool_name="get_asset_credentials",
        ok=False,
        error=f"asset '{asset_id}' not found",
    )


def send_report(payload: dict[str, Any], destination: str = "local://outbox") -> ToolResult:
    """Simulate sending an incident report. Writes a local JSON file only."""

    SENT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    out_path = SENT_REPORTS_DIR / f"report_{timestamp}.json"
    out_path.write_text(
        json.dumps({"destination": destination, "payload": payload}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return ToolResult(
        tool_name="send_report",
        ok=True,
        output={"destination": destination, "stored_at": str(out_path)},
    )
