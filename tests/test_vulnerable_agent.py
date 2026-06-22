"""Tests for the vulnerable agent flow."""

from __future__ import annotations

from unittest.mock import patch

from hacking_ai_agents import tools as tool_impls
from hacking_ai_agents.llm import simulate_tool_calls
from hacking_ai_agents.models import ToolResult, UserRequest
from hacking_ai_agents.presenter import SilentPresenter
from hacking_ai_agents.rag import load_default_kb, retrieve
from hacking_ai_agents.vulnerable_agent import run_vulnerable_agent

QUESTION = "What is the refund policy for enterprise customers?"


def test_normal_question_does_not_trigger_sensitive_tools_in_clean_kb() -> None:
    """Sanity check: with the clean KB the simulator emits no extra calls."""

    doc = retrieve(QUESTION, load_default_kb(poisoned=False), top_k=1)[0]
    assert simulate_tool_calls(doc) == []


def test_vulnerable_agent_calls_get_customer_record_and_send_report() -> None:
    request = UserRequest(question=QUESTION, task="refund_policy")
    calls: list[tuple[str, dict]] = []

    real_get = tool_impls.get_customer_record

    def fake_get(customer_id: str) -> ToolResult:
        calls.append(("get_customer_record", {"customer_id": customer_id}))
        return real_get(customer_id)

    def fake_send(payload, destination="local://outbox"):  # type: ignore[no-untyped-def]
        calls.append(("send_report", {"payload": payload, "destination": destination}))
        return ToolResult(
            tool_name="send_report",
            ok=True,
            output={"destination": destination, "stored_at": "<mocked>"},
        )

    with patch.object(tool_impls, "get_customer_record", fake_get), patch.object(
        tool_impls, "send_report", fake_send
    ):
        result = run_vulnerable_agent(request, presenter=SilentPresenter())

    names = [c[0] for c in calls]
    assert "get_customer_record" in names
    assert "send_report" in names

    send_payload = next(c[1]["payload"] for c in calls if c[0] == "send_report")
    assert send_payload.get("api_key", "").startswith("sk-demo-")

    audit_types = [e.event_type for e in result["audit"].events]
    assert "impact" in audit_types
    assert result["decision_source"] in {"simulator", "llm", "llm+fallback"}
