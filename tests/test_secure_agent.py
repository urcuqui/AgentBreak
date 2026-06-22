"""Tests for the secure agent flow."""

from __future__ import annotations

from unittest.mock import patch

from hacking_ai_agents import tools as tool_impls
from hacking_ai_agents.models import UserRequest
from hacking_ai_agents.presenter import SilentPresenter
from hacking_ai_agents.secure_agent import run_secure_agent

QUESTION = "What is the refund policy for enterprise customers?"


def test_secure_agent_blocks_get_customer_record_for_refund_policy() -> None:
    request = UserRequest(question=QUESTION, task="refund_policy")

    def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("get_customer_record must never run in secure mode")

    def boom_send(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("send_report must never run in secure mode")

    with patch.object(tool_impls, "get_customer_record", boom), patch.object(
        tool_impls, "send_report", boom_send
    ):
        result = run_secure_agent(request, presenter=SilentPresenter())

    assert result["sensitive_accessed"] is False
    assert result["report_sent"] is False

    decisions = [
        e.decision
        for e in result["audit"].events
        if e.event_type == "policy_decision" and e.decision is not None
    ]
    blocks = [d for d in decisions if not d.allowed]
    assert blocks, "expected at least one BLOCK decision"
    assert any(d.policy_name == "tool_allowlist" for d in blocks)


def test_secure_agent_blocks_send_report_specifically() -> None:
    request = UserRequest(question=QUESTION, task="refund_policy")
    with patch.object(
        tool_impls, "send_report", side_effect=AssertionError("must not run")
    ):
        result = run_secure_agent(request, presenter=SilentPresenter())

    blocked_tools = {
        e.tool_name
        for e in result["audit"].events
        if e.decision is not None and not e.decision.allowed
    }
    assert "send_report" in blocked_tools


def test_secure_agent_reports_no_sensitive_access_and_no_report_sent() -> None:
    request = UserRequest(question=QUESTION, task="refund_policy")
    result = run_secure_agent(request, presenter=SilentPresenter())
    assert result["sensitive_accessed"] is False
    assert result["report_sent"] is False
