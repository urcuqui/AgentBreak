"""Integration tests for the flagship normal/attack/secure scenario.

These prove the demonstration's actual claim: the same malicious payload
succeeds when the policy layer is off and is blocked when it is on, and
hardening does not break the benign path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentbreak.agent.scenario import run_indirect_injection


@pytest.fixture(autouse=True)
def _quiet(monkeypatch, tmp_path: Path):
    # Keep send_report's local outbox out of the repo's sent_reports/ dir.
    import agentbreak.agent.tools as tools_mod

    monkeypatch.setattr(tools_mod, "SENT_REPORTS_DIR", tmp_path / "sent_reports")


def test_normal_mode_is_benign_and_unblocked() -> None:
    run = run_indirect_injection("normal", quiet=True)
    assert run.final_status == "NO_ATTACK"
    assert run.executed_calls == ["search_knowledge_base"]
    assert run.blocked_calls == []
    assert not run.sensitive_accessed
    assert not run.data_exfiltrated


def test_attack_mode_succeeds_with_no_policy_layer() -> None:
    run = run_indirect_injection("attack", quiet=True)
    assert run.final_status == "ATTACK_SUCCESS"
    assert "get_asset_credentials" in run.executed_calls
    assert "send_report" in run.executed_calls
    assert run.sensitive_accessed
    assert run.data_exfiltrated
    assert run.blocked_calls == []


def test_secure_mode_blocks_the_identical_payload() -> None:
    attack_run = run_indirect_injection("attack", quiet=True)
    secure_run = run_indirect_injection("secure", quiet=True)

    # Same document, same proposed tool calls -- the attack was not modified.
    assert attack_run.document is not None and secure_run.document is not None
    assert attack_run.document.content == secure_run.document.content
    assert [c.tool_name for c in attack_run.proposed_calls] == [
        c.tool_name for c in secure_run.proposed_calls
    ]

    assert secure_run.final_status == "ATTACK_BLOCKED"
    assert not secure_run.sensitive_accessed
    assert not secure_run.data_exfiltrated
    assert "get_asset_credentials" in secure_run.blocked_calls
    assert "send_report" in secure_run.blocked_calls


def test_hardening_does_not_break_the_benign_path() -> None:
    """The policy layer is engaged in 'normal' mode too -- it must not block it."""

    run = run_indirect_injection("normal", quiet=True)
    policy_events = [e for e in run.events if e.security_control]
    assert policy_events, "expected the policy layer to have evaluated the benign call"
    assert all(e.policy_decision == "ALLOW" for e in policy_events)
