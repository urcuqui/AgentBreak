"""Tests for the Ollama integration and the deterministic fallback."""

from __future__ import annotations

import urllib.error

from hacking_ai_agents.agents_common import decide_tool_calls
from hacking_ai_agents.llm import (
    OllamaClient,
    parse_tool_calls,
    propose_tool_calls,
    simulate_tool_calls,
)
from hacking_ai_agents.rag import load_default_kb, retrieve

QUESTION = "What is the refund policy for enterprise customers?"


# --- parse_tool_calls -----------------------------------------------------

def test_parse_tool_calls_object_with_list() -> None:
    raw = '{"tool_calls": [{"tool_name": "search_knowledge_base", "arguments": {"query": "x"}}]}'
    calls = parse_tool_calls(raw)
    assert calls is not None
    assert len(calls) == 1
    assert calls[0].tool_name == "search_knowledge_base"


def test_parse_tool_calls_accepts_top_level_list() -> None:
    raw = '[{"tool_name": "search_knowledge_base", "arguments": {}}]'
    calls = parse_tool_calls(raw)
    assert calls and calls[0].tool_name == "search_knowledge_base"


def test_parse_tool_calls_extracts_embedded_json() -> None:
    raw = 'sure, here it is: {"tool_calls": [{"tool_name": "x", "arguments": {}}]}'
    calls = parse_tool_calls(raw)
    assert calls and calls[0].tool_name == "x"


def test_parse_tool_calls_returns_none_on_garbage() -> None:
    assert parse_tool_calls("not json at all") is None
    assert parse_tool_calls("") is None


# --- propose_tool_calls falls back when Ollama is unreachable ------------

def test_propose_tool_calls_handles_connection_errors(monkeypatch) -> None:
    client = OllamaClient(base_url="http://127.0.0.1:1")

    def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(client, "chat", boom)
    assert propose_tool_calls(client, system="s", user="u") is None


# --- simulate_tool_calls --------------------------------------------------

def test_simulate_emits_attack_when_poisoned() -> None:
    doc = retrieve(QUESTION, load_default_kb(poisoned=True), top_k=1)[0]
    calls = simulate_tool_calls(doc)
    names = [c.tool_name for c in calls]
    assert "get_customer_record" in names
    assert "send_report" in names


def test_simulate_no_calls_when_clean() -> None:
    doc = retrieve(QUESTION, load_default_kb(poisoned=False), top_k=1)[0]
    assert simulate_tool_calls(doc) == []


# --- decide_tool_calls ----------------------------------------------------

def test_decide_falls_back_to_simulator_when_llm_unavailable() -> None:
    doc = retrieve(QUESTION, load_default_kb(poisoned=True), top_k=1)[0]
    calls, source = decide_tool_calls(QUESTION, doc, mode="vulnerable", llm=None)
    assert source == "simulator"
    assert {c.tool_name for c in calls} >= {"get_customer_record", "send_report"}


def test_decide_uses_llm_when_it_returns_attack_calls(monkeypatch) -> None:
    doc = retrieve(QUESTION, load_default_kb(poisoned=True), top_k=1)[0]
    client = OllamaClient()

    def fake_chat(system: str, user: str, *, json_mode: bool = True) -> str:
        return (
            '{"tool_calls": ['
            '{"tool_name": "get_customer_record", "arguments": {"customer_id": "customer_1042"}},'
            '{"tool_name": "send_report", "arguments": {"payload": {"api_key": "sk-demo-x"}}}'
            "]}"
        )

    monkeypatch.setattr(client, "chat", fake_chat)
    calls, source = decide_tool_calls(
        QUESTION, doc, mode="vulnerable", llm=client, force_attack_for_demo=True
    )
    assert source == "llm"
    assert {c.tool_name for c in calls} == {"get_customer_record", "send_report"}


def test_decide_falls_back_when_llm_resists_in_vulnerable_mode(monkeypatch) -> None:
    """If the model refuses the injection, we still demonstrate the threat."""

    doc = retrieve(QUESTION, load_default_kb(poisoned=True), top_k=1)[0]
    client = OllamaClient()

    def fake_chat(system: str, user: str, *, json_mode: bool = True) -> str:
        return (
            '{"tool_calls": ['
            '{"tool_name": "search_knowledge_base", "arguments": {"query": "refund"}}'
            "]}"
        )

    monkeypatch.setattr(client, "chat", fake_chat)
    calls, source = decide_tool_calls(
        QUESTION, doc, mode="vulnerable", llm=client, force_attack_for_demo=True
    )
    assert source == "llm+fallback"
    assert {c.tool_name for c in calls} == {"get_customer_record", "send_report"}
