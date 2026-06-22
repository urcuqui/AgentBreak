"""Tests for the FastAPI web app.

We use Starlette's test client (re-exported by FastAPI) so no real socket is
ever opened. The SSE endpoint is consumed synchronously.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from hacking_ai_agents.webapp import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_index_is_served() -> None:
    with _client() as c:
        r = c.get("/")
    assert r.status_code == 200
    assert "Hacking AI Agents" in r.text


def test_static_assets_are_served() -> None:
    with _client() as c:
        r = c.get("/static/app.js")
    assert r.status_code == 200
    assert "EventSource" in r.text


def test_health_endpoint_reports_status() -> None:
    with _client() as c:
        r = c.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "ollama_available" in data
    # We do not assert on availability: Ollama may or may not be installed.


def test_unknown_mode_returns_404() -> None:
    with _client() as c:
        r = c.get("/api/run/unknown")
    assert r.status_code == 404


def _parse_sse(text: str) -> list[dict]:
    events: list[dict] = []
    for line in text.splitlines():
        if line.startswith("data: "):
            payload = line[len("data: "):]
            try:
                events.append(json.loads(payload))
            except json.JSONDecodeError:
                continue
    return events


def test_attack_mode_streams_outcome_event() -> None:
    with _client() as c:
        with c.stream("GET", "/api/run/attack?use_llm=false") as r:
            assert r.status_code == 200
            text = "".join(chunk for chunk in r.iter_text())
    events = _parse_sse(text)
    types = [e["type"] for e in events]
    assert "banner" in types
    assert "outcome" in types
    outcome = next(e for e in events if e["type"] == "outcome")
    assert outcome["success"] is False
    assert "EXFILTRATION" in outcome["title"]


def test_secure_mode_blocks_and_streams_policy_decisions() -> None:
    with _client() as c:
        with c.stream("GET", "/api/run/secure?use_llm=false") as r:
            assert r.status_code == 200
            text = "".join(chunk for chunk in r.iter_text())
    events = _parse_sse(text)
    types = [e["type"] for e in events]
    assert "policy_decisions" in types
    outcome = next(e for e in events if e["type"] == "outcome")
    assert outcome["success"] is True
    assert outcome["title"] == "ATTACK BLOCKED"


def test_normal_mode_streams_clean_outcome() -> None:
    with _client() as c:
        with c.stream("GET", "/api/run/normal") as r:
            assert r.status_code == 200
            text = "".join(chunk for chunk in r.iter_text())
    events = _parse_sse(text)
    outcome = next(e for e in events if e["type"] == "outcome")
    assert outcome["success"] is True
    assert "ANSWER" in outcome["title"].upper()
