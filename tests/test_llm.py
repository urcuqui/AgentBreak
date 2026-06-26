"""Tests for the optional Ollama client and its graceful degradation.

These tests never require a running Ollama server: the client must return safe
defaults whenever the local HTTP API is unreachable.
"""

from __future__ import annotations

from agentbreak.llm import OllamaClient


def _unreachable() -> OllamaClient:
    # Port 1 is reserved and never serves HTTP, so every call fails fast.
    return OllamaClient(base_url="http://127.0.0.1:1", timeout=0.5)


def test_is_available_false_when_unreachable() -> None:
    assert _unreachable().is_available() is False


def test_list_models_empty_when_unreachable() -> None:
    assert _unreachable().list_models() == []


def test_model_present_false_when_unreachable() -> None:
    assert _unreachable().model_present() is False


def test_model_present_checks_installed_models(monkeypatch) -> None:
    client = OllamaClient(model="llama3.2:3b")
    monkeypatch.setattr(client, "list_models", lambda: ["llama3.2:3b", "qwen2:7b"])
    assert client.model_present() is True
    monkeypatch.setattr(client, "list_models", lambda: ["qwen2:7b"])
    assert client.model_present() is False
