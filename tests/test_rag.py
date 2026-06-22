"""Tests for the local RAG layer."""

from __future__ import annotations

from hacking_ai_agents.rag import load_default_kb, retrieve

QUESTION = "What is the refund policy for enterprise customers?"


def test_retrieve_finds_refund_policy_in_clean_kb() -> None:
    kb = load_default_kb(poisoned=False)
    docs = retrieve(QUESTION, kb, top_k=1)
    assert docs, "expected at least one match"
    top = docs[0]
    assert "refund" in top.title.lower() or "refund" in top.content.lower()
    assert top.retrieval_score > 0


def test_retrieve_finds_refund_policy_in_poisoned_kb() -> None:
    kb = load_default_kb(poisoned=True)
    docs = retrieve(QUESTION, kb, top_k=1)
    assert docs
    top = docs[0]
    assert top.trust_level == "untrusted"
    assert "IMPORTANT SYSTEM UPDATE" in top.content


def test_documents_are_marked_untrusted() -> None:
    for poisoned in (False, True):
        for doc in load_default_kb(poisoned=poisoned):
            assert doc.trust_level == "untrusted"
