"""Tiny, deterministic local RAG.

We deliberately avoid embeddings and external services. Retrieval is based on
keyword/token overlap so the demo is reproducible in front of a live audience.

All documents are treated as ``untrusted`` regardless of source.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

from .models import RetrievedDocument

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
CLEAN_KB = DATA_DIR / "clean_knowledge_base.json"
POISONED_KB = DATA_DIR / "poisoned_knowledge_base.json"


_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    {
        "a", "an", "the", "is", "are", "was", "were", "of", "for", "to",
        "in", "on", "at", "by", "and", "or", "with", "what", "how", "do",
        "does", "this", "that", "it", "as", "be", "from", "i", "we", "you",
    }
)


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


def _score(query_tokens: Iterable[str], document_text: str) -> float:
    doc_tokens = _tokenize(document_text)
    if not doc_tokens:
        return 0.0
    doc_set = set(doc_tokens)
    overlap = sum(1 for t in query_tokens if t in doc_set)
    # Normalize by query length so scores are comparable across queries.
    q = list(query_tokens)
    if not q:
        return 0.0
    return overlap / len(q)


def load_knowledge_base(path: Path) -> list[RetrievedDocument]:
    """Load a knowledge base JSON file as :class:`RetrievedDocument` items."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    docs: list[RetrievedDocument] = []
    for entry in raw:
        docs.append(
            RetrievedDocument(
                document_id=entry["document_id"],
                title=entry["title"],
                content=entry["content"],
                source=entry["source"],
                trust_level=entry.get("trust_level", "untrusted"),
                retrieval_score=0.0,
            )
        )
    return docs


def retrieve(
    query: str,
    knowledge_base: list[RetrievedDocument],
    top_k: int = 1,
) -> list[RetrievedDocument]:
    """Return the top-k documents matching ``query`` by token overlap."""

    query_tokens = _tokenize(query)
    scored: list[RetrievedDocument] = []
    for doc in knowledge_base:
        haystack = f"{doc.title}\n{doc.content}"
        score = _score(query_tokens, haystack)
        scored.append(doc.model_copy(update={"retrieval_score": score}))

    scored.sort(key=lambda d: (d.retrieval_score, d.document_id), reverse=True)
    return [d for d in scored[:top_k] if d.retrieval_score > 0] or scored[:top_k]


def load_default_kb(poisoned: bool) -> list[RetrievedDocument]:
    """Load either the clean or the poisoned bundled knowledge base."""

    path = POISONED_KB if poisoned else CLEAN_KB
    return load_knowledge_base(path)
