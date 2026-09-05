"""Lightweight security regression lab.

Each file under ``tests/security_cases/`` describes one context an agent
might retrieve, plus the result the vulnerable and secure paths are expected
to reach. This is the corpus the brief asks for: a small, versioned set of
inputs that keeps proving the same attacks stay caught as the code changes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentbreak.agent import scenario
from agentbreak.agent.agent_models import RetrievedDocument

CASES_DIR = Path(__file__).parent / "security_cases"
CASE_FILES = sorted(CASES_DIR.glob("*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _isolated_outbox(monkeypatch, tmp_path: Path):
    import agentbreak.agent.tools as tools_mod

    monkeypatch.setattr(tools_mod, "SENT_REPORTS_DIR", tmp_path / "sent_reports")


@pytest.mark.parametrize("case_file", CASE_FILES, ids=[f.stem for f in CASE_FILES])
def test_security_case(case_file: Path) -> None:
    case = _load(case_file)
    task = case.get("task", scenario.TASK)
    approved = case.get("approved", False)
    doc = RetrievedDocument(
        document_id=case["scenario"],
        title=case["scenario"],
        content=case["context"],
        source=f"regression-case:{case['scenario']}",
        trust_level="untrusted",
    )

    vulnerable = scenario.run_document(case["input"], doc, "attack", task=task, quiet=True)
    secure = scenario.run_document(
        case["input"], doc, "secure", task=task, approved=approved, quiet=True
    )

    assert vulnerable.final_status == case["expected_vulnerable_result"], (
        f"{case_file.name}: vulnerable path expected "
        f"{case['expected_vulnerable_result']!r}, got {vulnerable.final_status!r}"
    )
    assert secure.final_status == case["expected_secure_result"], (
        f"{case_file.name}: secure path expected "
        f"{case['expected_secure_result']!r}, got {secure.final_status!r}"
    )


def test_corpus_is_not_empty() -> None:
    assert len(CASE_FILES) >= 4
