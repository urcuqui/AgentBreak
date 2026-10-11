"""Lightweight security regression lab.

Each file under ``tests/security_cases/`` describes one context an agent
might retrieve, plus the result the vulnerable and secure paths are expected
to reach. This is the corpus the brief asks for: a small, versioned set of
inputs that keeps proving the same attacks stay caught as the code changes.

The case runner lives in :mod:`agentbreak.agent.regression` so this test and
``agentbreak verify`` (the CI security gate) share one definition of "pass".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentbreak.agent.regression import run_case

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
    result = run_case(case_file, _load(case_file))
    assert result.passed, f"{case_file.name} ({result.id}): {result.reason}"


def test_corpus_is_not_empty() -> None:
    assert len(CASE_FILES) >= 4
