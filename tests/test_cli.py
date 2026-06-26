"""Tests for the AgentBreak command-line interface.

Journal state and report output are redirected to a temp directory so the suite
never touches the project's reports/ folder.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from agentbreak import journal as journal_mod
from agentbreak import reporting as reporting_mod
from agentbreak.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(journal_mod, "DEFAULT_JOURNAL_PATH", tmp_path / "journal.json")
    monkeypatch.setattr(reporting_mod, "DEFAULT_REPORT_DIR", tmp_path / "reports")


def test_scan_reports_all_vulnerable() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert "10/10" in result.stdout


def test_scan_only_subset() -> None:
    result = runner.invoke(app, ["scan", "--only", "LLM01,LLM06"])
    assert result.exit_code == 0
    assert "LLM01" in result.stdout
    assert "LLM06" in result.stdout


def test_scan_with_report_writes_file(tmp_path) -> None:
    result = runner.invoke(app, ["scan", "--report"])
    assert result.exit_code == 0
    assert "Report written" in result.stdout
    assert list((tmp_path / "reports").glob("report_*.md"))


def test_journal_shows_progress() -> None:
    result = runner.invoke(app, ["journal"])
    assert result.exit_code == 0
    assert "0/10" in result.stdout


def test_scan_then_journal_reflects_unlock() -> None:
    runner.invoke(app, ["scan"])
    result = runner.invoke(app, ["journal"])
    assert result.exit_code == 0
    assert "10/10" in result.stdout


def test_report_command_writes_both_artifacts(tmp_path) -> None:
    result = runner.invoke(app, ["report"])
    assert result.exit_code == 0
    assert list((tmp_path / "reports").glob("report_*.md"))
    assert list((tmp_path / "reports").glob("report_*.json"))
