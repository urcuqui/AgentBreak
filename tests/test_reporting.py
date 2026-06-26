"""Tests for the English report generator (Markdown + JSON)."""

from __future__ import annotations

import json
from pathlib import Path

from agentbreak.owasp import OWASP_CODES, get_category
from agentbreak.reporting import build_json, render_markdown, save_report
from agentbreak.scanner import run_scan


def test_build_json_has_finding_per_category() -> None:
    payload = build_json(run_scan())
    codes = [f["code"] for f in payload["findings"]]
    assert codes == list(OWASP_CODES)
    assert payload["version"] == "OWASP Top 10 for LLM Applications v1.1"
    assert payload["summary"]["discovered"] == 10


def test_build_json_marks_vulnerable_status() -> None:
    payload = build_json(run_scan(only=["LLM01"]))
    finding = payload["findings"][0]
    assert finding["status"] == "VULNERABLE"
    assert finding["remediation"] == get_category("LLM01").remediation


def test_markdown_lists_every_category() -> None:
    md = render_markdown(run_scan())
    for code in OWASP_CODES:
        assert code in md
    assert md.startswith("# AgentBreak")
    assert "OWASP Top 10 for LLM Applications v1.1" in md


def test_markdown_flags_vulnerable_findings() -> None:
    md = render_markdown(run_scan(only=["LLM06"]))
    assert "VULNERABLE" in md


def test_save_report_writes_both_artifacts(tmp_path: Path) -> None:
    paths = save_report(run_scan(), out_dir=tmp_path)
    md_path = Path(paths["markdown"])
    json_path = Path(paths["json"])
    assert md_path.exists()
    assert json_path.exists()
    assert md_path.suffix == ".md"
    assert json_path.suffix == ".json"


def test_saved_json_is_valid_and_complete(tmp_path: Path) -> None:
    paths = save_report(run_scan(), out_dir=tmp_path)
    data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert len(data["findings"]) == 10
    assert "disclaimer" in data
