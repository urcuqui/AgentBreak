"""Tests for the unlocking journal (the diary that fills page by page)."""

from __future__ import annotations

from pathlib import Path

from agentbreak.journal import Journal
from agentbreak.owasp import OWASP_CODES
from agentbreak.scanner import run_scan


def _journal(tmp_path: Path) -> Journal:
    return Journal(path=tmp_path / "journal_state.json")


def test_fresh_journal_starts_fully_locked(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    unlocked, total = journal.progress()
    assert (unlocked, total) == (0, len(OWASP_CODES))
    assert all(not e.unlocked for e in journal.ordered_entries())


def test_apply_results_unlocks_discovered_pages(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    newly = journal.apply_results(run_scan())
    assert sorted(newly) == sorted(OWASP_CODES)
    assert journal.progress() == (10, 10)


def test_unlocked_entry_records_evidence_and_payload(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal.apply_results(run_scan(only=["LLM01"]))
    entry = journal.state.entries["LLM01"]
    assert entry.unlocked is True
    assert entry.evidence
    assert entry.payload
    assert entry.discovered_at is not None


def test_partial_scan_unlocks_only_matching_pages(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal.apply_results(run_scan(only=["LLM06"]))
    assert journal.state.entries["LLM06"].unlocked is True
    assert journal.state.entries["LLM01"].unlocked is False
    assert journal.progress() == (1, 10)


def test_reapplying_results_does_not_reannounce(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    results = run_scan(only=["LLM01"])
    assert journal.apply_results(results) == ["LLM01"]
    assert journal.apply_results(results) == []


def test_state_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "journal_state.json"
    Journal(path=path).apply_results(run_scan(only=["LLM03"]))
    reopened = Journal(path=path)
    assert reopened.state.entries["LLM03"].unlocked is True


def test_reset_relocks_everything(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    journal.apply_results(run_scan())
    assert journal.progress() == (10, 10)
    journal.reset()
    assert journal.progress() == (0, 10)


def test_locked_entry_blurb_mentions_code(tmp_path: Path) -> None:
    entry = _journal(tmp_path).state.entries["LLM05"]
    assert "LLM05" in entry.locked_blurb()


def test_fresh_entries_carry_hints(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    for entry in journal.ordered_entries():
        assert entry.hints, f"{entry.code} should expose hints"


def test_save_writes_file(tmp_path: Path) -> None:
    path = tmp_path / "journal_state.json"
    journal = Journal(path=path)
    journal.apply_results(run_scan(only=["LLM02"]))
    assert path.exists()
    assert "LLM02" in path.read_text(encoding="utf-8")
