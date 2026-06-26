"""The Journal: a diary of the OWASP Top 10 for LLM that unlocks page by page.

Every category starts *locked*. When the offensive scanner discovers a
vulnerability in the chatbot, the matching page is unlocked and stamped with the
evidence and the payload that revealed it. State is persisted to disk so the
diary keeps filling in across runs of the CLI and the web app.
"""

from __future__ import annotations

from pathlib import Path

from .models import JournalEntry, JournalState, ProbeResult, utcnow
from .owasp import OWASP_TOP10

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JOURNAL_PATH = PROJECT_ROOT / "reports" / "journal_state.json"


def _initial_state() -> JournalState:
    entries = {
        c.code: JournalEntry(
            code=c.code,
            title=c.title,
            summary=c.summary,
            severity=c.severity,
            remediation=c.remediation,
            hints=list(c.hints),
        )
        for c in OWASP_TOP10
    }
    return JournalState(entries=entries)


class Journal:
    """Load, mutate and persist the unlocking diary state."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DEFAULT_JOURNAL_PATH
        self.state = self.load()

    # --- persistence ------------------------------------------------------
    def load(self) -> JournalState:
        if self.path.exists():
            try:
                state = JournalState.model_validate_json(
                    self.path.read_text(encoding="utf-8")
                )
                return self._ensure_complete(state)
            except (ValueError, OSError):
                pass
        return _initial_state()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.state.updated_at = utcnow()
        self.path.write_text(
            self.state.model_dump_json(indent=2), encoding="utf-8"
        )

    def reset(self) -> None:
        self.state = _initial_state()
        self.save()

    # --- unlocking --------------------------------------------------------
    def apply_results(self, results: list[ProbeResult]) -> list[str]:
        """Unlock pages for newly discovered vulnerabilities.

        Returns the list of OWASP codes unlocked by *this* call (so callers can
        celebrate fresh discoveries without re-announcing old ones).
        """

        newly: list[str] = []
        for r in results:
            entry = self.state.entries.get(r.code)
            if entry is None or not r.discovered or entry.unlocked:
                continue
            entry.unlocked = True
            entry.discovered_at = r.timestamp
            entry.evidence = r.evidence
            entry.payload = r.payload
            newly.append(r.code)
        if newly:
            self.save()
        return newly

    # --- views ------------------------------------------------------------
    def ordered_entries(self) -> list[JournalEntry]:
        return [self.state.entries[c.code] for c in OWASP_TOP10]

    def progress(self) -> tuple[int, int]:
        return self.state.unlocked_count, self.state.total

    def _ensure_complete(self, state: JournalState) -> JournalState:
        base = _initial_state()
        for code, entry in base.entries.items():
            existing = state.entries.get(code)
            if existing is None:
                state.entries[code] = entry
                continue
            # Refresh static catalog fields so older saved journals gain hints.
            existing.hints = entry.hints
            existing.summary = entry.summary
            existing.remediation = entry.remediation
        return state
