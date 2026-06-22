"""Presenter abstraction.

Agents emit semantic events ("step", "document", "policy_decision", ...) through
a :class:`Presenter`. Different presenters render those events to different
surfaces:

* :class:`RichPresenter` -> Rich-formatted terminal output (CLI).
* :class:`WebPresenter`  -> structured dicts pushed to a queue (web UI / SSE).
* :class:`SilentPresenter` -> no output, used in tests.

Keeping presentation out of the agent logic lets the same code drive both the
conference CLI demo and the browser-based visualization.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

from .models import RetrievedDocument, SecurityDecision, SuspiciousFinding

Kind = str  # "neutral" | "danger" | "safe" | "warning" | "info"


@runtime_checkable
class Presenter(Protocol):
    """Surface-agnostic UI for agents."""

    def banner(self, title: str, subtitle: str = "", kind: Kind = "neutral") -> None: ...
    def info(self, message: str) -> None: ...
    def step(
        self, n: int, message: str, detail: str | None = None, kind: Kind = "neutral"
    ) -> None: ...
    def document(self, doc: RetrievedDocument, *, wrapped_text: str | None = None) -> None: ...
    def tools_tree(self, allowed: dict[str, frozenset[str]]) -> None: ...
    def suspicious_findings(self, findings: list[SuspiciousFinding]) -> None: ...
    def policy_decisions(self, decisions: list[SecurityDecision]) -> None: ...
    def outcome(self, *, success: bool, title: str, message: str) -> None: ...


_KIND_TO_RICH = {
    "neutral": "cyan",
    "danger": "red",
    "safe": "green",
    "warning": "yellow",
    "info": "blue",
}


class RichPresenter:
    """Renders events to a terminal using Rich."""

    def __init__(self, console: Console) -> None:
        self.console = console

    def banner(self, title: str, subtitle: str = "", kind: Kind = "neutral") -> None:
        style = _KIND_TO_RICH.get(kind, "cyan")
        body = f"[bold]{title}[/bold]" + (f"\n[dim]{subtitle}[/dim]" if subtitle else "")
        self.console.print(Panel.fit(body, style=style))

    def info(self, message: str) -> None:
        self.console.print(f"[dim]{message}[/dim]")

    def step(
        self, n: int, message: str, detail: str | None = None, kind: Kind = "neutral"
    ) -> None:
        color = _KIND_TO_RICH.get(kind, "cyan")
        self.console.print(f"[{color}][{n}][/{color}] {message}")
        if detail:
            self.console.print(f"    [dim]{detail}[/dim]")

    def document(
        self, doc: RetrievedDocument, *, wrapped_text: str | None = None
    ) -> None:
        body = wrapped_text if wrapped_text is not None else doc.content
        self.console.print(
            Panel(
                body,
                title=f"[bold]{doc.title}[/bold]  ({doc.source})",
                subtitle=f"trust_level={doc.trust_level}",
                style="yellow",
            )
        )

    def tools_tree(self, allowed: dict[str, frozenset[str]]) -> None:
        tree = Tree("[bold]Allowed tools by task[/bold]")
        for task, tools in allowed.items():
            node = tree.add(task)
            for t in sorted(tools):
                node.add(t)
        self.console.print(tree)

    def suspicious_findings(self, findings: list[SuspiciousFinding]) -> None:
        for f in findings[:5]:
            self.console.print(f"      [yellow]-[/yellow] pattern={f.pattern!r}")

    def policy_decisions(self, decisions: list[SecurityDecision]) -> None:
        for d in decisions:
            mark = "[OK]" if d.allowed else "[X]"
            color = "green" if d.allowed else "red"
            self.console.print(
                f"      [{color}]{mark}[/{color}] {d.policy_name}: {d.reason}"
            )

    def outcome(self, *, success: bool, title: str, message: str) -> None:
        style = "bold green" if success else "bold red"
        symbol = "[OK]" if success else "[X]"
        self.console.print(
            Panel.fit(
                f"{symbol} {title}\n{message}",
                style=style,
                title="OUTCOME" if success else "IMPACT",
            )
        )


class SilentPresenter:
    """Discards every event. Useful for tests."""

    def banner(self, title: str, subtitle: str = "", kind: Kind = "neutral") -> None: ...
    def info(self, message: str) -> None: ...
    def step(self, n: int, message: str, detail: str | None = None, kind: Kind = "neutral") -> None: ...
    def document(self, doc: RetrievedDocument, *, wrapped_text: str | None = None) -> None: ...
    def tools_tree(self, allowed: dict[str, frozenset[str]]) -> None: ...
    def suspicious_findings(self, findings: list[SuspiciousFinding]) -> None: ...
    def policy_decisions(self, decisions: list[SecurityDecision]) -> None: ...
    def outcome(self, *, success: bool, title: str, message: str) -> None: ...


class WebPresenter:
    """Collects events as JSON-serializable dicts (one per emit)."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def _push(self, kind: str, **payload: Any) -> None:
        self.events.append({"type": kind, **payload})

    def banner(self, title: str, subtitle: str = "", kind: Kind = "neutral") -> None:
        self._push("banner", title=title, subtitle=subtitle, level=kind)

    def info(self, message: str) -> None:
        self._push("info", message=message)

    def step(
        self, n: int, message: str, detail: str | None = None, kind: Kind = "neutral"
    ) -> None:
        self._push("step", n=n, message=message, detail=detail, level=kind)

    def document(
        self, doc: RetrievedDocument, *, wrapped_text: str | None = None
    ) -> None:
        self._push(
            "document",
            document_id=doc.document_id,
            title=doc.title,
            source=doc.source,
            trust_level=doc.trust_level,
            content=doc.content,
            wrapped_text=wrapped_text,
        )

    def tools_tree(self, allowed: dict[str, frozenset[str]]) -> None:
        self._push(
            "tools_tree",
            allowed={task: sorted(tools) for task, tools in allowed.items()},
        )

    def suspicious_findings(self, findings: list[SuspiciousFinding]) -> None:
        self._push(
            "suspicious_findings",
            findings=[{"pattern": f.pattern, "snippet": f.snippet} for f in findings],
        )

    def policy_decisions(self, decisions: list[SecurityDecision]) -> None:
        self._push(
            "policy_decisions",
            decisions=[d.model_dump() for d in decisions],
        )

    def outcome(self, *, success: bool, title: str, message: str) -> None:
        self._push("outcome", success=success, title=title, message=message)
