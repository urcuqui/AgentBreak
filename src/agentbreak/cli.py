"""Command-line interface for AgentBreak.

Commands
--------
* ``chat``    talk to the simulated vulnerable chatbot.
* ``scan``    run the offensive probes and unlock journal pages.
* ``journal`` show the OWASP Top 10 diary (locked / unlocked).
* ``report``  run a scan and write an English Markdown + JSON report.
* ``serve``   start the web UI.
"""

from __future__ import annotations

import sys

import typer
from rich.console import Console
from rich.table import Table

from .chatbot import SimChatbot
from .journal import Journal
from .llm import DEFAULT_MODEL, OllamaClient
from .reporting import save_report
from .scanner import run_scan, summarize

app = typer.Typer(add_completion=False, help="AgentBreak — OWASP Top 10 for LLM lab.")
console = Console()


def _parse_only(only: str | None) -> list[str] | None:
    if not only:
        return None
    return [c.strip().upper() for c in only.split(",") if c.strip()]


def _maybe_client(use_llm: bool, model: str) -> OllamaClient | None:
    if not use_llm:
        return None
    client = OllamaClient(model=model)
    if not client.is_available():
        console.print("[yellow]Ollama not reachable — using the simulator.[/yellow]")
        return None
    console.print(f"[green]Using Ollama (model={model}) for benign replies.[/green]")
    return client


@app.command("chat")
def cmd_chat(
    use_llm: bool = typer.Option(False, "--use-llm", help="Phrase benign replies with Ollama."),
    model: str = typer.Option(DEFAULT_MODEL, "--model"),
) -> None:
    """Interactive chat with the simulated chatbot. Type 'exit' to quit."""

    bot = SimChatbot(client=_maybe_client(use_llm, model))
    console.print("[bold]HelpBot[/bold] (simulated). Type 'exit' to quit.")
    while True:
        try:
            msg = console.input("[cyan]you> [/cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if msg.lower() in {"exit", "quit"}:
            break
        if not msg:
            continue
        console.print(f"[green]bot>[/green] {bot.respond(msg).text}")


@app.command("scan")
def cmd_scan(
    only: str = typer.Option(None, "--only", help="Comma list, e.g. LLM01,LLM06."),
    report: bool = typer.Option(False, "--report", help="Also write a report."),
) -> None:
    """Run the offensive probes and unlock the matching journal pages."""

    results = run_scan(only=_parse_only(only))
    journal = Journal()
    newly = journal.apply_results(results)

    table = Table(title="OWASP Top 10 for LLM — scan results")
    table.add_column("Code"); table.add_column("Category")
    table.add_column("Result"); table.add_column("Severity")
    for r in results:
        mark = "[red]VULNERABLE[/red]" if r.discovered else "[green]ok[/green]"
        table.add_row(r.code, r.name, mark, r.severity)
    console.print(table)

    s = summarize(results)
    console.print(f"[bold]{s['discovered']}/{s['total']}[/bold] categories vulnerable.")
    if newly:
        console.print(f"[magenta]Journal unlocked:[/magenta] {', '.join(newly)}")
    if report:
        paths = save_report(results)
        console.print(f"Report written: {paths['markdown']}")


@app.command("journal")
def cmd_journal(reset: bool = typer.Option(False, "--reset")) -> None:
    """Show the OWASP Top 10 diary and unlocking progress."""

    journal = Journal()
    if reset:
        journal.reset()
        console.print("[yellow]Journal reset.[/yellow]")
    unlocked, total = journal.progress()
    console.print(f"[bold]Journal progress:[/bold] {unlocked}/{total} pages unlocked\n")
    for e in journal.ordered_entries():
        if e.unlocked:
            console.print(f"[green]🔓 {e.code} — {e.title}[/green]")
            console.print(f"   evidence: {e.evidence}")
        else:
            console.print(f"[dim]🔒 {e.code} — {e.locked_blurb()}[/dim]")


@app.command("report")
def cmd_report(
    only: str = typer.Option(None, "--only", help="Comma list of probe codes."),
) -> None:
    """Run a scan and write an English Markdown + JSON report under reports/."""

    results = run_scan(only=_parse_only(only))
    Journal().apply_results(results)
    paths = save_report(results)
    console.print(f"Markdown: {paths['markdown']}")
    console.print(f"JSON:     {paths['json']}")


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """Start the FastAPI web app."""

    import uvicorn

    uvicorn.run("agentbreak.webapp:app", host=host, port=port, reload=reload)


def main(argv: list[str] | None = None) -> int:
    try:
        app(args=argv if argv is not None else None, standalone_mode=False)
    except typer.Exit as exc:  # pragma: no cover
        return int(exc.exit_code or 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
