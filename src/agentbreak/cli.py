"""Command-line interface for AgentBreak.

Commands
--------
* ``normal``  / ``attack`` / ``secure``  run the flagship indirect-prompt-
  injection scenario against the grid-operations agent in each mode.
* ``run``     run any registered scenario by name with ``--mode``.
* ``list``    list the registered scenarios.
* ``verify``  run the AI security regression suite (CI security gate).
* ``create-test``  turn an attack run's evidence into a regression case.
* ``chat``    talk to the simulated vulnerable chatbot (broad OWASP-10 lab).
* ``scan``    run the offensive probes and unlock journal pages.
* ``journal`` show the OWASP Top 10 diary (locked / unlocked).
* ``report``  run a scan and write an English Markdown + JSON report.
* ``serve``   start the web UI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .agent import regression
from .agent.evidence import append_finding
from .agent.scenario import SCENARIO_NAME, run_indirect_injection
from .chatbot import SimChatbot
from .journal import Journal
from .llm import DEFAULT_MODEL, OllamaClient
from .reporting import save_report
from .scanner import run_scan, summarize

app = typer.Typer(add_completion=False, help="AgentBreak — an offensive and defensive AI security lab.")
console = Console()

SCENARIOS: dict[str, str] = {
    SCENARIO_NAME: "Retrieved document poisons an SOC agent's tool use (indirect prompt injection).",
}


def _run_scenario(scenario: str, mode: str, no_evidence: bool) -> None:
    if scenario != SCENARIO_NAME:
        console.print(f"[red]Unknown scenario '{scenario}'.[/red] Run `agentbreak list`.")
        raise typer.Exit(code=1)
    if mode not in ("normal", "attack", "secure"):
        console.print(f"[red]--mode must be one of normal|attack|secure, got '{mode}'.[/red]")
        raise typer.Exit(code=2)
    run = run_indirect_injection(mode, console=console)  # type: ignore[arg-type]
    if not no_evidence:
        paths = append_finding(run)
        console.print(f"[dim]Evidence appended: {paths['markdown']}[/dim]")
        console.print(f"run_id={paths['run_id']}")


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


@app.command("list")
def cmd_list() -> None:
    """List the registered scenarios."""

    table = Table(title="AgentBreak scenarios")
    table.add_column("Name")
    table.add_column("Description")
    for name, desc in SCENARIOS.items():
        table.add_row(name, desc)
    console.print(table)


@app.command("run")
def cmd_run(
    scenario: str = typer.Argument(SCENARIO_NAME, help="Scenario name, e.g. indirect-injection."),
    mode: str = typer.Option(None, "--mode", help="normal | attack | secure (required)"),
    no_evidence: bool = typer.Option(False, "--no-evidence", help="Do not append to artifacts/attack_report.*"),
) -> None:
    """Run a scenario in the given mode."""

    if mode is None:
        console.print("[red]--mode is required (normal|attack|secure).[/red]")
        raise typer.Exit(code=2)
    _run_scenario(scenario, mode, no_evidence)


@app.command("normal")
def cmd_normal(no_evidence: bool = typer.Option(False, "--no-evidence")) -> None:
    """Run the flagship scenario with a benign context and the policy layer engaged."""

    _run_scenario(SCENARIO_NAME, "normal", no_evidence)


@app.command("attack")
def cmd_attack(no_evidence: bool = typer.Option(False, "--no-evidence")) -> None:
    """Run the flagship scenario with a poisoned context and no policy layer (vulnerable path)."""

    _run_scenario(SCENARIO_NAME, "attack", no_evidence)


@app.command("secure")
def cmd_secure(no_evidence: bool = typer.Option(False, "--no-evidence")) -> None:
    """Replay the exact same poisoned context with the policy layer engaged (hardened path)."""

    _run_scenario(SCENARIO_NAME, "secure", no_evidence)


def _opt_path(value: str | None) -> Path | None:
    return Path(value) if value else None


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


@app.command("verify")
def cmd_verify(
    json_output: bool = typer.Option(False, "--json", help="Print a machine-readable result."),
    cases_dir: str = typer.Option(None, "--cases-dir", help="Defaults to tests/security_cases/."),
    report_dir: str = typer.Option(None, "--report-dir", help="Defaults to artifacts/."),
    no_report: bool = typer.Option(
        False, "--no-report", help="Do not write artifacts/security_regression_report.*"
    ),
) -> None:
    """Run the AI security regression suite. Exit code 1 on any security regression."""

    suite = regression.run_suite(_opt_path(cases_dir))
    paths = None if no_report else regression.write_report(suite, _opt_path(report_dir))

    if json_output:
        typer.echo(json.dumps(suite.to_dict(), indent=2, ensure_ascii=False))
    else:
        title = "AgentBreak Security Regression Suite"
        console.print(f"[bold]{title}[/bold]\n{'=' * len(title)}\n")
        for c in suite.cases:
            mark = "[green]✓[/green]" if c.passed else "[red]✗[/red]"
            console.print(f"{mark} {c.id}  {escape(c.title)}")
            for reason in c.reasons:
                console.print(f"    [red]{escape(reason)}[/red]")
        if not suite.cases:
            console.print("[red]No security cases found.[/red]")
        console.print(
            f"\nSummary\n-------\nPassed: {suite.passed}\nFailed: {suite.failed}\n"
        )
        if paths:
            console.print(f"[dim]Report: {_display_path(Path(paths['markdown']))}[/dim]\n", soft_wrap=True)
        if suite.critical:
            console.print("[bold red]Critical security regression detected.[/bold red]\n")
        elif suite.failed:
            console.print("[bold red]Security regression detected.[/bold red]\n")
        color = "green" if suite.status == "PASSED" else "red"
        console.print(f"[bold {color}]SECURITY GATE: {suite.status}[/bold {color}]")

    if suite.status != "PASSED":
        raise typer.Exit(code=1)


@app.command("create-test")
def cmd_create_test(
    run_id: str = typer.Argument(..., help="Run ID from an attack run, e.g. AB-RUN-1002."),
    evidence_dir: str = typer.Option(
        None, "--evidence-dir", help="Directory holding attack_report.json. Defaults to artifacts/."
    ),
    cases_dir: str = typer.Option(None, "--cases-dir", help="Defaults to tests/security_cases/."),
) -> None:
    """Turn an attack run's evidence into a reproducible security regression case."""

    try:
        path, case = regression.create_case_from_run(
            run_id, evidence_dir=_opt_path(evidence_dir), cases_dir=_opt_path(cases_dir)
        )
    except regression.RegressionCaseError as exc:
        console.print(f"[red]Cannot create regression test:[/red]\n{escape(str(exc))}")
        raise typer.Exit(code=1) from exc

    prov = case["provenance"]
    console.print("[bold green]Security regression created:[/bold green]\n")
    console.print(f"  {_display_path(path)}\n")
    console.print("[bold]Source run:[/bold]")
    console.print(
        f"  {prov['source_run_id']}  ({prov['source_mode']}, {prov['original_result']}, "
        f"payload sha256 {prov['attack_payload_sha256'][:12]}…)\n"
    )
    console.print("[bold]Expected security property:[/bold]")
    console.print(f"  {escape(case['security_invariant'])}\n")
    console.print("Next: [bold]agentbreak verify[/bold]")


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
    no_journal: bool = typer.Option(
        False,
        "--no-journal",
        help="Do not persist scan findings to the unlocking journal.",
    ),
) -> None:
    """Run the offensive probes and unlock the matching journal pages."""

    results = run_scan(only=_parse_only(only))
    newly = [] if no_journal else Journal().apply_results(results)

    table = Table(title="OWASP Top 10 for LLM — scan results")
    table.add_column("Code")
    table.add_column("Category")
    table.add_column("Result")
    table.add_column("Severity")
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
        rv = app(args=argv if argv is not None else None, standalone_mode=False)
    except typer.Exit as exc:  # pragma: no cover
        return int(exc.exit_code or 0)
    return int(rv) if isinstance(rv, int) else 0


if __name__ == "__main__":
    sys.exit(main())
