"""Command-line interface for the demo."""

from __future__ import annotations

import sys

import typer
from rich.console import Console

from . import tools as tool_impls
from .llm import DEFAULT_MODEL, OllamaClient
from .logging_utils import AuditLog
from .models import AuditEvent, UserRequest
from .presenter import RichPresenter
from .rag import load_default_kb, retrieve
from .secure_agent import run_secure_agent
from .vulnerable_agent import run_vulnerable_agent

app = typer.Typer(
    add_completion=False,
    help="Hacking AI Agents demo. Educational, local-only.",
)


QUESTION = "What is the refund policy for enterprise customers?"
TASK = "refund_policy"


def _console(no_color: bool) -> Console:
    return Console(no_color=no_color, soft_wrap=False, highlight=False)


def _maybe_llm(use_llm: bool, model: str, presenter: RichPresenter) -> OllamaClient | None:
    if not use_llm:
        return None
    client = OllamaClient(model=model)
    if not client.is_available():
        presenter.info("Ollama not reachable. Falling back to simulator.")
        return None
    if not client.model_present():
        installed = ", ".join(client.list_models()) or "none"
        presenter.info(
            f"Model '{model}' not pulled (run: ollama pull {model}). "
            f"Installed: {installed}. Falling back to simulator."
        )
        return None
    presenter.info(f"Using local Ollama (model={model}).")
    return client


def _pause(no_pause: bool, console: Console) -> None:
    if no_pause:
        return
    try:
        console.input("[dim]-- press Enter to continue --[/dim]")
    except EOFError:
        return


def _run_normal(presenter: RichPresenter) -> None:
    audit = AuditLog()
    presenter.banner("NORMAL MODE", "Clean knowledge base, safe behavior.", kind="info")
    request = UserRequest(question=QUESTION, task=TASK)
    presenter.step(1, "User question received", request.question, kind="info")
    audit.record(AuditEvent(event_type="user_request", message=request.question))

    presenter.step(2, "Retrieving knowledge from clean KB", kind="info")
    doc = retrieve(request.question, load_default_kb(poisoned=False), top_k=1)[0]
    presenter.document(doc)

    presenter.step(3, "Agent selected tool: search_knowledge_base", kind="info")
    tool_impls.search_knowledge_base(request.question, poisoned=False)
    presenter.outcome(
        success=True,
        title="ANSWERED",
        message="Enterprise refunds within 30 days. No sensitive tools were used.",
    )


# Shared option declarations to avoid repetition.
_VerboseOpt = typer.Option(False, "--verbose")
_NoColorOpt = typer.Option(False, "--no-color")
_UseLlmOpt = typer.Option(False, "--use-llm", help="Use local Ollama if available.")
_NoLlmOpt = typer.Option(False, "--no-llm", help="Force the deterministic simulator.")
_ModelOpt = typer.Option(DEFAULT_MODEL, "--model", help="Ollama model tag.")


def _resolve_llm_flag(use_llm: bool, no_llm: bool) -> bool:
    if no_llm:
        return False
    return use_llm


@app.command("normal")
def cmd_normal(
    verbose: bool = _VerboseOpt,
    no_color: bool = _NoColorOpt,
) -> None:
    """Run the agent against the clean KB. No sensitive tools are used."""

    presenter = RichPresenter(_console(no_color))
    _run_normal(presenter)
    _ = verbose  # no extra detail in normal mode for now


@app.command("attack")
def cmd_attack(
    verbose: bool = _VerboseOpt,
    no_color: bool = _NoColorOpt,
    use_llm: bool = _UseLlmOpt,
    no_llm: bool = _NoLlmOpt,
    model: str = _ModelOpt,
) -> None:
    """Run the vulnerable agent against the poisoned KB."""

    console = _console(no_color)
    presenter = RichPresenter(console)
    llm = _maybe_llm(_resolve_llm_flag(use_llm, no_llm), model, presenter)
    request = UserRequest(question=QUESTION, task=TASK)
    result = run_vulnerable_agent(request, presenter=presenter, llm=llm)
    if verbose:
        for e in result["audit"].events:
            console.print(e.to_log_dict())


@app.command("secure")
def cmd_secure(
    verbose: bool = _VerboseOpt,
    no_color: bool = _NoColorOpt,
    use_llm: bool = _UseLlmOpt,
    no_llm: bool = _NoLlmOpt,
    model: str = _ModelOpt,
) -> None:
    """Run the secure agent against the poisoned KB."""

    console = _console(no_color)
    presenter = RichPresenter(console)
    llm = _maybe_llm(_resolve_llm_flag(use_llm, no_llm), model, presenter)
    request = UserRequest(question=QUESTION, task=TASK)
    result = run_secure_agent(request, presenter=presenter, llm=llm)
    if verbose:
        for e in result["audit"].events:
            console.print(e.to_log_dict())


@app.command("full-demo")
def cmd_full_demo(
    verbose: bool = _VerboseOpt,
    no_color: bool = _NoColorOpt,
    use_llm: bool = _UseLlmOpt,
    no_llm: bool = _NoLlmOpt,
    model: str = _ModelOpt,
    no_pause: bool = typer.Option(False, "--no-pause", help="Skip interactive pauses."),
) -> None:
    """Run normal, attack and secure stages in sequence."""

    console = _console(no_color)
    presenter = RichPresenter(console)
    presenter.banner(
        "Hacking AI Agents - Full Demo",
        "Stages: normal -> attack -> secure",
        kind="info",
    )
    _pause(no_pause, console)

    _run_normal(presenter)
    _pause(no_pause, console)

    llm = _maybe_llm(_resolve_llm_flag(use_llm, no_llm), model, presenter)
    req = UserRequest(question=QUESTION, task=TASK)
    run_vulnerable_agent(req, presenter=presenter, llm=llm)
    _pause(no_pause, console)

    run_secure_agent(req, presenter=presenter, llm=llm)
    presenter.banner(
        "The model may choose the action, "
        "but Python must decide whether that action is allowed.",
        kind="info",
    )
    _ = verbose


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload for development."),
) -> None:
    """Start the FastAPI web app on the given host/port."""

    import uvicorn

    uvicorn.run(
        "hacking_ai_agents.webapp:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


def main(argv: list[str] | None = None) -> int:
    try:
        app(args=argv if argv is not None else None, standalone_mode=False)
    except typer.Exit as exc:  # pragma: no cover - typer raises on --help etc.
        return int(exc.exit_code or 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
