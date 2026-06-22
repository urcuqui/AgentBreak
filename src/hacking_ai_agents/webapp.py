"""FastAPI web app for the demo.

Endpoints
---------
* ``GET /``                  serves the single-page UI.
* ``GET /api/health``        returns status, including Ollama availability.
* ``GET /api/run/{mode}``    runs ``normal | attack | secure`` and streams the
                             events as Server-Sent Events.

All execution is local. Nothing here calls the network except the optional
local Ollama instance.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import StreamingResponse

from . import tools as tool_impls
from .llm import DEFAULT_MODEL, OllamaClient
from .models import UserRequest
from .presenter import WebPresenter
from .rag import load_default_kb, retrieve
from .secure_agent import run_secure_agent
from .vulnerable_agent import run_vulnerable_agent

WEB_DIR = Path(__file__).resolve().parent / "web"

QUESTION = "What is the refund policy for enterprise customers?"
TASK = "refund_policy"


def create_app() -> FastAPI:
    """Application factory used by ``uvicorn`` and by tests."""

    app = FastAPI(title="Hacking AI Agents demo", docs_url=None, redoc_url=None)
    app.mount(
        "/static", StaticFiles(directory=str(WEB_DIR), html=False), name="static"
    )

    @app.get("/", response_class=HTMLResponse)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/health")
    async def health(model: str = Query(default=DEFAULT_MODEL)) -> JSONResponse:
        client = OllamaClient(model=model)
        available = client.is_available()
        installed = client.list_models() if available else []
        return JSONResponse(
            {
                "ok": True,
                "ollama_available": available,
                "model": model,
                "model_present": model in installed,
                "installed_models": installed,
            }
        )

    @app.get("/api/run/{mode}")
    async def run(
        mode: str,
        use_llm: bool = Query(default=False),
        model: str = Query(default=DEFAULT_MODEL),
    ) -> StreamingResponse:
        if mode not in {"normal", "attack", "secure"}:
            raise HTTPException(status_code=404, detail="unknown mode")
        llm = OllamaClient(model=model) if use_llm else None
        if llm is not None and (not llm.is_available() or not llm.model_present()):
            llm = None  # gracefully fall back

        async def stream() -> AsyncIterator[bytes]:
            async for chunk in _run_streaming(mode, llm):
                yield chunk

        return StreamingResponse(stream(), media_type="text/event-stream")

    return app


def _sse(event: dict) -> bytes:
    return f"data: {json.dumps(event)}\n\n".encode()


async def _run_streaming(
    mode: str, llm: OllamaClient | None
) -> AsyncIterator[bytes]:
    """Run a mode in a thread and stream its events as SSE chunks."""

    presenter = WebPresenter()

    def runner() -> None:
        request = UserRequest(question=QUESTION, task=TASK)
        if mode == "normal":
            _run_normal(presenter)
        elif mode == "attack":
            run_vulnerable_agent(request, presenter=presenter, llm=llm)
        else:
            run_secure_agent(request, presenter=presenter, llm=llm)

    loop = asyncio.get_event_loop()
    task = loop.run_in_executor(None, runner)

    # Drain events as they accumulate, with a small heartbeat interval.
    sent = 0
    while not task.done() or sent < len(presenter.events):
        if sent < len(presenter.events):
            for ev in presenter.events[sent:]:
                yield _sse(ev)
            sent = len(presenter.events)
        else:
            yield b": keep-alive\n\n"
            await asyncio.sleep(0.05)
    yield _sse({"type": "done"})


def _run_normal(presenter: WebPresenter) -> None:
    """Inline normal-mode flow for the web UI."""

    request = UserRequest(question=QUESTION, task=TASK)
    presenter.banner("NORMAL MODE", "Clean knowledge base, safe behavior.", kind="info")
    presenter.step(1, "User question received", request.question, kind="info")
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


# uvicorn entry point: `uvicorn hacking_ai_agents.webapp:app`
app = create_app()
