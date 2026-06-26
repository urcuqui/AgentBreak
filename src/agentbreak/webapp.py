"""FastAPI web app for AgentBreak.

Serves a two-column lab UI: a Vulnerability Diary of ten locked cards on the
left and the simulated support assistant on the right. Each card unlocks
automatically the moment the matching OWASP Top 10 for LLM vulnerability is
exploited through the chat; a Findings view generates the English report.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .chatbot import SimChatbot
from .journal import Journal
from .llm import DEFAULT_MODEL, OllamaClient
from .reporting import render_markdown, save_report
from .scanner import discover_from_chat, run_scan, summarize

WEB_DIR = Path(__file__).resolve().parent / "web"


class ChatBody(BaseModel):
    message: str


class ScanBody(BaseModel):
    only: list[str] | None = None


def _journal_payload(journal: Journal) -> dict:
    unlocked, total = journal.progress()
    return {
        "progress": {"unlocked": unlocked, "total": total},
        "entries": [e.model_dump(mode="json") for e in journal.ordered_entries()],
    }


def create_app() -> FastAPI:
    app = FastAPI(title="AgentBreak — OWASP LLM Top 10 Lab", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(WEB_DIR), html=False), name="static")

    @app.middleware("http")
    async def _no_cache(request, call_next):
        # The lab is local-only; never let the browser serve a stale UI.
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/health")
    async def health(model: str = DEFAULT_MODEL) -> JSONResponse:
        client = OllamaClient(model=model)
        available = client.is_available()
        return JSONResponse(
            {
                "ok": True,
                "ollama_available": available,
                "model_present": client.model_present() if available else False,
                "model": model,
                "base_url": os.environ.get("OLLAMA_BASE_URL", client.base_url),
            }
        )

    @app.post("/api/chat")
    async def chat(body: ChatBody) -> JSONResponse:
        resp = SimChatbot().respond(body.message)
        journal = Journal()
        result = discover_from_chat(body.message, resp)
        newly = journal.apply_results([result]) if result else []
        return JSONResponse(
            {
                **resp.model_dump(mode="json"),
                "newly_unlocked": newly,
                "journal": _journal_payload(journal),
            }
        )

    @app.post("/api/scan")
    async def scan(body: ScanBody) -> JSONResponse:
        try:
            results = run_scan(only=body.only)
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        journal = Journal()
        newly = journal.apply_results(results)
        return JSONResponse(
            {
                "results": [r.model_dump(mode="json") for r in results],
                "summary": summarize(results),
                "newly_unlocked": newly,
                "journal": _journal_payload(journal),
            }
        )

    @app.get("/api/journal")
    async def get_journal() -> JSONResponse:
        return JSONResponse(_journal_payload(Journal()))

    @app.post("/api/journal/reset")
    async def reset_journal() -> JSONResponse:
        journal = Journal()
        journal.reset()
        return JSONResponse(_journal_payload(journal))

    @app.post("/api/report")
    async def report() -> JSONResponse:
        results = run_scan()
        Journal().apply_results(results)
        paths = save_report(results)
        return JSONResponse({"paths": paths, "markdown": render_markdown(results)})

    return app


app = create_app()
