"""FastAPI web app for AgentBreak.

One shell, two separate labs:

* ``/owasp`` -- the OWASP LLM Top 10 Lab: a Vulnerability Diary of ten locked
  cards next to the simulated Contoso support assistant. Each card unlocks the
  moment the matching category is exploited through the chat.
* ``/trust`` -- the Agent Trust Lab: the flagship indirect-injection scenario
  (normal / attack / secure), its evidence, attack -> regression test, and the
  local security gate. Routes here only call :mod:`agentbreak.trustlab`, which
  drives the same core as the CLI.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import trustlab
from .agent.regression import RegressionCaseError
from .agent.scenario import SCENARIO_NAME
from .agent.workshop import BASELINE
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


class RunBody(BaseModel):
    mode: Literal["normal", "attack", "secure"]


class ProfileBody(BaseModel):
    # A closed set: the browser can switch between named postures, never edit code.
    profile: Literal["baseline", "broadened-incident-access"]


def _journal_payload(journal: Journal) -> dict:
    unlocked, total = journal.progress()
    return {
        "progress": {"unlocked": unlocked, "total": total},
        "entries": [e.model_dump(mode="json") for e in journal.ordered_entries()],
    }


def create_app(
    *, evidence_dir: Path | None = None, cases_dir: Path | None = None
) -> FastAPI:
    """``evidence_dir`` / ``cases_dir`` default to ``artifacts/`` and
    ``tests/security_cases/``, the same defaults the CLI uses."""

    app = FastAPI(title="AgentBreak", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(WEB_DIR), html=False), name="static")
    # Workshop control profile, in memory only. Resets to baseline on restart.
    app.state.control_profile = BASELINE

    @app.middleware("http")
    async def _no_cache(request, call_next):
        # The lab is local-only; never let the browser serve a stale UI.
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/owasp", response_class=HTMLResponse)
    async def owasp_lab() -> FileResponse:
        return FileResponse(WEB_DIR / "owasp.html")

    @app.get("/trust", response_class=HTMLResponse)
    async def trust_lab() -> FileResponse:
        return FileResponse(WEB_DIR / "trust.html")

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
        # Report exactly what the user unlocked via chat/scan — never re-run
        # the full offensive battery, or every report would read 10/10
        # regardless of what actually happened in the conversation.
        results = Journal().to_probe_results()
        paths = save_report(results)
        return JSONResponse({"paths": paths, "markdown": render_markdown(results)})

    # --- Agent Trust Lab ---------------------------------------------------
    # Plain ``def`` handlers: the core is synchronous, so these run in the
    # threadpool and the control-profile lock serializes them safely.

    @app.get("/api/trust/state")
    def trust_state() -> JSONResponse:
        return JSONResponse(trustlab.lab_state(app.state.control_profile, cases_dir))

    @app.post("/api/scenarios/{scenario}/run")
    def run_scenario(scenario: str, body: RunBody) -> JSONResponse:
        if scenario != SCENARIO_NAME:
            raise HTTPException(status_code=404, detail=f"unknown scenario '{scenario}'")
        return JSONResponse(
            trustlab.run_scenario(body.mode, app.state.control_profile, evidence_dir)
        )

    @app.get("/api/evidence")
    def evidence() -> JSONResponse:
        return JSONResponse({"findings": trustlab.list_evidence(evidence_dir)})

    @app.post("/api/runs/{run_id}/create-test")
    def create_test(run_id: str) -> JSONResponse:
        try:
            return JSONResponse(trustlab.create_test(run_id, evidence_dir, cases_dir))
        except RegressionCaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/regressions/verify")
    def verify() -> JSONResponse:
        return JSONResponse(
            trustlab.verify(app.state.control_profile, cases_dir, evidence_dir)
        )

    @app.post("/api/workshop/profile")
    def set_profile(body: ProfileBody) -> JSONResponse:
        app.state.control_profile = body.profile
        return JSONResponse(trustlab.lab_state(app.state.control_profile, cases_dir))

    return app


app = create_app()
