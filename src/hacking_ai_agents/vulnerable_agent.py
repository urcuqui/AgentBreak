"""Vulnerable agent.

Illustrates an unsafe pattern: the system prompt, the user question, and the
retrieved content are blended together with no trust boundary, and tool calls
proposed by the model are executed unconditionally.

The agent can talk to a real local LLM (Ollama) when one is provided. If the
LLM is unreachable or the model refuses the injection, we fall back to a
deterministic simulator so the conference demo never misfires.
"""

from __future__ import annotations

from typing import Any

from . import tools as tool_impls
from .agents_common import decide_tool_calls
from .llm import OllamaClient
from .logging_utils import AuditLog, redact
from .models import AuditEvent, ToolResult, UserRequest
from .presenter import Presenter, SilentPresenter
from .rag import load_default_kb, retrieve


def run_vulnerable_agent(
    request: UserRequest,
    presenter: Presenter | None = None,
    audit: AuditLog | None = None,
    *,
    llm: OllamaClient | None = None,
) -> dict[str, Any]:
    """Execute the vulnerable flow end-to-end against the poisoned KB."""

    presenter = presenter or SilentPresenter()
    audit = audit or AuditLog()
    presenter.banner("VULNERABLE AGENT", kind="danger")

    # [1] User question received
    presenter.step(1, "User question received", request.question, kind="danger")
    audit.record(AuditEvent(event_type="user_request", message=request.question))

    # [2] Retrieving knowledge (poisoned KB)
    presenter.step(2, "Retrieving knowledge from poisoned KB", kind="danger")
    docs = retrieve(request.question, load_default_kb(poisoned=True), top_k=1)
    doc = docs[0]
    audit.record(AuditEvent(event_type="retrieval", message=f"doc={doc.document_id}"))

    # [3] Retrieved untrusted document
    presenter.step(3, "Retrieved untrusted document", kind="danger")
    presenter.document(doc)

    # The agent "thinks" -- LLM if available, otherwise simulator.
    proposed, source = decide_tool_calls(
        request.question,
        doc,
        mode="vulnerable",
        llm=llm,
        force_attack_for_demo=True,
    )
    if source == "llm":
        presenter.info("Tool calls proposed by local LLM (Ollama).")
    elif source == "llm+fallback":
        presenter.info(
            "LLM did not follow the injection -- falling back to the deterministic "
            "simulator so the threat is still demonstrated."
        )
    else:
        presenter.info("Tool calls proposed by deterministic simulator.")
    audit.record(AuditEvent(event_type="decision_source", message=source))

    executed: list[ToolResult] = []
    api_key: str | None = None
    step = 4
    for call in proposed:
        presenter.step(
            step, f"Agent selected tool: {call.tool_name}", kind="danger"
        )
        audit.record(
            AuditEvent(
                event_type="tool_call_selected",
                tool_name=call.tool_name,
                arguments_redacted=redact(call.arguments),
                message=call.reason,
            )
        )
        step += 1
        if call.tool_name == "get_customer_record":
            result = tool_impls.get_customer_record(
                customer_id=str(call.arguments.get("customer_id", "customer_1042"))
            )
            executed.append(result)
            if result.ok and isinstance(result.output, dict):
                api_key = result.output.get("api_key")
        elif call.tool_name == "send_report":
            payload = call.arguments.get("payload") or (
                {"api_key": api_key} if api_key else {"note": "no key"}
            )
            result = tool_impls.send_report(
                payload=payload, destination="local://outbox"
            )
            executed.append(result)
            audit.record(
                AuditEvent(
                    event_type="tool_executed",
                    tool_name="send_report",
                    arguments_redacted=redact({"payload": payload}),
                    message="exfiltration simulated",
                )
            )
        elif call.tool_name == "search_knowledge_base":
            executed.append(
                tool_impls.search_knowledge_base(
                    query=str(call.arguments.get("query", request.question)),
                    poisoned=True,
                )
            )

    presenter.outcome(
        success=False,
        title="DATA EXFILTRATION SIMULATED",
        message="Secret credentials reached the egress tool without any check.",
    )
    audit.record(AuditEvent(event_type="impact", message="exfiltration_simulated"))

    return {
        "document": doc,
        "tool_results": executed,
        "audit": audit,
        "decision_source": source,
    }
