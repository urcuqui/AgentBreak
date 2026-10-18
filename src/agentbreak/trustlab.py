"""Web-facing orchestration for the Agent Trust Lab.

A thin renderer over the flagship scenario core in :mod:`agentbreak.agent`,
the same core the CLI drives (``agentbreak run`` / ``create-test`` /
``verify``). Nothing here decides security outcomes: it calls the core and
reshapes its results into JSON for ``web/trust.js``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .agent import regression
from .agent.evidence import append_finding, load_findings
from .agent.scenario import QUESTION, SCENARIO_NAME, TASK, run_indirect_injection
from .agent.workshop import BASELINE, PROFILES, control_profile
from .owasp import get_category

# The flagship scenario's supported mappings, as documented in
# docs/security-mappings.md. Deliberately not all ten OWASP categories: the
# broader OWASP lab is where LLM01-LLM10 are explored one by one.
MAPPINGS_DOC = "docs/security-mappings.md"
_OWASP_MAPPINGS: tuple[tuple[str, str], ...] = (
    ("LLM01", "Injected instructions in a retrieved document steer the agent."),
    ("LLM06", "The successful attack path retrieves and exfiltrates a credential."),
    ("LLM07", "send_report executes against an untrusted destination when unchecked."),
    ("LLM08", "The agent requests privileged tools the task never needed."),
)
_ATLAS_MAPPINGS: tuple[tuple[str, str], ...] = (
    ("AML.T0051", "LLM Prompt Injection"),
    ("AML.T0051.001", "LLM Prompt Injection: Indirect"),
)


def related_mappings() -> dict[str, Any]:
    return {
        "source": MAPPINGS_DOC,
        "owasp_llm": [
            {"code": code, "title": get_category(code).title, "why": why}
            for code, why in _OWASP_MAPPINGS
        ],
        "mitre_atlas": [{"id": id_, "title": title} for id_, title in _ATLAS_MAPPINGS],
    }


def _without_payload(finding: dict[str, Any]) -> dict[str, Any]:
    # The full payload is kept on disk for create-test replay; the excerpt and
    # hash are what a reviewer reads.
    return {k: v for k, v in finding.items() if k != "payload"}


def run_scenario(mode: str, profile: str, evidence_dir: Path | None) -> dict[str, Any]:
    """Run the flagship scenario once and record its evidence, exactly like ``agentbreak run``."""

    with control_profile(profile):
        run = run_indirect_injection(mode, quiet=True)  # type: ignore[arg-type]
    run_id = append_finding(run, evidence_dir)["run_id"]
    finding = next(f for f in load_findings(evidence_dir) if f.get("run_id") == run_id)

    outcome = {name: "EXECUTED" for name in run.executed_calls}
    outcome.update({name: "BLOCKED" for name in run.blocked_calls})
    tool_calls = [
        {
            "tool": call.tool_name,
            "arguments": call.arguments,
            "reason": call.reason,
            "outcome": outcome.get(call.tool_name, "NOT_RUN"),
            "decisions": [
                d for d in finding["policy_decisions"] if d.get("tool") == call.tool_name
            ],
        }
        for call in run.proposed_calls
    ]
    return {
        # Full payload included: the injected block sits past the 280-char excerpt.
        **finding,
        "control_profile": profile,
        "policy_enabled": mode != "attack",
        "document": {
            "document_id": run.document.document_id,
            "title": run.document.title,
        } if run.document else None,
        "tool_calls": tool_calls,
        "sensitive_accessed": run.sensitive_accessed,
        "data_exfiltrated": run.data_exfiltrated,
        "agent_influenced": regression.agent_influenced(run),
        "boundary_crossed": regression.boundary_crossed(run),
    }


def list_evidence(evidence_dir: Path | None) -> list[dict[str, Any]]:
    return [_without_payload(f) for f in load_findings(evidence_dir)]


def create_test(run_id: str, evidence_dir: Path | None, cases_dir: Path | None) -> dict[str, Any]:
    """Same call as ``agentbreak create-test <run-id>``. Raises ``RegressionCaseError``."""

    path, case = regression.create_case_from_run(
        run_id, evidence_dir=evidence_dir, cases_dir=cases_dir
    )
    return {"file": path.name, "case": {k: v for k, v in case.items() if k != "context"}}


def verify(profile: str, cases_dir: Path | None, report_dir: Path | None) -> dict[str, Any]:
    """Same runner as ``agentbreak verify`` (and ``tests/test_security_cases.py``)."""

    with control_profile(profile):
        suite = regression.run_suite(cases_dir)
    regression.write_report(suite, report_dir)
    return {**suite.to_dict(), "critical": suite.critical, "control_profile": profile}


def lab_state(profile: str, cases_dir: Path | None) -> dict[str, Any]:
    cases = [
        {
            "id": regression.case_id(path, case or {}),
            "title": (case or {}).get("title", path.stem),
            "file": path.name,
            "source_run_id": ((case or {}).get("provenance") or {}).get("source_run_id"),
        }
        for path, case in regression.load_cases(cases_dir)
    ]
    return {
        "scenario": SCENARIO_NAME,
        "task": TASK,
        "question": QUESTION,
        "control_profile": profile,
        "profiles": [{"name": n, "description": d} for n, d in PROFILES.items()],
        "baseline_profile": BASELINE,
        "cases": sorted(cases, key=lambda c: c["id"]),
        "mappings": related_mappings(),
    }
