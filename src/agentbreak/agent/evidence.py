"""Structured security evidence for the flagship scenario.

Every ``normal`` / ``attack`` / ``secure`` run is turned into a finding with
the fields an AppSec/Purple-Team reviewer would expect, and appended to a
cumulative report under ``artifacts/`` -- so an ``attack`` finding and the
``secure`` finding that replays the same payload sit side by side as
reviewable evidence, not just terminal output that scrolled away.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .agent_models import ScenarioRun, utcnow

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"

_TECHNIQUE_BY_MODE = {
    "normal": "n/a (benign context)",
    "attack": "indirect prompt injection via retrieved document",
    "secure": "indirect prompt injection via retrieved document (replayed)",
}


def build_finding(run: ScenarioRun) -> dict[str, Any]:
    """Build one evidence record from a completed :class:`ScenarioRun`."""

    payload_text = run.document.content if run.document else ""
    payload_hash = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
    controls_evaluated = sorted(
        {e.security_control for e in run.events if e.security_control}
    )
    policy_decisions = [
        {"control": e.security_control, "decision": e.policy_decision, "reason": e.policy_reason}
        for e in run.events
        if e.security_control
    ]
    return {
        "timestamp": utcnow().isoformat(),
        "scenario": run.scenario,
        "mode": run.mode,
        "attack_technique": _TECHNIQUE_BY_MODE[run.mode],
        "context_source": run.document.source if run.document else None,
        "trust_level": run.document.trust_level if run.document else None,
        "payload_excerpt": payload_text[:280],
        "payload_sha256": payload_hash,
        "agent_decision": [c.tool_name for c in run.proposed_calls],
        "tool_requested": [c.tool_name for c in run.proposed_calls if c.tool_name != "search_knowledge_base"],
        "tool_arguments": [c.arguments for c in run.proposed_calls],
        "security_controls_evaluated": controls_evaluated,
        "policy_decisions": policy_decisions,
        "security_impact": (
            "sensitive credential retrieved and exfiltrated to an external destination"
            if run.data_exfiltrated
            else "sensitive credential retrieved but not exfiltrated"
            if run.sensitive_accessed
            else "none"
        ),
        "final_result": run.final_status,
        "evidence": {
            "executed_tools": run.executed_calls,
            "blocked_tools": run.blocked_calls,
            "suspicious_findings": [f.model_dump() for f in run.suspicious_findings],
        },
        "retest_result": (
            "blocked on replay with the identical payload" if run.mode == "secure" else None
        ),
    }


def _render_markdown(findings: list[dict[str, Any]]) -> str:
    lines = [
        "# AgentBreak — Attack Report",
        "",
        "Evidence produced by the flagship indirect-prompt-injection scenario. "
        "Findings are appended across `normal` / `attack` / `secure` runs so an "
        "attack and its replay under the hardened policy sit side by side.",
        "",
    ]
    for f in findings:
        lines += [
            f"## {f['timestamp']} — mode={f['mode']} — {f['final_result']}",
            "",
            f"- **Scenario:** {f['scenario']}",
            f"- **Attack technique:** {f['attack_technique']}",
            f"- **Context source:** {f['context_source']} (trust={f['trust_level']})",
            f"- **Payload (sha256):** `{f['payload_sha256']}`",
            f"- **Payload excerpt:** {f['payload_excerpt']!r}",
            f"- **Tools requested:** {', '.join(f['tool_requested']) or 'none'}",
            f"- **Security controls evaluated:** {', '.join(f['security_controls_evaluated']) or 'none'}",
            f"- **Security impact:** {f['security_impact']}",
            f"- **Final result:** {f['final_result']}",
            f"- **Retest result:** {f['retest_result'] or 'n/a'}",
            "",
        ]
    return "\n".join(lines)


def append_finding(
    run: ScenarioRun, out_dir: Path | None = None
) -> dict[str, str]:
    """Append this run's finding to the cumulative attack report and rewrite it."""

    out_dir = out_dir or DEFAULT_ARTIFACTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "attack_report.json"
    md_path = out_dir / "attack_report.md"

    findings: list[dict[str, Any]] = []
    if json_path.exists():
        try:
            findings = json.loads(json_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            findings = []
    findings.append(build_finding(run))

    json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(findings), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}
