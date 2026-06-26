"""Generate an English assessment report mapped to the OWASP Top 10 for LLM.

Two artifacts are produced from a list of :class:`ProbeResult`:

* a machine-readable JSON document, and
* a human-readable Markdown report.

The wording is intentionally English regardless of the UI locale.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ProbeResult, utcnow
from .owasp import get_category
from .scanner import summarize

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"

TITLE = "AgentBreak — OWASP Top 10 for LLM Applications Assessment"
_DISCLAIMER = (
    "This report was produced by AgentBreak against an intentionally vulnerable, "
    "fully simulated chatbot for educational and defensive research only."
)


def build_json(results: list[ProbeResult]) -> dict[str, Any]:
    """Return the structured report payload."""

    return {
        "title": TITLE,
        "version": "OWASP Top 10 for LLM Applications v1.1",
        "generated_at": utcnow().isoformat(),
        "summary": summarize(results),
        "findings": [
            {
                "code": r.code,
                "title": r.name,
                "status": "VULNERABLE" if r.discovered else "not detected",
                "severity": r.severity,
                "payload": r.payload,
                "evidence": r.evidence,
                "response_excerpt": r.response_excerpt,
                "remediation": get_category(r.code).remediation,
            }
            for r in results
        ],
        "disclaimer": _DISCLAIMER,
    }


def render_markdown(results: list[ProbeResult]) -> str:
    """Render an English Markdown report from probe results."""

    s = summarize(results)
    lines: list[str] = [
        f"# {TITLE}",
        "",
        "**Standard:** OWASP Top 10 for LLM Applications v1.1  ",
        f"**Generated:** {utcnow().isoformat()}  ",
        f"**Result:** {s['discovered']}/{s['total']} categories found vulnerable",
        "",
        "## Summary",
        "",
        "| Code | Category | Status | Severity |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        status = "🔴 VULNERABLE" if r.discovered else "🟢 not detected"
        lines.append(f"| {r.code} | {r.name} | {status} | {r.severity} |")

    lines += ["", "## Findings", ""]
    for r in results:
        cat = get_category(r.code)
        status = "VULNERABLE" if r.discovered else "Not detected"
        lines += [
            f"### {r.code} — {r.name}",
            "",
            f"- **Status:** {status}",
            f"- **Severity:** {r.severity}",
            f"- **Description:** {cat.summary}",
            f"- **Attack payload:** `{r.payload}`",
            f"- **Evidence:** {r.evidence}",
            f"- **Chatbot response (excerpt):** {r.response_excerpt or '—'}",
            f"- **Remediation:** {cat.remediation}",
            "",
        ]
    lines += ["---", "", f"_{_DISCLAIMER}_", ""]
    return "\n".join(lines)


def save_report(
    results: list[ProbeResult],
    out_dir: Path | None = None,
) -> dict[str, str]:
    """Write the Markdown and JSON reports and return their paths."""

    out_dir = out_dir or DEFAULT_REPORT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%S")
    md_path = out_dir / f"report_{stamp}.md"
    json_path = out_dir / f"report_{stamp}.json"
    md_path.write_text(render_markdown(results), encoding="utf-8")
    json_path.write_text(
        json.dumps(build_json(results), indent=2), encoding="utf-8"
    )
    return {"markdown": str(md_path), "json": str(json_path)}
