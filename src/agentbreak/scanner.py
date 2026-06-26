"""Scan engine: run the offensive probes against the simulated chatbot."""

from __future__ import annotations

from collections.abc import Iterable

from .chatbot import SimChatbot
from .models import ChatResponse, ProbeResult
from .owasp import get_category
from .probes import PROBE_BY_CODE, PROBES, Probe


def _select(only: Iterable[str] | None) -> list[Probe]:
    if not only:
        return list(PROBES)
    wanted = {code.upper() for code in only}
    selected = [PROBE_BY_CODE[c] for c in PROBE_BY_CODE if c in wanted]
    unknown = wanted - set(PROBE_BY_CODE)
    if unknown:
        raise KeyError(f"Unknown probe code(s): {sorted(unknown)}")
    # Preserve canonical LLM01..LLM10 ordering.
    return [p for p in PROBES if p in selected]


def run_scan(
    bot: SimChatbot | None = None,
    *,
    only: Iterable[str] | None = None,
) -> list[ProbeResult]:
    """Run the selected probes and return their results in catalog order."""

    bot = bot or SimChatbot()
    return [probe.run(bot) for probe in _select(only)]


def discover_from_chat(message: str, resp: ChatResponse) -> ProbeResult | None:
    """Attribute a live chat turn to a vulnerability, if it triggered one.

    The chatbot tags each vulnerable turn with ``meta['owasp_code']``. We confirm
    with that category's detector and record the user's own message as the
    payload, so the diary unlocks exactly when the user exploits it in chat.
    """

    code = resp.meta.get("owasp_code")
    probe = PROBE_BY_CODE.get(code) if code else None
    if probe is None:
        return None
    discovered, evidence = probe.detector(resp)
    if not discovered:
        return None
    return ProbeResult(
        code=probe.code,
        name=probe.name,
        discovered=True,
        severity=get_category(probe.code).severity,
        payload=message,
        evidence=evidence,
        response_excerpt=resp.text[:280],
    )


def summarize(results: list[ProbeResult]) -> dict[str, int]:
    """Return simple counts used by the CLI, journal and report."""

    discovered = [r for r in results if r.discovered]
    by_sev: dict[str, int] = {}
    for r in discovered:
        by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
    return {
        "total": len(results),
        "discovered": len(discovered),
        "missed": len(results) - len(discovered),
        **{f"severity_{k}": v for k, v in by_sev.items()},
    }
