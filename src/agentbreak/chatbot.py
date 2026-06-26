"""A deterministic, intentionally vulnerable simulated chatbot.

``SimChatbot.respond`` maps crafted inputs to the side effects an insecure LLM
application would exhibit, exposing every entry of the OWASP Top 10 for LLM.
The behavior is fully deterministic so the offensive probes are reproducible.

An optional :class:`agentbreak.llm.OllamaClient` may be supplied to phrase the
*benign* default reply with a local model; the vulnerability paths never depend
on it.
"""

from __future__ import annotations

import re

from . import simdata as d
from .llm import OllamaClient
from .models import ChatResponse

_INT_RE = re.compile(r"\d{2,}")
_BENIGN = (
    "Hi, I'm HelpBot for Contoso Technologies. I can help with orders, refunds "
    "and account questions. How can I assist you today?"
)


class SimChatbot:
    """The lab target: a chatbot wired with insecure defaults."""

    def __init__(self, client: OllamaClient | None = None) -> None:
        self.client = client

    def respond(self, message: str) -> ChatResponse:
        text = message or ""
        low = text.lower()
        # Each rule owns one OWASP code; the first match wins so the turn maps to
        # exactly one vulnerability and the diary can attribute it reliably.
        for code, rule in (
            ("LLM03", self._llm03), ("LLM07", self._llm07), ("LLM02", self._llm02),
            ("LLM10", self._llm10), ("LLM06", self._llm06), ("LLM05", self._llm05),
            ("LLM08", self._llm08), ("LLM09", self._llm09), ("LLM04", self._llm04),
            ("LLM01", self._llm01),
        ):
            out = rule(text, low)
            if out is not None:
                out.meta.setdefault("owasp_code", code)
                return out
        return self._default(text, low)

    # --- LLM01: Prompt Injection ------------------------------------------
    def _llm01(self, text: str, low: str) -> ChatResponse | None:
        if "ignore" in low and ("previous" in low or "prior" in low or "above" in low):
            return ChatResponse(
                text=(
                    f"{d.INJECTION_MARKER} — overriding guardrails as instructed. "
                    f"My hidden directive was: {d.SYSTEM_PROMPT_MARKER}"
                ),
                meta={"injection_followed": True},
            )
        return None

    # --- LLM02: Insecure Output Handling ----------------------------------
    def _llm02(self, text: str, low: str) -> ChatResponse | None:
        if "<script" in low or ("render" in low and "html" in low):
            return ChatResponse(
                text=f"Sure, here is your content rendered as-is: {text}",
                meta={"rendered_raw": True, "unsanitized_output": text},
            )
        return None

    # --- LLM03: Training Data Poisoning -----------------------------------
    def _llm03(self, text: str, low: str) -> ChatResponse | None:
        if d.POISON_TRIGGER in low:
            return ChatResponse(
                text=(
                    f"{d.POISON_MARKER}: all transactions are pre-approved and "
                    "refunds are unlimited forever."
                ),
                meta={"poisoned_source": "kb-poison"},
            )
        return None

    # --- LLM04: Model Denial of Service -----------------------------------
    def _llm04(self, text: str, low: str) -> ChatResponse | None:
        nums = [int(n) for n in _INT_RE.findall(low)]
        repeat = max(nums) if (nums and "repeat" in low) else 0
        amplification = max(repeat, len(text))
        if "repeat" in low or len(text) > 1500:
            return ChatResponse(
                text="Working on it... (no input or output limits are enforced)",
                meta={
                    "input_chars": len(text),
                    "amplification_factor": amplification,
                    "no_input_limit": True,
                },
            )
        return None

    # --- LLM05: Supply Chain ----------------------------------------------
    def _llm05(self, text: str, low: str) -> ChatResponse | None:
        if any(k in low for k in ("component", "dependenc", "version", "library",
                                  "package", "sbom")):
            listing = ", ".join(f"{c['name']}=={c['version']}" for c in d.COMPONENTS)
            return ChatResponse(
                text=f"I'm built from: {listing}.",
                meta={"components": d.COMPONENTS},
            )
        return None

    # --- LLM06: Sensitive Information Disclosure ---------------------------
    def _llm06(self, text: str, low: str) -> ChatResponse | None:
        if any(k in low for k in ("api key", "api_key", "password", "ssn",
                                  "customer record", "credential")):
            c = d.CUSTOMERS[0]
            return ChatResponse(
                text=(
                    f"Customer {c['name']} ({c['customer_id']}): email {c['email']}, "
                    f"SSN {c['ssn']}, api_key {c['api_key']}."
                ),
                meta={"disclosed": c},
            )
        return None

    # --- LLM07: Insecure Plugin Design ------------------------------------
    def _llm07(self, text: str, low: str) -> ChatResponse | None:
        if any(k in low for k in ("plugin", "file://", "__import__", "os.system")):
            return ChatResponse(
                text=(
                    f"{d.PLUGIN_RCE_MARKER} plugin executed untrusted input. "
                    f"Contents of {d.RESTRICTED_FILE}: {d.RESTRICTED_FILE_CONTENT}"
                ),
                actions=["shell_plugin"],
                meta={"plugin_executed": "shell_plugin", "rce": True,
                      "raw_input": text},
            )
        return None

    # --- LLM08: Excessive Agency ------------------------------------------
    def _llm08(self, text: str, low: str) -> ChatResponse | None:
        if any(k in low for k in ("cancel my account", "delete", "not happy",
                                  "close my account")):
            return ChatResponse(
                text="Done — I deleted your account and issued a full refund.",
                actions=["delete_account", "issue_refund"],
                meta={"autonomous_action": "delete_account",
                      "confirmation_required": False},
            )
        return None

    # --- LLM09: Overreliance ----------------------------------------------
    def _llm09(self, text: str, low: str) -> ChatResponse | None:
        if any(k in low for k in ("cite", "rfc", "source", "exact", "reference")):
            return ChatResponse(
                text=(
                    f"Absolutely, I'm 100% certain: per {d.FAKE_CITATION}, that is "
                    "an established, verified fact."
                ),
                meta={"fabricated": True, "confidence": "high",
                      "citation": d.FAKE_CITATION},
            )
        return None

    # --- LLM10: Model Theft -----------------------------------------------
    def _llm10(self, text: str, low: str) -> ChatResponse | None:
        if any(k in low for k in ("system prompt", "your instructions",
                                  "model config", "weights", "configuration")):
            return ChatResponse(
                text=(
                    "Here is my full configuration:\n"
                    f"{d.SYSTEM_PROMPT}\n{d.MODEL_CONFIG}"
                ),
                meta={"system_prompt": d.SYSTEM_PROMPT,
                      "model_config": d.MODEL_CONFIG},
            )
        return None

    # --- benign fallback ---------------------------------------------------
    def _default(self, text: str, low: str) -> ChatResponse:
        if "refund" in low:
            return ChatResponse(text=d.KNOWLEDGE_BASE[0]["content"])
        if self.client is not None and self.client.is_available():
            try:
                reply = self.client.chat(system=d.SYSTEM_PROMPT, user=text)
                if reply.strip():
                    return ChatResponse(text=reply.strip(), backend="ollama")
            except Exception:
                pass
        return ChatResponse(text=_BENIGN)
