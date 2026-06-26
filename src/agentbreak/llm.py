"""Optional local LLM integration via Ollama, using the standard library only.

The lab is driven by a deterministic *simulator* (see :mod:`agentbreak.chatbot`)
so it is reproducible and never freezes. When an Ollama server is reachable the
chatbot can optionally use it to phrase its replies, but the vulnerability
behavior and the offensive detectors always rely on the deterministic path.

No third-party SDK is required: we talk to Ollama over plain HTTP.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
DEFAULT_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "30"))


@dataclass
class OllamaClient:
    """Tiny client for the local Ollama HTTP API."""

    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: float = DEFAULT_TIMEOUT

    def is_available(self) -> bool:
        """Return True if the Ollama server responds at ``/api/tags``."""

        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            return False

    def list_models(self) -> list[str]:
        """Return locally installed model tags, or ``[]`` on any error."""

        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError):
            return []
        models = payload.get("models") or []
        return [m.get("name") for m in models if isinstance(m, dict) and m.get("name")]

    def model_present(self) -> bool:
        """Return True if ``self.model`` is installed locally."""

        return self.model in self.list_models()

    def chat(self, system: str, user: str) -> str:
        """Send a single chat turn and return the assistant text (best effort)."""

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0.0},
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload.get("message", {}).get("content", "") or ""
