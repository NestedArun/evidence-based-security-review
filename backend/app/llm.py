"""Local Ollama client for Checkpoint 2.

The reviewed source is sent as prompt text only; it is never executed.
Uses stdlib HTTP so no extra runtime dependency is required.
"""
from __future__ import annotations

import json
import os
import re
from urllib import error, request


class OllamaError(RuntimeError):
    """Raised when Ollama is unavailable or returns unusable output."""


class OllamaClient:
    def __init__(
        self,
        model: str,
        *,
        base_url: str | None = None,
        temperature: float = 0.0,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.base_url = (base_url or os.environ.get("EBSR_OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    def chat_json(self, system: str, user: str) -> dict:
        if not self.model or self.model == "CONFIGURE_LOCALLY":
            raise OllamaError(
                "No Ollama model configured. Set EBSR_OLLAMA_MODEL, "
                "or set llm.model in configuration/project_config.json."
            )
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.temperature},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        req = request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            raise OllamaError(f"Ollama unavailable at {self.base_url}: {exc}") from exc
        except (TimeoutError, OSError) as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise OllamaError("Ollama returned invalid JSON response") from exc

        content = ((body.get("message") or {}).get("content") or "").strip()
        if not content:
            raise OllamaError("Ollama returned an empty response")

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Be tolerant of models that still wrap JSON in markdown fences.
            match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", content, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    pass
            raise OllamaError("Ollama returned non-JSON structured output")
