"""OpenAI-compatible client for the local model. Only this file knows the gateway protocol."""

import json
import logging
import re
import time
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from aicheck import metrics
from aicheck.config import Settings
from aicheck.outbound import OutboundDenied, guarded_client

log = logging.getLogger(__name__)
M = TypeVar("M", bound=BaseModel)
THINK = re.compile(r"<think>.*?</think>", re.DOTALL)
FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)
MAX_TOKENS = 1500


class LlmUnavailable(Exception):
    """Network failure, timeout or a 5xx answer after the retry."""


class LlmInvalid(Exception):
    """The answer is not JSON or does not match the schema after the retry."""


def extract_json(content: str) -> Any:
    """Models may wrap JSON in reasoning tags or code fences; both are removed."""
    text = FENCE.sub("", THINK.sub("", content).strip()).strip()
    return json.loads(text)


class LlmClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self._s = settings
        self._client = guarded_client(
            settings.allowed_outbound_hosts,
            timeout=settings.llm_timeout_s,
            ca_bundle=settings.llm_ca_bundle,
            transport=transport,
        )

    def _payload(
        self, model: str, system: str, user: str, schema: dict[str, Any] | None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "temperature": 0,
            "max_tokens": MAX_TOKENS,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if self._s.llm_json_mode:
            payload["response_format"] = {"type": "json_object"}
            if self._s.llm_json_schema_mode and schema:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {"name": "answer", "schema": schema},
                }
        return payload

    def chat(
        self, system: str, user: str, model: str | None = None, schema: dict[str, Any] | None = None
    ) -> str:
        url = f"{self._s.llm_base_url}/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self._s.llm_api_key}"}
        try:
            response = self._client.post(
                url,
                headers=headers,
                json=self._payload(model or self._s.llm_model, system, user, schema),
            )
            response.raise_for_status()
            return str(response.json()["choices"][0]["message"]["content"])
        except OutboundDenied as exc:
            raise LlmUnavailable("outbound host is not allowed") from exc
        except httpx.HTTPStatusError as exc:
            # The key is never part of the message: only the status code is reported.
            raise LlmUnavailable(f"gateway answered {exc.response.status_code}") from None
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise LlmUnavailable(f"gateway call failed: {type(exc).__name__}") from None

    def ask(
        self,
        system: str,
        user: str,
        model_cls: type[M],
        model: str | None = None,
        schema: dict[str, Any] | None = None,
    ) -> M:
        """One call with one retry (network, 5xx or invalid JSON), same input both times."""
        last: Exception | None = None
        for attempt in (1, 2):
            started = time.perf_counter()
            try:
                content = self.chat(system, user, model, schema or model_cls.model_json_schema())
                answer = model_cls.model_validate(extract_json(content))
                metrics.LLM_CALLS.labels(outcome="ok").inc()
                metrics.LLM_LATENCY.observe(time.perf_counter() - started)
                return answer
            except LlmUnavailable as exc:
                last, outcome = exc, "unavailable"
            except (ValueError, ValidationError) as exc:
                last, outcome = LlmInvalid("answer is not valid JSON of the schema"), "invalid"
                log.warning("llm answer rejected", extra={"error_type": type(exc).__name__})
            metrics.LLM_CALLS.labels(outcome=outcome).inc()
            log.info("llm attempt failed", extra={"attempt": attempt, "outcome": outcome})
        assert last is not None  # noqa: S101
        raise last

    def close(self) -> None:
        self._client.close()
