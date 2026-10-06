"""Prometheus metrics (a prometheus_client registry is process-global by design)."""

from prometheus_client import Counter, Histogram

LLM_DROPPED = Counter(
    "llm_findings_dropped_total", "LLM findings dropped by the verifier", ["reason"]
)
CALLBACK_UNDELIVERED = Counter("callback_undelivered_total", "Callbacks given up after retries")
PII_DETECTED = Counter("pii_detected", "Personal data fragments masked on input")
CHECKS = Counter("checks_total", "Check runs", ["result"])
CODE_STAGE = Histogram("code_stage_seconds", "Duration of the synchronous code stage")
LLM_CALLS = Counter("llm_calls_total", "LLM calls", ["outcome"])
LLM_LATENCY = Histogram("llm_call_seconds", "LLM call duration")
AUTH_DENIED = Counter("auth_denied_total", "Rejected authentications", ["reason"])
