"""Environment configuration. The service refuses to start on missing settings."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    database_url: str = field(repr=False)
    org_code: str
    llm_base_url: str
    llm_api_key: str = field(repr=False)
    llm_model: str
    jwt_issuer: str
    jwt_public_key: str
    allowed_outbound_hosts: tuple[str, ...]
    hse_catalog_export_url: str
    hse_callback_url: str = ""
    callback_hmac_secret: str = field(default="", repr=False)
    jwt_audience: str = "ai-check"
    llm_timeout_s: float = 12.0
    llm_json_mode: bool = True
    llm_json_schema_mode: bool = False
    llm_min_confidence: float = 0.6
    llm_ca_bundle: str | None = None
    llm_model_alt: str = ""
    allow_insecure_llm: bool = False
    prompt_version: str = "v1"
    max_body_kb: int = 256
    poll_interval_s: float = 1.0
    log_level: str = "INFO"
    idp_jwks_url: str = ""
    idp_issuer: str = ""
    idp_audience: str = ""
    cors_allowed_origins: tuple[str, ...] = ()
    user_runs_per_hour: int = 30
    service_runs_per_hour: int = 600
    kb_max_file_mb: int = 20
    kb_context_chars: int = 12000
    kb_fts_limit: int = 8


def _read_secret(path: str, name: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"{name}: secret file is not readable") from exc
    if not value:
        raise ConfigError(f"{name}: secret file is empty")
    return value


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _check_llm_url(url: str, insecure_ok: bool) -> None:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and (insecure_ok or host_of(url) in LOOPBACK):
        return
    raise ConfigError("LLM_BASE_URL: https:// is required (http only for loopback or dev flag)")


REQUIRED = (
    "DATABASE_URL_FILE",
    "ORG_CODE",
    "LLM_BASE_URL",
    "LLM_MODEL",
    "JWT_ISSUER",
    "JWT_PUBLIC_KEY_FILE",
    "ALLOWED_OUTBOUND_HOSTS",
    "HSE_CATALOG_EXPORT_URL",
)


def _optional(e: Mapping[str, str]) -> dict[str, Any]:
    """Settings that have defaults."""
    return {
        "jwt_audience": e.get("JWT_AUDIENCE", "ai-check"),
        "llm_timeout_s": float(e.get("LLM_TIMEOUT_S", "12")),
        "llm_json_mode": _bool(e.get("LLM_JSON_MODE", "true")),
        "llm_json_schema_mode": _bool(e.get("LLM_JSON_SCHEMA_MODE", "false")),
        "llm_min_confidence": float(e.get("LLM_MIN_CONFIDENCE", "0.6")),
        "llm_ca_bundle": e.get("LLM_CA_BUNDLE") or None,
        "llm_model_alt": e.get("LLM_MODEL_ALT", ""),
        "prompt_version": e.get("PROMPT_VERSION", "v1"),
        "max_body_kb": int(e.get("MAX_BODY_KB", "256")),
        "poll_interval_s": float(e.get("POLL_INTERVAL_S", "1")),
        "log_level": e.get("LOG_LEVEL", "INFO"),
        "idp_jwks_url": e.get("IDP_JWKS_URL", ""),
        "idp_issuer": e.get("IDP_ISSUER", ""),
        "idp_audience": e.get("IDP_AUDIENCE", ""),
        "cors_allowed_origins": _csv(e.get("CORS_ALLOWED_ORIGINS", "")),
        "user_runs_per_hour": int(e.get("USER_RUNS_PER_HOUR", "30")),
        "kb_max_file_mb": int(e.get("KB_MAX_FILE_MB", "20")),
        "kb_context_chars": int(e.get("KB_CONTEXT_CHARS", "12000")),
        "kb_fts_limit": int(e.get("KB_FTS_LIMIT", "8")),
    }


def _llm_key(e: Mapping[str, str]) -> str:
    """The key comes from a secret file (preferred) or, for local runs, from LLM_API_KEY."""
    if e.get("LLM_API_KEY_FILE"):
        return _read_secret(e["LLM_API_KEY_FILE"], "LLM_API_KEY_FILE")
    return e["LLM_API_KEY"].strip()


def _public_key(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError("JWT_PUBLIC_KEY_FILE: file is not readable") from exc


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env
    missing = [name for name in REQUIRED if not e.get(name)]
    if not (e.get("LLM_API_KEY_FILE") or e.get("LLM_API_KEY")):
        missing.append("LLM_API_KEY_FILE")
    if missing:
        raise ConfigError("missing required variables: " + ", ".join(missing))
    insecure = _bool(e.get("ALLOW_INSECURE_LLM", "false"))
    _check_llm_url(e["LLM_BASE_URL"], insecure)
    callback_url = e.get("HSE_CALLBACK_URL", "")
    secret = ""
    if callback_url:
        if not e.get("CALLBACK_HMAC_SECRET_FILE"):
            raise ConfigError("CALLBACK_HMAC_SECRET_FILE is required with HSE_CALLBACK_URL")
        secret = _read_secret(e["CALLBACK_HMAC_SECRET_FILE"], "CALLBACK_HMAC_SECRET_FILE")
    return Settings(
        database_url=_read_secret(e["DATABASE_URL_FILE"], "DATABASE_URL_FILE"),
        org_code=e["ORG_CODE"],
        llm_base_url=e["LLM_BASE_URL"].rstrip("/"),
        llm_api_key=_llm_key(e),
        llm_model=e["LLM_MODEL"],
        jwt_issuer=e["JWT_ISSUER"],
        jwt_public_key=_public_key(e["JWT_PUBLIC_KEY_FILE"]),
        allowed_outbound_hosts=tuple(h.lower() for h in _csv(e["ALLOWED_OUTBOUND_HOSTS"])),
        hse_catalog_export_url=e["HSE_CATALOG_EXPORT_URL"],
        hse_callback_url=callback_url,
        callback_hmac_secret=secret,
        allow_insecure_llm=insecure,
        **_optional(e),
    )


def validate_outbound(settings: Settings) -> None:
    """Startup check: every outbound URL must point to an allowed host."""
    urls = [settings.llm_base_url, settings.hse_catalog_export_url, settings.hse_callback_url]
    urls.append(settings.idp_jwks_url)
    for url in filter(None, urls):
        if host_of(url) not in settings.allowed_outbound_hosts:
            raise ConfigError("outbound host is not in ALLOWED_OUTBOUND_HOSTS")
