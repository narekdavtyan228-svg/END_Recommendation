"""FastAPI application factory and error handlers."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

from aicheck.api import routes_admin, routes_checks, routes_health, routes_kb
from aicheck.api.asgi import RequestGuard
from aicheck.api.auth import Jwks
from aicheck.errors import AppError
from aicheck.runtime import Runtime

log = logging.getLogger(__name__)
UPLOAD_PREFIX = "/v1/admin/kb/documents"
TITLE = "AI check of work permit section 2"


def error_body(code: str, message: str, field: str | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "field": field}}


def _app_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)  # noqa: S101 - registered for AppError only
    headers = {"Retry-After": "60"} if exc.status == 429 else None
    return JSONResponse(error_body(exc.code, exc.message, exc.field), exc.status, headers)


def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    """Field path and error kind only: never the submitted values."""
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    errors = exc.errors()
    first = errors[0] if errors else {"loc": (), "type": "invalid"}
    path = ".".join(str(p) for p in first["loc"] if p != "body")
    if first["type"] == "json_invalid":
        return JSONResponse(error_body("schema_invalid", "request body is not valid JSON"), 400)
    return JSONResponse(
        error_body("validation_failed", f"invalid value ({first['type']})", path or None), 422
    )


def _unexpected(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled error", extra={"error_type": type(exc).__name__})
    return JSONResponse(error_body("internal_error", "internal error"), 500)


def create_app(rt: Runtime | None = None, jwks: Jwks | None = None) -> FastAPI:
    app = FastAPI(title=TITLE, version="1.0.0")
    app.state.rt = rt
    app.state.jwks = jwks or (Jwks(rt.settings) if rt and rt.settings.idp_jwks_url else None)
    app.add_exception_handler(AppError, _app_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unexpected)
    for module in (routes_checks, routes_admin, routes_health, routes_kb):
        app.include_router(module.router)
    settings = rt.settings if rt else None
    if settings and settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_allowed_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-Id"],
        )
    limit = (settings.max_body_kb if settings else 256) * 1024
    upload = ((settings.kb_max_file_mb if settings else 20) + 1) * 1024 * 1024
    app.add_middleware(
        RequestGuard, default_limit=limit, upload_prefix=UPLOAD_PREFIX, upload_limit=upload
    )
    return app
