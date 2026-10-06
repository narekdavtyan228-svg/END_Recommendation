"""Liveness, readiness and metrics (internal network, no token)."""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from aicheck.api.deps import Rt
from aicheck.errors import Unavailable

router = APIRouter()


@router.get("/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/v1/ready")
def ready(rt: Rt, response: Response) -> dict[str, str]:
    try:
        ok = rt.db.ping()
        if ok:
            rt.active_rules()
    except Unavailable:
        ok = False
    response.status_code = 200 if ok else 503
    return {"status": "ready" if ok else "not_ready"}


@router.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
