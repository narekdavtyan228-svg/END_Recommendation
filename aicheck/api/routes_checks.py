"""Checks, findings actions, gate, catalog."""

from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Header
from pydantic import BaseModel, ConfigDict

from aicheck import runs
from aicheck.api.deps import AdminP, AnyP, Rt, ServiceP, to_actor
from aicheck.catalog import sync
from aicheck.contracts import ActionRequest, AnswersRequest, CheckRequest, CheckResult
from aicheck.contracts.catalog import CatalogBody
from aicheck.contracts.models import Gate
from aicheck.db import queries
from aicheck.errors import ValidationError
from aicheck.hashing import content_hash
from aicheck.logging import security_event

router = APIRouter(prefix="/v1")
IdemKey = Annotated[str | None, Header(alias="Idempotency-Key")]


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str


@router.post("/checks", response_model=CheckResult)
def post_checks(
    body: CheckRequest, rt: Rt, principal: AnyP, idempotency_key: IdemKey = None
) -> CheckResult:
    actual = content_hash(body)
    if body.end.contentHash != actual:
        raise ValidationError(
            "contentHash does not match the content", "end.contentHash", "content_hash_mismatch"
        )
    if idempotency_key != actual:
        raise ValidationError(
            "Idempotency-Key must equal contentHash", "Idempotency-Key", "idempotency_key_mismatch"
        )
    actor = to_actor(principal)
    if not principal.service:  # mode A: the requester is the token subject, never the body
        body.requestedBy.userRef, body.requestedBy.role = principal.sub, principal.role
    return runs.start_run(rt, body, actor)


@router.get("/checks/{run_id}", response_model=CheckResult)
def get_check(run_id: str, rt: Rt, principal: AnyP) -> CheckResult:
    return runs.get_result(rt, run_id, to_actor(principal))


@router.post("/checks/{run_id}/answers", response_model=CheckResult)
def post_answers(run_id: str, body: AnswersRequest, rt: Rt, principal: AnyP) -> CheckResult:
    return runs.answer_run(rt, run_id, body, to_actor(principal))


@router.post("/findings/{finding_id}/actions", status_code=201)
def post_action(
    finding_id: str, body: ActionRequest, rt: Rt, principal: AnyP, idempotency_key: IdemKey = None
) -> dict[str, str]:
    action_id = runs.record_action(rt, finding_id, body, to_actor(principal), idempotency_key)
    return {"actionId": action_id}


@router.get("/gate", response_model=Gate)
def get_gate(endRef: str, contentHash: str, rt: Rt, principal: ServiceP) -> Gate:  # noqa: N803
    return runs.gate(rt, endRef, contentHash)


@router.post("/sync", status_code=202)
def post_sync(
    body: SyncRequest, rt: Rt, principal: ServiceP, tasks: BackgroundTasks
) -> dict[str, str]:
    tasks.add_task(sync.sync_from_hse, rt, body.version)
    return {"status": "accepted"}


@router.get("/catalog/version")
def get_catalog_version(rt: Rt, principal: ServiceP) -> dict[str, Any]:
    with rt.db.tx() as conn:
        return {"version": queries.latest_catalog_version(conn, rt.settings.org_code)}


@router.post("/admin/catalog", status_code=201)
def post_catalog(body: CatalogBody, rt: Rt, principal: AdminP) -> dict[str, str]:
    sync.import_catalog(rt, body)
    security_event(
        "admin_action", action="catalog_import", actor=principal.sub, version=body.version
    )
    return {"version": body.version}
