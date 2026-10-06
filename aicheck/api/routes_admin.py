"""Rule package administration."""

import json
from typing import Any

from fastapi import APIRouter, Body

from aicheck.api.deps import AdminP, Rt
from aicheck.db import queries
from aicheck.errors import Conflict, NotFound, ValidationError
from aicheck.logging import security_event
from aicheck.rules.loader import RulesError, parse_ruleset

router = APIRouter(prefix="/v1/admin")


@router.post("/rulesets", status_code=201)
def post_ruleset(rt: Rt, principal: AdminP, body: dict[str, Any] = Body(...)) -> dict[str, Any]:  # noqa: B008
    text = json.dumps(body, ensure_ascii=False, sort_keys=True)
    try:
        ruleset = parse_ruleset(text)
    except RulesError as exc:
        raise ValidationError(str(exc), code="ruleset_invalid") from exc
    with rt.db.tx() as conn:
        new_id = queries.insert_ruleset(
            conn, rt.settings.org_code, ruleset.version, body, ruleset.sha256
        )
    if new_id < 0:
        raise Conflict("rule package with this version already exists", "version")
    security_event(
        "admin_action", action="ruleset_upload", actor=principal.sub, version=ruleset.version
    )
    return {"id": new_id, "version": ruleset.version, "status": "draft"}


@router.post("/rulesets/{ruleset_id}/activate")
def activate_ruleset(ruleset_id: int, rt: Rt, principal: AdminP) -> dict[str, Any]:
    with rt.db.tx() as conn:
        row = queries.get_ruleset(conn, ruleset_id)
        if row is None or row["org_code"] != rt.settings.org_code:
            raise NotFound("rule package not found")
        if row["status"] == "active":
            raise Conflict("rule package is already active")
        queries.activate_ruleset(conn, ruleset_id, rt.settings.org_code)
    rt.active_rules(force=True)
    security_event(
        "admin_action", action="ruleset_activate", actor=principal.sub, ruleset_id=ruleset_id
    )
    return {"id": ruleset_id, "version": row["version"], "status": "active"}
