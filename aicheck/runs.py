"""Use cases: start a run, read it, answers, actions, gate."""

import logging
import time
import uuid
from datetime import timedelta
from typing import Any

from pydantic import ValidationError as PydanticError
from sqlalchemy.exc import IntegrityError

from aicheck import clock, metrics
from aicheck.contracts import ActionRequest, AnswersRequest, CheckRequest, CheckResult, Finding
from aicheck.contracts.models import Gate
from aicheck.db import queries
from aicheck.engine.context import build_context
from aicheck.engine.run import run_code_stage
from aicheck.errors import Conflict, NotFound, TooManyRequests, ValidationError
from aicheck.hashing import content_hash
from aicheck.llm.residue import build_residue
from aicheck.results import build_result, finding_to_row, new_id
from aicheck.runtime import Runtime
from aicheck.sanitize import clean_text, mask_personal

log = logging.getLogger(__name__)
HANDLED_ANY = {"accept", "edit", "reject", "answer", "hide"}
HANDLED_CRITICAL = {"accept", "edit", "reject"}
BLOCKER_TEXT = {
    "no_run": "Проверка для текущего содержимого не выполнена",
    "critical_open": "Необработанные критичные замечания: {n}",
    "question_open": "Есть открытые вопросы, влияющие на критичные правила: {n}",
}


class Actor:
    """Who calls: the HSE backend (service) or a user in mode A."""

    def __init__(self, ref: str, role: str, service: bool) -> None:
        self.ref, self.role, self.service = ref, role, service


def sanitize_request(request: CheckRequest) -> tuple[CheckRequest, int]:
    """Clean and mask every free text before it is stored or sent anywhere."""
    found = 0

    def fix(value: str | None) -> str | None:
        nonlocal found
        if value is None:
            return None
        masked, count = mask_personal(clean_text(value))
        found += count
        return masked

    data = request.model_dump()
    data["context"]["description"] = fix(data["context"]["description"]) or ""
    for measure in data["measures"]:
        measure["text"] = fix(measure["text"]) or ""
        measure["notApplicableReason"] = fix(measure["notApplicableReason"])
    metrics.PII_DETECTED.inc(found)
    try:
        return CheckRequest.model_validate(data), found
    except PydanticError as exc:  # masking can lengthen a text that was at the limit
        raise ValidationError("text is too long after masking", "measures") from exc


def check_rate(rt: Runtime, actor: Actor) -> None:
    since = clock.now() - timedelta(hours=1)
    with rt.db.tx() as conn:
        if actor.service:
            used = queries.count_runs_since(conn, since)
            limit = rt.settings.service_runs_per_hour
        else:
            used = queries.count_runs_since(conn, since, actor.ref)
            limit = rt.settings.user_runs_per_hour
    if used >= limit:
        raise TooManyRequests("run limit exceeded")


def _authorize_run(actor: Actor, run: dict[str, Any]) -> None:
    """Mode A: only the author sees a run; anything else looks like a missing run."""
    if not actor.service and run["request"]["requestedBy"]["userRef"] != actor.ref:
        raise NotFound("run not found")


def _load_catalog(rt: Runtime, version: str) -> Any:
    catalog = rt.catalog(version)
    if catalog is None:
        raise Conflict(
            "catalog version is unknown", "context.catalogVersion", "catalog_version_unknown"
        )
    return catalog


def start_run(rt: Runtime, request: CheckRequest, actor: Actor) -> CheckResult:
    """Execute the code stage synchronously and queue the LLM stage when there is a residue."""
    if request.tenant.orgCode != rt.settings.org_code:
        raise ValidationError("unknown organisation", "tenant.orgCode")
    active = rt.active_rules()
    with rt.db.tx() as conn:
        existing = queries.find_run(
            conn, request.end.endRef, request.end.contentHash, active.ruleset_id
        )
        if existing:
            _authorize_run(actor, existing)
            return build_result(conn, existing, active.ruleset.version)
    check_rate(rt, actor)
    catalog = _load_catalog(rt, request.context.catalogVersion)
    clean, _ = sanitize_request(request)
    started = time.perf_counter()
    ctx = build_context(clean, active.ruleset, catalog, rt.kb_basis())
    findings = run_code_stage(ctx)
    for finding in findings:
        finding.findingId = new_id()
    residue = build_residue(ctx, findings)
    metrics.CODE_STAGE.observe(time.perf_counter() - started)
    run_id = new_id()
    llm = "skipped" if residue.empty else "pending"
    try:
        with rt.db.tx() as conn:
            _persist(conn, run_id, clean, active.ruleset_id, findings, llm)
            run = queries.get_run(conn, run_id)
            assert run is not None  # noqa: S101 - just inserted
            result = build_result(conn, run, active.ruleset.version)
    except IntegrityError:  # a concurrent identical request won the race
        with rt.db.tx() as conn:
            run = queries.find_run(conn, clean.end.endRef, clean.end.contentHash, active.ruleset_id)
            if run is None:
                raise
            return build_result(conn, run, active.ruleset.version)
    metrics.CHECKS.labels(result="created").inc()
    return result


def _persist(
    conn: Any,
    run_id: str,
    request: CheckRequest,
    ruleset_id: int,
    findings: list[Finding],
    llm: str,
) -> None:
    queries.insert_run(
        conn,
        {
            "id": run_id,
            "end_ref": request.end.endRef,
            "content_hash": request.end.contentHash,
            "ruleset_id": ruleset_id,
            "catalog_version": request.context.catalogVersion,
            "request": request.model_dump(mode="json"),
        },
    )
    queries.insert_event(conn, run_id, "code_done", llm)
    queries.insert_findings(conn, run_id, [finding_to_row(f) for f in findings])
    if llm == "pending":
        queries.enqueue_job(conn, run_id)


def get_result(rt: Runtime, run_id: str, actor: Actor) -> CheckResult:
    with rt.db.tx() as conn:
        run = queries.get_run(conn, run_id) if _is_uuid(run_id) else None
        if run is None:
            raise NotFound("run not found")
        _authorize_run(actor, run)
        ruleset = rt.ruleset_by_id(run["ruleset_id"])
        return build_result(conn, run, ruleset.version if ruleset else "")


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def answer_run(rt: Runtime, run_id: str, body: AnswersRequest, actor: Actor) -> CheckResult:
    """New run over the same snapshot with updated factor answers."""
    with rt.db.tx() as conn:
        run = queries.get_run(conn, run_id) if _is_uuid(run_id) else None
    if run is None:
        raise NotFound("run not found")
    _authorize_run(actor, run)
    data = dict(run["request"])
    data["factorAnswers"] = body.factorAnswers
    data["end"] = {**data["end"], "contentHash": body.contentHash}
    request = CheckRequest.model_validate(data)
    if content_hash(request) != body.contentHash:
        raise ValidationError(
            "contentHash does not match the snapshot", "contentHash", "content_hash_mismatch"
        )
    return start_run(rt, request, actor)


def record_action(
    rt: Runtime, finding_id: str, body: ActionRequest, actor: Actor, idempotency_key: str | None
) -> str:
    if body.action == "reject" and not body.reasonCode:
        raise ValidationError("reasonCode is required for reject", "reasonCode")
    with rt.db.tx() as conn:
        finding = queries.get_finding(conn, finding_id) if _is_uuid(finding_id) else None
        run = queries.get_run(conn, str(finding["run_id"])) if finding else None
        if finding is None or run is None:
            raise NotFound("finding not found")
        _authorize_run(actor, run)
        _check_action_allowed(finding, body)
        action_id = new_id()
        stored = queries.insert_action(
            conn,
            {
                "id": action_id,
                "finding_id": finding_id,
                "action": body.action,
                "reason_code": body.reasonCode,
                "comment": _clean(body.comment),
                "applied_text": _clean(body.appliedText),
                "user_ref": _user_ref(actor, body),
                "user_role": _user_role(actor, body),
                "idempotency_key": idempotency_key,
            },
        )
    if not stored:
        raise Conflict("action with this Idempotency-Key is already recorded", code="action_exists")
    return action_id


def _clean(value: str | None) -> str | None:
    return mask_personal(clean_text(value))[0] if value is not None else None


def _user_ref(actor: Actor, body: ActionRequest) -> str:
    return (body.userRef or actor.ref) if actor.service else actor.ref


def _user_role(actor: Actor, body: ActionRequest) -> str:
    return (body.userRole or actor.role) if actor.service else actor.role


def _check_action_allowed(finding: dict[str, Any], body: ActionRequest) -> None:
    if body.action == "answer" and finding["kind"] != "question":
        raise ValidationError("only questions can be answered", "action")
    if body.action == "hide" and finding["severity"] == "critical":
        raise ValidationError("critical findings cannot be hidden", "action")
    if body.action == "edit" and not body.appliedText:
        raise ValidationError("appliedText is required for edit", "appliedText")


def _blocker(code: str, n: int | None = None) -> dict[str, str]:
    return {"code": code, "text": BLOCKER_TEXT[code].format(n=n)}


def gate(rt: Runtime, end_ref: str, content_hash_value: str) -> Gate:
    with rt.db.tx() as conn:
        run = queries.find_run_by_hash(conn, end_ref, content_hash_value)
        if run is None:
            return Gate(allowed=False, blockers=[_blocker("no_run")])
        findings = queries.list_findings(conn, str(run["id"]))
        actions = queries.latest_actions(conn, str(run["id"]))
    critical = [f for f in findings if f["severity"] == "critical" and f["kind"] == "issue"]
    open_critical = [f for f in critical if actions.get(str(f["id"])) not in HANDLED_CRITICAL]
    questions = [f for f in findings if f["kind"] == "question" and f["body"].get("blocking")]
    open_questions = [f for f in questions if actions.get(str(f["id"])) != "answer"]
    blockers = []
    if open_critical:
        blockers.append(_blocker("critical_open", len(open_critical)))
    if open_questions:
        blockers.append(_blocker("question_open", len(open_questions)))
    return Gate(allowed=not blockers, blockers=blockers)
