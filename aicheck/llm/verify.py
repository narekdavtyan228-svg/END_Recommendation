"""Verifier of LLM findings: nine filters in a fixed order (spec section 7)."""

from dataclasses import dataclass, field
from typing import Any

from aicheck import metrics
from aicheck.contracts import Basis, Finding, Recommendation, Target, Text
from aicheck.engine.context import CheckContext
from aicheck.engine.findings import basis_from_rule, make_finding
from aicheck.engine.inapplicable import _group_allowed
from aicheck.engine.normalize import compare_form, stem_regex
from aicheck.kb.retrieve import ClauseRef
from aicheck.llm.schema import LlmAnswer, LlmFinding
from aicheck.rules.loader import severity_of
from aicheck.sanitize import clean_text, mask_personal

MAX_MESSAGE = 500
MAX_EVIDENCE = 200


@dataclass
class VerifyInput:
    ctx: CheckContext
    code_findings: list[Finding]
    kb: list[ClauseRef]
    rule_codes: set[str]  # rules that were passed to the model
    row_ids: dict[str, str]  # rows that were passed: rowId -> section ("" for risk rows)
    min_confidence: float
    dropped: dict[str, int] = field(default_factory=dict)


def _drop(vin: VerifyInput, reason: str) -> None:
    metrics.LLM_DROPPED.labels(reason=reason).inc()
    vin.dropped[reason] = vin.dropped.get(reason, 0) + 1


def _text(value: str, limit: int) -> str:
    return mask_personal(clean_text(value).replace("<<<", "").replace(">>>", ""))[0][:limit]


def _target(item: LlmFinding, vin: VerifyInput) -> Target | None:
    row_id, section = item.target.rowId, item.target.section
    if row_id:
        if row_id not in vin.row_ids:
            return None
        section = vin.row_ids[row_id] or None
        return Target(type="measure" if section else "risk", section=section, rowId=row_id)
    if section:
        return Target(type="section", section=section) if section.startswith("5.") else None
    return Target(type="description")


def _forbidden_group(vin: VerifyInput, text: str) -> bool:
    ctx = vin.ctx
    for group in ctx.ruleset.markers:
        if group.handled_by or _group_allowed(ctx, group):
            continue
        if any(stem_regex(s).search(text) for s in group.stems):
            return True
    return False


def _foreign_norm(vin: VerifyInput, text: str) -> bool:
    return any(p.search(text) for p in vin.ctx.ruleset.foreign_norms)


def _catalog_ids(vin: VerifyInput, ids: list[int]) -> tuple[list[int], bool]:
    """Keep ids of the request category only; True when something was removed."""
    catalog, category = vin.ctx.catalog, vin.ctx.category_code
    kept = []
    for i in ids:
        item = catalog.measures.get(i)
        if item and (not item["categories"] or category in item["categories"]):
            kept.append(i)
    return kept, len(kept) != len(ids)


def _basis(vin: VerifyInput, rule: dict[str, Any], refs: list[str]) -> tuple[Basis, bool]:
    """(basis, lost): `lost` when the rule needs a basis but no valid reference is left."""
    index = {c.ref: c for c in vin.kb}
    valid = [index[r] for r in refs if r in index]
    json_basis = basis_from_rule(rule, vin.ctx.ruleset)
    if valid:
        first = valid[0]
        return Basis(
            doc=first.doc_code,
            title=first.title,
            clause=first.clause_no,
            url=first.url,
            status="linked",
            excerpt=first.text[:300],
        ), False
    needs = json_basis.status in ("verified", "to_verify") and bool(vin.kb)
    return json_basis, needs


def _build(item: LlmFinding, vin: VerifyInput, target: Target, rule: dict[str, Any]) -> Finding:
    kind = "question" if item.status == "need_input" or severity_of(rule) == "question" else "issue"
    message = _text(item.message, MAX_MESSAGE) or str(rule.get("check") or rule.get("name") or "")
    row = next((m for m in vin.ctx.rows if m.row_id == target.rowId), None)
    evidence = _text(item.evidence, MAX_EVIDENCE)
    if evidence and (not row or compare_form(evidence) not in compare_form(row.text)):
        evidence = ""
    ids, _ = _catalog_ids(vin, item.catalog_ids)
    basis, lost = _basis(vin, rule, item.basis_refs)
    recommendation = None
    if item.recommendation_text:
        mode = "replace" if target.type == "measure" else "append"
        recommendation = Recommendation(
            mode=mode,
            text=Text(ru=_text(item.recommendation_text, MAX_MESSAGE)),
            catalogItemIds=ids,
            generated=True,
        )
    finding = make_finding(
        vin.ctx,
        rule,
        target,
        kind=kind,
        message=message,
        evidence=evidence,
        recommendation=recommendation,
    )
    if kind != "question" and (lost or item.confidence < vin.min_confidence):
        finding.kind = "suggestion"
    update: dict[str, Any] = {"source": "ai", "generated": True, "confidence": item.confidence}
    if basis.status == "linked":
        update["basis"] = basis
    return finding.model_copy(update=update)


def verify(answer: LlmAnswer, vin: VerifyInput) -> list[Finding]:
    result: list[Finding] = []
    seen = {(f.ruleCode, f.target.model_dump_json(exclude_none=True)) for f in vin.code_findings}
    for item in answer.findings:
        if item.rule_code not in vin.rule_codes or not vin.ctx.ruleset.has_rule(item.rule_code):
            _drop(vin, "unknown_rule")
            continue
        target = _target(item, vin)
        if target is None:
            _drop(vin, "unknown_target")
            continue
        rule = vin.ctx.ruleset.rule(item.rule_code)
        text = f"{item.message} {item.recommendation_text or ''}"
        if item.status in ("pass", "not_applicable"):
            hidden = _build(item, vin, target, rule)
            result.append(hidden.model_copy(update={"hidden": True}))
            continue
        if item.recommendation_text and _forbidden_group(vin, item.recommendation_text):
            _drop(vin, "forbidden_markers")
            continue
        if _foreign_norm(vin, text):
            _drop(vin, "foreign_norms")
            continue
        key = (item.rule_code, target.model_dump_json(exclude_none=True))
        if key in seen:
            _drop(vin, "duplicate_code")
            continue
        seen.add(key)
        result.append(_build(item, vin, target, rule))
    return result
