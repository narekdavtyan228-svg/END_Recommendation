"""Canonical contentHash of section 2 (spec section 16)."""

import hashlib
import json
import unicodedata
from typing import Any

from aicheck.contracts import CheckRequest

FLAG_KEYS = ("adjacentApproval", "contractorStaff", "fireService", "gasAirControl")
RISK_ID_LISTS = ("victimIds", "harmIds", "existingControlIds", "additionalControlIds")
RISK_SCALARS = (
    "rowId",
    "hazardId",
    "b1",
    "p1",
    "b2",
    "p2",
    "controlResponsibleRoleId",
    "implementWhenId",
)


def canon_text(value: str | None) -> str | None:
    if value is None:
        return None
    return unicodedata.normalize("NFC", value).replace("\r\n", "\n").strip()


def canonical_object(request: CheckRequest) -> dict[str, Any]:
    ctx = request.context
    flags = {k: getattr(ctx.flags, k) for k in FLAG_KEYS}
    measures = sorted(request.measures, key=lambda m: (m.section, m.rowId))
    risks = sorted(request.risks, key=lambda r: r.rowId)
    return {
        "orgCode": canon_text(request.tenant.orgCode),
        "workType": canon_text(ctx.workType),
        "categoryCode": canon_text(ctx.categoryCode),
        "description": canon_text(ctx.description),
        "flags": flags,
        "measures": [
            {
                "rowId": canon_text(m.rowId),
                "section": m.section,
                "text": canon_text(m.text),
                "notApplicable": m.notApplicable,
            }
            for m in measures
        ],
        "risks": [_risk(r) for r in risks],
        "factorAnswers": dict(sorted(request.factorAnswers.items())),
    }


def _risk(risk: Any) -> dict[str, Any]:
    data: dict[str, Any] = {k: getattr(risk, k) for k in RISK_SCALARS}
    data["rowId"] = canon_text(risk.rowId)
    for key in RISK_ID_LISTS:
        data[key] = sorted(getattr(risk, key))
    return data


def canonical_bytes(request: CheckRequest) -> bytes:
    text = json.dumps(
        canonical_object(request), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return text.encode("utf-8")


def content_hash(request: CheckRequest) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(request)).hexdigest()
