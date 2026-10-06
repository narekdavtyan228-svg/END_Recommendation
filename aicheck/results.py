"""Conversion between findings, DB rows and API results."""

import uuid
from typing import Any

from sqlalchemy import Connection

from aicheck.contracts import CheckResult, Finding
from aicheck.db import queries
from aicheck.engine.run import order_findings, questions_of, summarize

BODY_KEYS = (
    "title",
    "message",
    "evidence",
    "recommendation",
    "basis",
    "autofix",
    "blocking",
    "hidden",
)


def new_id() -> str:
    return str(uuid.uuid4())


def finding_to_row(finding: Finding) -> dict[str, Any]:
    dumped = finding.model_dump(mode="json")
    return {
        "id": finding.findingId,
        "rule_code": finding.ruleCode,
        "source": finding.source,
        "severity": finding.severity,
        "kind": finding.kind,
        "target": dumped["target"],
        "body": {k: dumped[k] for k in BODY_KEYS},
        "generated": finding.generated,
        "confidence": round(finding.confidence, 2),
    }


def row_to_finding(row: dict[str, Any]) -> Finding:
    return Finding.model_validate(
        {
            **row["body"],
            "findingId": str(row["id"]),
            "ruleCode": row["rule_code"],
            "source": row["source"],
            "severity": row["severity"],
            "kind": row["kind"],
            "target": row["target"],
            "generated": row["generated"],
            "confidence": float(row["confidence"] if row["confidence"] is not None else 1),
        }
    )


def build_result(conn: Connection, run: dict[str, Any], ruleset_version: str) -> CheckResult:
    findings = [row_to_finding(r) for r in queries.list_findings(conn, str(run["id"]))]
    event = queries.last_event(conn, str(run["id"])) or {}
    request = run["request"]
    rows = {m["rowId"]: i for i, m in enumerate(request.get("measures", []))}
    risks = {r["rowId"]: i for i, r in enumerate(request.get("risks", []))}
    visible = order_findings([f for f in findings if not f.hidden], rows, risks)
    return CheckResult(
        runId=str(run["id"]),
        status=event.get("status", "code_done"),
        llm=event.get("llm_status", "skipped"),
        rulesetVersion=ruleset_version,
        catalogVersion=run["catalog_version"],
        contentHash=run["content_hash"],
        model=event.get("model"),
        promptVersion=event.get("prompt_version"),
        summary=summarize(visible),
        findings=visible,
        questions=questions_of(visible),
        autofixes=[
            {
                "rowId": f.autofix.rowId,
                "ruleCode": f.ruleCode,
                "before": f.autofix.before,
                "after": f.autofix.after,
            }
            for f in visible
            if f.autofix
        ],
    )
