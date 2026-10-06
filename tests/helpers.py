"""Small helpers for engine tests."""

from typing import Any

from aicheck.contracts import Finding
from aicheck.engine.run import check
from tests import factory


def run(
    measures: list[dict[str, Any]] | None = None,
    risks: list[dict[str, Any]] | None = None,
    category: str = "GP",
    params: bool = False,
    answers: dict[str, str] | None = None,
    catalog: Any = None,
    **context: Any,
) -> list[Finding]:
    req = factory.request(category, measures, risks, **context)
    if answers:
        req = factory.with_answers(req, answers)
    _, findings = check(req, factory.ruleset(params), catalog or factory.catalog())
    return findings


def by_rule(findings: list[Finding], code: str) -> list[Finding]:
    return [f for f in findings if f.ruleCode == code]


def has(findings: list[Finding], code: str, row: str | None = None) -> bool:
    return any(f.ruleCode == code and (row is None or f.target.rowId == row) for f in findings)


def m(section: str, text: str, **extra: Any) -> dict[str, Any]:
    return {"section": section, "text": text, **extra}
