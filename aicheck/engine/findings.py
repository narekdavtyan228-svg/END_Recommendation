"""make_finding: the one place where findings are created from rules."""

from collections.abc import Mapping
from typing import Any

from aicheck.contracts import Autofix, Basis, Finding, Recommendation, Target, Text
from aicheck.engine.context import CheckContext
from aicheck.rules.loader import SEVERITY, Ruleset

TO_VERIFY_MARKS = ("сверить", "наполнить", "решение омг")


class SafeDict(dict[str, Any]):
    """Unknown template keys stay as they are."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def render(template: str, values: Mapping[str, Any]) -> str:
    return template.format_map(SafeDict({k: str(v) for k, v in values.items()}))


def rule_id(rule: Mapping[str, Any]) -> str:
    return str(rule.get("id") or rule.get("code"))


def basis_from_rule(rule: Mapping[str, Any], ruleset: Ruleset) -> Basis:
    text = str(rule.get("basis", "")).strip()
    if text in ("", "—", "-"):
        return Basis()
    found = [(text.find(code), code) for code in ruleset.sources if code in text]
    status = "to_verify" if any(m in text.lower() for m in TO_VERIFY_MARKS) else "verified"
    if not found:
        return Basis(clause=text, status="to_verify" if status == "to_verify" else "none")
    pos, code = min(found)
    url = str(ruleset.sources[code].get("url", ""))
    clause = text[pos + len(code) :].strip(" :,—")
    return Basis(doc=code, clause=clause, url="" if url == "—" else url, status=status)


def _level(rule: Mapping[str, Any], severity: str | None, basis: Basis, kind: str) -> str:
    level = severity or SEVERITY.get(str(rule.get("severity", "")).strip(), "recommendation")
    if level == "critical" and basis.status == "to_verify":
        return "significant"  # a basis that is not confirmed cannot make a finding critical
    return "question" if kind == "question" else level


def make_finding(
    ctx: CheckContext,
    rule: Mapping[str, Any],
    target: Target,
    values: Mapping[str, Any] | None = None,
    *,
    kind: str = "issue",
    severity: str | None = None,
    evidence: str = "",
    recommendation: Recommendation | None = None,
    autofix: Autofix | None = None,
    blocking: bool = False,
    message: str | None = None,
) -> Finding:
    """Severity, texts and basis come from the rule; `values` fill {placeholders}."""
    code = rule_id(rule)
    vals: dict[str, Any] = {"section": target.section or "", **(values or {})}
    template = message or str(rule.get("message") or rule.get("check") or rule.get("name") or "")
    if target.section:
        template = template.replace("5.x", target.section)
    basis = ctx.kb_basis.get(code) or basis_from_rule(rule, ctx.ruleset)
    level = _level(rule, severity, basis, kind)
    return Finding(
        ruleCode=code,
        severity=level,
        kind=kind,
        source="rules",
        target=target,
        title=Text(ru=str(rule.get("name") or rule.get("check") or code)),
        message=Text(ru=render(template, vals)),
        evidence=evidence,
        recommendation=recommendation,
        basis=basis,
        autofix=autofix,
        blocking=blocking,
    )


def row_target(row: Any) -> Target:
    return Target(type="measure", section=row.section, rowId=row.row_id)
