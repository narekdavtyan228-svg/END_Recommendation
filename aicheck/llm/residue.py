"""What goes to the LLM: only rows the code could not settle (spec section 7)."""

from dataclasses import dataclass, field
from typing import Any

from aicheck.contracts import Finding, Risk
from aicheck.engine.context import CheckContext, Row
from aicheck.engine.registry import RULES
from aicheck.rules.loader import check_type, severity_of

CRITICAL_SYNTAX = {f"S0{n}" for n in range(1, 7)}
# Risk rules that the code settles only with catalog link markup; the LLM covers the rest.
RISK_LLM_RULES = ("RA09", "RA16", "RA17", "RA19", "RA20", "RA23")
NO_MARKUP_EXPLAIN = "link markup"


@dataclass(frozen=True)
class Residue:
    measure_rows: list[Row] = field(default_factory=list)
    reason_rows: list[Row] = field(default_factory=list)
    risk_rows: list[Risk] = field(default_factory=list)
    measure_rules: list[dict[str, Any]] = field(default_factory=list)
    risk_rules: list[dict[str, Any]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.measure_rows or self.reason_rows or self.risk_rows)

    @property
    def needs_measures(self) -> bool:
        return bool(self.measure_rows or self.reason_rows)


def llm_rules(ctx: CheckContext) -> list[dict[str, Any]]:
    """Applicable rules whose executor is the LLM or code+LLM and that the code does not run."""
    rules = ctx.ruleset
    pool = list(rules.inapplicability.values()) + [
        r for code, r in rules.category_rules.items() if code.startswith(ctx.category_code + "-")
    ]
    selected = []
    for rule in pool:
        code = str(rule["id"])
        if code in RULES or check_type(rule) not in ("llm", "code_llm"):
            continue
        selected.append(
            {
                "id": code,
                "check": rule.get("check") or rule.get("description"),
                "basis": rule.get("basis", ""),
                "question": severity_of(rule) == "question",
            }
        )
    return selected


def has_markup(ctx: CheckContext, risk: Risk) -> bool:
    hazard = ctx.catalog.hazards.get(risk.hazardId) if risk.hazardId is not None else None
    if not hazard:
        return False
    return bool(
        hazard["victim_ids"]
        and hazard["harm_ids"]
        and (hazard["typical_existing_control_ids"] or hazard["typical_additional_control_ids"])
    )


def build_residue(ctx: CheckContext, findings: list[Finding]) -> Residue:
    blocked = {
        f.target.rowId
        for f in findings
        if f.ruleCode in CRITICAL_SYNTAX and f.severity == "critical" and f.target.rowId
    }
    rows = [
        r
        for r in ctx.rows
        if r.live and r.origin in ("catalog_edited", "manual") and r.row_id not in blocked
    ]
    reasons = [r for r in ctx.rows if r.dash and r.reason]
    risks = [r for r in ctx.request.risks if not has_markup(ctx, r)]
    rules = llm_rules(ctx)
    risk_rules = [
        {
            "id": c,
            "check": ctx.ruleset.risk_rules[c]["check"],
            "basis": ctx.ruleset.risk_rules[c].get("basis", ""),
        }
        for c in RISK_LLM_RULES
    ]
    return Residue(rows, reasons, risks, rules, risk_rules)
