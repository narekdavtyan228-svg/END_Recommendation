"""Category matrix: which sections of 5.1-5.10 are mandatory for a category."""

from typing import Any

from aicheck.contracts import Finding, Target
from aicheck.engine.context import CheckContext
from aicheck.engine.factors import factor_state
from aicheck.engine.findings import make_finding
from aicheck.rules.loader import FACTOR_CODE

SECTIONS = tuple(f"5.{n}" for n in range(1, 11))


def entries(ctx: CheckContext) -> list[dict[str, Any]]:
    """Matrix records of the request category in section order."""
    items = [ctx.ruleset.matrix.get((ctx.category_code, s)) for s in SECTIONS]
    return [m for m in items if m]


def entry_factors(entry: dict[str, Any]) -> list[str]:
    return FACTOR_CODE.findall(str(entry.get("factors", "")))


def required_state(ctx: CheckContext, entry: dict[str, Any]) -> str:
    """yes: the section must be filled; no: not required; unknown: depends on an open factor."""
    if entry["status"] == "Ядро":
        return "yes"
    codes = entry_factors(entry)
    return factor_state(codes, ctx.factors) if codes else "no"


def check_matrix(ctx: CheckContext) -> list[Finding]:
    """MX: a required section has no rows at all (an empty row is reported by S01)."""
    out = []
    s01 = ctx.ruleset.syntax["S01"]
    for entry in entries(ctx):
        if required_state(ctx, entry) != "yes" or ctx.rows_in(entry["section"]):
            continue
        rule = {
            "id": "MX",
            "name": f"Пункт {entry['section']} обязателен для категории",
            "severity": entry["severity_if_missing"],
            "message": s01["message"],
            "basis": entry["basis"],
        }
        target = Target(type="section", section=entry["section"])
        out.append(make_finding(ctx, rule, target, evidence=entry["min_content"]))
    return out
