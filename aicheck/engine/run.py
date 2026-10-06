"""Code stage: normalise -> rules in the fixed order -> dedupe -> sort."""

from collections.abc import Mapping

from aicheck.catalog.model import Catalog
from aicheck.contracts import Basis, CheckRequest, Finding, Question, Text
from aicheck.engine.context import CheckContext, build_context
from aicheck.engine.matrix import check_matrix
from aicheck.engine.registry import RULES
from aicheck.rules.loader import Ruleset

SEVERITY_RANK = {"critical": 0, "significant": 2, "recommendation": 3, "question": 1}
# Symptoms already explained by a stronger rule on the same row.
SUPPRESSED_BY = {"S04": {"S02", "S03", "S05", "S06"}}
# Rule -> (covering rule, same target needed). The covered rule is a duplicate of the other.
COVERED_BY: dict[str, tuple[tuple[str, ...], bool]] = {
    "ZP-01": (("N12",), True),
    "GO-01": (("N12",), True),
    "OG-05": (("N12",), True),
}


def _bucket(f: Finding) -> int:
    if f.kind == "question":
        return 1
    if f.kind == "suggestion":
        return 4
    if f.kind == "autofix":
        return 5
    return SEVERITY_RANK[f.severity]


def _target_key(f: Finding) -> str:
    return f.target.model_dump_json(exclude_none=True)


def _applies(ctx: CheckContext, code: str) -> bool:
    if "-" in code:  # category rules are limited to their own category
        return code.split("-", 1)[0] == ctx.category_code
    return True


def _ordered_codes(ctx: CheckContext) -> list[str]:
    """Spec order: syntax, inapplicability, (matrix), category rules, risk rules."""

    def rank(code: str) -> int:
        if code.startswith("S"):
            return 0
        return 1 if code.startswith("N") else 3 if "-" in code else 4

    return sorted((c for c in RULES if _applies(ctx, c)), key=lambda c: (rank(c), c))


def run_rules(ctx: CheckContext) -> list[Finding]:
    found: list[Finding] = []
    for code in _ordered_codes(ctx):
        params = ctx.ruleset.rule(code) if ctx.ruleset.has_rule(code) else {}
        found.extend(RULES[code](ctx, params))
    found.extend(check_matrix(ctx))
    return found


def suppress(findings: list[Finding]) -> list[Finding]:
    """Drop findings that duplicate or merely echo another finding."""
    by_code: dict[str, set[str]] = {}
    for f in findings:
        by_code.setdefault(f.ruleCode, set()).add(_target_key(f))
    kept = []
    for f in findings:
        key = _target_key(f)
        if any(key in by_code.get(c, ()) for c in SUPPRESSED_BY.get(f.ruleCode, ())):
            continue
        covered = COVERED_BY.get(f.ruleCode)
        if covered:
            codes, same = covered
            if any(key in by_code.get(c, ()) if same else c in by_code for c in codes):
                continue
        kept.append(f)
    return kept


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (rule, target); on a clash the higher severity stays."""
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.ruleCode, _target_key(f))
        old = best.get(key)
        if old is None or SEVERITY_RANK[f.severity] < SEVERITY_RANK[old.severity]:
            best[key] = f
    return list(best.values())


def _section_key(section: str | None) -> int:
    return int(section.split(".")[1]) if section else 99


def order_findings(
    findings: list[Finding], rows: Mapping[str, int], risks: Mapping[str, int]
) -> list[Finding]:
    """Code findings first, then AI findings; inside: kind/severity, section, row, rule."""

    def key(f: Finding) -> tuple[int, int, int, int, str, str]:
        row_id = f.target.rowId or ""
        position = rows.get(row_id, risks.get(row_id, 0))
        return (
            0 if f.source == "rules" else 1,
            _bucket(f),
            _section_key(f.target.section),
            position,
            f.ruleCode,
            f.target.model_dump_json(exclude_none=True),
        )

    return sorted(findings, key=key)


def sort_findings(ctx: CheckContext, findings: list[Finding]) -> list[Finding]:
    rows = {r.row_id: r.index for r in ctx.rows}
    risks = {r.rowId: i for i, r in enumerate(ctx.request.risks)}
    return order_findings(findings, rows, risks)


def run_code_stage(ctx: CheckContext) -> list[Finding]:
    return sort_findings(ctx, dedupe(suppress(run_rules(ctx))))


def check(
    request: CheckRequest,
    ruleset: Ruleset,
    catalog: Catalog,
    kb_basis: dict[str, Basis] | None = None,
) -> tuple[CheckContext, list[Finding]]:
    ctx = build_context(request, ruleset, catalog, kb_basis)
    return ctx, run_code_stage(ctx)


def questions_of(findings: list[Finding]) -> list[Question]:
    result = []
    for f in findings:
        if f.kind == "question" and f.target.type == "factor" and f.target.factorCode:
            result.append(Question(factorCode=f.target.factorCode, text=Text(ru=f.title.ru)))
    return result


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {"critical": 0, "significant": 0, "recommendation": 0, "questions": 0, "autofix": 0}
    for f in findings:
        if f.kind == "question":
            summary["questions"] += 1
        elif f.kind == "autofix":
            summary["autofix"] += 1
        elif f.kind != "suggestion" and f.severity in summary:
            summary[f.severity] += 1
    return summary
