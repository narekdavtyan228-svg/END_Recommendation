"""Risk assessment rules RA01-RA25 (code part). R is always computed as B x P."""

from typing import Any

from rapidfuzz import fuzz

from aicheck.contracts import Autofix, Finding, Recommendation, Risk, Target, Text
from aicheck.engine.context import CheckContext
from aicheck.engine.findings import make_finding
from aicheck.engine.normalize import compare_form
from aicheck.rules.loader import FACTOR_CODE

Params = dict[str, Any]
FIELDS = (
    ("hazardId", "опасность"),
    ("victimIds", "кто может пострадать"),
    ("harmIds", "как пострадают"),
    ("existingControlIds", "существующие меры"),
    ("b1", "В"),
    ("p1", "П"),
)
CONTROL_SIMILARITY = 0.9


def r_value(b: int | None, p: int | None) -> int | None:
    return b * p if b is not None and p is not None else None


def risk_rule(ctx: CheckContext, code: str) -> dict[str, Any]:
    return ctx.ruleset.risk_rules[code]


def risk_target(risk: Risk | None = None, field: str | None = None) -> Target:
    if risk is None:
        return Target(type="risks")
    return Target(type="risk", rowId=risk.rowId, field=field)


def risk_rows(ctx: CheckContext) -> list[tuple[int, Risk]]:
    return list(enumerate(ctx.request.risks, start=1))


def zone(ctx: CheckContext, key: str) -> int | None:
    cfg = ctx.ruleset.config("P10")
    value = (cfg or {}).get("zones", {}).get(key)
    return int(value) if value is not None else None


def hazard_name(ctx: CheckContext, hazard_id: int | None) -> str:
    hazard = ctx.catalog.hazards.get(hazard_id) if hazard_id is not None else None
    return hazard["name"] if hazard else str(hazard_id)


def control_text(ctx: CheckContext, control_id: int) -> str:
    control = ctx.catalog.controls.get(control_id)
    return control["text"] if control else str(control_id)


def risk_finding(
    ctx: CheckContext,
    code: str,
    risk: Risk | None,
    values: dict[str, Any],
    field: str | None = None,
    **kw: Any,
) -> Finding:
    return make_finding(ctx, risk_rule(ctx, code), risk_target(risk, field), values, **kw)


def check_ra01(ctx: CheckContext, params: Params) -> list[Finding]:
    if ctx.request.risks:
        return []
    return [make_finding(ctx, params, risk_target(), {"category": ctx.category_name})]


def check_ra02(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        for field, label in FIELDS:
            value = getattr(risk, field)
            if value is None or value == []:
                out.append(risk_finding(ctx, "RA02", risk, {"n": n, "field": label}, field))
    return out


def check_ra03(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = ctx.ruleset.config("P10")
    if not cfg:
        return []
    lo, hi = int(cfg["scale_min"]), int(cfg["scale_max"])
    out = []
    for n, risk in risk_rows(ctx):
        for field in ("b1", "p1", "b2", "p2"):
            value = getattr(risk, field)
            if value is not None and not lo <= value <= hi:
                values = {"n": n, "field": field.upper(), "value": value, "min": lo, "max": hi}
                out.append(risk_finding(ctx, "RA03", risk, values, field))
    return out


def check_ra04(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        for b, p, given, field in (
            (risk.b1, risk.p1, risk.r1, "r1"),
            (risk.b2, risk.p2, risk.r2, "r2"),
        ):
            real = r_value(b, p)
            if real is not None and given is not None and given != real:
                values = {"n": n, "B": b, "P": p, "R": real}
                rec = Recommendation(mode="set_field", field=field, value=str(real), text=Text())
                fix = Autofix(rowId=risk.rowId, before=str(given), after=str(real))
                out.append(
                    risk_finding(
                        ctx,
                        "RA04",
                        risk,
                        values,
                        field,
                        kind="autofix",
                        recommendation=rec,
                        autofix=fix,
                    )
                )
    return out


def check_ra05(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        r1, r2 = r_value(risk.b1, risk.p1), r_value(risk.b2, risk.p2)
        if r1 is not None and r2 is not None and r2 > r1:
            out.append(risk_finding(ctx, "RA05", risk, {"n": n, "R1": r1, "R2": r2}))
    return out


def check_ra06(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        lowered = (
            None not in (risk.b1, risk.p1, risk.b2, risk.p2)
            and (risk.b2 < risk.b1 or risk.p2 < risk.p1)  # type: ignore[operator]
        )
        if lowered and not risk.additionalControlIds:
            out.append(risk_finding(ctx, "RA06", risk, {"n": n}))
    return out


def check_ra07(ctx: CheckContext, params: Params) -> list[Finding]:
    return [
        risk_finding(ctx, "RA07", risk, {"n": n})
        for n, risk in risk_rows(ctx)
        if risk.additionalControlIds and (risk.b2 is None or risk.p2 is None)
    ]


def check_ra08(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        for cid in risk.additionalControlIds:
            if _repeats_existing(ctx, cid, risk.existingControlIds):
                out.append(
                    risk_finding(
                        ctx,
                        "RA08",
                        risk,
                        {"n": n, "m": control_text(ctx, cid)},
                        "additionalControlIds",
                    )
                )
                break
    return out


def _repeats_existing(ctx: CheckContext, control_id: int, existing: list[int]) -> bool:
    if control_id in existing:
        return True
    text = compare_form(control_text(ctx, control_id))
    return any(
        fuzz.ratio(text, compare_form(control_text(ctx, e))) / 100 >= CONTROL_SIMILARITY
        for e in existing
        if e in ctx.catalog.controls and control_id in ctx.catalog.controls
    )


def check_ra09(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        controls = [ctx.catalog.controls.get(c) for c in risk.additionalControlIds]
        known = [c for c in controls if c and c.get("affects")]
        lowered = risk.b1 is not None and risk.b2 is not None and risk.b2 < risk.b1
        if not (lowered and controls and len(known) == len(controls)):
            continue
        if not any("В" in c["affects"] for c in known):
            names = "; ".join(c["text"] for c in known)
            out.append(
                risk_finding(ctx, "RA09", risk, {"n": n, "B1": risk.b1, "B2": risk.b2, "m": names})
            )
    return out


def check_ra10(ctx: CheckContext, params: Params) -> list[Finding]:
    limit = zone(ctx, "unacceptable")
    out = []
    for n, risk in risk_rows(ctx):
        r2 = r_value(risk.b2, risk.p2)
        if limit is not None and r2 is not None and r2 >= limit:
            out.append(risk_finding(ctx, "RA10", risk, {"n": n, "R2": r2}))
    return out


def check_ra11(ctx: CheckContext, params: Params) -> list[Finding]:
    limit = zone(ctx, "requires_measures")
    out = []
    for n, risk in risk_rows(ctx):
        r1 = r_value(risk.b1, risk.p1)
        if limit is not None and r1 is not None and r1 >= limit and not risk.additionalControlIds:
            out.append(risk_finding(ctx, "RA11", risk, {"n": n, "R1": r1}))
    return out


def _json_hazards(ctx: CheckContext) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    """Hazards of the rule package for the category with their catalog record (by name)."""
    result = []
    for hazard in ctx.ruleset.hazards:
        if hazard["category"] == ctx.category_name:
            result.append((hazard, ctx.catalog.hazard_by_name.get(compare_form(hazard["hazard"]))))
    return result


def _present(ctx: CheckContext, cat_hazard: dict[str, Any] | None) -> bool:
    return bool(cat_hazard) and any(r.hazardId == cat_hazard["id"] for r in ctx.request.risks)  # type: ignore[index]


def check_ra12(ctx: CheckContext, params: Params) -> list[Finding]:
    if not ctx.request.risks:
        return []
    out = []
    for hazard, cat in _json_hazards(ctx):
        if hazard["required_when"] == "Всегда" and cat and not _present(ctx, cat):
            rule = dict(risk_rule(ctx, "RA12"), severity=hazard["severity_if_missing"])
            target = Target(type="risks", field=hazard["hazard"])
            vals = {"category": ctx.category_name, "hazard": hazard["hazard"]}
            out.append(make_finding(ctx, rule, target, vals))
    return out


def check_ra13(ctx: CheckContext, params: Params) -> list[Finding]:
    if not ctx.request.risks:
        return []
    out = []
    for hazard, cat in _json_hazards(ctx):
        codes = FACTOR_CODE.findall(hazard["required_when"])
        yes = [c for c in codes if ctx.factor(c) == "yes"]
        if yes and cat and not _present(ctx, cat):
            question = str(ctx.ruleset.factors.get(yes[0], {}).get("question", yes[0]))
            target = Target(type="risks", field=hazard["hazard"])
            out.append(
                make_finding(ctx, params, target, {"factor": question, "hazard": hazard["hazard"]})
            )
    return out


def check_ra14(ctx: CheckContext, params: Params) -> list[Finding]:
    seen: dict[tuple[Any, ...], int] = {}
    out = []
    for n, risk in risk_rows(ctx):
        key = (risk.hazardId, tuple(sorted(risk.victimIds)), tuple(sorted(risk.harmIds)))
        if risk.hazardId is None:
            continue
        if key in seen:
            out.append(risk_finding(ctx, "RA14", risk, {"n1": seen[key], "n2": n}))
        else:
            seen[key] = n
    return out
