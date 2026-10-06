"""Risk assessment rules RA01-RA14 (completeness, arithmetic, reduction logic, hazard set)."""

from typing import Any

from rapidfuzz import fuzz

from aicheck.contracts import Autofix, Finding, Recommendation, Risk, Target, Text
from aicheck.engine.context import CheckContext
from aicheck.engine.findings import make_finding
from aicheck.engine.normalize import compare_form
from aicheck.engine.params import (
    initial_r,
    r_value,
    residual_r,
    scale,
    zone_of,
)
from aicheck.rules.loader import SEVERITY

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


def risk_rule(ctx: CheckContext, code: str) -> dict[str, Any]:
    return ctx.ruleset.risk_rules[code]


def risk_target(risk: Risk | None = None, field: str | None = None) -> Target:
    if risk is None:  # a finding about the table as a whole; `field` names the hazard
        return Target(type="risk", field=field)
    return Target(type="risk", rowId=risk.rowId, field=field)


def risk_rows(ctx: CheckContext) -> list[tuple[int, Risk]]:
    return list(enumerate(ctx.request.risks, start=1))


def hazard_name(ctx: CheckContext, hazard_id: int | None) -> str:
    hazard = ctx.catalog.hazards.get(hazard_id) if hazard_id is not None else None
    return str(hazard["name"]) if hazard else str(hazard_id)


def control_text(ctx: CheckContext, control_id: int) -> str:
    control = ctx.catalog.controls.get(control_id)
    return str(control["name"]) if control else str(control_id)


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
    out = []
    for n, risk in risk_rows(ctx):
        for field in ("b1", "p1", "b2", "p2"):
            limits = scale(ctx, field[0].upper())
            value = getattr(risk, field)
            if limits and value is not None and not limits[0] <= value <= limits[1]:
                values = {
                    "n": n,
                    "field": field.upper(),
                    "value": value,
                    "min": limits[0],
                    "max": limits[1],
                }
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
        r1, r2 = initial_r(risk), r_value(risk.b2, risk.p2)
        if r1 is not None and r2 is not None and r2 > r1:
            out.append(risk_finding(ctx, "RA05", risk, {"n": n, "R1": r1, "R2": r2}))
    return out


def check_ra06(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        lowered = None not in (risk.b1, risk.p1, risk.b2, risk.p2) and (
            risk.b2 < risk.b1 or risk.p2 < risk.p1  # type: ignore[operator]
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


def _repeats_existing(ctx: CheckContext, control_id: int, existing: list[int]) -> bool:
    if control_id in existing:
        return True
    text = compare_form(control_text(ctx, control_id))
    return any(
        fuzz.ratio(text, compare_form(control_text(ctx, e))) / 100 >= CONTROL_SIMILARITY
        for e in existing
        if e in ctx.catalog.controls and control_id in ctx.catalog.controls
    )


def check_ra08(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        for cid in risk.additionalControlIds:
            if _repeats_existing(ctx, cid, risk.existingControlIds):
                values = {"n": n, "m": control_text(ctx, cid)}
                out.append(risk_finding(ctx, "RA08", risk, values, "additionalControlIds"))
                break
    return out


def check_ra09(ctx: CheckContext, params: Params) -> list[Finding]:
    """Severity lowered, but no additional control affects severity (`affects` has B)."""
    out = []
    for n, risk in risk_rows(ctx):
        controls = [ctx.catalog.controls.get(c) for c in risk.additionalControlIds]
        known = [c for c in controls if c and c.get("affects")]
        lowered = risk.b1 is not None and risk.b2 is not None and risk.b2 < risk.b1
        if not (lowered and controls and len(known) == len(controls)):
            continue
        if not any("B" in c["affects"] for c in known):
            names = "; ".join(c["name"] for c in known)
            values = {"n": n, "B1": risk.b1, "B2": risk.b2, "m": names}
            out.append(risk_finding(ctx, "RA09", risk, values, "b2"))
    return out


def check_ra10(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        r2 = residual_r(ctx, risk)
        if zone_of(ctx, r2) == "unacceptable":
            out.append(risk_finding(ctx, "RA10", risk, {"n": n, "R2": r2}))
    return out


def check_ra11(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        r1 = initial_r(risk)
        if zone_of(ctx, r1) == "needs_controls" and not risk.additionalControlIds:
            out.append(risk_finding(ctx, "RA11", risk, {"n": n, "R1": r1}))
    return out


def _present(ctx: CheckContext, hazard: dict[str, Any]) -> bool:
    return any(r.hazardId == hazard["id"] for r in ctx.request.risks)


def check_ra12(ctx: CheckContext, params: Params) -> list[Finding]:
    """A hazard that the catalog marks as always required is missing from the table."""
    if not ctx.request.risks:
        return []  # an empty table is RA01
    out = []
    for hazard in ctx.catalog.hazards_of(ctx.category_code):
        if hazard["required"] != "always" or _present(ctx, hazard):
            continue
        rule = dict(risk_rule(ctx, "RA12"), severity=_severity_name(hazard))
        values = {"category": ctx.category_name, "hazard": hazard["name"]}
        found = make_finding(ctx, rule, risk_target(None, hazard["name"]), values)
        out.append(found.model_copy(update={"hazardName": hazard["name"]}))
    return out


def _severity_name(hazard: dict[str, Any]) -> str:
    names = {v: k for k, v in SEVERITY.items()}
    return names.get(str(hazard["severity_if_missing"]), "Существенно")


def check_ra13(ctx: CheckContext, params: Params) -> list[Finding]:
    """A hazard required by a factor that is «yes» is missing from the table."""
    if not ctx.request.risks:
        return []
    out = []
    for hazard in ctx.catalog.hazards_of(ctx.category_code):
        yes = [f for f in hazard["factors"] if ctx.factor(f) == "yes"]
        if hazard["required"] != "factor" or not yes or _present(ctx, hazard):
            continue
        question = str(ctx.ruleset.factors.get(yes[0], {}).get("question", yes[0]))
        target = risk_target(None, hazard["name"])
        found = make_finding(ctx, params, target, {"factor": question, "hazard": hazard["name"]})
        out.append(found.model_copy(update={"hazardName": hazard["name"]}))
    return out


def check_ra14(ctx: CheckContext, params: Params) -> list[Finding]:
    seen: dict[tuple[Any, ...], int] = {}
    out = []
    for n, risk in risk_rows(ctx):
        if risk.hazardId is None:
            continue
        key = (risk.hazardId, tuple(sorted(risk.victimIds)), tuple(sorted(risk.harmIds)))
        if key in seen:
            out.append(risk_finding(ctx, "RA14", risk, {"n1": seen[key], "n2": n}))
        else:
            seen[key] = n
    return out
