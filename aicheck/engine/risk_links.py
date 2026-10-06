"""Risk rules RA15-RA25: links to the catalog, section 5 and the risk zones."""

from typing import Any

from rapidfuzz import fuzz

from aicheck.contracts import Finding, Risk
from aicheck.engine.context import CheckContext
from aicheck.engine.findings import make_finding
from aicheck.engine.normalize import compare_form
from aicheck.engine.params import (
    before_start_ids,
    data,
    initial_r,
    zone_of,
)
from aicheck.engine.risk import (
    Params,
    control_text,
    hazard_name,
    risk_finding,
    risk_rows,
    risk_target,
)

LOW_LEVELS = ("administrative", "ppe")


def _hazard(ctx: CheckContext, risk: Risk) -> dict[str, Any] | None:
    return ctx.catalog.hazards.get(risk.hazardId) if risk.hazardId is not None else None


def check_ra15(ctx: CheckContext, params: Params) -> list[Finding]:
    """A hazard of another category without the factor that would make it relevant."""
    out = []
    for _, risk in risk_rows(ctx):
        hazard = _hazard(ctx, risk)
        if not hazard or not hazard["category"] or hazard["category"] == ctx.category_code:
            continue
        if any(ctx.factor(f) == "yes" for f in hazard["factors"]):
            continue
        values = {"hazard": hazard["name"], "category": ctx.category_name}
        out.append(risk_finding(ctx, "RA15", risk, values, "hazardId"))
    return out


def check_ra16(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        hazard = _hazard(ctx, risk)
        if not hazard:
            continue
        pairs = (
            ("victims", risk.victimIds, hazard["victim_ids"], "victimIds"),
            ("harms", risk.harmIds, hazard["harm_ids"], "harmIds"),
        )
        for kind, ids, allowed, field in pairs:
            bad = [i for i in ids if allowed and i not in allowed]
            if bad:
                name = ctx.catalog.names.get(kind, {}).get(bad[0], str(bad[0]))
                values = {"n": n, "harm": name, "hazard": hazard["name"]}
                out.append(risk_finding(ctx, "RA16", risk, values, field))
                break
    return out


def _linked(hazard: dict[str, Any], control_id: int, control: dict[str, Any] | None) -> bool | None:
    """True/False when the catalog knows the link, None when it has no markup."""
    typical = hazard["typical_existing_control_ids"] + hazard["typical_additional_control_ids"]
    if control and hazard["id"] in control["hazard_ids"]:
        return True
    if typical or (control and control["hazard_ids"]):
        return control_id in typical
    return None


def check_ra17(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        hazard = _hazard(ctx, risk)
        if not hazard:
            continue
        for cid in risk.existingControlIds + risk.additionalControlIds:
            if _linked(hazard, cid, ctx.catalog.controls.get(cid)) is False:
                values = {"n": n, "m": control_text(ctx, cid), "hazard": hazard["name"]}
                out.append(risk_finding(ctx, "RA17", risk, values))
                break
    return out


def check_ra18(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = data(ctx, "P14")
    if not cfg:
        return []
    out = []
    for _, risk in risk_rows(ctx):
        hazard, r1 = _hazard(ctx, risk), initial_r(risk)
        if not hazard or r1 is None or r1 < int(cfg["min_R"]) or not hazard["linked_sections"]:
            continue
        sections = hazard["linked_sections"]
        if not any(ctx.live_in(s) for s in sections):
            values = {"hazard": hazard["name"], "section": ", ".join(sections)}
            out.append(risk_finding(ctx, "RA18", risk, values))
    return out


def _reflected(ctx: CheckContext, control: dict[str, Any]) -> bool:
    text = compare_form(control["name"])
    items = [compare_form(i) for r in ctx.live_in(control["linked_section"]) for i in r.items]
    return any(fuzz.token_set_ratio(text, i) >= 85 for i in items)


def check_ra20(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for _, risk in risk_rows(ctx):
        for cid in risk.additionalControlIds:
            control = ctx.catalog.controls.get(cid)
            if control and control["linked_section"] and not _reflected(ctx, control):
                values = {"m": control["name"], "section": control["linked_section"]}
                out.append(risk_finding(ctx, "RA20", risk, values, "additionalControlIds"))
    return out


def check_ra21(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = data(ctx, "P13")
    out = []
    for n, risk in risk_rows(ctx):
        hazard = _hazard(ctx, risk)
        level = hazard["min_severity_level"] if hazard else None
        need = cfg.get(level) if cfg and level else None
        if need is not None and risk.b1 is not None and risk.b1 < int(need):
            values = {"n": n, "hazard": hazard_name(ctx, risk.hazardId), "B": risk.b1, "Bmin": need}
            out.append(risk_finding(ctx, "RA21", risk, values, "b1"))
    return out


def check_ra22(ctx: CheckContext, params: Params) -> list[Finding]:
    pairs = {(r.b1, r.p1) for r in ctx.request.risks}
    if len(ctx.request.risks) < 2 or len(pairs) != 1 or None in next(iter(pairs)):
        return []
    b, p = next(iter(pairs))
    return [make_finding(ctx, params, risk_target(), {"B": b, "P": p}, kind="question")]


def check_ra23(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = data(ctx, "P10")
    if not cfg:
        return []
    out = []
    for n, risk in risk_rows(ctx):
        controls = [ctx.catalog.controls.get(c) for c in risk.additionalControlIds]
        high = zone_of(ctx, initial_r(risk)) == cfg.get("high_zone_for_RA23")
        if not high or not controls or not all(c and c["hierarchy_level"] for c in controls):
            continue
        if all(c["hierarchy_level"] in LOW_LEVELS for c in controls if c):
            out.append(risk_finding(ctx, "RA23", risk, {"n": n}))
    return out


def check_ra24(ctx: CheckContext, params: Params) -> list[Finding]:
    return [
        risk_finding(ctx, "RA24", risk, {"n": n})
        for n, risk in risk_rows(ctx)
        if risk.additionalControlIds
        and (risk.controlResponsibleRoleId is None or risk.implementWhenId is None)
    ]


def check_ra25(ctx: CheckContext, params: Params) -> list[Finding]:
    """Without the control the risk is unacceptable, yet it is implemented after the start."""
    before = before_start_ids(ctx)
    out = []
    for n, risk in risk_rows(ctx):
        r1 = initial_r(risk)
        late = risk.implementWhenId is not None and risk.implementWhenId not in before
        if not (
            before and late and risk.additionalControlIds and zone_of(ctx, r1) == "unacceptable"
        ):
            continue
        values = {"n": n, "R1": r1, "m": control_text(ctx, risk.additionalControlIds[0])}
        out.append(risk_finding(ctx, "RA25", risk, values, "implementWhenId"))
    return out
