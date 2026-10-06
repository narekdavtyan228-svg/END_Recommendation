"""Risk rules RA15-RA25: links to the catalog, section 5 and the zones of parameter P10."""

from typing import Any

from rapidfuzz import fuzz

from aicheck.contracts import Finding, Risk
from aicheck.engine.context import CheckContext
from aicheck.engine.findings import make_finding
from aicheck.engine.normalize import compare_form
from aicheck.engine.risk import (
    Params,
    control_text,
    hazard_name,
    r_value,
    risk_finding,
    risk_rows,
    risk_target,
    zone,
)
from aicheck.rules.loader import FACTOR_CODE

LOW_LEVELS = ("СИЗ", "организационная")


def _hazard_scope(ctx: CheckContext, hazard_id: int) -> tuple[set[str], set[str]] | None:
    """(category codes, required factors) of a hazard known to the package, else None."""
    cat = ctx.catalog.hazards.get(hazard_id)
    if not cat:
        return None
    jh = next(
        (h for h in ctx.ruleset.hazards if compare_form(h["hazard"]) == compare_form(cat["name"])),
        None,
    )
    codes = set(cat["categories"])
    if not codes and jh:
        codes = {c for c, n in ctx.ruleset.category_names.items() if n == jh["category"]}
    factors = set(FACTOR_CODE.findall(jh["required_when"])) if jh else set()
    return (codes, factors) if codes else None


def check_ra15(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for _, risk in risk_rows(ctx):
        scope = _hazard_scope(ctx, risk.hazardId) if risk.hazardId is not None else None
        if (
            not scope
            or ctx.category_code in scope[0]
            or any(ctx.factor(f) == "yes" for f in scope[1])
        ):
            continue
        values = {"hazard": hazard_name(ctx, risk.hazardId), "category": ctx.category_name}
        out.append(risk_finding(ctx, "RA15", risk, values, "hazardId"))
    return out


def check_ra16(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        hazard = ctx.catalog.hazards.get(risk.hazardId) if risk.hazardId is not None else None
        if not hazard:
            continue
        pairs = (
            ("victims", risk.victimIds, hazard["victim_ids"]),
            ("harms", risk.harmIds, hazard["harm_ids"]),
        )
        for kind, ids, allowed in pairs:
            bad = [i for i in ids if allowed and i not in allowed]
            if bad:
                name = ctx.catalog.names.get(kind, {}).get(bad[0], str(bad[0]))
                values = {"n": n, "harm": name, "hazard": hazard["name"]}
                out.append(
                    risk_finding(
                        ctx, "RA16", risk, values, "victimIds" if kind == "victims" else "harmIds"
                    )
                )
                break
    return out


def check_ra17(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        hazard = ctx.catalog.hazards.get(risk.hazardId) if risk.hazardId is not None else None
        if not hazard:
            continue
        for cid in risk.existingControlIds + risk.additionalControlIds:
            if _unlinked_control(ctx, hazard, cid):
                values = {"n": n, "m": control_text(ctx, cid), "hazard": hazard["name"]}
                out.append(risk_finding(ctx, "RA17", risk, values))
                break
    return out


def _unlinked_control(ctx: CheckContext, hazard: dict[str, Any], control_id: int) -> bool:
    control = ctx.catalog.controls.get(control_id)
    if hazard["control_ids"]:
        return control_id not in hazard["control_ids"]
    if control and control["hazard_ids"]:
        return hazard["id"] not in control["hazard_ids"]
    return False  # no link markup: left to the LLM


def _sections_of(ctx: CheckContext, risk: Risk) -> list[str]:
    name = compare_form(hazard_name(ctx, risk.hazardId))
    for hazard in ctx.ruleset.hazards:
        if compare_form(hazard["hazard"]) == name:
            return [
                s.strip()
                for s in str(hazard["linked_sections"]).split(",")
                if s.strip().startswith("5.")
            ]
    return []


def check_ra18(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = ctx.ruleset.config("P14")
    if not cfg:
        return []
    out = []
    for _, risk in risk_rows(ctx):
        r1, sections = r_value(risk.b1, risk.p1), _sections_of(ctx, risk)
        if r1 is None or r1 < int(cfg["threshold"]) or not sections:
            continue
        if not any(ctx.live_in(s) for s in sections):
            values = {"hazard": hazard_name(ctx, risk.hazardId), "section": ", ".join(sections)}
            out.append(risk_finding(ctx, "RA18", risk, values))
    return out


def _reflected(ctx: CheckContext, control: dict[str, Any]) -> bool:
    text = compare_form(control["text"])
    items = [compare_form(i) for r in ctx.live_in(control["section"]) for i in r.items]
    return any(fuzz.token_set_ratio(text, i) >= 85 for i in items)


def check_ra20(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for _, risk in risk_rows(ctx):
        for cid in risk.additionalControlIds:
            control = ctx.catalog.controls.get(cid)
            if control and control["section"] and not _reflected(ctx, control):
                values = {"m": control["text"], "section": control["section"]}
                out.append(risk_finding(ctx, "RA20", risk, values, "additionalControlIds"))
    return out


def _min_severity(ctx: CheckContext, risk: Risk) -> int | None:
    cfg = ctx.ruleset.config("P13")
    name = compare_form(hazard_name(ctx, risk.hazardId))
    for hazard in ctx.ruleset.hazards:
        if compare_form(hazard["hazard"]) == name and cfg:
            level = cfg.get(hazard["min_severity_level"])
            return int(level) if level is not None else None
    return None


def check_ra21(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for n, risk in risk_rows(ctx):
        need = _min_severity(ctx, risk)
        if need is not None and risk.b1 is not None and risk.b1 < need:
            values = {
                "n": n,
                "hazard": hazard_name(ctx, risk.hazardId),
                "B": risk.b1,
                "Bmin": need,
            }
            out.append(risk_finding(ctx, "RA21", risk, values, "b1"))
    return out


def check_ra22(ctx: CheckContext, params: Params) -> list[Finding]:
    pairs = {(r.b1, r.p1) for r in ctx.request.risks}
    if len(ctx.request.risks) < 2 or len(pairs) != 1 or None in next(iter(pairs)):
        return []
    b, p = next(iter(pairs))
    return [make_finding(ctx, params, risk_target(), {"B": b, "P": p}, kind="question")]


def check_ra23(ctx: CheckContext, params: Params) -> list[Finding]:
    limit = zone(ctx, "high")
    out = []
    for n, risk in risk_rows(ctx):
        r1 = r_value(risk.b1, risk.p1)
        controls = [ctx.catalog.controls.get(c) for c in risk.additionalControlIds]
        if limit is None or r1 is None or r1 < limit or not controls:
            continue
        if all(c and c["level"] for c in controls) and all(
            c["level"] in LOW_LEVELS for c in controls if c
        ):
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
    limit = zone(ctx, "unacceptable")
    out = []
    for n, risk in risk_rows(ctx):
        r1 = r_value(risk.b1, risk.p1)
        before = (
            ctx.catalog.timing.get(risk.implementWhenId)
            if risk.implementWhenId is not None
            else None
        )
        if (
            limit is None
            or r1 is None
            or r1 < limit
            or not risk.additionalControlIds
            or before is not False
        ):
            continue
        values = {"n": n, "R1": r1, "m": control_text(ctx, risk.additionalControlIds[0])}
        out.append(risk_finding(ctx, "RA25", risk, values, "implementWhenId"))
    return out
