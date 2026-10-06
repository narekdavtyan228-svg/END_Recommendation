"""Inapplicability rules (code part): N01-N06, N10-N12, N14."""

import re
from datetime import date
from typing import Any

from aicheck.contracts import Finding, Recommendation, Target, Text
from aicheck.engine.context import CheckContext, Row
from aicheck.engine.factors import factor_state
from aicheck.engine.findings import make_finding, row_target
from aicheck.engine.matrix import entries, entry_factors, required_state
from aicheck.engine.normalize import find_stem, short, stem_regex
from aicheck.rules.loader import FACTOR_CODE, MarkerGroup

Params = dict[str, Any]
# Flag required by category (rule N12 text): gas control for GO/ZP, neighbour approval for ZR.
FLAG_RULES = {
    "GO": ("gasAirControl", "Контроль газо-воздушной среды"),
    "ZP": ("gasAirControl", "Контроль газо-воздушной среды"),
    "ZR": ("adjacentApproval", "Согласование со смежными цехами/участками"),
}
YES_NO = {True: "Да", False: "Нет", None: "Нет"}


def _n(ctx: CheckContext, code: str) -> dict[str, Any]:
    return ctx.ruleset.inapplicability[code]


def group_hit(ctx: CheckContext, row: Row, group: MarkerGroup) -> str | None:
    """Matched word of a marker group; words that occur in the section hint are exceptions."""
    hint = ctx.hint(row.section)
    stems = tuple(s for s in group.stems if not (hint and stem_regex(s).search(hint)))
    return find_stem(row.text, stems)


def _group_allowed(ctx: CheckContext, group: MarkerGroup) -> bool:
    return ctx.category_code in group.categories or any(
        ctx.factor(f) == "yes" for f in group.factors
    )


def _absent_in_profile(ctx: CheckContext, group: MarkerGroup) -> bool:
    if len(group.factors) != 1:
        return False
    value = ctx.factors.get(next(iter(group.factors)))
    return bool(value and value.value == "no" and value.source == "profile")


def check_n01(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in (r for r in ctx.rows if r.live):
        for group in ctx.ruleset.markers:
            if group.handled_by or _group_allowed(ctx, group) or _absent_in_profile(ctx, group):
                continue
            hit = group_hit(ctx, row, group)
            if hit:
                values = {
                    "short": short(row.text),
                    "group": group.name,
                    "category": ctx.category_name,
                }
                out.append(make_finding(ctx, _n(ctx, "N01"), row_target(row), values, evidence=hit))
                break
    return out


def _factor_question(ctx: CheckContext, code: str) -> str:
    return str(ctx.ruleset.factors.get(code, {}).get("question", code))


def check_n02(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for entry in entries(ctx):
        codes = entry_factors(entry)
        if entry["status"] != "Условное" or not codes or factor_state(codes, ctx.factors) != "no":
            continue
        for row in ctx.rows_in(entry["section"]):
            if row.live and row.origin in ("catalog", "catalog_edited"):
                rec = Recommendation(mode="not_applicable")
                values = {"factor": _factor_question(ctx, codes[0])}
                out.append(
                    make_finding(ctx, _n(ctx, "N02"), row_target(row), values, recommendation=rec)
                )
    return out


def _season_markers(detect: str) -> tuple[list[re.Pattern[str]], list[re.Pattern[str]]]:
    """Cold and heat markers are quoted in the rule text: `cold / heat`."""
    body = detect.split("маркеры:", 1)[-1]
    cold_text, _, heat_text = body.partition(" / ")
    return _marker_patterns(cold_text), _marker_patterns(heat_text)


def _marker_patterns(text: str) -> list[re.Pattern[str]]:
    patterns = []
    for token in (t.strip() for t in text.split(",")):
        if re.fullmatch(r"[−+\-]\d+", token):
            patterns.append(re.compile(r"(?<!\d)" + re.escape(token.replace("−", "-")) + r"(?!\d)"))
        elif token.startswith("ниже"):
            patterns.append(re.compile(r"ниже\s*[−-]\s*\d+", re.IGNORECASE))
        elif token:
            patterns.append(stem_regex(token))
    return patterns


def _in_warm(start: date, end: date, cfg: dict[str, Any]) -> bool | None:
    """True: whole interval is in the warm period; False: wholly outside; None: mixed."""
    warm_from, warm_to = cfg["warm_from"], cfg["warm_to"]

    def inside(d: date) -> bool:
        return bool(warm_from <= f"{d.month:02d}-{d.day:02d}" <= warm_to)

    flags = {inside(start), inside(end)}
    return flags.pop() if len(flags) == 1 else None


def check_n03(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = ctx.ruleset.config("P09")
    start, end = ctx.request.context.startAt, ctx.request.context.endAt
    if not cfg or not start or not end:
        return []  # the warm period is an OMG parameter that has not been set
    warm = _in_warm(start.date(), end.date(), cfg)
    if warm is None:
        return []
    cold, heat = _season_markers(str(params.get("detect", "")))
    patterns, season = (cold, "низких температур") if warm else (heat, "жары")
    dates = f"{start:%d.%m.%Y}–{end:%d.%m.%Y}"
    out = []
    for row in (r for r in ctx.rows if r.live):
        match = next((m.group(0) for p in patterns if (m := p.search(row.text))), None)
        if match:
            out.append(
                make_finding(
                    ctx, params, row_target(row), {"season": season, "dates": dates}, evidence=match
                )
            )
    return out


def check_n04(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in (r for r in ctx.rows if r.live):
        for group in ctx.ruleset.markers:
            if group.handled_by or not _absent_in_profile(ctx, group):
                continue
            hit = group_hit(ctx, row, group)
            if hit:
                out.append(
                    make_finding(ctx, params, row_target(row), {"object": group.name}, evidence=hit)
                )
                break
    return out


def check_n05(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in (r for r in ctx.rows if r.live and r.item):
        wanted = row.item["section"] if row.item else row.section
        if wanted != row.section:
            values = {"short": short(row.text), "target": wanted}
            out.append(make_finding(ctx, params, row_target(row), values))
    return out


def check_n06(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for entry in entries(ctx):
        if required_state(ctx, entry) != "yes":
            continue
        for row in ctx.rows_in(entry["section"]):
            if row.dash:
                out.append(
                    make_finding(ctx, params, row_target(row), {"category": ctx.category_name})
                )
    return out


def check_n10(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    groups = [g for g in ctx.ruleset.markers if g.handled_by == "N10"]
    for row in (r for r in ctx.rows if r.live):
        hit = next((h for g in groups if (h := group_hit(ctx, row, g))), None)
        if hit:
            out.append(make_finding(ctx, params, row_target(row), evidence=hit))
    return out


def check_n11(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in (r for r in ctx.rows if r.live):
        text = row.text[:2000]
        match = next((m for p in ctx.ruleset.foreign_norms if (m := p.search(text))), None)
        if match:
            out.append(
                make_finding(
                    ctx, params, row_target(row), {"ref": match.group(0)}, evidence=match.group(0)
                )
            )
    return out


def check_n12(ctx: CheckContext, params: Params) -> list[Finding]:
    flags = ctx.request.context.flags
    rule = FLAG_RULES.get(ctx.category_code)
    out = []
    if rule and getattr(flags, rule[0]) is not True:
        target = Target(type="flag", flag=rule[0])
        values = {"category": ctx.category_name, "flag": rule[1], "value": "Да"}
        out.append(make_finding(ctx, params, target, values))
    cfg = ctx.ruleset.config("P11")
    wrong_fire = (
        ctx.category_code == "OG"
        and cfg is not None
        and "fire_service" in cfg
        and flags.fireService is not bool(cfg["fire_service"])
    )
    if wrong_fire and cfg:
        target = Target(type="flag", flag="fireService")
        values = {
            "category": ctx.category_name,
            "flag": "Противопожарная служба",
            "value": YES_NO[bool(cfg["fire_service"])],
        }
        out.append(make_finding(ctx, params, target, values))
    return out


def open_factors(ctx: CheckContext) -> dict[str, bool]:
    """Unknown factors that decide conditional sections or hazards -> blocking flag."""
    result: dict[str, bool] = {}
    for entry in entries(ctx):
        codes = entry_factors(entry)
        if (
            entry["status"] == "Условное"
            and codes
            and factor_state(codes, ctx.factors) == "unknown"
        ):
            for code in (c for c in codes if ctx.factor(c) == "unknown"):
                result[code] = result.get(code, False) or entry["severity_if_missing"] == "Критично"
    for hazard in ctx.ruleset.hazards:
        codes = [c for c in _hazard_factors(hazard) if hazard["category"] == ctx.category_name]
        if codes and factor_state(codes, ctx.factors) == "unknown":
            for code in (c for c in codes if ctx.factor(c) == "unknown"):
                result[code] = (
                    result.get(code, False) or hazard["severity_if_missing"] == "Критично"
                )
    return result


def _hazard_factors(hazard: dict[str, Any]) -> list[str]:
    return FACTOR_CODE.findall(str(hazard.get("required_when", "")))


def check_n14(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for code, blocking in sorted(open_factors(ctx).items()):
        question = _factor_question(ctx, code)
        target = Target(type="factor", factorCode=code)
        finding = make_finding(
            ctx, params, target, {"factor_question": question}, kind="question", blocking=blocking
        )
        out.append(finding.model_copy(update={"title": Text(ru=question)}))
    return out
