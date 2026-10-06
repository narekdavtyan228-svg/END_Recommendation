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
from aicheck.rules.loader import MarkerGroup

Params = dict[str, Any]
# Flag required by category (rule N12 text): gas control for GO/ZP, neighbour approval for ZR.
FLAG_RULES = {
    "GO": ("gasAirControl", "Контроль газо-воздушной среды"),
    "ZP": ("gasAirControl", "Контроль газо-воздушной среды"),
    "ZR": ("adjacentApproval", "Согласование со смежными цехами/участками"),
}


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
            if hit and not _from_own_catalog(ctx, row, hit):
                values = {
                    "short": short(row.text),
                    "group": group.name,
                    "category": ctx.category_name,
                }
                out.append(make_finding(ctx, _n(ctx, "N01"), row_target(row), values, evidence=hit))
                break
    return out


def _from_own_catalog(ctx: CheckContext, row: Row, hit: str) -> bool:
    """A marker that comes from a catalog record of the request category is not a foreign one."""
    item = row.item
    if not item or item["category"] != ctx.category_code:
        return False
    return hit.lower() in str(item["text_ru"]).lower()


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


def _in_period(day: date, period: dict[str, str]) -> bool:
    """`from`/`to` are MM-DD; a period may wrap over the new year (cold: 11-15 .. 03-15)."""
    mark = f"{day.month:02d}-{day.day:02d}"
    start, stop = period["from"], period["to"]
    return start <= mark <= stop if start <= stop else mark >= start or mark <= stop


def _season(start: date, end: date, cfg: dict[str, Any]) -> str | None:
    """`warm` or `cold` when both dates of the work lie inside one period, else None."""
    for name in ("warm", "cold"):
        if _in_period(start, cfg[name]) and _in_period(end, cfg[name]):
            return name
    return None


def check_n03(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = ctx.ruleset.config("P09")
    start, end = ctx.request.context.startAt, ctx.request.context.endAt
    if not cfg or not start or not end:
        return []  # the season periods are an OMG parameter
    season_now = _season(start.date(), end.date(), cfg)
    if season_now is None:
        return []  # transition dates: the rule stays silent
    cold, heat = _season_markers(str(params.get("detect", "")))
    patterns, season = (cold, "низких температур") if season_now == "warm" else (heat, "жары")
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
        target = Target(type="flag", field=rule[0])
        values = {"category": ctx.category_name, "flag": rule[1], "value": "Да"}
        out.append(make_finding(ctx, params, target, values))
    out.extend(_fire_service(ctx, params))
    return out


def fire_service_required(ctx: CheckContext) -> bool:
    """P11: for hot work the fire service flag must be «yes» when a listed factor is «yes»."""
    cfg = ctx.ruleset.config("P11")
    if not cfg or ctx.category_code != cfg["category"]:
        return False
    return any(ctx.factor(f) == "yes" for f in cfg["when_any_factor_yes"])


def _fire_service(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = ctx.ruleset.config("P11")
    if not (cfg and fire_service_required(ctx)):
        return []
    if getattr(ctx.request.context.flags, cfg["flag"]) is bool(cfg["required_value"]):
        return []
    values = {"category": ctx.category_name, "flag": "Противопожарная служба", "value": "Да"}
    target = Target(type="flag", field=cfg["flag"])
    return [make_finding(ctx, params, target, values, severity=cfg["severity"])]


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
    for hazard in ctx.catalog.hazards_of(ctx.category_code):
        codes = hazard["factors"] if hazard["required"] == "factor" else []
        if codes and factor_state(codes, ctx.factors) == "unknown":
            for code in (c for c in codes if ctx.factor(c) == "unknown"):
                critical = hazard["severity_if_missing"] == "critical"
                result[code] = result.get(code, False) or critical
    return result


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


# Flag -> stems of text that presumes the flag is «yes» (rule N13: the flag says «no», the text does the work).
FLAG_TEXT = {
    "gasAirControl": (
        ("анализ воздух", "анализ воздушн", "газоанализ", "газовый анализ", "газовый контроль"),
        "Контроль газо-воздушной среды",
    ),
    "adjacentApproval": (
        ("лэп", "ВЛ ", "линию электропередач", "линии электропередач"),
        "Согласование со смежными цехами/участками",
    ),
}


def check_n13(ctx: CheckContext, params: Params) -> list[Finding]:
    """Flag = «no», but a measure in the text works for that flag."""
    out = []
    for flag, (stems, title) in FLAG_TEXT.items():
        if getattr(ctx.request.context.flags, flag) is True:
            continue
        for row in (r for r in ctx.rows if r.live):
            hit = find_stem(row.text, stems)
            if hit:
                values = {"flag": title, "value": "Нет", "p": row.section, "short": short(row.text)}
                out.append(
                    make_finding(ctx, params, Target(type="flag", field=flag), values, evidence=hit)
                )
                break
    return out
