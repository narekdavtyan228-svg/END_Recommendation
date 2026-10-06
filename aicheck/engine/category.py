"""Category rules (code part): ZR-, GP-, ZP-, OG-, GO-, VS-.

Rules whose executor is the LLM (or code+LLM with no deterministic part) are not here: the
engine skips them and the LLM stage confirms them. DR- rules are LLM-only.
Keyword tuples below come from the wording of the rule check itself.
"""

import re
from typing import Any

from aicheck.contracts import Finding, Target
from aicheck.engine.context import CheckContext, Row
from aicheck.engine.findings import make_finding, row_target
from aicheck.engine.inapplicable import YES_NO, check_n12
from aicheck.engine.normalize import find_stem, short

Params = dict[str, Any]
ANALYSIS = ("анализ", "газоанализ", "проб", "ПДК", "НКПР")
PROHIBIT = ("запрещ", "запрет", "не допуск", "исключ", "не въезж")
FIVE_ELEMENTS = ("мест", "врем", "пери", "приб", "резу")  # 5.4 template of rule GO-02


def _rule(ctx: CheckContext, code: str) -> dict[str, Any]:
    return ctx.ruleset.category_rules[code]


def _live(ctx: CheckContext, sections: tuple[str, ...] | None = None) -> list[Row]:
    return [r for r in ctx.rows if r.live and (sections is None or r.section in sections)]


def _any(rows: list[Row], stems: tuple[str, ...]) -> bool:
    return any(find_stem(r.text, stems) for r in rows)


def _section_finding(ctx: CheckContext, code: str, section: str, **values: Any) -> Finding:
    return make_finding(ctx, _rule(ctx, code), Target(type="section", section=section), values)


def check_zr01(ctx: CheckContext, params: Params) -> list[Finding]:
    """Section 5.7 must state the approval with owners of communications.

    A missing or dash-only section is reported by the matrix (MX) and N06, not here.
    """
    rows = _live(ctx, ("5.7",))
    if not rows or _any(rows, ("согласова",)):
        return []
    return [_section_finding(ctx, "ZR-01", "5.7")]


def check_zr02(ctx: CheckContext, params: Params) -> list[Finding]:
    attached = any(a.kind == "scheme" and a.count > 0 for a in ctx.request.context.attachments)
    target = Target(type="description")
    return [] if attached else [make_finding(ctx, _rule(ctx, "ZR-02"), target)]


def _analysis_missing(ctx: CheckContext, code: str) -> list[Finding]:
    rows = _live(ctx, ("5.4",))
    if ctx.factor("F03") != "yes" or not rows or _any(rows, ANALYSIS):
        return []
    return [_section_finding(ctx, code, "5.4")]


def check_zr04(ctx: CheckContext, params: Params) -> list[Finding]:
    return _analysis_missing(ctx, "ZR-04")


def check_og03(ctx: CheckContext, params: Params) -> list[Finding]:
    return _analysis_missing(ctx, "OG-03")


def check_gp01(ctx: CheckContext, params: Params) -> list[Finding]:
    if ctx.factor("F02") != "yes" or ctx.request.context.flags.adjacentApproval is True:
        return []
    target = Target(type="flag", flag="adjacentApproval")
    return [make_finding(ctx, _rule(ctx, "GP-01"), target)]


def check_gp03(ctx: CheckContext, params: Params) -> list[Finding]:
    if ctx.factor("F05") != "yes" or _any(_live(ctx), ("времен", "разделен")):
        return []
    return [make_finding(ctx, _rule(ctx, "GP-03"), Target(type="description"))]


def _flag_rule(ctx: CheckContext, code: str) -> list[Finding]:
    """ZP-01 / GO-01 are the same flag check as N12; run.py drops the duplicate."""
    return [
        make_finding(ctx, _rule(ctx, code), f.target, {"flag": f.message.ru})
        for f in check_n12(ctx, {})
    ]


def check_zp01(ctx: CheckContext, params: Params) -> list[Finding]:
    return _flag_rule(ctx, "ZP-01") if ctx.category_code == "ZP" else []


def check_go01(ctx: CheckContext, params: Params) -> list[Finding]:
    return _flag_rule(ctx, "GO-01") if ctx.category_code == "GO" else []


def _permit_missing(ctx: CheckContext, code: str, stems: tuple[str, ...]) -> list[Finding]:
    rows = _live(ctx)
    if ctx.factor("F31") != "yes" or (_any(rows, ("наряд",)) and _any(rows, stems)):
        return []
    return [make_finding(ctx, _rule(ctx, code), Target(type="description"))]


def check_zp04(ctx: CheckContext, params: Params) -> list[Finding]:
    return _permit_missing(ctx, "ZP-04", ("огнев", "газоопасн"))


def check_og04(ctx: CheckContext, params: Params) -> list[Finding]:
    return _permit_missing(ctx, "OG-04", ("газоопасн",))


def check_og05(ctx: CheckContext, params: Params) -> list[Finding]:
    cfg = ctx.ruleset.config("P11")
    if not cfg or "fire_service" not in cfg:
        return []
    if ctx.request.context.flags.fireService is bool(cfg["fire_service"]):
        return []
    target = Target(type="flag", flag="fireService")
    return [
        make_finding(ctx, _rule(ctx, "OG-05"), target, {"value": YES_NO[bool(cfg["fire_service"])]})
    ]


def check_go02(ctx: CheckContext, params: Params) -> list[Finding]:
    rows = _live(ctx, ("5.4",))
    if not rows:
        return []
    words = re.findall(r"[а-яё]+", str(_rule(ctx, "GO-02")["check"]).split("5.4", 1)[-1].lower())
    missing = [w for w in words if len(w) >= 5 and not _any(rows, (w[:4],))]
    if not missing:
        return []
    return [
        make_finding(
            ctx,
            _rule(ctx, "GO-02"),
            Target(type="section", section="5.4"),
            evidence=", ".join(missing),
        )
    ]


def _phrase_pattern(phrase: str) -> re.Pattern[str]:
    """Words of a quoted phrase in order; endings may differ («нормы» / «нормам»)."""
    stems = [re.escape(w[: max(4, len(w) - 2)]) + r"\w*" for w in phrase.split()]
    return re.compile(r"\b" + r"\W+".join(stems), re.IGNORECASE)


def check_vs03(ctx: CheckContext, params: Params) -> list[Finding]:
    phrases: list[str] = []
    for group in ctx.ruleset.raw["stoplist"]:
        if "VS-03" in str(group.get("rule", "")):
            phrases = re.findall(r"«([^»]+)»", str(group["values"]))[:1]
    patterns = [_phrase_pattern(p) for p in phrases]
    out = []
    for row in _live(ctx):
        hit = next((m.group(0) for p in patterns if (m := p.search(row.text))), None)
        if hit:
            out.append(make_finding(ctx, _rule(ctx, "VS-03"), row_target(row), evidence=hit))
    return out


def radius_table(ctx: CheckContext) -> list[tuple[float, float]]:
    """P03 text `≤10 м → 4 м; ≤20 → 7; ... >200 → 30` -> [(height limit, radius)]."""
    text = str(ctx.ruleset.params.get("P03", {}).get("value", ""))
    pairs = re.findall(r"[≤>]\s*(\d+)\s*(?:м)?\s*→\s*(\d+(?:,\d+)?)", text)
    return [(float(h), float(r.replace(",", "."))) for h, r in pairs]


def required_radius(table: list[tuple[float, float]], height: float) -> float | None:
    for limit, radius in table:
        if height <= limit:
            return radius
    return table[-1][1] if table else None


def check_vs04(ctx: CheckContext, params: Params) -> list[Finding]:
    table = radius_table(ctx)
    for row in _live(ctx):
        h = re.search(r"высот\w*\D{0,20}?(\d+(?:[.,]\d+)?)\s*м(?![\w/])", row.text, re.IGNORECASE)
        r = re.search(r"радиус\w*\D{0,30}?(\d+(?:[.,]\d+)?)\s*м(?![\w/])", row.text, re.IGNORECASE)
        if not (h and r and table):
            continue
        need = required_radius(table, float(h.group(1).replace(",", ".")))
        if need is not None and float(r.group(1).replace(",", ".")) < need:
            return [
                make_finding(
                    ctx,
                    _rule(ctx, "VS-04"),
                    row_target(row),
                    {"required": need},
                    evidence=short(row.text),
                )
            ]
    return []


def check_vs07(ctx: CheckContext, params: Params) -> list[Finding]:
    if ctx.factor("F01") != "yes":
        return []
    rows = _live(ctx)
    lifting = next(g.stems for g in ctx.ruleset.markers if g.name == "Грузоподъёмные")
    if _any(rows, lifting + ("техник",)) and _any(rows, PROHIBIT):
        return []
    return [make_finding(ctx, _rule(ctx, "VS-07"), Target(type="description"))]


def check_vs08(ctx: CheckContext, params: Params) -> list[Finding]:
    if ctx.factor("F25") != "yes":
        return []
    rows = _live(ctx)
    if _any(rows, ("независим",)) and _any(rows, ("страх",)):
        return []
    return [make_finding(ctx, _rule(ctx, "VS-08"), Target(type="description"))]
