"""Syntax rules S01-S17: purely textual checks of every row of section 5."""

import re
from typing import Any

from rapidfuzz import fuzz

from aicheck.contracts import Autofix, Finding, Recommendation, Text
from aicheck.engine.context import CheckContext, Row
from aicheck.engine.findings import make_finding, row_target
from aicheck.engine.normalize import (
    collapse,
    compare_form,
    letter_ratio,
    short,
    significant_words,
)

Params = dict[str, Any]
LATIN_TO_CYR = str.maketrans("AaBCcEeHKMOoPpTXxy", "АаВСсЕеНКМОоРрТХху")
KAZAKH = "әғқңөұүһіӘҒҚҢӨҰҮҺІ"
UNITS = r"(?:м/с|мг/м3|мм|см|км|°C|°|кг|кВ|В|%|ppm|мин|лк|шт|чел\w*|м|ч|т)(?![\w/])"
UNIT_AFTER = re.compile(r"\s*" + UNITS)
NUMBER = re.compile(r"\b\d+(?:[.,]\d+)?\b")
REFERENCE_BEFORE = re.compile(r"(?:п\.|пп\.|№|пункт\w*|ст\.)\s*$", re.IGNORECASE)
NUMBER_CONTEXT = (
    "расстоян",
    "высот",
    "глубин",
    "радиус",
    "скорост",
    "масс",
    "напряжен",
    "концентрац",
)
RANGE_WORDS = {  # word in the rule text -> (stem in user text, unit pattern)
    "ветер": ("ветр|ветер", r"м/с"),
    "угол": ("угол|угл", r"°|град"),
    "высота": ("высот", r"м(?![\w/])"),
    "глубина": ("глубин", r"м(?![\w/])"),
    "расстояние": ("расстоян", r"м(?![\w/])"),
    "концентрация": ("концентрац", r"%"),
}
DEFAULT_LONG = 1500


def _fnd(
    ctx: CheckContext, code: str, row: Row, values: dict[str, Any] | None = None, **kw: Any
) -> Finding:
    return make_finding(ctx, ctx.ruleset.syntax[code], row_target(row), values, **kw)


def _live(ctx: CheckContext) -> list[Row]:
    return [r for r in ctx.rows if r.live]


def check_s01(ctx: CheckContext, params: Params) -> list[Finding]:
    return [_fnd(ctx, "S01", r) for r in ctx.rows if r.empty]


def check_s02(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        value = row.text.strip()[:2000]
        if any(p.search(value) for p in ctx.ruleset.patterns["S02"]):
            out.append(_fnd(ctx, "S02", row, {"value": value}, evidence=value))
    return out


def check_s03(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        hint = compare_form(ctx.hint(row.section))
        if hint and (row.norm == hint or (row.norm in hint and len(row.norm) >= 0.7 * len(hint))):
            out.append(_fnd(ctx, "S03", row, evidence=short(row.text)))
    return out


def check_s04(ctx: CheckContext, params: Params) -> list[Finding]:
    return [
        _fnd(ctx, "S04", r, evidence=short(r.text))
        for r in _live(ctx)
        if len(significant_words(r.text)) < 3
    ]


def check_s05(ctx: CheckContext, params: Params) -> list[Finding]:
    return [
        _fnd(ctx, "S05", r, evidence=short(r.text))
        for r in _live(ctx)
        if letter_ratio(r.text.strip()) < 0.5
    ]


def check_s06(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        text = row.text[:2000]
        if any(p.search(text) for p in ctx.ruleset.patterns["S06"]):
            fields = (row.item or {}).get("template_fields") or "пропущенные значения"
            out.append(_fnd(ctx, "S06", row, {"template_fields": fields}, evidence=short(text)))
    return out


def fix_punctuation(text: str) -> str:
    """Autofix for S07: artifacts of catalog record concatenation."""
    text = re.sub(r"^\s*\S+;\s*(?=[А-ЯЁ])", "", text)  # a stray word fragment at the start
    text = re.sub(r"^\s*[;,.]+\s*", "", text)
    text = re.sub(r"\.;", ".", text)
    text = re.sub(r";(?:\s*;)+", ";", text)
    return collapse(text)


def _autofix(ctx: CheckContext, code: str, row: Row, after: str) -> Finding:
    rec = Recommendation(mode="replace", text=Text(ru=after))
    fix = Autofix(rowId=row.row_id, before=row.text, after=after)
    return _fnd(ctx, code, row, recommendation=rec, autofix=fix, kind="autofix")


def check_s07(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        text = row.text[:2000]
        if any(p.search(text) for p in ctx.ruleset.patterns["S07"]):
            fixed = fix_punctuation(text)
            if fixed and fixed != row.text:
                out.append(_autofix(ctx, "S07", row, fixed))
    return out


def check_s08(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        t = row.text
        if t.count("(") != t.count(")") or t.count("«") != t.count("»") or t.count('"') % 2:
            out.append(_fnd(ctx, "S08", row, evidence=short(t)))
    return out


def check_s09(ctx: CheckContext, params: Params) -> list[Finding]:
    if ctx.request.locale != "ru":
        return []  # the Kazakh branch needs a Russian word dictionary that the package lacks
    pattern = ctx.ruleset.patterns["S09"][0] if "S09" in ctx.ruleset.patterns else None
    pattern = pattern or re.compile(f"[{KAZAKH}]")
    return [
        _fnd(ctx, "S09", r, evidence=short(r.text)) for r in _live(ctx) if pattern.search(r.text)
    ]


def fix_latin(text: str) -> str:
    """Autofix for S10: replace Latin look-alikes inside words that contain Cyrillic."""

    def fix(match: re.Match[str]) -> str:
        word = match.group(0)
        return word.translate(LATIN_TO_CYR) if re.search(r"[А-Яа-яЁё]", word) else word

    return re.sub(r"\w+", fix, text)


def check_s10(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        text = row.text[:2000]
        if any(p.search(text) for p in ctx.ruleset.patterns["S10"]):
            fixed = fix_latin(text)
            if fixed != row.text:
                out.append(_autofix(ctx, "S10", row, fixed))
    return out


def check_s11(ctx: CheckContext, params: Params) -> list[Finding]:
    seen: list[tuple[str, Row]] = []
    out = []
    for row in _live(ctx):
        for item in row.items:
            norm = compare_form(item)
            match = next((s for s in seen if _same(norm, s[0])), None)
            if match:
                values = {"short": short(item), "p1": match[1].section, "p2": row.section}
                out.append(_fnd(ctx, "S11", row, values, evidence=short(item)))
            seen.append((norm, row))
    return out


def _same(a: str, b: str) -> bool:
    return a == b or fuzz.ratio(a, b) / 100 >= 0.95


def fix_repeats(text: str) -> str:
    return re.sub(r"\b(\w+)\s+\1\b", r"\1", text, flags=re.IGNORECASE)


def check_s12(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        if ctx.ruleset.patterns["S12"][0].search(row.text[:2000]):
            fixed = fix_repeats(row.text)
            if fixed != row.text:
                out.append(_autofix(ctx, "S12", row, fixed))
    return out


def check_s13(ctx: CheckContext, params: Params) -> list[Finding]:
    """Service rule: dash normalisation happens while the context is built."""
    return []


def _has_unit(text: str, end: int) -> bool:
    return bool(UNIT_AFTER.match(text, end))


def check_s14(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in _live(ctx):
        for item in row.items:
            number = _number_without_unit(item)
            if number:
                out.append(_fnd(ctx, "S14", row, {"number": number}, evidence=short(item)))
                break
    return out


def _number_without_unit(item: str) -> str | None:
    lowered = item.lower()
    if not any(stem in lowered for stem in NUMBER_CONTEXT):
        return None
    for match in NUMBER.finditer(item):
        if REFERENCE_BEFORE.search(item[: match.start()]):
            continue
        if not _has_unit(item, match.end()):
            return match.group(0)
    return None


def _limits(detect: str) -> tuple[dict[str, float], tuple[float, float] | None]:
    upper = {w: float(v) for w, v in re.findall(r"([а-яё]+)\s*>\s*(\d+)", detect)}
    temp = re.search(r"[−-](\d+)…\+?(\d+)", detect)
    return upper, (-float(temp.group(1)), float(temp.group(2))) if temp else None


def check_s17(ctx: CheckContext, params: Params) -> list[Finding]:
    upper, temp = _limits(str(params.get("detect", "")))
    out = []
    for row in _live(ctx):
        for item in row.items:
            number = _out_of_range(item, upper, temp)
            if number:
                out.append(_fnd(ctx, "S17", row, {"number": number}, evidence=short(item)))
                break
    return out


def _out_of_range(
    item: str, upper: dict[str, float], temp: tuple[float, float] | None
) -> str | None:
    for word, limit in upper.items():
        stem, unit = RANGE_WORDS.get(word, ("", ""))
        if not stem:
            continue
        for m in re.finditer(
            rf"(?:{stem})\w*\D{{0,30}}?(\d+(?:[.,]\d+)?)\s*(?:{unit})", item, re.I
        ):
            if float(m.group(1).replace(",", ".")) > limit:
                return m.group(1)
    if temp:
        for m in re.finditer(r"температур\w*\D{0,30}?([+\-−]?\d+)\s*°", item, re.I):
            value = float(m.group(1).replace("−", "-"))
            if not temp[0] <= value <= temp[1]:
                return m.group(1)
    return None


def check_s15(ctx: CheckContext, params: Params) -> list[Finding]:
    out = []
    for row in ctx.rows:
        if row.empty:
            continue
        patterns = ctx.ruleset.patterns["S15"]
        if any(p.search(row.text) for p in patterns):
            fixed = row.text
            for p in patterns:
                fixed = p.sub("", fixed)
            out.append(_autofix(ctx, "S15", row, collapse(fixed)))
    return out


def check_s16(ctx: CheckContext, params: Params) -> list[Finding]:
    limit = DEFAULT_LONG
    cfg = re.search(r"\d+", str(ctx.ruleset.params.get("P12", {}).get("value", "")))
    if cfg:
        limit = int(cfg.group(0))
    return [_fnd(ctx, "S16", r) for r in _live(ctx) if len(r.text) > limit]
