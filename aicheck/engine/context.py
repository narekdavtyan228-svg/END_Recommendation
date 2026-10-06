"""CheckContext: the normalised request snapshot plus resolved factors."""

import logging
from dataclasses import dataclass, field
from typing import Any

from rapidfuzz import fuzz

from aicheck.catalog.model import Catalog, text_key
from aicheck.contracts import Basis, CheckRequest
from aicheck.engine.factors import FactorValue, resolve_factors
from aicheck.engine.normalize import compare_form, is_dash, split_items
from aicheck.rules.loader import Ruleset

log = logging.getLogger(__name__)
FUZZY_THRESHOLD = 85


@dataclass(frozen=True)
class Row:
    index: int
    row_id: str
    section: str
    text: str
    norm: str
    dash: bool
    empty: bool
    reason: str | None
    origin: str
    item: dict[str, Any] | None
    items: tuple[str, ...]

    @property
    def live(self) -> bool:
        """A row with real content (neither empty nor a dash)."""
        return not self.dash and not self.empty


@dataclass
class CheckContext:
    request: CheckRequest
    ruleset: Ruleset
    catalog: Catalog
    rows: list[Row]
    factors: dict[str, FactorValue]
    category_code: str
    category_name: str
    kb_basis: dict[str, Basis] = field(default_factory=dict)

    def rows_in(self, section: str) -> list[Row]:
        return [r for r in self.rows if r.section == section]

    def live_in(self, section: str) -> list[Row]:
        return [r for r in self.rows_in(section) if r.live]

    def factor(self, code: str) -> str:
        value = self.factors.get(code)
        return value.value if value else "unknown"

    def hint(self, section: str) -> str:
        return self.catalog.hints.get(section, "")


def match_catalog(text: str, section: str, catalog: Catalog) -> tuple[str, dict[str, Any] | None]:
    """Exact hash -> `catalog`; token_set_ratio >= 85 -> `catalog_edited`; else `manual`."""
    exact = catalog.by_hash.get(text_key(text))
    if exact:
        return "catalog", exact
    best: tuple[float, dict[str, Any] | None] = (0.0, None)
    target = compare_form(text)
    for item in catalog.measures.values():
        if item["section"] != section:
            continue
        score = fuzz.token_set_ratio(target, compare_form(item["text_ru"]))
        if score > best[0]:
            best = (score, item)
    if best[0] >= FUZZY_THRESHOLD:
        return "catalog_edited", best[1]
    return "manual", None


def _build_row(index: int, measure: Any, catalog: Catalog) -> Row:
    text = measure.text
    stripped = text.strip()
    dash = bool(measure.notApplicable) or (bool(stripped) and is_dash(stripped))
    empty = not stripped and not measure.notApplicable
    origin, item = ("manual", None)
    if not dash and not empty:
        origin, item = match_catalog(stripped, measure.section, catalog)
        if origin != measure.origin:
            log.warning("origin mismatch", extra={"row_id": measure.rowId})
    return Row(
        index=index,
        row_id=measure.rowId,
        section=measure.section,
        text=text,
        norm=compare_form(text),
        dash=dash,
        empty=empty,
        reason=measure.notApplicableReason,
        origin=origin,
        item=item,
        items=tuple(split_items(text)),
    )


def build_context(
    request: CheckRequest,
    ruleset: Ruleset,
    catalog: Catalog,
    kb_basis: dict[str, Basis] | None = None,
) -> CheckContext:
    rows = [_build_row(i, m, catalog) for i, m in enumerate(request.measures)]
    code = request.context.categoryCode
    return CheckContext(
        request=request,
        ruleset=ruleset,
        catalog=catalog,
        rows=rows,
        factors=resolve_factors(request, ruleset, catalog),
        category_code=code,
        category_name=ruleset.category_names.get(code, code),
        kb_basis=kb_basis or {},
    )
