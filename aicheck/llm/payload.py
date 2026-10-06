"""Prompt assembly from the files in llm/prompts (placeholders are filled here)."""

import json
import secrets
from pathlib import Path
from typing import Any

from aicheck.engine.context import CheckContext, Row
from aicheck.kb.retrieve import ClauseRef
from aicheck.llm.residue import Residue

PROMPTS = Path(__file__).parent / "prompts"
KB_ITEM_CHARS = 1200
CATALOG_ITEM_CHARS = 500
MAX_CATALOG_ITEMS = 80


def new_token() -> str:
    """Random delimiter marker, fresh for every call (tests replace this function)."""
    return secrets.token_hex(8)


def load_prompt(name: str, version: str) -> str:
    return (PROMPTS / f"{name}_{version}.txt").read_text(encoding="utf-8").strip()


def output_schema() -> dict[str, Any]:
    schema: dict[str, Any] = json.loads(
        (PROMPTS / "llm_output_schema.json").read_text(encoding="utf-8")
    )
    return schema


def fill(template: str, values: dict[str, str]) -> str:
    """Replace `{name}` placeholders; text of the data is never interpreted as a template."""
    for key, value in values.items():
        template = template.replace("{" + key + "}", value)
    return template


def wrap(text: str, marker: str, item_id: str = "") -> str:
    """User text as data between delimiters; the delimiter characters themselves are removed."""
    safe = text.replace("<<<", "<<").replace(">>>", ">>")
    return f"<<<USER_TEXT_{marker} id={item_id}>>>\n{safe}\n<<<END_{marker}>>>"


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _system(version: str, ctx: CheckContext, marker: str) -> str:
    return fill(load_prompt("system", version), {"locale": ctx.request.locale, "marker": marker})


def _context(ctx: CheckContext, marker: str) -> dict[str, Any]:
    c = ctx.request.context
    return {
        "category": {"code": ctx.category_code, "name": ctx.category_name},
        "workType": c.workType,
        "unitCode": c.unitCode,
        "description": wrap(c.description, marker, "description"),
        "startAt": c.startAt.isoformat() if c.startAt else None,
        "endAt": c.endAt.isoformat() if c.endAt else None,
        "flags": c.flags.model_dump(),
    }


def _factors(ctx: CheckContext) -> dict[str, str]:
    raw = ctx.request.factorAnswers
    return {c: raw.get(c, f.value) for c, f in ctx.factors.items() if f.value != "unknown"}


def _items(rows: list[Row], reasons: list[Row], marker: str) -> str:
    parts = [
        f"[row_id={r.row_id} section={r.section}]\n{wrap(r.text, marker, r.row_id)}" for r in rows
    ]
    parts += [
        f"[row_id={r.row_id} section={r.section} обоснование «Не требуется»]\n"
        + wrap(r.reason or "", marker, r.row_id)
        for r in reasons
    ]
    return "\n\n".join(parts)


def _kb_items(kb: list[ClauseRef]) -> list[dict[str, str]]:
    return [{"ref": c.ref, "title": c.title, "text": c.text[:KB_ITEM_CHARS]} for c in kb]


def _measure_catalog(ctx: CheckContext, residue: Residue) -> list[dict[str, Any]]:
    sections = {r.section for r in residue.measure_rows}
    items = [
        {
            "id": m["id"],
            "section": m["section"],
            "text": m["text_ru"][:CATALOG_ITEM_CHARS],
            "type": m["item_type"],
            "factors": m["factors"],
            "key_elements": m["key_elements"],
        }
        for m in ctx.catalog.measures.values()
        if m["category"] == ctx.category_code and m["section"] in sections
    ]
    return items[:MAX_CATALOG_ITEMS]


def measures_task(
    ctx: CheckContext, residue: Residue, kb: list[ClauseRef], version: str, marker: str
) -> tuple[str, str]:
    values = {
        "context_json": dumps(_context(ctx, marker)),
        "factors_json": dumps(_factors(ctx)),
        "rules_json": dumps(residue.measure_rules),
        "catalog_json": dumps(_measure_catalog(ctx, residue)),
        "clauses_json": dumps(_kb_items(kb)),
        "examples_json": "[]",
        "items_with_markers": _items(residue.measure_rows, residue.reason_rows, marker),
        "output_schema_json": dumps(output_schema()),
    }
    return _system(version, ctx, marker), fill(load_prompt("measures", version), values)


def _risk_catalog(ctx: CheckContext, residue: Residue) -> dict[str, Any]:
    cat = ctx.catalog
    hazards = [cat.hazards[r.hazardId] for r in residue.risk_rows if r.hazardId in cat.hazards]
    control_ids = {
        c
        for h in hazards
        for c in h["typical_existing_control_ids"] + h["typical_additional_control_ids"]
    }
    for risk in residue.risk_rows:
        control_ids.update(risk.existingControlIds + risk.additionalControlIds)
    return {
        "hazards": [
            {
                "id": h["id"],
                "name": h["name"],
                "victim_ids": h["victim_ids"],
                "harm_ids": h["harm_ids"],
                "typical_existing_control_ids": h["typical_existing_control_ids"],
                "typical_additional_control_ids": h["typical_additional_control_ids"],
                "min_severity_level": h["min_severity_level"],
            }
            for h in hazards
        ],
        "controls": [cat.controls[i] for i in sorted(control_ids) if i in cat.controls],
        "victims": cat.names.get("victims", {}),
        "harms": cat.names.get("harms", {}),
    }


def _risk_rows(ctx: CheckContext, residue: Residue, marker: str) -> str:
    cat = ctx.catalog
    rows = []
    for r in residue.risk_rows:
        data = {
            "hazardId": r.hazardId,
            "victimIds": r.victimIds,
            "harmIds": r.harmIds,
            "existingControlIds": r.existingControlIds,
            "additionalControlIds": r.additionalControlIds,
            "b1": r.b1,
            "p1": r.p1,
            "b2": r.b2,
            "p2": r.p2,
            "hazard": cat.hazards.get(r.hazardId, {}).get("name")
            if r.hazardId is not None
            else None,
        }
        rows.append(f"[row_id={r.rowId}]\n{wrap(dumps(data), marker, r.rowId)}")
    return "\n\n".join(rows)


def risks_task(
    ctx: CheckContext, residue: Residue, kb: list[ClauseRef], version: str, marker: str
) -> tuple[str, str]:
    summary = [{"section": r.section, "text": r.text[:300]} for r in ctx.rows if r.live]
    values = {
        "context_json": dumps(_context(ctx, marker)),
        "factors_json": dumps(_factors(ctx)),
        "rules_json": dumps(residue.risk_rules),
        "risk_catalog_json": dumps(_risk_catalog(ctx, residue)),
        "clauses_json": dumps(_kb_items(kb)),
        "examples_json": "[]",
        "risk_rows_with_markers": _risk_rows(ctx, residue, marker),
        "measures_summary_json": dumps(summary),
        "output_schema_json": dumps(output_schema()),
    }
    return _system(version, ctx, marker), fill(load_prompt("risks", version), values)
