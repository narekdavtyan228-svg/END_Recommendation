"""Prompt assembly. Stable parts first (rules, documents), the permit data last."""

import json
import secrets
from pathlib import Path
from typing import Any

from aicheck.engine.context import CheckContext, Row
from aicheck.kb.retrieve import ClauseRef
from aicheck.llm.residue import Residue

PROMPTS = Path(__file__).parent / "prompts"
KB_ITEM_CHARS = 1200


def new_token() -> str:
    """Random delimiter id, fresh for every call (tests replace this function)."""
    return secrets.token_hex(8)


def load_prompt(name: str, version: str) -> str:
    return (PROMPTS / f"{name}_{version}.txt").read_text(encoding="utf-8").strip()


def wrap(text: str, token: str) -> str:
    """User text as data between delimiters; the delimiter characters themselves are removed."""
    safe = text.replace("<<<", "<<").replace(">>>", ">>")
    return f"<<<USER_TEXT id={token}>>>{safe}<<<END>>>"


def _kb_items(kb: list[ClauseRef]) -> list[dict[str, str]]:
    return [{"ref": c.ref, "title": c.title, "text": c.text[:KB_ITEM_CHARS]} for c in kb]


def _rows(rows: list[Row], token: str) -> list[dict[str, str]]:
    return [{"rowId": r.row_id, "section": r.section, "text": wrap(r.text, token)} for r in rows]


def measures_task(
    ctx: CheckContext, residue: Residue, kb: list[ClauseRef], version: str, token: str
) -> tuple[str, str]:
    body: dict[str, Any] = {
        "instruction": load_prompt("measures", version),
        "category": {"code": ctx.category_code, "name": ctx.category_name},
        "rules": residue.measure_rules,
        "kb": _kb_items(kb),
        "data": {
            "description": wrap(ctx.request.context.description, token),
            "factors": {c: f.value for c, f in ctx.factors.items() if f.value != "unknown"},
            "rows": _rows(residue.measure_rows, token),
            "reasons": [
                {"rowId": r.row_id, "section": r.section, "reason": wrap(r.reason or "", token)}
                for r in residue.reason_rows
            ],
        },
    }
    return load_prompt("system", version), json.dumps(body, ensure_ascii=False)


def _name(ctx: CheckContext, table: dict[int, dict[str, Any]], key: int | None, field: str) -> str:
    item = table.get(key) if key is not None else None
    return str(item[field]) if item else ""


def risks_task(
    ctx: CheckContext, residue: Residue, kb: list[ClauseRef], version: str, token: str
) -> tuple[str, str]:
    cat = ctx.catalog
    risk_rows = [
        {
            "rowId": r.rowId,
            "hazard": _name(ctx, cat.hazards, r.hazardId, "name"),
            "victims": [cat.names.get("victims", {}).get(i, str(i)) for i in r.victimIds],
            "harms": [cat.names.get("harms", {}).get(i, str(i)) for i in r.harmIds],
            "existingControls": [_name(ctx, cat.controls, i, "text") for i in r.existingControlIds],
            "additionalControls": [
                _name(ctx, cat.controls, i, "text") for i in r.additionalControlIds
            ],
            "b1": r.b1,
            "p1": r.p1,
            "b2": r.b2,
            "p2": r.p2,
        }
        for r in residue.risk_rows
    ]
    body: dict[str, Any] = {
        "instruction": load_prompt("risks", version),
        "category": {"code": ctx.category_code, "name": ctx.category_name},
        "rules": residue.risk_rules,
        "kb": _kb_items(kb),
        "data": {
            "rows": risk_rows,
            "measures": _rows([r for r in ctx.rows if r.live], token),
        },
    }
    return load_prompt("system", version), json.dumps(body, ensure_ascii=False)
