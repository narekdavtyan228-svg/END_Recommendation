"""In-memory view of a catalog snapshot with the lookups the engine needs."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from aicheck.contracts.catalog import CatalogBody
from aicheck.engine.normalize import compare_form

TYPES_IN_USE = ("core", "conditional", "optional", "template")


def text_key(text: str) -> str:
    return hashlib.sha256(compare_form(text).encode()).hexdigest()


@dataclass(frozen=True)
class Catalog:
    version: str
    measures: dict[int, dict[str, Any]] = field(default_factory=dict)  # active records only
    by_hash: dict[str, dict[str, Any]] = field(default_factory=dict)
    hints: dict[str, str] = field(default_factory=dict)
    hazards: dict[int, dict[str, Any]] = field(default_factory=dict)
    controls: dict[int, dict[str, Any]] = field(default_factory=dict)
    names: dict[str, dict[int, str]] = field(default_factory=dict)
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)

    @staticmethod
    def empty(version: str = "") -> "Catalog":
        return Catalog(version=version)

    @staticmethod
    def from_body(body: dict[str, Any]) -> "Catalog":
        data = CatalogBody.model_validate(body)
        measures = {
            m.id: m.model_dump() for m in data.measures if m.active and m.item_type in TYPES_IN_USE
        }
        return Catalog(
            version=data.version,
            measures=measures,
            by_hash={text_key(m["text_ru"]): m for m in measures.values()},
            hints=dict(data.hints),
            hazards={h.id: h.model_dump() for h in data.hazards},
            controls={c.id: c.model_dump() for c in data.controls},
            names={
                "victims": {v.id: v.name for v in data.victims},
                "harms": {h.id: h.name for h in data.harms},
                "roles": {r.id: r.name for r in data.roles},
                "implement_when": {i.id: i.name for i in data.implement_when},
            },
            profiles={p.unitCode: p.model_dump() for p in data.profiles},
        )

    def hazards_of(self, category: str) -> list[dict[str, Any]]:
        return [h for h in self.hazards.values() if h["category"] == category]
