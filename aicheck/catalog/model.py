"""In-memory view of a catalog snapshot with the lookups the engine needs."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from aicheck.contracts.catalog import CatalogBody
from aicheck.engine.normalize import compare_form


def text_key(text: str) -> str:
    return hashlib.sha256(compare_form(text).encode()).hexdigest()


@dataclass(frozen=True)
class Catalog:
    version: str
    measures: dict[int, dict[str, Any]] = field(default_factory=dict)
    by_hash: dict[str, dict[str, Any]] = field(default_factory=dict)
    hints: dict[str, str] = field(default_factory=dict)
    hazards: dict[int, dict[str, Any]] = field(default_factory=dict)
    hazard_by_name: dict[str, dict[str, Any]] = field(default_factory=dict)
    controls: dict[int, dict[str, Any]] = field(default_factory=dict)
    timing: dict[int, bool] = field(default_factory=dict)
    names: dict[str, dict[int, str]] = field(default_factory=dict)
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)

    @staticmethod
    def empty(version: str = "") -> "Catalog":
        return Catalog(version=version)

    @staticmethod
    def from_body(body: dict[str, Any]) -> "Catalog":
        data = CatalogBody.model_validate(body)
        dead = set(data.deactivated_ids)
        measures = {m.id: m.model_dump() for m in data.measures if m.id not in dead}
        hazards = {h.id: h.model_dump() for h in data.hazards}
        return Catalog(
            version=data.version,
            measures=measures,
            by_hash={text_key(m["text"]): m for m in measures.values()},
            hints=dict(data.hints),
            hazards=hazards,
            hazard_by_name={compare_form(h["name"]): h for h in hazards.values()},
            controls={c.id: c.model_dump() for c in data.controls},
            timing={t.id: t.before_start for t in data.implement_when},
            names={
                "victims": {v.id: v.name for v in data.victims},
                "harms": {h.id: h.name for h in data.harms},
            },
            profiles={k: v.model_dump() for k, v in data.profiles.items()},
        )
