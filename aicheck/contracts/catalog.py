"""Catalog snapshot (reference data from HSE) loaded through POST /v1/admin/catalog."""

from typing import Any

from pydantic import Field

from aicheck.contracts.models import Strict


class CatMeasure(Strict):
    id: int
    section: str = Field(pattern=r"^5\.(?:[1-9]|10)$")
    text: str = Field(max_length=2000)
    categories: list[str] = Field(default_factory=list)
    type: str = ""
    applies_when: list[str] = Field(default_factory=list)
    template_fields: str = ""


class CatHazard(Strict):
    id: int
    name: str
    categories: list[str] = Field(default_factory=list)
    victim_ids: list[int] = Field(default_factory=list)
    harm_ids: list[int] = Field(default_factory=list)
    control_ids: list[int] = Field(default_factory=list)


class CatControl(Strict):
    id: int
    text: str
    level: str = ""
    affects: str = ""
    hazard_ids: list[int] = Field(default_factory=list)
    section: str = ""
    categories: list[str] = Field(default_factory=list)


class CatTiming(Strict):
    id: int
    before_start: bool


class CatNamed(Strict):
    id: int
    name: str


class CatProfile(Strict):
    objects: list[str] = Field(default_factory=list)
    factors: dict[str, str] = Field(default_factory=dict)


class CatalogBody(Strict):
    version: str = Field(min_length=1, max_length=100)
    measures: list[CatMeasure] = Field(default_factory=list)
    hints: dict[str, str] = Field(default_factory=dict)
    hazards: list[CatHazard] = Field(default_factory=list)
    controls: list[CatControl] = Field(default_factory=list)
    victims: list[CatNamed] = Field(default_factory=list)
    harms: list[CatNamed] = Field(default_factory=list)
    implement_when: list[CatTiming] = Field(default_factory=list)
    profiles: dict[str, CatProfile] = Field(default_factory=dict)
    deactivated_ids: list[int] = Field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
