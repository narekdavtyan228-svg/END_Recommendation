"""Catalog snapshot (reference data from HSE) loaded through POST /v1/admin/catalog.

The format follows the exported test catalog of the specification: records carry the markup
the rules need (item type, factors, key elements, hazard links, control hierarchy level).
Unknown fields are ignored so that HSE can add its own attributes.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Record(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CatMeasure(Record):
    id: int
    section: str = Field(pattern=r"^5\.(?:[1-9]|10)$")
    text_ru: str = Field(max_length=4000)
    text_kk: str = ""
    code: str = ""
    category: str = ""
    item_type: str = "optional"  # core | conditional | optional | template | excluded
    factors: list[str] = Field(default_factory=list)
    key_elements: list[str] = Field(default_factory=list)
    active: bool = True
    version: int = 1


class CatHazard(Record):
    id: int
    name: str
    category: str = ""
    required: str = "always"  # always | factor | none
    factors: list[str] = Field(default_factory=list)
    min_severity_level: str | None = None  # high | medium | low
    victim_ids: list[int] = Field(default_factory=list)
    harm_ids: list[int] = Field(default_factory=list)
    typical_existing_control_ids: list[int] = Field(default_factory=list)
    typical_additional_control_ids: list[int] = Field(default_factory=list)
    linked_sections: list[str] = Field(default_factory=list)
    severity_if_missing: str = "significant"  # critical | significant


class CatControl(Record):
    id: int
    name: str
    hierarchy_level: str | None = (
        None  # elimination | substitution | engineering | administrative | ppe
    )
    affects: str | None = None  # P | B | PB
    hazard_ids: list[int] = Field(default_factory=list)
    linked_section: str | None = None


class CatNamed(Record):
    id: int
    name: str


class CatProfile(Record):
    unitCode: str
    objects: list[str] = Field(default_factory=list)
    factor_defaults: dict[str, str] = Field(default_factory=dict)


class CatalogBody(Record):
    version: str = Field(min_length=1, max_length=100)
    orgCode: str = ""
    measures: list[CatMeasure] = Field(default_factory=list)
    hazards: list[CatHazard] = Field(default_factory=list)
    controls: list[CatControl] = Field(default_factory=list)
    victims: list[CatNamed] = Field(default_factory=list)
    harms: list[CatNamed] = Field(default_factory=list)
    roles: list[CatNamed] = Field(default_factory=list)
    implement_when: list[CatNamed] = Field(default_factory=list)
    profiles: list[CatProfile] = Field(default_factory=list)
    hints: dict[str, str] = Field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
