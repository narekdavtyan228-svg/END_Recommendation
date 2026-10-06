"""Pydantic schema of the model answer; anything else is rejected."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LlmTarget(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rowId: str | None = None
    section: str | None = None


class LlmFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rule_code: str
    status: Literal["fail", "pass", "not_applicable", "need_input"]
    target: LlmTarget = Field(default_factory=LlmTarget)
    evidence: str = ""
    message: str = ""
    recommendation_text: str | None = None
    catalog_ids: list[int] = Field(default_factory=list)
    basis_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class LlmAnswer(BaseModel):
    model_config = ConfigDict(extra="ignore")
    findings: list[LlmFinding]
