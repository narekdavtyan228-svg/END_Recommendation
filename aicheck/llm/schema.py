"""Pydantic mirror of llm/prompts/llm_output_schema.json; anything else is rejected."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LlmTarget(BaseModel):
    model_config = ConfigDict(extra="ignore")
    type: Literal["measure", "risk", "flag", "factor"] = "measure"
    section: str | None = None
    row_id: str | None = None
    field: str | None = None


class LlmFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rule_code: str
    status: Literal["fail", "pass", "need_input", "not_applicable"]
    target: LlmTarget = Field(default_factory=LlmTarget)
    evidence: str = ""
    reason: str = ""
    question: str | None = None
    catalog_ids: list[int] = Field(default_factory=list)
    recommendation: str | None = None
    generated: bool = False
    basis_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class LlmAnswer(BaseModel):
    model_config = ConfigDict(extra="ignore")
    findings: list[LlmFinding]
