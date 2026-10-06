"""Pydantic contracts of the /v1 API. Unknown fields are rejected everywhere."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Section = Annotated[str, StringConstraints(pattern=r"^5\.(?:[1-9]|10)$")]
Severity = Literal["critical", "significant", "recommendation", "question"]
Kind = Literal["issue", "question", "autofix", "suggestion"]
Origin = Literal["catalog", "catalog_edited", "manual"]
Tri = Literal["yes", "no", "unknown"]
MAX_TEXT = 2000
MAX_ROWS_PER_SECTION = 30
MAX_RISK_ROWS = 50


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Text(Strict):
    ru: str = ""
    kk: str = ""


class Tenant(Strict):
    orgCode: str = Field(min_length=1, max_length=20)


class EndInfo(Strict):
    endRef: str = Field(min_length=1, max_length=200)
    snapshotVersion: int = 0
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    mode: Literal["full", "additions"] = "full"


class Flags(Strict):
    adjacentApproval: bool | None = None
    gasAirControl: bool | None = None
    fireService: bool | None = None
    contractorStaff: bool | None = None


class Attachment(Strict):
    kind: str = Field(max_length=50)
    count: int = Field(ge=0)


class Context(Strict):
    workType: str = Field(max_length=50)
    categoryCode: str = Field(max_length=10)
    unitCode: str | None = Field(default=None, max_length=50)
    shopCode: str | None = Field(default=None, max_length=50)
    description: str = Field(default="", max_length=MAX_TEXT * 2)
    startAt: datetime | None = None
    endAt: datetime | None = None
    flags: Flags = Field(default_factory=Flags)
    attachments: list[Attachment] = Field(default_factory=list, max_length=20)
    catalogVersion: str = Field(min_length=1, max_length=100)


class Measure(Strict):
    rowId: str = Field(min_length=1, max_length=100)
    section: Section
    text: str = Field(default="", max_length=MAX_TEXT)
    catalogItemId: int | None = None
    catalogItemVersion: int | None = None
    origin: Origin = "manual"
    notApplicable: bool = False
    notApplicableReason: str | None = Field(default=None, max_length=MAX_TEXT)


class Risk(Strict):
    rowId: str = Field(min_length=1, max_length=100)
    hazardId: int | None = None
    victimIds: list[int] = Field(default_factory=list, max_length=50)
    harmIds: list[int] = Field(default_factory=list, max_length=50)
    existingControlIds: list[int] = Field(default_factory=list, max_length=50)
    b1: int | None = None
    p1: int | None = None
    r1: int | None = None
    additionalControlIds: list[int] = Field(default_factory=list, max_length=50)
    b2: int | None = None
    p2: int | None = None
    r2: int | None = None
    controlResponsibleRoleId: int | None = None
    implementWhenId: int | None = None


class RequestedBy(Strict):
    userRef: str = Field(min_length=1, max_length=200)
    role: str = Field(max_length=50)


class CheckRequest(Strict):
    schemaVersion: Literal["1.0"]
    tenant: Tenant
    end: EndInfo
    context: Context
    measures: list[Measure] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list, max_length=MAX_RISK_ROWS)
    factorAnswers: dict[str, Tri] = Field(default_factory=dict)
    locale: Literal["ru", "kk"] = "ru"
    requestedBy: RequestedBy

    @field_validator("measures")
    @classmethod
    def _limit_rows(cls, measures: list[Measure]) -> list[Measure]:
        counts: dict[str, int] = {}
        for measure in measures:
            counts[measure.section] = counts.get(measure.section, 0) + 1
            if counts[measure.section] > MAX_ROWS_PER_SECTION:
                raise ValueError(f"more than {MAX_ROWS_PER_SECTION} rows in a section")
        return measures


class Target(Strict):
    type: Literal["measure", "risk", "risks", "section", "flag", "factor", "description"]
    section: str | None = None
    rowId: str | None = None
    field: str | None = None
    flag: str | None = None
    factorCode: str | None = None


class Recommendation(Strict):
    mode: Literal["replace", "append", "set_field", "select_ids", "not_applicable"]
    text: Text = Field(default_factory=Text)
    catalogItemIds: list[int] = Field(default_factory=list)
    field: str | None = None
    value: str | None = None
    generated: bool = False


class Basis(Strict):
    doc: str = ""
    title: str = ""
    clause: str = ""
    url: str = ""
    status: Literal["verified", "to_verify", "linked", "none"] = "none"
    excerpt: str = ""


class Autofix(Strict):
    rowId: str
    before: str
    after: str


class Finding(Strict):
    findingId: str = ""
    ruleCode: str
    severity: Severity
    kind: Kind = "issue"
    source: Literal["rules", "ai"] = "rules"
    target: Target
    title: Text
    message: Text
    evidence: str = ""
    recommendation: Recommendation | None = None
    basis: Basis = Field(default_factory=Basis)
    autofix: Autofix | None = None
    blocking: bool = False
    hidden: bool = False  # kept in the journal, not shown (LLM said pass / not_applicable)
    generated: bool = False
    confidence: float = 1.0


class Question(Strict):
    factorCode: str
    text: Text
    options: list[str] = Field(default_factory=lambda: ["yes", "no"])


class Gate(Strict):
    allowed: bool
    blockers: list[dict[str, str]] = Field(default_factory=list)


GateResult = Gate


class CheckResult(Strict):
    runId: str
    status: Literal["code_done", "done", "llm_unavailable", "failed"]
    llm: Literal["pending", "skipped", "done", "unavailable", "invalid"]
    rulesetVersion: str
    catalogVersion: str = ""
    contentHash: str
    model: str | None = None
    promptVersion: str | None = None
    summary: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    questions: list[Question] = Field(default_factory=list)
    autofixes: list[dict[str, str]] = Field(default_factory=list)


class AnswersRequest(Strict):
    contentHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    factorAnswers: dict[str, Tri]


class ActionRequest(Strict):
    action: Literal["accept", "edit", "reject", "answer", "hide", "reopen"]
    reasonCode: Literal["not_applicable", "done_otherwise", "ai_error", "other"] | None = None
    comment: str | None = Field(default=None, max_length=MAX_TEXT)
    appliedText: str | None = Field(default=None, max_length=MAX_TEXT)
    userRef: str | None = Field(default=None, max_length=200)
    userRole: str | None = Field(default=None, max_length=50)
    answer: Tri | None = None
