"""Document base endpoints (section 14)."""

from typing import Annotated, Any

from fastapi import APIRouter, File, Form, UploadFile
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticError

from aicheck.api.deps import AdminP, AnyP, Rt
from aicheck.db import kb_queries
from aicheck.errors import NotFound, ValidationError
from aicheck.kb import ingest, versions
from aicheck.logging import security_event

router = APIRouter()


class DocPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    meta: dict[str, Any] | None = None
    org_codes: list[str] | None = None
    work_types: list[str] | None = None
    categories: list[str] | None = None


class ClausePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    clause_no: str | None = Field(default=None, max_length=40)
    body: str | None = Field(default=None, max_length=20000)
    excluded: bool | None = None


class RefItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_code: str = Field(max_length=20)
    doc_code: str = Field(max_length=60)
    clause_no: str = Field(max_length=40)


class RefsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refs: list[RefItem] = Field(max_length=2000)


@router.post("/v1/admin/kb/documents", status_code=201)
def upload_document(
    rt: Rt, principal: AdminP, file: Annotated[UploadFile, File()], meta: Annotated[str, Form()]
) -> dict[str, Any]:
    try:
        parsed = ingest.DocMeta.model_validate_json(meta)
    except PydanticError as exc:
        raise ValidationError("document metadata is invalid", "meta") from exc
    limit = rt.settings.kb_max_file_mb * 1024 * 1024
    data = file.file.read(limit + 1)
    doc_id = ingest.create_document(rt, parsed, file.filename or "", data, principal.sub)
    security_event("admin_action", action="kb_upload", actor=principal.sub, document_id=doc_id)
    return {"id": doc_id, "status": "draft"}


@router.get("/v1/admin/kb/documents")
def list_documents(
    rt: Rt,
    principal: AdminP,
    org: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> Any:
    with rt.db.tx() as conn:
        return jsonable_encoder(kb_queries.list_documents(conn, org, category, status))


@router.get("/v1/admin/kb/documents/{doc_id}")
def get_document(doc_id: int, rt: Rt, principal: AdminP) -> Any:
    with rt.db.tx() as conn:
        doc = kb_queries.get_document(conn, doc_id)
        if doc is None:
            raise NotFound("document not found")
        clauses = kb_queries.list_clauses(conn, doc_id)
    return jsonable_encoder({**doc, "clauses": clauses})


@router.patch("/v1/admin/kb/documents/{doc_id}")
def patch_document(doc_id: int, body: DocPatch, rt: Rt, principal: AdminP) -> dict[str, str]:
    fields = body.model_dump(exclude_none=True)
    with rt.db.tx() as conn:
        doc = kb_queries.get_document(conn, doc_id)
        if doc is None:
            raise NotFound("document not found")
        if "meta" in fields:
            fields["meta"] = {**doc["meta"], **fields["meta"]}
        if fields:
            kb_queries.update_document(conn, doc_id, fields)
        kb_queries.insert_event(conn, doc_id, "doc_edit", principal.sub, {"fields": sorted(fields)})
    return {"status": "ok"}


@router.patch("/v1/admin/kb/clauses/{clause_id}")
def patch_clause(clause_id: int, body: ClausePatch, rt: Rt, principal: AdminP) -> dict[str, str]:
    with rt.db.tx() as conn:
        versions.edit_clause(conn, clause_id, body.model_dump(exclude_none=True), principal.sub)
    return {"status": "ok"}


@router.post("/v1/admin/kb/documents/{doc_id}/activate")
def activate_document(doc_id: int, rt: Rt, principal: AdminP) -> dict[str, Any]:
    with rt.db.tx() as conn:
        versions.activate(conn, doc_id, principal.sub)
    security_event("admin_action", action="kb_activate", actor=principal.sub, document_id=doc_id)
    return {"id": doc_id, "status": "active"}


@router.get("/v1/admin/kb/documents/{doc_id}/diff")
def document_diff(doc_id: int, rt: Rt, principal: AdminP) -> Any:
    with rt.db.tx() as conn:
        return jsonable_encoder(versions.diff(conn, doc_id))


@router.put("/v1/admin/kb/rule-refs")
def put_rule_refs(body: RefsBody, rt: Rt, principal: AdminP) -> dict[str, int]:
    with rt.db.tx() as conn:
        kb_queries.set_rule_refs(conn, [r.model_dump() for r in body.refs])
        kb_queries.insert_event(conn, None, "rule_refs", principal.sub, {"count": len(body.refs)})
    return {"count": len(body.refs)}


@router.get("/v1/admin/kb/rule-refs/broken")
def broken_refs(rt: Rt, principal: AdminP) -> Any:
    with rt.db.tx() as conn:
        return jsonable_encoder(kb_queries.broken_refs(conn))


@router.get("/v1/kb/clauses/{code}/{clause_no:path}")
def get_clause(code: str, clause_no: str, rt: Rt, principal: AnyP) -> Any:
    with rt.db.tx() as conn:
        row = kb_queries.clause_by_ref(conn, code, clause_no)
    if row is None:
        raise NotFound("clause not found")
    meta = row["meta"]
    return {
        "code": code,
        "clauseNo": row["clause_no"],
        "heading": row["heading"],
        "text": row["body"],
        "title": meta.get("title", ""),
        "url": meta.get("source_url", ""),
    }
