"""Upload validation, parse jobs and document metadata."""

import hashlib
import io
import logging
import multiprocessing
import zipfile
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aicheck.db import kb_queries
from aicheck.errors import ValidationError
from aicheck.kb.parse import ParseError, parse_document
from aicheck.runtime import Runtime

log = logging.getLogger(__name__)
PARSE_TIMEOUT_S = 60
EXTENSIONS = (".pdf", ".docx", ".txt", ".md")


class DocMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(pattern=r"^[A-Za-z0-9._\-]{1,60}$")
    title: str = Field(min_length=1, max_length=500)
    number: str = Field(default="", max_length=100)
    adopted_at: str = Field(default="", max_length=20)
    issuer: str = Field(default="", max_length=200)
    edition_date: str = Field(default="", max_length=20)
    source_url: str = Field(default="", pattern=r"^(https://\S+)?$", max_length=500)
    layer: Literal["law", "corporate", "org"]
    language: Literal["ru", "kk"] = "ru"
    org_codes: list[str] = Field(default_factory=list)
    work_types: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)


def validate_upload(file_name: str, data: bytes, max_mb: int) -> None:
    """Type by signature (not by name), size limit."""
    if len(data) > max_mb * 1024 * 1024:
        raise ValidationError("file is too large", "file", "file_too_large")
    name = file_name.lower()
    if not name.endswith(EXTENSIONS):
        raise ValidationError("unsupported file type", "file", "file_type_invalid")
    ok = (
        data.startswith(b"%PDF")
        if name.endswith(".pdf")
        else _is_docx(data)
        if name.endswith(".docx")
        else b"\x00" not in data
    )
    if not ok:
        raise ValidationError("file content does not match its type", "file", "file_type_invalid")


def _is_docx(data: bytes) -> bool:
    if not data.startswith(b"PK\x03\x04"):
        return False
    try:
        return "word/document.xml" in zipfile.ZipFile(io.BytesIO(data)).namelist()
    except zipfile.BadZipFile:
        return False


def create_document(rt: Runtime, meta: DocMeta, file_name: str, data: bytes, user_ref: str) -> int:
    validate_upload(file_name, data, rt.settings.kb_max_file_mb)
    with rt.db.tx() as conn:
        doc_id = kb_queries.insert_document(
            conn,
            {
                "code": meta.code,
                "meta": meta.model_dump(exclude={"org_codes", "work_types", "categories"}),
                "org_codes": meta.org_codes,
                "work_types": meta.work_types,
                "categories": meta.categories,
                "file_name": file_name,
                "file_bytes": data,
                "file_sha256": hashlib.sha256(data).hexdigest(),
                "created_by": user_ref,
            },
        )
        kb_queries.enqueue_parse(conn, doc_id)
        kb_queries.insert_event(
            conn, doc_id, "upload", user_ref, {"code": meta.code, "bytes": len(data)}
        )
    return doc_id


def _parse_child(pipe: Any, file_name: str, data: bytes) -> None:
    try:
        result = parse_document(file_name, data)
        clauses = [vars(c) for c in result.clauses]
        pipe.send(("ok", clauses, result.report))
    except ParseError as exc:
        pipe.send(("error", str(exc), {}))
    except Exception as exc:  # noqa: BLE001 - the child must always answer
        pipe.send(("error", f"parse failed: {type(exc).__name__}", {}))


def parse_with_timeout(
    file_name: str, data: bytes, timeout_s: float = PARSE_TIMEOUT_S
) -> tuple[str, Any, dict[str, Any]]:
    """Parse in a child process that is killed after the timeout (hostile files cannot hang us)."""
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_parse_child, args=(child, file_name, data), daemon=True)
    proc.start()
    child.close()
    try:
        if parent.poll(timeout_s):
            return parent.recv()  # type: ignore[no-any-return]
        return ("error", "parse timeout", {})
    except EOFError:
        return ("error", "parse failed", {})
    finally:
        if proc.is_alive():
            proc.terminate()
        proc.join(5)


def process_next(rt: Runtime) -> bool:
    """Take one parse job; True when a job was handled."""
    with rt.db.tx() as conn:
        job = kb_queries.take_parse_job(conn)
    if job is None:
        return False
    with rt.db.tx() as conn:
        file = kb_queries.get_document_file(conn, job["document_id"])
    assert file is not None  # noqa: S101 - the job references an existing document
    state, payload, report = parse_with_timeout(file["file_name"], bytes(file["file_bytes"]))
    with rt.db.tx() as conn:
        if state == "ok":
            rows = [
                {
                    **c,
                    "heading": c["heading"],
                    "body_sha256": hashlib.sha256(c["body"].encode()).hexdigest(),
                }
                for c in payload
            ]
            kb_queries.replace_clauses(conn, job["document_id"], rows)
            kb_queries.set_parse_report(conn, job["document_id"], report)
        else:
            kb_queries.set_parse_report(conn, job["document_id"], {"error": payload})
        kb_queries.finish_parse_job(conn, job["id"], "done" if state == "ok" else "failed")
        kb_queries.insert_event(conn, job["document_id"], "parse", "system", {"state": state})
    return True
