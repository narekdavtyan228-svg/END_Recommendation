"""Activation, comparison of versions, links between rules and clauses."""

import hashlib
from typing import Any

from sqlalchemy import Connection

from aicheck.db import kb_queries
from aicheck.errors import Conflict, NotFound


def activate(conn: Connection, doc_id: int, user_ref: str) -> None:
    doc = kb_queries.get_document(conn, doc_id)
    if doc is None:
        raise NotFound("document not found")
    if doc["status"] != "draft":
        raise Conflict("only a draft can be activated", code="not_draft")
    report = doc["parse_report"] or {}
    if not report or "error" in report:
        raise Conflict("document has not been parsed", code="not_parsed")
    previous = kb_queries.active_document(conn, doc["code"])
    if previous:
        kb_queries.set_status(conn, previous["id"], "archived")
    kb_queries.set_status(conn, doc_id, "active")
    kb_queries.insert_event(
        conn,
        doc_id,
        "activate",
        user_ref,
        {"code": doc["code"], "replaced": previous["id"] if previous else None},
    )


def _by_no(conn: Connection, doc_id: int) -> dict[str, dict[str, Any]]:
    return {c["clause_no"]: c for c in kb_queries.list_clauses(conn, doc_id) if not c["excluded"]}


def diff(conn: Connection, doc_id: int) -> dict[str, Any]:
    """Clauses added, removed and changed against the active version of the same code."""
    doc = kb_queries.get_document(conn, doc_id)
    if doc is None:
        raise NotFound("document not found")
    active = kb_queries.active_document(conn, doc["code"])
    new = _by_no(conn, doc_id)
    old = _by_no(conn, active["id"]) if active and active["id"] != doc_id else {}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(
        n for n in set(new) & set(old) if new[n]["body_sha256"] != old[n]["body_sha256"]
    )
    touched = removed + changed
    rules = kb_queries.refs_for_rules(conn, doc["code"], touched) if touched else []
    return {
        "code": doc["code"],
        "against": active["id"] if active else None,
        "added": added,
        "removed": removed,
        "changed": changed,
        "affected_rules": rules,
    }


def edit_clause(conn: Connection, clause_id: int, fields: dict[str, Any], user_ref: str) -> None:
    clause = kb_queries.get_clause(conn, clause_id)
    if clause is None:
        raise NotFound("clause not found")
    doc = kb_queries.get_document(conn, clause["document_id"])
    if doc is None or doc["status"] != "draft":
        raise Conflict("clauses can be edited in a draft only", code="not_draft")
    update = dict(fields)
    if "body" in update:
        update["body_sha256"] = hashlib.sha256(update["body"].encode()).hexdigest()
    kb_queries.update_clause(conn, clause_id, update)
    kb_queries.insert_event(
        conn, doc["id"], "clause_edit", user_ref, {"clause_id": clause_id, "fields": sorted(fields)}
    )
