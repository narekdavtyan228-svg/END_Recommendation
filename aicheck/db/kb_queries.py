"""SQL of the normative document base (section 14).

Statements marked `nosec B608` are assembled from module constants or whitelisted column names only;
every value is a bound parameter.
"""

import json
from typing import Any

from sqlalchemy import Connection, text

from aicheck.db.queries import Row, _all, _j, _one

FILTER = (
    "(cardinality(d.org_codes) = 0 OR :org = ANY(d.org_codes)) AND "
    "(cardinality(d.work_types) = 0 OR :wt = ANY(d.work_types)) AND "
    "(cardinality(d.categories) = 0 OR :cat = ANY(d.categories))"
)


def insert_document(conn: Connection, doc: Row) -> int:
    row = _one(
        conn,
        "INSERT INTO aicheck.kb_document (code, version_no, status, meta, org_codes, work_types, categories, "
        "file_name, file_bytes, file_sha256, created_by) VALUES (:code, "
        "(SELECT coalesce(max(version_no), 0) + 1 FROM aicheck.kb_document WHERE code = :code), 'draft', "
        "CAST(:meta AS jsonb), :org_codes, :work_types, :categories, :file_name, :file_bytes, :file_sha256, "
        ":created_by) RETURNING id",
        **{**doc, "meta": _j(doc["meta"])},
    )
    return int(row["id"]) if row else -1


DOC_COLUMNS = (
    "id, code, version_no, status, meta, org_codes, work_types, categories, file_name, file_sha256, "
    "parse_report, created_by, created_at"
)


def list_documents(
    conn: Connection, org: str | None, category: str | None, status: str | None
) -> list[Row]:
    return _all(
        conn,
        f"SELECT {DOC_COLUMNS} FROM aicheck.kb_document d WHERE (CAST(:s AS text) IS NULL OR status = :s) "  # nosec B608
        "AND (CAST(:org AS text) IS NULL OR cardinality(org_codes) = 0 OR :org = ANY(org_codes)) "
        "AND (CAST(:cat AS text) IS NULL OR cardinality(categories) = 0 OR :cat = ANY(categories)) "
        "ORDER BY code, version_no DESC",
        s=status,
        org=org,
        cat=category,
    )


def get_document(conn: Connection, doc_id: int) -> Row | None:
    return _one(conn, f"SELECT {DOC_COLUMNS} FROM aicheck.kb_document d WHERE id = :i", i=doc_id)  # nosec B608


def get_document_file(conn: Connection, doc_id: int) -> Row | None:
    return _one(
        conn,
        "SELECT id, file_name, file_bytes, meta FROM aicheck.kb_document WHERE id = :i",
        i=doc_id,
    )


DOC_FIELDS = frozenset({"meta", "org_codes", "work_types", "categories"})
CLAUSE_FIELDS = frozenset({"clause_no", "body", "body_sha256", "excluded"})


def _checked(fields: Row, allowed: frozenset[str]) -> None:
    """Column names go into the SQL text, so only known names are accepted."""
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError("unknown column")


def update_document(conn: Connection, doc_id: int, fields: Row) -> None:
    _checked(fields, DOC_FIELDS)
    sets = ", ".join(
        f"{k} = {'CAST(:' + k + ' AS jsonb)' if k == 'meta' else ':' + k}" for k in fields
    )
    params = {k: (_j(v) if k == "meta" else v) for k, v in fields.items()}
    statement = f"UPDATE aicheck.kb_document SET {sets} WHERE id = :id"  # nosec B608
    conn.execute(text(statement), {**params, "id": doc_id})


def set_parse_report(conn: Connection, doc_id: int, report: Row) -> None:
    conn.execute(
        text("UPDATE aicheck.kb_document SET parse_report = CAST(:r AS jsonb) WHERE id = :i"),
        {"r": _j(report), "i": doc_id},
    )


def replace_clauses(conn: Connection, doc_id: int, clauses: list[Row]) -> None:
    conn.execute(text("DELETE FROM aicheck.kb_clause WHERE document_id = :i"), {"i": doc_id})
    if clauses:
        conn.execute(
            text(
                "INSERT INTO aicheck.kb_clause (document_id, clause_no, heading, body, body_sha256, position) "
                "VALUES (:document_id, :clause_no, :heading, :body, :body_sha256, :position)"
            ),
            [{**c, "document_id": doc_id} for c in clauses],
        )


def list_clauses(conn: Connection, doc_id: int) -> list[Row]:
    return _all(
        conn,
        "SELECT id, document_id, clause_no, heading, body, body_sha256, position, excluded "
        "FROM aicheck.kb_clause WHERE document_id = :i ORDER BY position",
        i=doc_id,
    )


def get_clause(conn: Connection, clause_id: int) -> Row | None:
    return _one(conn, "SELECT * FROM aicheck.kb_clause WHERE id = :i", i=clause_id)


def update_clause(conn: Connection, clause_id: int, fields: Row) -> None:
    _checked(fields, CLAUSE_FIELDS)
    sets = ", ".join(f"{k} = :{k}" for k in fields)
    statement = f"UPDATE aicheck.kb_clause SET {sets} WHERE id = :id"  # nosec B608
    conn.execute(text(statement), {**fields, "id": clause_id})


def active_document(conn: Connection, code: str) -> Row | None:
    return _one(
        conn,
        f"SELECT {DOC_COLUMNS} FROM aicheck.kb_document d WHERE code = :c AND status = 'active'",  # nosec B608
        c=code,
    )


def set_status(conn: Connection, doc_id: int, status: str) -> None:
    conn.execute(
        text("UPDATE aicheck.kb_document SET status = :s WHERE id = :i"), {"s": status, "i": doc_id}
    )


def insert_event(
    conn: Connection, document_id: int | None, action: str, user_ref: str, details: Any = None
) -> None:
    conn.execute(
        text(
            "INSERT INTO aicheck.kb_event (document_id, action, user_ref, details) "
            "VALUES (:d, :a, :u, CAST(:x AS jsonb))"
        ),
        {
            "d": document_id,
            "a": action,
            "u": user_ref,
            "x": json.dumps(details or {}, ensure_ascii=False),
        },
    )


def kb_version(conn: Connection) -> int:
    row = _one(conn, "SELECT coalesce(max(id), 0) AS v FROM aicheck.kb_event")
    return int(row["v"]) if row else 0


def set_rule_refs(conn: Connection, refs: list[Row]) -> None:
    """Replace the links of every rule mentioned in `refs`."""
    for code in sorted({r["rule_code"] for r in refs}):
        conn.execute(text("DELETE FROM aicheck.kb_rule_ref WHERE rule_code = :c"), {"c": code})
    if refs:
        conn.execute(
            text(
                "INSERT INTO aicheck.kb_rule_ref (rule_code, doc_code, clause_no) "
                "VALUES (:rule_code, :doc_code, :clause_no) ON CONFLICT DO NOTHING"
            ),
            refs,
        )


def broken_refs(conn: Connection) -> list[Row]:
    return _all(
        conn,
        "SELECT r.rule_code, r.doc_code, r.clause_no FROM aicheck.kb_rule_ref r WHERE NOT EXISTS ("
        "SELECT 1 FROM aicheck.kb_document d JOIN aicheck.kb_clause c ON c.document_id = d.id "
        "WHERE d.code = r.doc_code AND d.status = 'active' AND c.clause_no = r.clause_no AND NOT c.excluded) "
        "ORDER BY 1, 2, 3",
    )


def refs_for_rules(conn: Connection, doc_code: str, clause_nos: list[str]) -> list[Row]:
    return _all(
        conn,
        "SELECT rule_code, doc_code, clause_no FROM aicheck.kb_rule_ref "
        "WHERE doc_code = :d AND clause_no = ANY(:n) ORDER BY 1, 3",
        d=doc_code,
        n=clause_nos,
    )


def all_rule_refs(conn: Connection) -> list[Row]:
    return _all(
        conn,
        "SELECT r.rule_code, r.doc_code, r.clause_no, d.meta, c.body FROM aicheck.kb_rule_ref r "
        "JOIN aicheck.kb_document d ON d.code = r.doc_code AND d.status = 'active' "
        "JOIN aicheck.kb_clause c ON c.document_id = d.id AND c.clause_no = r.clause_no AND NOT c.excluded "
        "ORDER BY r.rule_code, r.doc_code, r.clause_no",
    )


def clause_by_ref(conn: Connection, code: str, clause_no: str) -> Row | None:
    return _one(
        conn,
        "SELECT d.code, d.meta, c.clause_no, c.heading, c.body FROM aicheck.kb_document d "
        "JOIN aicheck.kb_clause c ON c.document_id = d.id WHERE d.code = :c AND d.status = 'active' "
        "AND c.clause_no = :n AND NOT c.excluded",
        c=code,
        n=clause_no,
    )


def linked_clauses(
    conn: Connection, rule_codes: list[str], org: str, wt: str, cat: str
) -> list[Row]:
    return _all(
        conn,
        "SELECT DISTINCT d.code, d.meta, c.clause_no, c.heading, c.body, c.position FROM aicheck.kb_rule_ref r "  # nosec B608
        "JOIN aicheck.kb_document d ON d.code = r.doc_code AND d.status = 'active' "
        "JOIN aicheck.kb_clause c ON c.document_id = d.id AND c.clause_no = r.clause_no AND NOT c.excluded "
        f"WHERE r.rule_code = ANY(:rules) AND {FILTER} ORDER BY d.code, c.position",
        rules=rule_codes,
        org=org,
        wt=wt,
        cat=cat,
    )


def search_clauses(
    conn: Connection, query: str, org: str, wt: str, cat: str, limit: int
) -> list[Row]:
    return _all(
        conn,
        "SELECT d.code, d.meta, c.clause_no, c.heading, c.body, "  # nosec B608
        "ts_rank(c.tsv, websearch_to_tsquery('russian', :q)) AS rank FROM aicheck.kb_clause c "
        "JOIN aicheck.kb_document d ON d.id = c.document_id AND d.status = 'active' "
        f"WHERE c.tsv @@ websearch_to_tsquery('russian', :q) AND NOT c.excluded AND {FILTER} "
        "ORDER BY rank DESC, d.code, c.position LIMIT :n",
        q=query,
        org=org,
        wt=wt,
        cat=cat,
        n=limit,
    )


def enqueue_parse(conn: Connection, doc_id: int) -> None:
    conn.execute(text("INSERT INTO aicheck.kb_job (document_id) VALUES (:d)"), {"d": doc_id})


def take_parse_job(conn: Connection) -> Row | None:
    return _one(
        conn,
        "UPDATE aicheck.kb_job SET state = 'running', locked_at = now(), attempts = attempts + 1 "
        "WHERE id = (SELECT id FROM aicheck.kb_job WHERE state = 'queued' AND not_before <= now() "
        "ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
    )


def finish_parse_job(conn: Connection, job_id: int, state: str) -> None:
    conn.execute(
        text("UPDATE aicheck.kb_job SET state = :s, locked_at = NULL WHERE id = :i"),
        {"s": state, "i": job_id},
    )
