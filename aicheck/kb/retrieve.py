"""Clause package for a check: rule links + full-text search, with a size limit."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection

from aicheck.contracts import Basis
from aicheck.db import kb_queries
from aicheck.engine.normalize import significant_words

EXCERPT = 300
MAX_QUERY_WORDS = 20


@dataclass(frozen=True)
class ClauseRef:
    ref: str  # "RK-355:33"
    doc_code: str
    clause_no: str
    title: str
    url: str
    text: str


def kb_version(conn: Connection) -> int:
    return kb_queries.kb_version(conn)


def _basis(row: dict[str, Any]) -> Basis:
    meta = row["meta"]
    return Basis(
        doc=row["doc_code"],
        title=str(meta.get("title", "")),
        clause=row["clause_no"],
        url=str(meta.get("source_url", "")),
        status="linked",
        excerpt=str(row["body"])[:EXCERPT],
    )


def rule_basis(conn: Connection) -> dict[str, Basis]:
    """First linked clause of every rule: the basis shown in code findings."""
    result: dict[str, Basis] = {}
    for row in kb_queries.all_rule_refs(conn):
        result.setdefault(row["rule_code"], _basis(row))
    return result


def _ref(row: dict[str, Any]) -> ClauseRef:
    meta = row["meta"]
    return ClauseRef(
        ref=f"{row['code']}:{row['clause_no']}",
        doc_code=row["code"],
        clause_no=row["clause_no"],
        title=str(meta.get("title", "")),
        url=str(meta.get("source_url", "")),
        text=str(row["body"]),
    )


def search_query(texts: list[str]) -> str:
    words: list[str] = []
    for text in texts:
        for word in significant_words(text):
            if len(word) >= 4 and word not in words:
                words.append(word)
    return " or ".join(words[:MAX_QUERY_WORDS])


def build_package(
    conn: Connection,
    rule_codes: list[str],
    org: str,
    work_type: str,
    category: str,
    texts: list[str],
    *,
    fts_limit: int,
    max_chars: int,
) -> list[ClauseRef]:
    """Clauses linked to the rules first, then up to `fts_limit` found by full-text search."""
    rows = kb_queries.linked_clauses(conn, rule_codes, org, work_type, category)
    refs = [_ref(r) for r in rows]
    query = search_query(texts)
    if query and fts_limit > 0:
        known = {r.ref for r in refs}
        found = kb_queries.search_clauses(conn, query, org, work_type, category, fts_limit)
        refs += [r for r in map(_ref, found) if r.ref not in known]
    return _within(refs, max_chars)


def _within(refs: list[ClauseRef], max_chars: int) -> list[ClauseRef]:
    kept, total = [], 0
    for ref in refs:
        if total + len(ref.text) > max_chars:
            break
        kept.append(ref)
        total += len(ref.text)
    return kept
