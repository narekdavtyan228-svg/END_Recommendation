"""Stage 1: migrations, roles, append-only journal, queries."""

import re
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aicheck.db import migrate, queries
from tests.conftest import ADMIN_URL, _url

pytestmark = pytest.mark.stage1
ROOT = Path(__file__).resolve().parents[2]
TABLES = {
    "ruleset",
    "catalog_snapshot",
    "check_run",
    "run_event",
    "finding",
    "finding_action",
    "job",
    "callback_outbox",
    "llm_cache",
    "kb_document",
    "kb_clause",
    "kb_rule_ref",
    "kb_event",
    "kb_job",
}
JOURNAL = ("check_run", "run_event", "finding", "finding_action", "kb_event")


def test_migrations_go_up_and_down(db_names: dict[str, str]) -> None:
    name = db_names["name"] + "_mig"
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
        )
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = _url("postgres", "postgres", name)
    try:
        migrate.upgrade(url)
        with psycopg.connect(url) as conn:
            found = {
                r[0]
                for r in conn.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'aicheck'"
                )
            }
            assert found >= TABLES
        migrate.downgrade(url)
        with psycopg.connect(url) as conn:
            assert not conn.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'aicheck'"
            ).fetchone()
        migrate.upgrade(url)  # and up again
    finally:
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


def _run_row(ruleset_id: int) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "end_ref": "e1",
        "content_hash": "sha256:" + "a" * 64,
        "ruleset_id": ruleset_id,
        "catalog_version": "v1",
        "request": {"requestedBy": {"userRef": "u1"}},
    }


@pytest.fixture
def run_id(db) -> str:
    with db.tx() as conn:
        rid = queries.insert_ruleset(conn, "OMG", "v-test", {"a": 1}, "sha")
        row = _run_row(rid)
        queries.insert_run(conn, row)
        queries.insert_event(conn, row["id"], "code_done", "skipped")
    return row["id"]


@pytest.mark.parametrize("table", JOURNAL)
def test_sec02_app_role_cannot_update_or_delete_the_journal(db, run_id: str, table: str) -> None:
    for statement in (
        f"UPDATE aicheck.{table} SET created_at = now()",
        f"DELETE FROM aicheck.{table}",
    ):
        with pytest.raises(DBAPIError), db.tx() as conn:
            conn.execute(text(statement))
    with pytest.raises(DBAPIError), db.tx() as conn:
        conn.execute(text(f"TRUNCATE aicheck.{table} CASCADE"))


@pytest.mark.parametrize("table", JOURNAL)
def test_sec02_triggers_stop_even_the_owner(db_names: dict[str, str], table: str) -> None:
    """The append-only triggers hold for the owner role as well (no way to switch them off in code)."""
    with psycopg.connect(db_names["owner"], autocommit=False) as conn:
        conn.execute(
            "INSERT INTO aicheck.ruleset (org_code, version, status, body, body_sha256) VALUES ('X','t','draft','{}','s')"
        )
        rid = conn.execute("SELECT id FROM aicheck.ruleset WHERE version = 't'").fetchone()[0]
        run = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO aicheck.check_run (id, end_ref, content_hash, ruleset_id, catalog_version, request) "
            "VALUES (%s,'e','h',%s,'v','{}')",
            (run, rid),
        )
        conn.execute(
            "INSERT INTO aicheck.run_event (run_id, status, llm_status) VALUES (%s,'code_done','skipped')",
            (run,),
        )
        conn.execute("INSERT INTO aicheck.kb_event (action, user_ref) VALUES ('a','u')")
        fid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO aicheck.finding (id, run_id, rule_code, source, severity, kind, target, body) "
            "VALUES (%s,%s,'S01','rules','critical','issue','{}','{}')",
            (fid, run),
        )
        conn.execute(
            "INSERT INTO aicheck.finding_action (id, finding_id, action, user_ref, user_role) "
            "VALUES (%s,%s,'accept','u','r')",
            (str(uuid.uuid4()), fid),
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only"):
            conn.execute(f"UPDATE aicheck.{table} SET created_at = now()")
        conn.rollback()


def test_sec01_no_code_deletes_the_journal() -> None:
    pattern = re.compile(
        r"\b(DELETE\s+FROM|TRUNCATE(\s+TABLE)?)\s+(aicheck\.)?(check_run|run_event|finding|finding_action|kb_event)\b",
        re.I,
    )
    for path in list((ROOT / "aicheck").rglob("*.py")):
        assert not pattern.search(path.read_text(encoding="utf-8")), path
    assert not any(
        "DELETE FROM" in p.read_text(encoding="utf-8").upper().replace("OR DELETE", "")
        for p in (ROOT / "aicheck/db/migrations").rglob("*.py")
    )


def test_app_role_has_no_dangerous_privileges(db_names: dict[str, str]) -> None:
    with psycopg.connect(db_names["owner"]) as conn:
        rows = conn.execute(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE grantee = 'aicheck_app' AND table_schema = 'aicheck'"
        ).fetchall()
    granted = {(t, p) for t, p in rows}
    for table in JOURNAL:
        assert (table, "INSERT") in granted and (table, "SELECT") in granted
        assert not {(table, p) for p in ("UPDATE", "DELETE", "TRUNCATE")} & granted


def test_ruleset_activation_keeps_one_active_package(db) -> None:
    with db.tx() as conn:
        a = queries.insert_ruleset(conn, "OMG", "1", {"v": 1}, "s1")
        b = queries.insert_ruleset(conn, "OMG", "2", {"v": 2}, "s2")
        assert queries.insert_ruleset(conn, "OMG", "2", {"v": 2}, "s2") == -1  # duplicate version
        queries.activate_ruleset(conn, a, "OMG")
        assert queries.get_active_ruleset(conn, "OMG")["id"] == a
        queries.activate_ruleset(conn, b, "OMG")
        assert queries.get_active_ruleset(conn, "OMG")["id"] == b
        assert queries.get_ruleset(conn, a)["status"] == "archived"


def test_catalog_versions_are_immutable_inserts(db) -> None:
    with db.tx() as conn:
        assert queries.insert_catalog(conn, "OMG", "c1", {"a": 1})
        assert not queries.insert_catalog(conn, "OMG", "c1", {"a": 2})
        assert queries.get_catalog(conn, "OMG", "c1")["body"] == {"a": 1}
        assert queries.latest_catalog_version(conn, "OMG") == "c1"
        assert queries.get_catalog(conn, "OMG", "zz") is None


def test_run_unique_key_and_last_event_wins(db, run_id: str) -> None:
    with db.tx() as conn:
        run = queries.get_run(conn, run_id)
        assert queries.find_run(conn, "e1", run["content_hash"], run["ruleset_id"])[
            "id"
        ] == uuid.UUID(run_id)
        queries.insert_event(
            conn, run_id, "done", "done", model="m", prompt_version="v1", duration_ms=5
        )
        assert queries.last_event(conn, run_id)["status"] == "done"
    with pytest.raises(DBAPIError), db.tx() as conn:
        queries.insert_run(conn, {**_run_row(run["ruleset_id"]), "id": str(uuid.uuid4())})


def test_action_idempotency_key_is_unique(db, run_id: str) -> None:
    fid = str(uuid.uuid4())
    with db.tx() as conn:
        queries.insert_findings(
            conn,
            run_id,
            [
                {
                    "id": fid,
                    "rule_code": "S01",
                    "source": "rules",
                    "severity": "critical",
                    "kind": "issue",
                    "target": {},
                    "body": {},
                    "generated": False,
                    "confidence": 1,
                }
            ],
        )
        action = {
            "id": str(uuid.uuid4()),
            "finding_id": fid,
            "action": "accept",
            "reason_code": None,
            "comment": None,
            "applied_text": None,
            "user_ref": "u",
            "user_role": "r",
            "idempotency_key": "k1",
        }
        assert queries.insert_action(conn, action)
        assert not queries.insert_action(conn, {**action, "id": str(uuid.uuid4())})
        assert queries.latest_actions(conn, run_id) == {fid: "accept"}


def test_rate_counters(db, run_id: str, frozen_clock) -> None:
    from datetime import timedelta

    from aicheck import clock

    with db.tx() as conn:
        since = clock.now() - timedelta(days=3650)
        assert queries.count_runs_since(conn, since) == 1
        assert queries.count_runs_since(conn, since, "u1") == 1
        assert queries.count_runs_since(conn, since, "nobody") == 0


def test_cache_roundtrip(db) -> None:
    with db.tx() as conn:
        assert queries.get_cache(conn, "k") is None
        queries.put_cache(conn, "k", {"x": [1]})
        assert queries.get_cache(conn, "k") == {"x": [1]}
        assert queries.purge_cache(conn, 30) == 0
