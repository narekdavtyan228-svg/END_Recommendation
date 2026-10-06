"""All SQL of the service (SQLAlchemy Core, explicit statements)."""

import json
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

Row = dict[str, Any]


def _one(conn: Connection, sql: str, **params: Any) -> Row | None:
    result = conn.execute(text(sql), params).mappings().first()
    return dict(result) if result else None


def _all(conn: Connection, sql: str, **params: Any) -> list[Row]:
    return [dict(r) for r in conn.execute(text(sql), params).mappings().all()]


def _j(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


# --- rule packages ---------------------------------------------------------------------------


def insert_ruleset(conn: Connection, org: str, version: str, body: dict[str, Any], sha: str) -> int:
    row = _one(
        conn,
        "INSERT INTO aicheck.ruleset (org_code, version, status, body, body_sha256) "
        "VALUES (:o, :v, 'draft', CAST(:b AS jsonb), :s) "
        "ON CONFLICT (org_code, version) DO NOTHING RETURNING id",
        o=org,
        v=version,
        b=_j(body),
        s=sha,
    )
    return int(row["id"]) if row else -1


def get_ruleset(conn: Connection, ruleset_id: int) -> Row | None:
    return _one(conn, "SELECT * FROM aicheck.ruleset WHERE id = :i", i=ruleset_id)


def get_active_ruleset(conn: Connection, org: str) -> Row | None:
    return _one(
        conn, "SELECT * FROM aicheck.ruleset WHERE org_code = :o AND status = 'active'", o=org
    )


def activate_ruleset(conn: Connection, ruleset_id: int, org: str) -> None:
    conn.execute(
        text(
            "UPDATE aicheck.ruleset SET status = 'archived' WHERE org_code = :o AND status = 'active'"
        ),
        {"o": org},
    )
    conn.execute(
        text("UPDATE aicheck.ruleset SET status = 'active', activated_at = now() WHERE id = :i"),
        {"i": ruleset_id},
    )


# --- catalog ----------------------------------------------------------------------------------


def insert_catalog(conn: Connection, org: str, version: str, body: dict[str, Any]) -> bool:
    row = _one(
        conn,
        "INSERT INTO aicheck.catalog_snapshot (org_code, version, body) "
        "VALUES (:o, :v, CAST(:b AS jsonb)) ON CONFLICT DO NOTHING RETURNING version",
        o=org,
        v=version,
        b=_j(body),
    )
    return row is not None


def get_catalog(conn: Connection, org: str, version: str) -> Row | None:
    return _one(
        conn,
        "SELECT * FROM aicheck.catalog_snapshot WHERE org_code = :o AND version = :v",
        o=org,
        v=version,
    )


def latest_catalog_version(conn: Connection, org: str) -> str | None:
    row = _one(
        conn,
        "SELECT version FROM aicheck.catalog_snapshot WHERE org_code = :o "
        "ORDER BY received_at DESC, version DESC LIMIT 1",
        o=org,
    )
    return str(row["version"]) if row else None


# --- runs and findings ------------------------------------------------------------------------


def find_run(conn: Connection, end_ref: str, content_hash: str, ruleset_id: int) -> Row | None:
    return _one(
        conn,
        "SELECT * FROM aicheck.check_run WHERE end_ref = :e AND content_hash = :h AND ruleset_id = :r",
        e=end_ref,
        h=content_hash,
        r=ruleset_id,
    )


def find_run_by_hash(conn: Connection, end_ref: str, content_hash: str) -> Row | None:
    return _one(
        conn,
        "SELECT * FROM aicheck.check_run WHERE end_ref = :e AND content_hash = :h "
        "ORDER BY created_at DESC LIMIT 1",
        e=end_ref,
        h=content_hash,
    )


def get_run(conn: Connection, run_id: str) -> Row | None:
    return _one(conn, "SELECT * FROM aicheck.check_run WHERE id = :i", i=run_id)


def insert_run(conn: Connection, run: Row) -> None:
    conn.execute(
        text(
            "INSERT INTO aicheck.check_run (id, end_ref, content_hash, ruleset_id, catalog_version, request) "
            "VALUES (:id, :end_ref, :content_hash, :ruleset_id, :catalog_version, CAST(:request AS jsonb))"
        ),
        {**run, "request": _j(run["request"])},
    )


def insert_event(conn: Connection, run_id: str, status: str, llm_status: str, **extra: Any) -> None:
    conn.execute(
        text(
            "INSERT INTO aicheck.run_event (run_id, status, llm_status, model, prompt_version, duration_ms) "
            "VALUES (:r, :s, :l, :m, :p, :d)"
        ),
        {
            "r": run_id,
            "s": status,
            "l": llm_status,
            "m": extra.get("model"),
            "p": extra.get("prompt_version"),
            "d": extra.get("duration_ms"),
        },
    )


def last_event(conn: Connection, run_id: str) -> Row | None:
    return _one(
        conn, "SELECT * FROM aicheck.run_event WHERE run_id = :r ORDER BY id DESC LIMIT 1", r=run_id
    )


def insert_findings(conn: Connection, run_id: str, rows: list[Row]) -> None:
    if not rows:
        return
    conn.execute(
        text(
            "INSERT INTO aicheck.finding (id, run_id, rule_code, source, severity, kind, target, body, generated, confidence) "
            "VALUES (:id, :run_id, :rule_code, :source, :severity, :kind, CAST(:target AS jsonb), "
            "CAST(:body AS jsonb), :generated, :confidence)"
        ),
        [{**r, "run_id": run_id, "target": _j(r["target"]), "body": _j(r["body"])} for r in rows],
    )


def list_findings(conn: Connection, run_id: str) -> list[Row]:
    return _all(
        conn, "SELECT * FROM aicheck.finding WHERE run_id = :r ORDER BY created_at, id", r=run_id
    )


def get_finding(conn: Connection, finding_id: str) -> Row | None:
    return _one(conn, "SELECT * FROM aicheck.finding WHERE id = :i", i=finding_id)


def count_runs_since(conn: Connection, since: datetime, user_ref: str | None = None) -> int:
    if user_ref is None:
        row = _one(
            conn, "SELECT count(*) AS n FROM aicheck.check_run WHERE created_at > :t", t=since
        )
    else:
        row = _one(
            conn,
            "SELECT count(*) AS n FROM aicheck.check_run "
            "WHERE created_at > :t AND request->'requestedBy'->>'userRef' = :u",
            t=since,
            u=user_ref,
        )
    return int(row["n"]) if row else 0


# --- actions ----------------------------------------------------------------------------------


def insert_action(conn: Connection, action: Row) -> bool:
    row = _one(
        conn,
        "INSERT INTO aicheck.finding_action (id, finding_id, action, reason_code, comment, applied_text, "
        "user_ref, user_role, idempotency_key) VALUES (:id, :finding_id, :action, :reason_code, :comment, "
        ":applied_text, :user_ref, :user_role, :idempotency_key) "
        "ON CONFLICT (idempotency_key) DO NOTHING RETURNING id",
        **action,
    )
    return row is not None


def latest_actions(conn: Connection, run_id: str) -> dict[str, str]:
    """finding id -> last action over all findings of a run."""
    rows = _all(
        conn,
        "SELECT DISTINCT ON (a.finding_id) a.finding_id, a.action FROM aicheck.finding_action a "
        "JOIN aicheck.finding f ON f.id = a.finding_id WHERE f.run_id = :r "
        "ORDER BY a.finding_id, a.created_at DESC, a.id DESC",
        r=run_id,
    )
    return {str(r["finding_id"]): r["action"] for r in rows}


# --- jobs and callbacks -----------------------------------------------------------------------


def enqueue_job(conn: Connection, run_id: str) -> None:
    conn.execute(text("INSERT INTO aicheck.job (run_id) VALUES (:r)"), {"r": run_id})


def take_job(conn: Connection) -> Row | None:
    return _one(
        conn,
        "UPDATE aicheck.job SET state = 'running', locked_at = now(), attempts = attempts + 1 "
        "WHERE id = (SELECT id FROM aicheck.job WHERE state = 'queued' AND not_before <= now() "
        "ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
    )


def finish_job(conn: Connection, job_id: int, state: str = "done") -> None:
    conn.execute(
        text("UPDATE aicheck.job SET state = :s, locked_at = NULL WHERE id = :i"),
        {"s": state, "i": job_id},
    )


def requeue_stale(conn: Connection, max_attempts: int = 3, stale_s: int = 60) -> list[Row]:
    """Stuck jobs go back to the queue; after `max_attempts` they fail (returned for the event)."""
    conn.execute(
        text(
            "UPDATE aicheck.job SET state = 'queued', locked_at = NULL WHERE state = 'running' "
            "AND locked_at < now() - make_interval(secs => :s) AND attempts < :m"
        ),
        {"s": stale_s, "m": max_attempts},
    )
    return _all(
        conn,
        "UPDATE aicheck.job SET state = 'failed', locked_at = NULL WHERE state = 'running' "
        "AND locked_at < now() - make_interval(secs => :s) AND attempts >= :m RETURNING *",
        s=stale_s,
        m=max_attempts,
    )


def insert_outbox(conn: Connection, run_id: str, payload: dict[str, Any]) -> None:
    conn.execute(
        text(
            "INSERT INTO aicheck.callback_outbox (run_id, payload) VALUES (:r, CAST(:p AS jsonb))"
        ),
        {"r": run_id, "p": _j(payload)},
    )


def due_callbacks(conn: Connection, limit: int = 10) -> list[Row]:
    return _all(
        conn,
        "SELECT * FROM aicheck.callback_outbox WHERE delivered_at IS NULL AND next_try_at <= now() "
        "ORDER BY id FOR UPDATE SKIP LOCKED LIMIT :n",
        n=limit,
    )


def mark_delivered(conn: Connection, outbox_id: int) -> None:
    conn.execute(
        text("UPDATE aicheck.callback_outbox SET delivered_at = now() WHERE id = :i"),
        {"i": outbox_id},
    )


def reschedule_callback(conn: Connection, outbox_id: int, delay_s: int) -> None:
    conn.execute(
        text(
            "UPDATE aicheck.callback_outbox SET attempts = attempts + 1, "
            "next_try_at = now() + make_interval(secs => :d) WHERE id = :i"
        ),
        {"i": outbox_id, "d": delay_s},
    )


def give_up_callback(conn: Connection, outbox_id: int) -> None:
    conn.execute(
        text(
            "UPDATE aicheck.callback_outbox SET attempts = attempts + 1, "
            "next_try_at = 'infinity' WHERE id = :i"
        ),
        {"i": outbox_id},
    )


# --- LLM cache --------------------------------------------------------------------------------


def get_cache(conn: Connection, key: str) -> Any | None:
    row = _one(conn, "SELECT result FROM aicheck.llm_cache WHERE key = :k", k=key)
    return row["result"] if row else None


def put_cache(conn: Connection, key: str, result: Any) -> None:
    conn.execute(
        text(
            "INSERT INTO aicheck.llm_cache (key, result) VALUES (:k, CAST(:r AS jsonb)) "
            "ON CONFLICT (key) DO NOTHING"
        ),
        {"k": key, "r": _j(result)},
    )


def purge_cache(conn: Connection, ttl_days: int = 30) -> int:
    result = conn.execute(
        text("DELETE FROM aicheck.llm_cache WHERE created_at < now() - make_interval(days => :d)"),
        {"d": ttl_days},
    )
    return int(result.rowcount)
