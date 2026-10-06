"""Job queue on a table: SELECT ... FOR UPDATE SKIP LOCKED (see db/queries.py)."""

from typing import Any

from aicheck.db import queries
from aicheck.db.engine import Database

MAX_ATTEMPTS = 3
STALE_S = 60


def take(db: Database) -> dict[str, Any] | None:
    with db.tx() as conn:
        return queries.take_job(conn)


def done(db: Database, job_id: int, state: str = "done") -> None:
    with db.tx() as conn:
        queries.finish_job(conn, job_id, state)


def recover_stale(db: Database) -> list[dict[str, Any]]:
    """Return stuck jobs to the queue; jobs out of attempts are returned as failed."""
    with db.tx() as conn:
        return queries.requeue_stale(conn, MAX_ATTEMPTS, STALE_S)
