"""Callback to HSE: outbox in the database, HMAC-signed body, growing retry pauses."""

import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

from aicheck import clock, metrics
from aicheck.config import Settings
from aicheck.db import queries
from aicheck.db.engine import Database
from aicheck.outbound import OutboundDenied, guarded_client

log = logging.getLogger(__name__)
RETRY_DELAYS_S = (5, 30, 120, 300, 900)


def encode(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def enqueue(db: Database, run_id: str, payload: dict[str, Any]) -> None:
    with db.tx() as conn:
        queries.insert_outbox(conn, run_id, payload)


def _send(client: httpx.Client, settings: Settings, body: bytes) -> bool:
    timestamp = int(clock.now().timestamp())
    headers = {
        "Content-Type": "application/json",
        "X-Timestamp": str(timestamp),
        "X-Signature": sign(settings.callback_hmac_secret, timestamp, body),
    }
    try:
        return client.post(settings.hse_callback_url, content=body, headers=headers).is_success
    except (OutboundDenied, httpx.HTTPError):
        return False


def deliver_due(db: Database, settings: Settings, client: httpx.Client | None = None) -> int:
    """Try every due callback once; returns the number delivered."""
    if not settings.hse_callback_url:
        return 0
    own = client or guarded_client(settings.allowed_outbound_hosts, timeout=10.0)
    delivered = 0
    try:
        with db.tx() as conn:
            for row in queries.due_callbacks(conn):
                if _send(own, settings, encode(row["payload"])):
                    queries.mark_delivered(conn, row["id"])
                    delivered += 1
                elif row["attempts"] < len(RETRY_DELAYS_S):
                    queries.reschedule_callback(conn, row["id"], RETRY_DELAYS_S[row["attempts"]])
                else:
                    queries.give_up_callback(conn, row["id"])
                    metrics.CALLBACK_UNDELIVERED.inc()
                    log.warning("callback undelivered", extra={"run_id": str(row["run_id"])})
    finally:
        if client is None:
            own.close()
    return delivered
