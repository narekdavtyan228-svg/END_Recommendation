"""Catalog import: a JSON file (pilot) or a delta export from HSE (by versions)."""

import logging
from typing import Any

import httpx

from aicheck.contracts.catalog import CatalogBody
from aicheck.db import queries
from aicheck.errors import Conflict, Unavailable, ValidationError
from aicheck.outbound import OutboundDenied, guarded_client
from aicheck.runtime import Runtime

log = logging.getLogger(__name__)
LIST_KEYS = ("measures", "hazards", "controls", "victims", "harms", "roles", "implement_when")


def import_catalog(rt: Runtime, body: CatalogBody) -> None:
    """Store a full snapshot; a version is immutable, so a different body under it is a conflict."""
    data = body.as_json()
    with rt.db.tx() as conn:
        if queries.insert_catalog(conn, rt.settings.org_code, body.version, data):
            return
        stored = queries.get_catalog(conn, rt.settings.org_code, body.version)
    if stored and stored["body"] != data:
        raise Conflict("catalog version already exists with different content", "version")


def merge_snapshot(base: dict[str, Any] | None, delta: dict[str, Any]) -> dict[str, Any]:
    """Apply an HSE delta: added or changed records by id; deactivation is `active: false`."""
    merged: dict[str, Any] = dict(base or {})
    for key in LIST_KEYS:
        by_id = {r["id"]: r for r in merged.get(key, [])}
        by_id.update({r["id"]: r for r in delta.get(key, [])})
        merged[key] = list(by_id.values())
    units = {p["unitCode"]: p for p in merged.get("profiles", [])}
    units.update({p["unitCode"]: p for p in delta.get("profiles", [])})
    merged["profiles"] = list(units.values())
    merged["hints"] = {**merged.get("hints", {}), **delta.get("hints", {})}
    merged["version"] = delta["version"]
    return merged


def sync_from_hse(
    rt: Runtime, target_version: str, client: httpx.Client | None = None
) -> str | None:
    """Fetch changes since the latest local version; returns the stored version."""
    s = rt.settings
    with rt.db.tx() as conn:
        latest = queries.latest_catalog_version(conn, s.org_code)
        base_row = queries.get_catalog(conn, s.org_code, latest) if latest else None
    own = client or guarded_client(s.allowed_outbound_hosts, timeout=10.0)
    try:
        response = own.get(s.hse_catalog_export_url, params={"since": latest or ""})
        response.raise_for_status()
        delta = response.json()
    except (OutboundDenied, httpx.HTTPError, ValueError) as exc:
        log.warning("catalog sync failed", extra={"reason": type(exc).__name__})
        raise Unavailable("catalog export is unavailable") from exc
    finally:
        if client is None:
            own.close()
    try:
        body = CatalogBody.model_validate(
            merge_snapshot(base_row["body"] if base_row else None, delta)
        )
    except Exception as exc:
        raise ValidationError("catalog export has an invalid structure") from exc
    import_catalog(rt, body)
    if body.version != target_version:
        log.warning("catalog sync returned another version")
    return body.version
