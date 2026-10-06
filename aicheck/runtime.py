"""Process-level services: settings, database and the caches of rules, catalog and documents."""

import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from aicheck.catalog.model import Catalog
from aicheck.config import Settings
from aicheck.contracts import Basis
from aicheck.db import queries
from aicheck.db.engine import Database
from aicheck.errors import Unavailable
from aicheck.kb import retrieve
from aicheck.rules.loader import Ruleset, parse_ruleset

REFRESH_S = 30.0
CATALOG_CACHE_SIZE = 8


@dataclass
class ActiveRules:
    ruleset_id: int
    ruleset: Ruleset


@dataclass
class Runtime:
    settings: Settings
    db: Database
    _rules: ActiveRules | None = None
    _checked_at: float = 0.0
    _catalogs: "OrderedDict[str, Catalog]" = field(default_factory=OrderedDict)
    _by_id: dict[int, Ruleset] = field(default_factory=dict)
    _kb_version: int = -1
    _kb_basis: dict[str, Basis] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def active_rules(self, force: bool = False) -> ActiveRules:
        """The active rule package; the database is asked at most every 30 seconds."""
        with self._lock:
            fresh = time.monotonic() - self._checked_at < REFRESH_S
            if self._rules is not None and fresh and not force:
                return self._rules
            with self.db.tx() as conn:
                row = queries.get_active_ruleset(conn, self.settings.org_code)
            if row is None:
                raise Unavailable("no active rule package", code="ruleset_missing")
            if self._rules is None or self._rules.ruleset_id != row["id"]:
                self._rules = ActiveRules(row["id"], self._parse(row["id"], row["body"]))
            self._checked_at = time.monotonic()
            return self._rules

    def _parse(self, ruleset_id: int, body: dict[str, object]) -> Ruleset:
        if ruleset_id not in self._by_id:
            self._by_id[ruleset_id] = parse_ruleset(json.dumps(body, ensure_ascii=False))
        return self._by_id[ruleset_id]

    def ruleset_by_id(self, ruleset_id: int) -> Ruleset | None:
        if ruleset_id in self._by_id:
            return self._by_id[ruleset_id]
        with self.db.tx() as conn:
            row = queries.get_ruleset(conn, ruleset_id)
        return self._parse(ruleset_id, row["body"]) if row else None

    def catalog(self, version: str) -> Catalog | None:
        """Catalog versions are immutable, so a cached one never goes stale."""
        with self._lock:
            if version in self._catalogs:
                self._catalogs.move_to_end(version)
                return self._catalogs[version]
        with self.db.tx() as conn:
            row = queries.get_catalog(conn, self.settings.org_code, version)
        if row is None:
            return None
        catalog = Catalog.from_body(row["body"])
        with self._lock:
            self._catalogs[version] = catalog
            while len(self._catalogs) > CATALOG_CACHE_SIZE:
                self._catalogs.popitem(last=False)
        return catalog

    def kb_basis(self) -> dict[str, Basis]:
        """Rule -> document clause links; rebuilt when the document base changes."""
        with self.db.tx() as conn:
            version = retrieve.kb_version(conn)
            if version != self._kb_version:
                self._kb_basis = retrieve.rule_basis(conn)
                self._kb_version = version
        return self._kb_basis
