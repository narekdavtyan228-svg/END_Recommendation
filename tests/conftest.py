"""Shared fixtures: per-worker database, per-test rolled-back transaction, tokens, clients."""

import os
import time
from collections.abc import Iterator
from typing import Any

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from psycopg import sql

from aicheck import clock
from aicheck.api.app import create_app
from aicheck.config import Settings
from aicheck.contracts.catalog import CatalogBody
from aicheck.db import migrate, queries
from aicheck.db.engine import Database
from aicheck.rules.loader import load_packaged
from aicheck.runtime import Runtime
from tests import factory

ADMIN_URL = os.environ.get(
    "TEST_DB_ADMIN_URL", "postgresql://postgres:postgres@localhost:5432/postgres"
)
APP_PASSWORD = "app-test-password"  # noqa: S105 - local test database only
ISSUER, AUDIENCE = "https://idp.test", "ai-check"


def _worker() -> str:
    return os.environ.get("PYTEST_XDIST_WORKER", "gw0")


def _url(user: str, password: str, dbname: str) -> str:
    base = ADMIN_URL.split("@", 1)[1].rsplit("/", 1)[0]
    return f"postgresql://{user}:{password}@{base}/{dbname}"


@pytest.fixture(scope="session")
def keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private, public


@pytest.fixture(scope="session")
def db_names() -> dict[str, str]:
    dbname = f"aicheck_test_{_worker()}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute("SELECT pg_advisory_lock(7001)")
        admin.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(dbname))
        )
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
        exists = admin.execute("SELECT 1 FROM pg_roles WHERE rolname = 'aicheck_app'").fetchone()
        if not exists:
            admin.execute("CREATE ROLE aicheck_app LOGIN")
        admin.execute(
            sql.SQL("ALTER ROLE aicheck_app PASSWORD {}").format(sql.Literal(APP_PASSWORD))
        )
        admin.execute("SELECT pg_advisory_unlock(7001)")
    owner_url = _url("postgres", "postgres", dbname)
    migrate.upgrade(owner_url)
    return {"owner": owner_url, "app": _url("aicheck_app", APP_PASSWORD, dbname), "name": dbname}


@pytest.fixture(scope="session")
def database(db_names: dict[str, str]) -> Iterator[Database]:
    db = Database(db_names["app"])
    yield db
    db.dispose()


@pytest.fixture
def db(database: Database) -> Iterator[Database]:
    """Every test works inside one transaction that is rolled back."""
    conn = database.engine.connect()
    trans = conn.begin()
    database.bind(conn)
    yield database
    database.bind(None)
    trans.rollback()
    conn.close()


@pytest.fixture
def settings(keypair: tuple[str, str]) -> Settings:
    return Settings(
        database_url="postgresql://unused",
        org_code="OMG",
        llm_base_url="https://llm.test",
        llm_api_key="test-llm-key-123",
        llm_model="test-model",
        jwt_issuer=ISSUER,
        jwt_public_key=keypair[1],
        allowed_outbound_hosts=("llm.test", "hse.test", "idp.test"),
        hse_catalog_export_url="https://hse.test/export",
        hse_callback_url="https://hse.test/callback",
        callback_hmac_secret="hmac-secret-test",
        jwt_audience=AUDIENCE,
        idp_issuer="https://corp-idp.test",
        idp_audience="ai-check-ui",
        idp_jwks_url="https://idp.test/jwks",
        cors_allowed_origins=("https://hse.test",),
    )


@pytest.fixture
def frozen_clock() -> Iterator[None]:
    from datetime import UTC, datetime

    clock.set_source(lambda: datetime(2026, 10, 6, 12, 0, tzinfo=UTC))
    yield
    clock.set_source(None)


@pytest.fixture
def rt(db: Database, settings: Settings) -> Runtime:
    """Runtime with the packaged rule package (active, with OMG parameters) and a test catalog."""
    runtime = Runtime(settings=settings, db=db)
    package = factory.ruleset(with_params=True)
    with db.tx() as conn:
        rid = queries.insert_ruleset(conn, "OMG", "test-1", package.raw, package.sha256)
        queries.activate_ruleset(conn, rid, "OMG")
        queries.insert_catalog(
            conn,
            "OMG",
            "omg-cat-test-1",
            CatalogBody.model_validate(factory.CATALOG_BODY).as_json(),
        )
    return runtime


def make_token(
    keypair: tuple[str, str],
    roles: list[str],
    *,
    mfa: bool = False,
    exp: int = 600,
    iss: str = ISSUER,
    aud: str = AUDIENCE,
    sub: str = "svc",
    kid: str | None = None,
) -> str:
    claims: dict[str, Any] = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "roles": roles,
        "exp": int(time.time()) + exp,
    }
    if mfa:
        claims["amr"] = ["pwd", "mfa"]
    return jwt.encode(claims, keypair[0], algorithm="RS256", headers={"kid": kid} if kid else None)


@pytest.fixture
def token(keypair: tuple[str, str]) -> Any:
    return lambda roles, **kw: make_token(keypair, roles, **kw)


@pytest.fixture
def client(rt: Runtime) -> TestClient:
    return TestClient(create_app(rt))


@pytest.fixture
def hse(token: Any) -> dict[str, str]:
    return {"Authorization": "Bearer " + token(["hse-backend"])}


@pytest.fixture
def admin(token: Any) -> dict[str, str]:
    return {"Authorization": "Bearer " + token(["ai-admin"], mfa=True)}


@pytest.fixture(scope="session")
def packaged_ruleset() -> Any:
    return load_packaged()
