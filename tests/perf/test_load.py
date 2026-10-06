"""Load test (run with `make perf`): 20 parallel runs, p95 of the code stage <= 1 s."""

import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

from aicheck.api.app import create_app
from aicheck.contracts.catalog import CatalogBody
from aicheck.db import queries
from aicheck.db.engine import Database
from aicheck.runtime import Runtime
from tests import factory
from tests.conftest import make_token

pytestmark = [pytest.mark.perf, pytest.mark.serial_db]


def body(i: int) -> dict[str, Any]:
    measures = [
        {
            "section": f"5.{n}",
            "text": f"Выполнить подготовительное мероприятие {n} на площадке работ {i}",
        }
        for n in range(1, 11)
    ]
    risks = [
        {
            "hazardId": 311,
            "victimIds": [12],
            "harmIds": [45],
            "existingControlIds": [801],
            "b1": 4,
            "p1": 1,
        }
    ]
    return factory.request("ZR", measures, risks, description=f"Работа номер {i}").model_dump(
        mode="json"
    )


def test_twenty_parallel_runs_p95_under_one_second(
    database: Database, db_names: dict[str, str], settings: Any, keypair: Any
) -> None:
    owner = psycopg.connect(db_names["owner"], autocommit=True)
    owner.execute(
        "TRUNCATE aicheck.job, aicheck.finding, aicheck.run_event, aicheck.check_run, aicheck.ruleset, "
        "aicheck.catalog_snapshot CASCADE"
    )
    package = factory.ruleset(with_params=True)
    with database.tx() as conn:
        rid = queries.insert_ruleset(conn, "OMG", "perf", package.raw, package.sha256)
        queries.activate_ruleset(conn, rid, "OMG")
        queries.insert_catalog(
            conn,
            "OMG",
            "omg-cat-test-1",
            CatalogBody.model_validate(factory.CATALOG_BODY).as_json(),
        )
    rt = Runtime(settings=settings, db=database)
    rt.active_rules()
    headers = {"Authorization": "Bearer " + make_token(keypair, ["hse-backend"])}
    app = create_app(rt)

    def call(i: int) -> float:
        payload = body(i)
        with TestClient(app) as client:
            started = time.perf_counter()
            r = client.post(
                "/v1/checks",
                content=json.dumps(payload),
                headers={
                    **headers,
                    "Idempotency-Key": payload["end"]["contentHash"],
                    "Content-Type": "application/json",
                },
            )
            elapsed = time.perf_counter() - started
        assert r.status_code == 200
        return elapsed

    try:
        with ThreadPoolExecutor(max_workers=20) as pool:
            times = sorted(pool.map(call, range(20)))
        p95 = times[int(0.95 * len(times)) - 1]
        report = f"# Load test\n\n20 parallel runs: p50 {statistics.median(times):.3f} s, p95 {p95:.3f} s, max {times[-1]:.3f} s\n"
        Path("reports").mkdir(exist_ok=True)
        Path("reports/perf.md").write_text(report, encoding="utf-8")
        assert p95 <= 1.0, report
    finally:
        owner.execute(
            "TRUNCATE aicheck.job, aicheck.finding, aicheck.run_event, aicheck.check_run, aicheck.ruleset, "
            "aicheck.catalog_snapshot CASCADE"
        )
        owner.close()
