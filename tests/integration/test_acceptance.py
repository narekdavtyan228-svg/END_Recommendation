"""The 19 acceptance cases of the specification (tests/golden/official), cases 16-18 through the API."""

import copy
import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aicheck import acceptance
from aicheck.api.app import create_app
from aicheck.contracts.catalog import CatalogBody
from aicheck.db import queries
from aicheck.db.engine import Database
from aicheck.jobs.worker import LlmWorker
from aicheck.llm.client import LlmClient
from aicheck.runtime import Runtime
from tests.fakes.fake_llm import FakeLlm

pytestmark = pytest.mark.stage3
OFFICIAL = Path(__file__).parents[1] / "golden" / "official"
BODY = acceptance.load_catalog_body(OFFICIAL)
CASES = {c["id"]: c for c in acceptance.load_cases(OFFICIAL)}
CODE_ONLY = [i for i, c in CASES.items() if c["mode"] == "code_only"]


def test_there_are_nineteen_cases_and_the_integration_ones_are_16_to_18() -> None:
    assert sorted(CASES) == [f"case_{n:02d}" for n in range(19)]
    assert [i for i, c in CASES.items() if c["mode"] == "integration"] == [
        "case_16",
        "case_17",
        "case_18",
    ]


@pytest.mark.parametrize("case_id", CODE_ONLY)
def test_code_only_case(case_id: str) -> None:
    assert acceptance.run_code_only(OFFICIAL)[case_id] == []


def test_case_00_is_a_clean_base_without_critical_and_significant_findings() -> None:
    from aicheck.catalog.model import Catalog
    from aicheck.engine.run import check

    _, findings = check(
        acceptance.build_request(CASES["case_00"]),
        acceptance.ruleset_for(BODY),
        Catalog.from_body(BODY),
    )
    assert [
        f for f in findings if f.severity in ("critical", "significant") and f.kind != "question"
    ] == []
    assert not [f for f in findings if f.kind == "question"]


def test_the_matcher_reports_missing_and_unexpected_findings() -> None:
    from aicheck.catalog.model import Catalog
    from aicheck.engine.run import check

    case = CASES["case_01"]
    _, findings = check(
        acceptance.build_request(case), acceptance.ruleset_for(BODY), Catalog.from_body(BODY)
    )
    assert acceptance.problems(case["expect"], findings) == []
    wrong = {
        "must_include": [{"rule_code": "S02", "severity": "critical", "target": {"rowId": "nope"}}],
        "must_not_include": ["S02"],
        "must_not_include_severity": ["critical"],
        "questions": ["F99"],
        "must_not_mention": ["тест"],
    }
    found = acceptance.problems(wrong, findings)
    assert (
        len(found) >= 5
        and any(p.startswith("missing") for p in found)
        and any("no question" in p for p in found)
    )


@pytest.fixture
def official(db: Database, settings: Any) -> tuple[TestClient, Runtime, dict[str, str]]:
    runtime = Runtime(settings=settings, db=db)
    package = acceptance.ruleset_for(BODY)
    with db.tx() as conn:
        rid = queries.insert_ruleset(conn, "OMG", "official-1", package.raw, package.sha256)
        queries.activate_ruleset(conn, rid, "OMG")
        queries.insert_catalog(
            conn, "OMG", BODY["version"], CatalogBody.model_validate(BODY).as_json()
        )
    from tests.conftest import make_token

    headers = {"Authorization": "Bearer " + make_token(settings_keypair(settings), ["hse-backend"])}
    return TestClient(create_app(runtime)), runtime, headers


def settings_keypair(settings: Any) -> tuple[str, str]:
    return _KEYS["pair"]


_KEYS: dict[str, tuple[str, str]] = {}


@pytest.fixture(autouse=True)
def _keys(keypair: tuple[str, str]) -> None:
    _KEYS["pair"] = keypair


def post(client: TestClient, headers: dict[str, str], body: dict[str, Any]) -> Any:
    return client.post(
        "/v1/checks", json=body, headers={**headers, "Idempotency-Key": body["end"]["contentHash"]}
    )


def request_body(case_id: str) -> dict[str, Any]:
    return acceptance.build_request(CASES[case_id]).model_dump(mode="json")


def test_case_16_llm_unavailable(official: Any) -> None:
    client, rt, headers = official
    first = post(client, headers, request_body("case_16")).json()
    assert first["status"] == "code_done" and first["llm"] == "pending" and first["findings"]
    fake = FakeLlm("timeout")
    LlmWorker(rt, LlmClient(rt.settings, transport=fake.transport())).step()
    expect = CASES["case_16"]["expect"]
    result = client.get(f"/v1/checks/{first['runId']}", headers=headers).json()
    assert result["status"] == expect["run_status"] and result["llm"] == expect["llm_status"]
    assert [f for f in result["findings"] if f["source"] == "rules"] == first["findings"]
    gate = client.get(
        "/v1/gate",
        params={"endRef": "END-TEST-9665", "contentHash": first["contentHash"]},
        headers=headers,
    )
    assert gate.json()["allowed"] is expect["gate_after_run"]["allowed"]


def test_case_17_repeated_check_returns_the_same_run_fast(official: Any) -> None:
    client, _, headers = official
    body = request_body("case_17")
    first = post(client, headers, body).json()
    started = time.perf_counter()
    second = post(client, headers, copy.deepcopy(body)).json()
    assert (time.perf_counter() - started) * 1000 < CASES["case_17"]["expect"]["second_call_max_ms"]
    assert first["runId"] == second["runId"]


def test_case_18_changed_section_closes_the_gate(official: Any) -> None:
    client, _, headers = official
    body = request_body("case_18")
    run = post(client, headers, body).json()
    for f in run["findings"]:
        if f["severity"] == "critical" or f["kind"] == "question":
            client.post(
                f"/v1/findings/{f['findingId']}/actions",
                headers=headers,
                json={"action": "accept", "userRef": "u"},
            )
    before = client.get(
        "/v1/gate",
        params={"endRef": body["end"]["endRef"], "contentHash": body["end"]["contentHash"]},
        headers=headers,
    )
    assert before.json()["allowed"] is CASES["case_18"]["expect"]["gate_before_change"]["allowed"]
    changed = copy.deepcopy(CASES["case_18"])
    row = next(m for m in changed["request"]["measures"] if m["rowId"] == "m-5.1-a")
    row["text"] = "Остановить работы при изменении условий."
    new_hash = acceptance.build_request(changed).end.contentHash
    after = client.get(
        "/v1/gate",
        params={"endRef": body["end"]["endRef"], "contentHash": new_hash},
        headers=headers,
    ).json()
    expect = CASES["case_18"]["expect"]["gate_after_change"]
    assert (
        after["allowed"] is expect["allowed"]
        and after["blockers"][0]["code"] == expect["blocker_code"]
    )
    assert json.dumps(after)  # a plain JSON answer
