"""Stage 6: catalog import and sync, rule package lifecycle, CLI, golden report, model comparison."""

import copy
import dataclasses
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aicheck import cli, golden
from aicheck.catalog import sync
from aicheck.catalog.model import Catalog
from aicheck.contracts.catalog import CatalogBody
from aicheck.db import queries
from aicheck.errors import Conflict, Unavailable, ValidationError
from aicheck.llm.client import LlmClient
from aicheck.rules.loader import DATA_FILE
from aicheck.runtime import Runtime
from tests import factory
from tests.fakes.fake_llm import FakeLlm

pytestmark = pytest.mark.stage6
GOLDEN = Path(__file__).parents[1] / "golden"


def catalog_body(version: str, **over: Any) -> dict[str, Any]:
    return {**copy.deepcopy(factory.CATALOG_BODY), "version": version, **over}


def test_catalog_upload_is_idempotent_and_versions_are_immutable(
    client: TestClient, admin: dict[str, str]
) -> None:
    body = catalog_body("omg-cat-new")
    assert client.post("/v1/admin/catalog", json=body, headers=admin).status_code == 201
    assert (
        client.post("/v1/admin/catalog", json=body, headers=admin).status_code == 201
    )  # the same content again
    changed = catalog_body("omg-cat-new", hints={"5.1": "другая подсказка"})
    r = client.post("/v1/admin/catalog", json=changed, headers=admin)
    assert r.status_code == 409 and r.json()["error"]["field"] == "version"
    assert (
        client.post(
            "/v1/admin/catalog", json={"version": "x", "unknown": 1}, headers=admin
        ).status_code
        == 422
    )


def test_merge_snapshot_applies_changes_and_deactivations() -> None:
    base = catalog_body("v1")
    delta = {
        "version": "v2",
        "measures": [
            {"id": 1042, "section": "5.3", "text": "Новый текст мероприятия", "categories": []},
            {"id": 3000, "section": "5.1", "text": "Добавленная запись", "categories": []},
        ],
        "deactivated_ids": [1017],
        "hints": {"5.5": "подсказка"},
    }
    merged = sync.merge_snapshot(base, delta)
    cat = Catalog.from_body(merged)
    assert (
        merged["version"] == "v2"
        and cat.measures[1042]["text"] == "Новый текст мероприятия"
        and 3000 in cat.measures
    )
    assert 1017 not in cat.measures and merged["deactivated_ids"] == [
        1017
    ]  # a deactivated record is no longer matched
    assert cat.hints["5.5"] == "подсказка" and cat.hints["5.1"]  # old hints stay
    assert Catalog.from_body(base).measures[1017]  # the old version is unchanged
    assert sync.merge_snapshot(None, {"version": "v1"})["measures"] == []


def exporter(responses: list[dict[str, Any] | int]) -> tuple[httpx.Client, list[httpx.Request]]:
    sent: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        item = queue.pop(0)
        return (
            httpx.Response(item, text="boom")
            if isinstance(item, int)
            else httpx.Response(200, json=item)
        )

    return httpx.Client(transport=httpx.MockTransport(handler)), sent


def test_sync_stores_new_versions_from_hse_deltas(rt: Runtime) -> None:
    client, sent = exporter(
        [
            {
                "version": "v-sync-1",
                "measures": [{"id": 7, "section": "5.1", "text": "Первая запись"}],
            },
            {"version": "v-sync-2", "deactivated_ids": [7], "hints": {"5.1": "новая"}},
        ]
    )
    assert sync.sync_from_hse(rt, "v-sync-1", client) == "v-sync-1"
    assert sync.sync_from_hse(rt, "v-sync-2", client) == "v-sync-2"
    assert (
        sent[1].url.params["since"] == "v-sync-1"
    )  # asks for changes since the latest local version
    first, second = rt.catalog("v-sync-1"), rt.catalog("v-sync-2")
    assert (
        first and 7 in first.measures and second and 7 not in second.measures
    )  # old versions stay readable
    with rt.db.tx() as conn:
        assert queries.latest_catalog_version(conn, "OMG") == "v-sync-2"


def test_sync_failures_are_reported_not_stored(rt: Runtime) -> None:
    client, _ = exporter([503])
    with pytest.raises(Unavailable):
        sync.sync_from_hse(rt, "x", client)
    client, _ = exporter([{"measures": "not a list", "version": "bad"}])
    with pytest.raises(ValidationError):
        sync.sync_from_hse(rt, "bad", client)
    blocked = Runtime(
        settings=dataclasses.replace(rt.settings, allowed_outbound_hosts=("llm.test",)), db=rt.db
    )
    with pytest.raises(Unavailable):
        sync.sync_from_hse(
            blocked, "x"
        )  # the export host is not on the allow-list: no request is made


def test_post_sync_is_accepted_and_runs_in_the_background(
    client: TestClient, hse: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(sync, "sync_from_hse", lambda rt, version: calls.append(version))
    r = client.post("/v1/sync", json={"version": "omg-cat-9"}, headers=hse)
    assert r.status_code == 202 and calls == ["omg-cat-9"]
    assert client.post("/v1/sync", json={}, headers=hse).status_code == 422


def ruleset_json(version: str) -> dict[str, Any]:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    raw["version"] = version
    return raw


def test_rule_package_lifecycle_upload_activate_and_roll_back(
    client: TestClient, admin: dict[str, str], hse: dict[str, str]
) -> None:
    first = client.post("/v1/admin/rulesets", json=ruleset_json("omg-2.0.0"), headers=admin)
    assert first.status_code == 201 and first.json()["status"] == "draft"
    assert (
        client.post("/v1/admin/rulesets", json=ruleset_json("omg-2.0.0"), headers=admin).status_code
        == 409
    )
    body = factory.request("GP", [{"section": "5.1", "text": "Тест"}]).model_dump(mode="json")
    headers = {**hse, "Idempotency-Key": body["end"]["contentHash"]}
    old = client.post("/v1/checks", json=body, headers=headers).json()
    assert old["rulesetVersion"] == "1.2-draft"
    assert (
        client.post(f"/v1/admin/rulesets/{first.json()['id']}/activate", headers=admin).json()[
            "status"
        ]
        == "active"
    )
    new = client.post("/v1/checks", json=body, headers=headers).json()
    assert (
        new["rulesetVersion"] == "omg-2.0.0" and new["runId"] != old["runId"]
    )  # a new package means a new run
    assert (
        client.post(f"/v1/admin/rulesets/{first.json()['id']}/activate", headers=admin).status_code
        == 409
    )
    assert client.get("/v1/ready").status_code == 200  # the service stays ready
    rt = client.app.state.rt
    with rt.db.tx() as conn:
        archived = conn.execute(
            text("SELECT id FROM aicheck.ruleset WHERE status = 'archived'")
        ).scalar()
    assert (
        client.post(f"/v1/admin/rulesets/{archived}/activate", headers=admin).json()["version"]
        == "test-1"
    )  # rollback
    assert (
        client.post("/v1/checks", json=body, headers=headers).json()["runId"] == old["runId"]
    )  # the old run again


def test_rule_package_validation_and_unknown_package(
    client: TestClient, admin: dict[str, str]
) -> None:
    broken = ruleset_json("bad")
    broken["syntax"][1]["detect"] = "the regex was removed"
    r = client.post("/v1/admin/rulesets", json=broken, headers=admin)
    assert r.status_code == 422 and r.json()["error"]["code"] == "ruleset_invalid"
    assert (
        client.post("/v1/admin/rulesets", json={"version": "1"}, headers=admin).status_code == 422
    )
    assert client.post("/v1/admin/rulesets/99999/activate", headers=admin).status_code == 404


def test_cli_import_rules_and_housekeeping(
    rt: Runtime, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "_runtime", lambda: rt)
    raw = ruleset_json("omg-cli-1")
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    assert cli.main(["import-rules", "--file", str(path), "--activate"]) == 0
    assert (
        "omg-cli-1" in capsys.readouterr().out
        and rt.active_rules(force=True).ruleset.version == "omg-cli-1"
    )
    assert (
        cli.main(["import-rules", "--file", str(path), "--activate"]) == 0
    )  # again: nothing breaks
    assert cli.main(["purge-cache", "--days", "30"]) == 0 and "purged 0" in capsys.readouterr().out
    assert cli.main(["retention-report"]) == 0 and "check_run: rows=0" in capsys.readouterr().out


def test_cli_openapi_command_writes_the_contract(tmp_path: Path) -> None:
    out = tmp_path / "openapi.json"
    assert cli.main(["openapi", "--out", str(out)]) == 0
    assert "/v1/checks" in json.loads(out.read_text(encoding="utf-8"))["paths"]


# --- golden set and model comparison ---------------------------------------------------------------


def test_golden_set_has_the_required_cases_and_all_match(tmp_path: Path) -> None:
    cases = golden.load_cases(GOLDEN / "cases")
    ids = {c["id"] for c in cases}
    assert len([i for i in ids if i.startswith("gen_")]) == 18
    for category in ("ZR", "GP", "ZP", "DR", "OG", "GO", "VS"):
        assert (
            len([i for i in ids if i.startswith(f"cat_{category}_")]) == 3
        )  # good, bad, borderline
    result = golden.run(GOLDEN / "cases", tmp_path / "golden.md")
    assert result["ok"] and result["recall"] == 1.0 and result["precision"] == 1.0
    assert "42/42" in (tmp_path / "golden.md").read_text(encoding="utf-8")


def test_golden_run_reports_a_difference(tmp_path: Path) -> None:
    case = copy.deepcopy(golden.load_cases(GOLDEN / "cases")[0])
    case["expected"].append(
        {"rule": "S01", "target": {"type": "measure", "rowId": "zz"}, "severity": "critical"}
    )
    found, expected, _ = golden.evaluate_case(case, GOLDEN)
    assert found != expected
    metrics = golden.metrics_of(found, expected)
    assert metrics["critical_recall"] < 1.0


def test_golden_cli_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        cli.main(
            ["run-golden", "--cases", str(GOLDEN / "cases"), "--report", str(tmp_path / "g.md")]
        )
        == 0
    )
    assert "critical recall 1.000" in capsys.readouterr().out


def test_compare_models_on_the_stub(rt: Runtime, tmp_path: Path) -> None:
    settings = dataclasses.replace(
        rt.settings, llm_model="deepseek-flash", llm_model_alt="qwen-alt"
    )
    fake = FakeLlm("ok")
    client = LlmClient(settings, transport=fake.transport())
    result = golden.compare_models(settings, GOLDEN / "cases", tmp_path / "models.md", client)
    assert {r["model"] for r in result["rows"]} == {"deepseek-flash", "qwen-alt"}
    assert {c["model"] for c in fake.calls} == {"deepseek-flash", "qwen-alt"}
    row = result["rows"][0]
    assert (
        row["valid_json"] == 1.0
        and row["precision"] == 1.0
        and row["recall"] == 1.0
        and row["dropped_share"] == 0.0
    )
    report = (tmp_path / "models.md").read_text(encoding="utf-8")
    assert "deepseek-flash" in report and "qwen-alt" in report and "p95" in report


def test_compare_models_counts_invalid_answers_and_drops(rt: Runtime, tmp_path: Path) -> None:
    settings = dataclasses.replace(rt.settings, llm_model="m1")
    broken = LlmClient(settings, transport=FakeLlm("invalid_json").transport())
    assert (
        golden.compare_models(settings, GOLDEN / "cases", tmp_path / "a.md", broken)["rows"][0][
            "valid_json"
        ]
        == 0.0
    )
    noisy = LlmClient(settings, transport=FakeLlm("unknown_rule_code").transport())
    row = golden.compare_models(settings, GOLDEN / "cases", tmp_path / "b.md", noisy)["rows"][0]
    assert row["dropped_share"] == 1.0 and row["recall"] == 0.0


def test_smoke_llm_reports_time_and_drop_share(rt: Runtime, tmp_path: Path) -> None:
    fake = FakeLlm("ok")
    client = LlmClient(rt.settings, transport=fake.transport())
    result = golden.smoke_llm(rt.settings, GOLDEN / "cases", tmp_path / "smoke.md", 2, client)
    assert len(fake.calls) == 2 and "smoke: 2 cases" in result["summary"]
    assert (tmp_path / "smoke.md").read_text(encoding="utf-8").startswith("# Smoke test")


def test_catalog_model_helpers() -> None:
    body = CatalogBody.model_validate(catalog_body("v"))
    assert Catalog.from_body(body.as_json()).hazards[311]["name"].startswith("Обрушение")
    with pytest.raises(Conflict):
        raise Conflict("x")
