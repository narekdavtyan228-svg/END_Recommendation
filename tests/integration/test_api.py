"""Stage 4: API of the code stage, idempotency, gate, authentication, limits."""

import copy
import dataclasses
import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import text

from aicheck.api.app import create_app
from aicheck.runtime import Runtime
from tests import factory
from tests.conftest import AUDIENCE, ISSUER

pytestmark = pytest.mark.stage4
BAD = [
    {"section": "5.1", "text": "Тест"},
    {"section": "5.5", "text": "Оградить зону работ сигнальной лентой по периметру"},
]


def body_of(
    measures: Any = None, risks: Any = None, category: str = "GP", **ctx: Any
) -> dict[str, Any]:
    return factory.request(
        category, measures if measures is not None else BAD, risks, **ctx
    ).model_dump(mode="json")


def post(
    client: TestClient, headers: dict[str, str], body: dict[str, Any], key: str | None = None
) -> Any:
    return client.post(
        "/v1/checks",
        json=body,
        headers={**headers, "Idempotency-Key": key or body["end"]["contentHash"]},
    )


def test_check_returns_code_findings_and_versions(client: TestClient, hse: dict[str, str]) -> None:
    r = post(client, hse, body_of())
    assert r.status_code == 200 and r.headers["x-request-id"]
    data = r.json()
    assert (
        data["status"] == "code_done"
        and data["llm"] == "pending"
        and data["rulesetVersion"] == "1.2-draft"
    )
    assert data["catalogVersion"] == "omg-cat-test-1" and data["contentHash"].startswith("sha256:")
    s02 = next(f for f in data["findings"] if f["ruleCode"] == "S02")
    assert s02["severity"] == "critical" and s02["source"] == "rules" and s02["findingId"]
    assert s02["title"]["ru"] and s02["message"]["ru"] and "kk" in s02["message"]
    assert data["summary"]["critical"] >= 1


def test_clean_request_skips_the_llm(client: TestClient, hse: dict[str, str]) -> None:
    good = [{"section": "5.5", "text": "Установить заглушки на трубопроводе", "origin": "catalog"}]
    data = post(client, hse, body_of(good)).json()
    assert data["llm"] == "skipped"


def test_same_hash_returns_the_same_run_without_recomputing(
    client: TestClient, hse: dict[str, str], db: Any
) -> None:
    body = body_of()
    first, second = post(client, hse, body).json(), post(client, hse, body).json()
    assert first["runId"] == second["runId"] and first["findings"] == second["findings"]
    with db.tx() as conn:
        assert conn.execute(text("SELECT count(*) FROM aicheck.check_run")).scalar() == 1


def test_get_result_and_not_found(client: TestClient, hse: dict[str, str]) -> None:
    run_id = post(client, hse, body_of()).json()["runId"]
    r = client.get(f"/v1/checks/{run_id}", headers=hse)
    assert r.status_code == 200 and r.json()["runId"] == run_id
    assert (
        client.get("/v1/checks/00000000-0000-0000-0000-000000000000", headers=hse).status_code
        == 404
    )
    missing = client.get("/v1/checks/not-a-uuid", headers=hse)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"


def test_unknown_catalog_version_is_409(client: TestClient, hse: dict[str, str]) -> None:
    r = post(client, hse, body_of(catalogVersion="omg-cat-unknown"))
    assert r.status_code == 409
    assert r.json()["error"] == {
        "code": "catalog_version_unknown",
        "message": "catalog version is unknown",
        "field": "context.catalogVersion",
    }


def test_hash_must_match_the_content_and_the_header(
    client: TestClient, hse: dict[str, str]
) -> None:
    body = body_of()
    r = post(client, hse, {**body, "end": {**body["end"], "contentHash": "sha256:" + "0" * 64}})
    assert r.status_code == 422 and r.json()["error"]["code"] == "content_hash_mismatch"
    r = post(client, hse, body, key="sha256:" + "1" * 64)
    assert r.status_code == 422 and r.json()["error"]["code"] == "idempotency_key_mismatch"
    r = client.post("/v1/checks", json=body, headers=hse)
    assert r.status_code == 422


def test_validation_errors_name_the_field_but_never_the_value(
    client: TestClient, hse: dict[str, str]
) -> None:
    body = body_of()
    body["unexpected"] = "SECRET-VALUE-123"
    r = post(client, hse, body)
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_failed"
    assert r.json()["error"]["field"] == "unexpected" and "SECRET-VALUE-123" not in r.text
    body = body_of()
    body["measures"][0]["section"] = "7.7"
    r = post(client, hse, body)
    assert r.json()["error"]["field"] == "measures.0.section"
    r = client.post(
        "/v1/checks",
        content=b"{broken",
        headers={**hse, "Content-Type": "application/json", "Idempotency-Key": "x"},
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == "schema_invalid"


def test_unknown_organisation_is_rejected(client: TestClient, hse: dict[str, str]) -> None:
    body = body_of()
    body["tenant"]["orgCode"] = "XXX"
    body["end"]["contentHash"] = body["end"]["contentHash"]  # org is part of the hash
    from aicheck.contracts import CheckRequest
    from aicheck.hashing import content_hash

    body["end"]["contentHash"] = content_hash(CheckRequest.model_validate(body))
    assert post(client, hse, body).status_code == 422


def test_sec13_body_limit_is_413(client: TestClient, hse: dict[str, str]) -> None:
    big = body_of()
    big["context"]["description"] = "а" * 300_000
    r = client.post(
        "/v1/checks", content=json.dumps(big), headers={**hse, "Content-Type": "application/json"}
    )
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"
    assert r.headers["x-request-id"]


def test_sec13_html_and_control_characters_are_removed_before_storage(
    client: TestClient, hse: dict[str, str], db: Any
) -> None:
    data = post(
        client,
        hse,
        body_of(
            [{"section": "5.5", "text": "<script>alert(1)</script>Оградить зону\x00 работ знаками"}]
        ),
    ).json()
    assert data["status"] == "code_done"
    with db.tx() as conn:
        stored = conn.execute(text("SELECT request FROM aicheck.check_run")).scalar()
    assert stored["measures"][0]["text"] == "alert(1)Оградить зону работ знаками"
    assert "<" not in json.dumps(stored)


def test_sec05_personal_data_is_masked_in_the_database(
    client: TestClient, hse: dict[str, str], db: Any
) -> None:
    text_in = "Связаться с Иваном ИИН 900101300123 по телефону +7 701 123 45 67 или ivan@corp.kz перед работой"
    post(
        client,
        hse,
        body_of([{"section": "5.10", "text": text_in}], description="Звонить 87011234567"),
    )
    with db.tx() as conn:
        stored = json.dumps(
            conn.execute(text("SELECT request FROM aicheck.check_run")).scalar(), ensure_ascii=False
        )
    for leaked in ("900101300123", "701 123 45 67", "ivan@corp.kz", "87011234567"):
        assert leaked not in stored
    assert "[ИИН]" in stored and "[ТЕЛ]" in stored and "[EMAIL]" in stored


def test_answers_create_a_new_run_with_new_factors(client: TestClient, hse: dict[str, str]) -> None:
    first = post(client, hse, body_of(category="ZR")).json()
    assert any(
        f["ruleCode"] == "N14" and f["target"]["factorCode"] == "F27" for f in first["findings"]
    )
    new = factory.with_answers(factory.request("ZR", BAD), {"F27": "no"})
    r = client.post(
        f"/v1/checks/{first['runId']}/answers",
        headers=hse,
        json={"contentHash": new.end.contentHash, "factorAnswers": {"F27": "no"}},
    )
    assert (
        r.status_code == 422 and r.json()["error"]["code"] == "content_hash_mismatch"
    )  # hash of the old snapshot
    from aicheck.hashing import content_hash

    stored = factory.request("ZR", BAD)
    with_answer = factory.with_answers(stored, {"F27": "no"})
    good_hash = content_hash(with_answer)
    r = client.post(
        f"/v1/checks/{first['runId']}/answers",
        headers=hse,
        json={"contentHash": good_hash, "factorAnswers": {"F27": "no"}},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["runId"] != first["runId"] and data["contentHash"] == good_hash
    assert not any(
        f["ruleCode"] == "N14" and f["target"]["factorCode"] == "F27" for f in data["findings"]
    )


def test_answers_for_unknown_run_is_404(client: TestClient, hse: dict[str, str]) -> None:
    r = client.post(
        "/v1/checks/00000000-0000-0000-0000-000000000000/answers",
        headers=hse,
        json={"contentHash": "sha256:" + "0" * 64, "factorAnswers": {}},
    )
    assert r.status_code == 404


def finding_id(
    client: TestClient, hse: dict[str, str], rule: str, body: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    data = post(client, hse, body).json()
    return next(f["findingId"] for f in data["findings"] if f["ruleCode"] == rule), data


def test_actions_are_recorded_and_validated(client: TestClient, hse: dict[str, str]) -> None:
    fid, _ = finding_id(client, hse, "S02", body_of())
    url = f"/v1/findings/{fid}/actions"
    r = client.post(
        url,
        headers={**hse, "Idempotency-Key": "k1"},
        json={"action": "reject", "reasonCode": "other", "userRef": "u_1"},
    )
    assert r.status_code == 201 and r.json()["actionId"]
    again = client.post(url, headers={**hse, "Idempotency-Key": "k1"}, json={"action": "accept"})
    assert again.status_code == 409 and again.json()["error"]["code"] == "action_exists"
    assert client.post(url, headers=hse, json={"action": "reject"}).status_code == 422
    assert client.post(url, headers=hse, json={"action": "edit"}).status_code == 422
    assert client.post(url, headers=hse, json={"action": "hide"}).status_code == 422  # critical
    assert (
        client.post(url, headers=hse, json={"action": "answer", "answer": "yes"}).status_code == 422
    )  # not a question
    assert client.post(url, headers=hse, json={"action": "accept", "extra": 1}).status_code == 422
    missing = client.post(
        "/v1/findings/00000000-0000-0000-0000-000000000000/actions",
        headers=hse,
        json={"action": "accept"},
    )
    assert missing.status_code == 404


def gate(client: TestClient, hse: dict[str, str], end_ref: str, digest: str) -> dict[str, Any]:
    r = client.get("/v1/gate", params={"endRef": end_ref, "contentHash": digest}, headers=hse)
    assert r.status_code == 200
    return r.json()


def act(client: TestClient, hse: dict[str, str], fid: str, **kw: Any) -> None:
    assert client.post(f"/v1/findings/{fid}/actions", headers=hse, json=kw).status_code == 201


def test_gate_six_scenarios(client: TestClient, hse: dict[str, str]) -> None:
    flags = {"adjacentApproval": True, "gasAirControl": True, "fireService": True}
    zr = body_of([], category="ZR", flags=flags)  # critical gaps and blocking questions
    digest = zr["end"]["contentHash"]
    # 1. no run for this hash yet
    g = gate(client, hse, "end_1", digest)
    assert not g["allowed"] and g["blockers"][0]["code"] == "no_run"
    # 2. open critical findings block
    data = post(client, hse, zr).json()
    g = gate(client, hse, "end_1", digest)
    assert not g["allowed"] and any(b["code"] == "critical_open" for b in g["blockers"])
    # 3. critical findings are handled, but an open question that blocks critical rules keeps the gate closed
    criticals = [
        f for f in data["findings"] if f["kind"] == "issue" and f["severity"] == "critical"
    ]
    questions = [f for f in data["findings"] if f["kind"] == "question"]
    assert criticals and questions
    for f in criticals:
        act(client, hse, f["findingId"], action="accept", userRef="u")
    g = gate(client, hse, "end_1", digest)
    assert not g["allowed"] and [b["code"] for b in g["blockers"]] == ["question_open"]
    # 4. answering the questions opens the gate
    for f in questions:
        act(client, hse, f["findingId"], action="answer", answer="no", userRef="u")
    assert gate(client, hse, "end_1", digest)["allowed"]
    # 5. reopen makes a handled critical finding open again
    act(client, hse, criticals[0]["findingId"], action="reopen", userRef="u")
    g = gate(client, hse, "end_1", digest)
    assert not g["allowed"] and any(b["code"] == "critical_open" for b in g["blockers"])
    # 6. rejecting with a reason handles it again; a changed content has no run
    act(client, hse, criticals[0]["findingId"], action="reject", reasonCode="other", userRef="u")
    assert gate(client, hse, "end_1", digest)["allowed"]
    other = body_of([{"section": "5.1", "text": "Другой текст"}], category="ZR", flags=flags)
    assert (
        gate(client, hse, "end_1", other["end"]["contentHash"])["blockers"][0]["code"] == "no_run"
    )


def test_gate_other_content_hash_is_blocked(client: TestClient, hse: dict[str, str]) -> None:
    post(client, hse, body_of())
    g = gate(client, hse, "end_1", "sha256:" + "f" * 64)
    assert not g["allowed"] and g["blockers"][0]["code"] == "no_run"


def test_catalog_version_endpoint(client: TestClient, hse: dict[str, str]) -> None:
    assert client.get("/v1/catalog/version", headers=hse).json() == {"version": "omg-cat-test-1"}


def test_health_ready_and_metrics_need_no_token(client: TestClient) -> None:
    assert client.get("/v1/health").json() == {"status": "ok"}
    assert client.get("/v1/ready").json() == {"status": "ready"}
    metrics = client.get("/metrics")
    assert metrics.status_code == 200 and "checks_total" in metrics.text


def test_ready_is_503_without_a_rule_package(db: Any, settings: Any) -> None:
    rt = Runtime(settings=settings, db=db)
    assert TestClient(create_app(rt)).get("/v1/ready").status_code == 503


def test_code_stage_is_fast(client: TestClient, hse: dict[str, str]) -> None:
    risks = [
        {
            "hazardId": 311,
            "victimIds": [12],
            "harmIds": [45],
            "existingControlIds": [801],
            "b1": 3,
            "p1": 2,
        }
    ]
    measures = [
        {
            "section": f"5.{i}",
            "text": f"Выполнить подготовительное мероприятие номер {i} на площадке {i}",
        }
        for i in range(1, 11)
    ]
    body = body_of(measures, risks, category="ZR")
    started = time.perf_counter()
    assert post(client, hse, body).status_code == 200
    assert time.perf_counter() - started < 0.5


# --- SEC-04: authentication and roles -------------------------------------------------------------


def test_sec04_missing_wrong_and_expired_tokens(
    client: TestClient, token: Any, keypair: Any
) -> None:
    body = body_of()
    h = {"Idempotency-Key": body["end"]["contentHash"]}
    assert client.post("/v1/checks", json=body, headers=h).status_code == 401
    assert (
        client.post(
            "/v1/checks", json=body, headers={**h, "Authorization": "Bearer garbage"}
        ).status_code
        == 401
    )
    expired = token(["hse-backend"], exp=-10)
    assert (
        client.post(
            "/v1/checks", json=body, headers={**h, "Authorization": "Bearer " + expired}
        ).status_code
        == 401
    )
    wrong_aud = token(["hse-backend"], aud="other")
    assert (
        client.post(
            "/v1/checks", json=body, headers={**h, "Authorization": "Bearer " + wrong_aud}
        ).status_code
        == 401
    )
    wrong_iss = token(["hse-backend"], iss="https://evil")
    assert (
        client.post(
            "/v1/checks", json=body, headers={**h, "Authorization": "Bearer " + wrong_iss}
        ).status_code
        == 401
    )
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "x",
            "roles": ["hse-backend"],
            "exp": int(time.time()) + 60,
        },
        other_key,
        algorithm="RS256",
    )
    assert (
        client.post(
            "/v1/checks", json=body, headers={**h, "Authorization": "Bearer " + forged}
        ).status_code
        == 401
    )
    hs = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "x",
            "roles": ["hse-backend"],
            "exp": int(time.time()) + 60,
        },
        "a-shared-secret-that-is-long-enough-for-hs256",
        algorithm="HS256",
    )
    assert (
        client.post(
            "/v1/checks", json=body, headers={**h, "Authorization": "Bearer " + hs}
        ).status_code
        == 401
    )
    none_alg = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "roles": ["hse-backend"]},
        None,
        algorithm="none",
    )
    assert (
        client.post(
            "/v1/checks", json=body, headers={**h, "Authorization": "Bearer " + none_alg}
        ).status_code
        == 401
    )


def test_sec04_roles_and_mfa(client: TestClient, token: Any, hse: dict[str, str]) -> None:
    other = {"Authorization": "Bearer " + token(["somebody"])}
    assert (
        client.get(
            "/v1/gate", params={"endRef": "e", "contentHash": "h"}, headers=other
        ).status_code
        == 403
    )
    assert (
        client.post("/v1/admin/rulesets", json={}, headers=hse).status_code == 403
    )  # hse-backend is not an admin
    no_mfa = {"Authorization": "Bearer " + token(["ai-admin"], mfa=False)}
    r = client.post("/v1/admin/catalog", json={"version": "v"}, headers=no_mfa)
    assert r.status_code == 403 and "multi-factor" in r.json()["error"]["message"]
    admin = {"Authorization": "Bearer " + token(["ai-admin"], mfa=True)}
    assert (
        client.post("/v1/admin/catalog", json={"version": "v-new"}, headers=admin).status_code
        == 201
    )


def test_sec04_admin_cannot_use_business_endpoints(
    client: TestClient, admin: dict[str, str]
) -> None:
    assert (
        client.get(
            "/v1/gate", params={"endRef": "e", "contentHash": "h"}, headers=admin
        ).status_code
        == 403
    )


# --- mode A: user tokens ----------------------------------------------------------------------------


class StubJwks:
    def __init__(self, public_key: Any, kid: str) -> None:
        self.jwk = jwt.PyJWK(
            json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key)) | {"kid": kid}
        )
        self.kid = kid

    def key(self, kid: str) -> Any:
        if kid != self.kid:
            from aicheck.errors import Unauthorized

            raise Unauthorized("invalid token")
        return self.jwk


@pytest.fixture
def user_client(rt: Runtime) -> Any:
    idp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = TestClient(create_app(rt, jwks=StubJwks(idp_key.public_key(), "idp-1")))

    def tok(sub: str, **over: Any) -> dict[str, str]:
        claims = {
            "iss": rt.settings.idp_issuer,
            "aud": rt.settings.idp_audience,
            "sub": sub,
            "exp": int(time.time()) + 300,
            **over,
        }
        return {
            "Authorization": "Bearer "
            + jwt.encode(claims, idp_key, algorithm="RS256", headers={"kid": "idp-1"})
        }

    return client, tok, rt


def test_sec15_user_runs_are_private_to_the_author(user_client: Any, hse: dict[str, str]) -> None:
    client, tok, _ = user_client
    body = body_of()
    r = post(client, tok("alice"), body)
    assert r.status_code == 200
    run_id = r.json()["runId"]
    assert client.get(f"/v1/checks/{run_id}", headers=tok("alice")).status_code == 200
    assert (
        client.get(f"/v1/checks/{run_id}", headers=tok("bob")).status_code == 404
    )  # someone else's run
    assert (
        client.get(f"/v1/checks/{run_id}", headers=hse).status_code == 200
    )  # the service token sees all
    fid = r.json()["findings"][0]["findingId"]
    assert (
        client.post(
            f"/v1/findings/{fid}/actions", headers=tok("bob"), json={"action": "accept"}
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/v1/findings/{fid}/actions", headers=tok("alice"), json={"action": "accept"}
        ).status_code
        == 201
    )


def test_sec15_user_identity_comes_from_the_token_not_the_body(user_client: Any, db: Any) -> None:
    client, tok, _ = user_client
    body = body_of()
    body["requestedBy"]["userRef"] = "someone-else"
    post(client, tok("alice"), body)
    with db.tx() as conn:
        assert (
            conn.execute(
                text("SELECT request->'requestedBy'->>'userRef' FROM aicheck.check_run")
            ).scalar()
            == "alice"
        )


def test_sec15_user_tokens_cannot_call_service_endpoints(user_client: Any) -> None:
    client, tok, _ = user_client
    assert (
        client.get(
            "/v1/gate", params={"endRef": "e", "contentHash": "h"}, headers=tok("alice")
        ).status_code
        == 403
    )
    assert client.post("/v1/sync", json={"version": "v"}, headers=tok("alice")).status_code == 403
    assert (
        client.post("/v1/admin/catalog", json={"version": "v"}, headers=tok("alice")).status_code
        == 403
    )
    assert client.get("/v1/catalog/version", headers=tok("alice")).status_code == 403


def test_sec15_bad_user_tokens(user_client: Any, token: Any) -> None:
    client, tok, rt = user_client
    body = body_of()
    assert post(client, tok("alice", exp=int(time.time()) - 5), body).status_code == 401
    assert post(client, tok("alice", iss="https://evil"), body).status_code == 401
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = {
        "iss": rt.settings.idp_issuer,
        "aud": rt.settings.idp_audience,
        "sub": "mallory",
        "exp": int(time.time()) + 300,
    }
    forged = jwt.encode(claims, stranger, algorithm="RS256", headers={"kid": "idp-1"})
    assert post(client, {"Authorization": "Bearer " + forged}, body).status_code == 401
    unknown_kid = jwt.encode(claims, stranger, algorithm="RS256", headers={"kid": "nope"})
    assert post(client, {"Authorization": "Bearer " + unknown_kid}, body).status_code == 401


def test_sec15_runs_per_hour_limit(rt: Runtime, user_client: Any) -> None:
    client, tok, runtime = user_client
    limited = Runtime(
        settings=dataclasses.replace(runtime.settings, user_runs_per_hour=2), db=runtime.db
    )
    limited_client = TestClient(create_app(limited, jwks=client.app.state.jwks))
    for i in range(2):
        assert (
            post(
                limited_client, tok("alice"), body_of([{"section": "5.1", "text": f"Тест {i}"}])
            ).status_code
            == 200
        )
    r = post(limited_client, tok("alice"), body_of([{"section": "5.1", "text": "Тест 99"}]))
    assert (
        r.status_code == 429
        and r.headers["retry-after"]
        and r.json()["error"]["code"] == "rate_limited"
    )
    # the same content is an existing run and is not counted again
    assert (
        post(
            limited_client, tok("alice"), body_of([{"section": "5.1", "text": "Тест 0"}])
        ).status_code
        == 200
    )
    assert (
        post(
            limited_client, tok("bob"), body_of([{"section": "5.1", "text": "Тест 5"}])
        ).status_code
        == 200
    )


def test_sec15_cors_only_for_the_hse_origin(client: TestClient) -> None:
    ok = client.options(
        "/v1/checks",
        headers={"Origin": "https://hse.test", "Access-Control-Request-Method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == "https://hse.test"
    bad = client.options(
        "/v1/checks",
        headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in bad.headers


def test_error_responses_carry_the_request_id(client: TestClient) -> None:
    r = client.get("/v1/gate", headers={"X-Request-Id": "req-42"})
    assert r.status_code == 401 and r.headers["x-request-id"] == "req-42"
    assert set(r.json()["error"]) == {"code", "message", "field"}


def test_original_request_is_not_mutated_by_masking() -> None:
    req = factory.request("GP", [{"section": "5.1", "text": "ИИН 900101300123"}])
    from aicheck.runs import sanitize_request

    clean, count = sanitize_request(req)
    assert (
        count == 1 and "[ИИН]" in clean.measures[0].text and "900101300123" in req.measures[0].text
    )
    assert copy.deepcopy(req) == req


def test_result_order_is_stable_critical_first_and_code_before_ai(
    client: TestClient, hse: dict[str, str], rt: Runtime
) -> None:
    body = body_of(
        [
            {"section": "5.10", "text": "Тест"},
            {"section": "5.2", "text": "Тест"},
            {"section": "5.5", "text": "Оградить зону работ знаками безопасности по периметру"},
        ]
    )
    first = post(client, hse, body).json()
    order = [(f["severity"], f["ruleCode"], f["target"].get("section")) for f in first["findings"]]
    assert order[0][0] == "critical" and [o for o in order if o[1] == "S02"] == [
        ("critical", "S02", "5.2"),
        ("critical", "S02", "5.10"),
    ]
    assert (
        first["findings"]
        == client.get(f"/v1/checks/{first['runId']}", headers=hse).json()["findings"]
    )
    from aicheck.jobs.worker import LlmWorker
    from aicheck.llm.client import LlmClient
    from tests.fakes.fake_llm import FakeLlm

    LlmWorker(rt, LlmClient(rt.settings, transport=FakeLlm("ok").transport())).step()
    after = client.get(f"/v1/checks/{first['runId']}", headers=hse).json()["findings"]
    sources = [f["source"] for f in after]
    assert sources == sorted(sources, key=lambda s: s != "rules")  # code findings, then AI findings
    assert [f for f in after if f["source"] == "rules"] == first["findings"]


def test_masking_that_lengthens_a_text_over_the_limit_is_a_422_not_a_crash(
    client: TestClient, hse: dict[str, str]
) -> None:
    text_ = ("a@b.c " * 330).strip()  # 1979 characters; each address becomes the longer [EMAIL]
    body = body_of([{"section": "5.1", "text": text_}])
    r = post(client, hse, body)
    assert r.status_code == 422 and "too long" in r.json()["error"]["message"]


def test_row_limits_name_the_field(client: TestClient, hse: dict[str, str]) -> None:
    body = body_of()
    body["measures"] = [{**body["measures"][0], "rowId": f"r{i}"} for i in range(31)]
    r = post(client, hse, body, key="sha256:" + "0" * 64)
    assert r.status_code == 422 and r.json()["error"]["field"] == "measures"
    body = body_of()
    body["measures"][0]["text"] = "а" * 2001
    assert post(client, hse, body).json()["error"]["field"] == "measures.0.text"
