"""Stage 7: metrics, outbound guard (SEC-09), event logging (SEC-03) end to end."""

import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from aicheck import logging as app_logging
from aicheck.outbound import OutboundDenied, check_url, guarded_client, tls_context
from tests import factory

pytestmark = pytest.mark.stage7


def test_metrics_expose_the_service_counters(client: TestClient, hse: dict[str, str]) -> None:
    body = factory.request(
        "GP", [{"section": "5.1", "text": "Тест 123 ИИН 900101300123"}]
    ).model_dump(mode="json")
    client.post(
        "/v1/checks", json=body, headers={**hse, "Idempotency-Key": body["end"]["contentHash"]}
    )
    client.get("/v1/gate", params={"endRef": "e", "contentHash": "h"})  # denied: no token
    text = client.get("/metrics").text
    for name in (
        "llm_findings_dropped_total",
        "callback_undelivered_total",
        "pii_detected_total",
        "checks_total",
        "code_stage_seconds_bucket",
        "auth_denied_total",
        "llm_calls_total",
    ):
        assert name in text, name
    assert "Тест" not in text and "900101300123" not in text  # no user data in the metrics


def test_sec09_guarded_client_refuses_foreign_hosts_without_a_request() -> None:
    sent: list[httpx.Request] = []
    transport = httpx.MockTransport(lambda r: (sent.append(r), httpx.Response(200))[1])
    with guarded_client(["llm.test"], timeout=1.0, transport=transport) as client:
        assert client.get("https://llm.test/v1/x").status_code == 200
        with pytest.raises(OutboundDenied):
            client.get("https://evil.test/steal")
        with pytest.raises(OutboundDenied):
            client.get("https://llm.test.evil.test/")  # a look-alike host
        with pytest.raises(OutboundDenied):
            client.get("http://127.0.0.1:9/")
    assert [r.url.host for r in sent] == ["llm.test"]
    with pytest.raises(OutboundDenied):
        check_url("https://evil.test", ["llm.test"])
    check_url("https://LLM.test/path", ["llm.test"])  # host names are case-insensitive


def test_sec09_redirects_are_not_followed() -> None:
    transport = httpx.MockTransport(
        lambda r: httpx.Response(302, headers={"location": "https://evil.test/"})
    )
    with guarded_client(["llm.test"], timeout=1.0, transport=transport) as client:
        assert (
            client.get("https://llm.test/").status_code == 302
        )  # the redirect is returned, not followed


def test_tls_context_requires_certificates_and_modern_protocol() -> None:
    import ssl

    ctx = tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_sec03_denials_and_admin_actions_are_logged_even_at_error_level(
    client: TestClient, admin: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    app_logging.configure("ERROR")
    try:
        client.get("/v1/gate", params={"endRef": "e", "contentHash": "h"})
        client.post("/v1/admin/catalog", json={"version": "v-log"}, headers=admin)
        out = capsys.readouterr().out
        assert "auth_denied" in out and "admin_action" in out and "catalog_import" in out
    finally:
        app_logging.configure("INFO")
        logging.getLogger().setLevel(logging.INFO)


def test_sec06_logs_never_contain_texts_or_personal_data(
    client: TestClient, hse: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    app_logging.configure("DEBUG")
    try:
        text = "Секретный текст мероприятия для Иванова ИИН 900101300123 тел +7 701 123 45 67"
        body = factory.request(
            "GP", [{"section": "5.1", "text": text}], description="Описание ivan@corp.kz"
        ).model_dump(mode="json")
        client.post(
            "/v1/checks", json=body, headers={**hse, "Idempotency-Key": body["end"]["contentHash"]}
        )
        bad = dict(body, unexpected="СЕКРЕТНОЕ-ЗНАЧЕНИЕ")
        client.post(
            "/v1/checks", json=bad, headers={**hse, "Idempotency-Key": body["end"]["contentHash"]}
        )
        logs = capsys.readouterr().out
        for leaked in (
            "Секретный текст",
            "900101300123",
            "701 123",
            "ivan@corp.kz",
            "СЕКРЕТНОЕ-ЗНАЧЕНИЕ",
            "Описание",
        ):
            assert leaked not in logs, leaked
    finally:
        app_logging.configure("INFO")
