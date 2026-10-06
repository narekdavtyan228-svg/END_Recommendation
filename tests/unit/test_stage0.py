"""Stage 0: configuration, logging scrubber, rule package loader, health."""

import json
import logging
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aicheck import logging as app_logging
from aicheck.api.app import create_app
from aicheck.config import ConfigError, load_settings, validate_outbound
from aicheck.rules import patterns
from aicheck.rules.loader import DATA_FILE, RulesError, load_packaged, parse_ruleset

pytestmark = pytest.mark.stage0


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    files = {
        "db": "postgresql://u:p@db/x",
        "key": "llm-secret-key",
        "hmac": "hmac-secret",
        "pub": "PUBLIC",
    }
    for name, value in files.items():
        (tmp_path / name).write_text(value + "\n")
    return {
        "DATABASE_URL_FILE": str(tmp_path / "db"),
        "ORG_CODE": "OMG",
        "LLM_BASE_URL": "https://llm.local/",
        "LLM_API_KEY_FILE": str(tmp_path / "key"),
        "LLM_MODEL": "deepseek",
        "JWT_ISSUER": "iss",
        "JWT_PUBLIC_KEY_FILE": str(tmp_path / "pub"),
        "ALLOWED_OUTBOUND_HOSTS": "llm.local, hse.local",
        "HSE_CATALOG_EXPORT_URL": "https://hse.local/export",
        "HSE_CALLBACK_URL": "https://hse.local/cb",
        "CALLBACK_HMAC_SECRET_FILE": str(tmp_path / "hmac"),
    }


def test_config_reads_secrets_from_files_and_applies_defaults(env: dict[str, str]) -> None:
    s = load_settings(env)
    assert s.llm_api_key == "llm-secret-key" and s.database_url.startswith("postgresql://")
    assert (
        s.llm_base_url == "https://llm.local" and s.llm_timeout_s == 12 and s.llm_json_mode is True
    )
    assert s.jwt_audience == "ai-check" and s.llm_min_confidence == 0.6 and s.max_body_kb == 256
    assert s.allowed_outbound_hosts == ("llm.local", "hse.local")


@pytest.mark.parametrize(
    "name",
    [
        "DATABASE_URL_FILE",
        "ORG_CODE",
        "LLM_BASE_URL",
        "LLM_MODEL",
        "JWT_ISSUER",
        "ALLOWED_OUTBOUND_HOSTS",
    ],
)
def test_config_refuses_to_start_without_required_variable(env: dict[str, str], name: str) -> None:
    del env[name]
    with pytest.raises(ConfigError, match="missing"):
        load_settings(env)


def test_llm_key_can_come_from_the_variable_when_there_is_no_file(env: dict[str, str]) -> None:
    del env["LLM_API_KEY_FILE"]
    with pytest.raises(ConfigError, match="LLM_API_KEY_FILE"):
        load_settings(env)
    env["LLM_API_KEY"] = " local-key "
    assert load_settings(env).llm_api_key == "local-key"


def test_config_unreadable_or_empty_secret(env: dict[str, str], tmp_path: Path) -> None:
    env["LLM_API_KEY_FILE"] = str(tmp_path / "nope")
    with pytest.raises(ConfigError, match="not readable"):
        load_settings(env)
    (tmp_path / "empty").write_text("\n")
    env["LLM_API_KEY_FILE"] = str(tmp_path / "empty")
    with pytest.raises(ConfigError, match="empty"):
        load_settings(env)


def test_config_llm_url_must_be_https_except_loopback_or_dev_flag(env: dict[str, str]) -> None:
    env["LLM_BASE_URL"] = "http://llm.local"
    with pytest.raises(ConfigError, match="https"):
        load_settings(env)
    env["LLM_BASE_URL"] = "http://localhost:8000"
    assert load_settings(env).llm_base_url == "http://localhost:8000"
    env["LLM_BASE_URL"] = "http://fake-llm:8080"
    env["ALLOW_INSECURE_LLM"] = "true"
    assert load_settings(env).allow_insecure_llm


def test_config_callback_secret_required_only_with_callback_url(env: dict[str, str]) -> None:
    del env["CALLBACK_HMAC_SECRET_FILE"]
    with pytest.raises(ConfigError, match="CALLBACK_HMAC_SECRET_FILE"):
        load_settings(env)
    del env["HSE_CALLBACK_URL"]
    assert load_settings(env).hse_callback_url == ""


def test_validate_outbound_checks_hosts(env: dict[str, str]) -> None:
    validate_outbound(load_settings(env))
    env["ALLOWED_OUTBOUND_HOSTS"] = "llm.local"
    with pytest.raises(ConfigError, match="ALLOWED_OUTBOUND_HOSTS"):
        validate_outbound(load_settings(env))


def test_scrubber_masks_secrets_and_personal_data() -> None:
    text = app_logging.scrub(
        "Authorization: Bearer abc.def.ghi api_key=sk-12345 secret: hush token=zzz "
        "ИИН 900101300123 тел +7 (701) 123-45-67 a@b.kz"
    )
    for leaked in ("abc.def.ghi", "sk-12345", "hush", "zzz", "900101300123", "701", "a@b.kz"):
        assert leaked not in text
    assert "[ИИН]" in text and "[ТЕЛ]" in text and "[EMAIL]" in text


def test_json_formatter_outputs_one_json_line_without_secrets() -> None:
    record = logging.LogRecord("x", logging.INFO, "f", 1, "key=%s", ("api_key=sk-1",), None)
    record.run_id = "r1"
    data = json.loads(app_logging.JsonFormatter().format(record))
    assert data["level"] == "INFO" and data["run_id"] == "r1" and "sk-1" not in data["msg"]


def test_loader_accepts_the_packaged_rules() -> None:
    rules = load_packaged()
    assert rules.version and len(rules.syntax) == 17 and len(rules.risk_rules) == 25
    assert set(rules.category_names) == {"ZR", "GP", "ZP", "DR", "OG", "GO", "VS"}


def test_loader_rejects_broken_json_and_structure() -> None:
    with pytest.raises(RulesError, match="valid JSON"):
        parse_ruleset("{not json")
    with pytest.raises(RulesError, match="object"):
        parse_ruleset("[]")
    with pytest.raises(RulesError, match="missing sections"):
        parse_ruleset("{}")


def test_loader_rejects_duplicate_ids() -> None:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    raw["syntax"].append(raw["syntax"][0])
    with pytest.raises(RulesError, match="duplicate"):
        parse_ruleset(json.dumps(raw))


def test_loader_rejects_regex_that_is_not_in_the_rule_text() -> None:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    raw["syntax"][1]["detect"] = "changed"
    with pytest.raises(RulesError, match="not present"):
        parse_ruleset(json.dumps(raw))


def test_loader_rejects_regex_that_does_not_compile(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    broken = "(unclosed"
    next(r for r in raw["syntax"] if r["id"] == "S12")["detect"] += " " + broken
    monkeypatch.setitem(patterns.PATTERNS, "S12", [broken])
    with pytest.raises(RulesError, match="compile"):
        parse_ruleset(json.dumps(raw))


def test_patterns_run_fast_on_adversarial_input() -> None:
    rules = load_packaged()
    samples = [
        "а" * 2000,
        " " * 2000,
        ";" * 2000,
        "а а " * 660,
        "." * 2000,
        "_" * 2000,
        "аб" * 1000,
    ]
    for code, compiled in rules.patterns.items():
        for pattern in compiled:
            for sample in samples:
                started = time.perf_counter()
                pattern.search(sample)
                assert time.perf_counter() - started < 0.010, (code, pattern.pattern)


def test_health_works_without_database() -> None:
    client = TestClient(create_app())
    response = client.get("/v1/health")
    assert response.status_code == 200 and response.json() == {"status": "ok"}
    assert response.headers["x-request-id"]


def test_request_id_is_taken_from_the_request_or_generated() -> None:
    client = TestClient(create_app())
    assert (
        client.get("/v1/health", headers={"X-Request-Id": "abc-123"}).headers["x-request-id"]
        == "abc-123"
    )
    bad = client.get("/v1/health", headers={"X-Request-Id": "bad id\twith space"}).headers[
        "x-request-id"
    ]
    assert bad != "bad id\twith space" and len(bad) == 36


def test_security_events_are_logged_whatever_the_log_level(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app_logging.configure("ERROR")
    try:
        logging.getLogger("aicheck.api").info("ordinary info is hidden")
        app_logging.security_event("auth_denied", reason="role")
        out = capsys.readouterr().out
        assert "auth_denied" in out and "ordinary info" not in out
    finally:
        app_logging.configure("INFO")


def test_secrets_are_not_part_of_the_settings_repr(env: dict[str, str]) -> None:
    shown = repr(load_settings(env))
    for secret in ("llm-secret-key", "hmac-secret", "postgresql://u:p@db/x"):
        assert secret not in shown
