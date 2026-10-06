"""Stage 7: SEC-10, SEC-12 and the code rules of the specification (static checks)."""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.stage7
ROOT = Path(__file__).resolve().parents[2]
SOURCES = list((ROOT / "aicheck").rglob("*.py")) + list((ROOT / "scripts").glob("*.py"))


def load_checker():
    spec = importlib.util.spec_from_file_location("check_code", ROOT / "scripts" / "check_code.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_code"] = module
    spec.loader.exec_module(module)
    return module


def test_sec10_tls_verification_is_never_disabled() -> None:
    for path in SOURCES:
        text = path.read_text(encoding="utf-8")
        if path.name != "check_code.py":
            assert not re.search(r"verify\s*=\s*False", text), path
            assert "CERT_NONE" not in text and "_create_unverified_context" not in text, path


def test_code_rules_hold_for_the_whole_package() -> None:
    checker = load_checker()
    problems = [p for path in checker.files() for p in checker.check_file(path)]
    assert problems == []


def test_the_checker_catches_what_it_promises(tmp_path: Path) -> None:
    checker = load_checker()
    bad = tmp_path / "bad.py"
    bad.write_text(
        "import pickle\nasync def f():\n    return eval('1')\nclient = x(verify=False)\nprint('x')\n"
        "key = 'sk-abcdefghijklmnopqrstuvwxyz'\n",
        encoding="utf-8",
    )
    checker.ROOT = tmp_path
    problems = " ".join(checker.check_file(bad))
    for expected in (
        "forbidden import pickle",
        "async/await",
        "eval is forbidden",
        "TLS verification",
        "print",
        "api key",
    ):
        assert expected in problems, expected
    long_function = tmp_path / "long.py"
    long_function.write_text("def f():\n" + "    x = 1\n" * 45, encoding="utf-8")
    assert "function f has" in " ".join(checker.check_file(long_function))


def test_async_exists_only_in_the_asgi_glue() -> None:
    offenders = [
        p
        for p in (ROOT / "aicheck").rglob("*.py")
        if re.search(r"\basync def\b", p.read_text(encoding="utf-8"))
    ]
    assert offenders == [ROOT / "aicheck" / "api" / "asgi.py"]


def test_no_orm_or_forbidden_frameworks_in_requirements() -> None:
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8").lower()
    for name in (
        "langchain",
        "llama-index",
        "celery",
        "redis",
        "kafka",
        "pika",
        "chromadb",
        "faiss",
        "requests==",
    ):
        assert name not in lock, name


def test_sec12_ci_fails_on_vulnerabilities_and_high_findings() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "bandit" in makefile and "-lll" not in makefile.split("sec:")[0]
    sec = makefile.split("\nsec:")[1].split("\n\n")[0]
    assert "bandit -r aicheck -ll" in sec and "pip_audit" in sec and "scripts/check_code.py" in sec
    assert "--strict" in sec
    ci = (ROOT / "scripts" / "ci.sh").read_text(encoding="utf-8")
    steps = [
        m.start()
        for m in (
            re.search(rf"make {t}\b", ci)
            for t in ("lint", "typecheck", "sec", "test-stage", "golden")
        )
        if m
    ]
    assert len(steps) == 5 and steps == sorted(steps)  # fast steps first, as in the specification
    assert "set -e" in ci


def test_requirements_lock_pins_versions_with_hashes() -> None:
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    pins = re.findall(r"^[A-Za-z0-9_.\-\[\]]+==[\w.\-+!]+", lock, re.MULTILINE)
    assert len(pins) > 30 and lock.count("--hash=sha256:") >= len(pins)


def test_container_runs_as_non_root_with_a_read_only_filesystem() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    stages = re.findall(r"^FROM .* AS (\w+)", dockerfile, re.MULTILINE)
    assert stages[:2] == ["build", "runtime"]  # compilers stay in the build stage
    runtime = dockerfile.split("AS runtime")[1]
    assert (
        re.search(r"^USER (?!root)\S+", runtime, re.MULTILINE)
        and "gcc" not in runtime
        and "build-essential" not in runtime
    )
    assert "--require-hashes" in dockerfile
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert (
        compose.count("read_only: true") >= 2
        and "cap_drop" in compose
        and "no-new-privileges" in compose
    )


def test_documents_for_the_security_review_exist() -> None:
    security = (ROOT / "docs" / "security.md").read_text(encoding="utf-8")
    for needle in (
        "3 года",
        "2 месяца",
        "832",
        "резервн",
        "инцидент",
        "матриц",
        "MFA",
        "94-V",
        "230-VIII",
        "[ИИН]",
    ):
        assert needle.lower() in security.lower(), needle
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for needle in (
        "X-Signature",
        "ALLOWED_OUTBOUND_HOSTS",
        "территории Республики Казахстан",
        "make test-stage",
        "hash_vectors",
    ):
        assert needle in readme, needle
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "LLM_API_KEY_FILE=" in example and not re.search(
        r"(?i)(secret|key|password)\s*=\s*[A-Za-z0-9+/]{16,}", example
    )
    assert (ROOT / "DECISIONS.md").stat().st_size > 500 and (
        ROOT / "CHANGELOG.md"
    ).stat().st_size > 500
