"""Stage 1: the saved OpenAPI contract must match the generated one."""

import json
from pathlib import Path

import pytest

from aicheck.api.app import create_app

pytestmark = pytest.mark.stage1
ROOT = Path(__file__).resolve().parents[2]


def test_openapi_json_matches_the_generated_contract() -> None:
    saved = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    generated = json.loads(json.dumps(create_app().openapi(), ensure_ascii=False))
    assert saved == generated, "run `make openapi` and review the contract change"


def test_openapi_describes_the_required_endpoints() -> None:
    paths = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))["paths"]
    required = [
        ("post", "/v1/checks"),
        ("get", "/v1/checks/{run_id}"),
        ("post", "/v1/checks/{run_id}/answers"),
        ("post", "/v1/findings/{finding_id}/actions"),
        ("get", "/v1/gate"),
        ("post", "/v1/sync"),
        ("get", "/v1/catalog/version"),
        ("post", "/v1/admin/rulesets"),
        ("post", "/v1/admin/rulesets/{ruleset_id}/activate"),
        ("post", "/v1/admin/catalog"),
        ("get", "/v1/health"),
        ("get", "/v1/ready"),
        ("get", "/metrics"),
        ("post", "/v1/admin/kb/documents"),
        ("get", "/v1/admin/kb/documents"),
        ("get", "/v1/admin/kb/documents/{doc_id}"),
        ("patch", "/v1/admin/kb/documents/{doc_id}"),
        ("patch", "/v1/admin/kb/clauses/{clause_id}"),
        ("post", "/v1/admin/kb/documents/{doc_id}/activate"),
        ("get", "/v1/admin/kb/documents/{doc_id}/diff"),
        ("put", "/v1/admin/kb/rule-refs"),
        ("get", "/v1/admin/kb/rule-refs/broken"),
        ("get", "/v1/kb/clauses/{code}/{clause_no}"),
    ]
    for method, path in required:
        assert method in paths.get(path, {}), (method, path)
