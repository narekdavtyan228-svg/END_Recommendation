"""Acceptance cases of the specification (tests/golden/official): format of `expect`."""

import copy
import json
from pathlib import Path
from typing import Any

from aicheck.catalog.model import Catalog
from aicheck.contracts import CheckRequest, Finding
from aicheck.engine.run import check
from aicheck.hashing import content_hash
from aicheck.rules.loader import Ruleset, load_packaged, parse_ruleset

TARGET_KEYS = ("type", "section", "rowId", "field")


def load_catalog_body(directory: Path) -> dict[str, Any]:
    body: dict[str, Any] = json.loads((directory / "test_catalog.json").read_text(encoding="utf-8"))
    return body


def ruleset_for(catalog_body: dict[str, Any]) -> Ruleset:
    """The packaged rules with the parameter overrides that the test catalog carries."""
    raw = copy.deepcopy(load_packaged().raw)
    overrides = catalog_body.get("test_parameters_override", {})
    for param in raw["parameters"]:
        if param["code"] in overrides:
            param["data"] = overrides[param["code"]]
    return parse_ruleset(json.dumps(raw, ensure_ascii=False))


def load_cases(directory: Path) -> list[dict[str, Any]]:
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((directory / "cases").glob("*.json"))
    ]


def build_request(case: dict[str, Any]) -> CheckRequest:
    """The request of a case with the contentHash computed by the service."""
    body = copy.deepcopy(case["request"])
    body["end"]["contentHash"] = "sha256:" + "0" * 64
    body["end"]["contentHash"] = content_hash(CheckRequest.model_validate(body))
    return CheckRequest.model_validate(body)


def _matches(finding: Finding, want: dict[str, Any]) -> bool:
    if finding.ruleCode != want["rule_code"]:
        return False
    if "severity" in want and finding.severity != want["severity"]:
        return False
    target = finding.target.model_dump(exclude_none=True)
    if any(target.get(k) != v for k, v in want.get("target", {}).items() if k in TARGET_KEYS):
        return False
    return "hazard_name" not in want or finding.hazardName == want["hazard_name"]


def _texts(findings: list[Finding]) -> str:
    return " ".join(f"{f.title.ru} {f.message.ru} {f.evidence}" for f in findings).lower()


def problems(expect: dict[str, Any], findings: list[Finding]) -> list[str]:
    """What the findings lack or contain against the `expect` block of a code-only case."""
    found: list[str] = []
    for want in expect.get("must_include", []):
        if not any(_matches(f, want) for f in findings):
            found.append(f"missing {want}")
    for group in expect.get("must_include_any", []):
        if not any(_matches(f, w) for f in findings for w in group):
            found.append(f"none of {group}")
    bad_rules = set(expect.get("must_not_include", []))
    found += [f"unexpected {f.ruleCode}" for f in findings if f.ruleCode in bad_rules]
    bad_levels = set(expect.get("must_not_include_severity", []))
    found += [
        f"unexpected {f.severity} {f.ruleCode}"
        for f in findings
        if f.severity in bad_levels and f.kind != "question"
    ]
    asked = {f.target.factorCode for f in findings if f.kind == "question"}
    found += [f"no question {c}" for c in expect.get("questions", []) if c not in asked]
    text = _texts(findings)
    found += [f"mentions {s!r}" for s in expect.get("must_not_mention", []) if s.lower() in text]
    return found


def run_code_only(directory: Path) -> dict[str, list[str]]:
    """Case id -> problems, for every `code_only` case (an empty list means the case passes)."""
    body = load_catalog_body(directory)
    ruleset, catalog = ruleset_for(body), Catalog.from_body(body)
    result = {}
    for case in load_cases(directory):
        if case["mode"] == "code_only":
            _, findings = check(build_request(case), ruleset, catalog)
            result[case["id"]] = problems(case["expect"], findings)
    return result
