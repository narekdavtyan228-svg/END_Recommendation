"""Stage 3: dedupe, sort, safe templates, make_finding."""

import pytest

from aicheck.contracts import Finding, Target, Text
from aicheck.engine.findings import SafeDict, basis_from_rule, make_finding, render
from aicheck.engine.run import SEVERITY_RANK, dedupe, sort_findings, summarize
from tests import factory
from tests.helpers import m, run

pytestmark = pytest.mark.stage3


def finding(
    code: str,
    severity: str,
    section: str | None = None,
    kind: str = "issue",
    row: str | None = None,
) -> Finding:
    return Finding(
        ruleCode=code,
        severity=severity,
        kind=kind,
        target=Target(type="measure", section=section, rowId=row),
        title=Text(),
        message=Text(),
    )  # type: ignore[arg-type]


def test_render_keeps_unknown_keys() -> None:
    assert (
        render("Пункт {section}: {value} {unknown}", {"section": "5.1", "value": "x"})
        == "Пункт 5.1: x {unknown}"
    )
    assert SafeDict()["k"] == "{k}"
    assert render("{__class__}", {}) == "{__class__}"


def test_dedupe_keeps_the_higher_severity_per_rule_and_target() -> None:
    kept = dedupe(
        [
            finding("S02", "recommendation", "5.1", row="a"),
            finding("S02", "critical", "5.1", row="a"),
            finding("S02", "critical", "5.1", row="b"),
        ]
    )
    assert sorted((f.target.rowId, f.severity) for f in kept) == [
        ("a", "critical"),
        ("b", "critical"),
    ]


def test_sort_order_critical_question_significant_recommendation_suggestion_autofix() -> None:
    items = [
        finding("a", "recommendation", "5.1", kind="autofix"),
        finding("b", "recommendation", "5.1"),
        finding("c", "significant", "5.1"),
        finding("d", "question", None, kind="question"),
        finding("e", "critical", "5.9"),
        finding("f", "significant", "5.1", kind="suggestion"),
        finding("g", "critical", "5.2"),
    ]
    ctx_req = factory.request("GP", [])
    from aicheck.engine.context import build_context

    ctx = build_context(ctx_req, factory.ruleset(), factory.catalog())
    assert [f.ruleCode for f in sort_findings(ctx, items)] == ["g", "e", "d", "c", "b", "f", "a"]


def test_sections_sort_numerically() -> None:
    f = run([m("5.10", "Тест"), m("5.2", "Тест")])
    s02 = [x.target.section for x in f if x.ruleCode == "S02"]
    assert s02 == ["5.2", "5.10"]


def test_summary_counts() -> None:
    items = [
        finding("a", "critical"),
        finding("b", "significant"),
        finding("c", "question", kind="question"),
        finding("d", "recommendation", kind="autofix"),
    ]
    assert summarize(items) == {
        "critical": 1,
        "significant": 1,
        "recommendation": 0,
        "questions": 1,
        "autofix": 1,
    }
    assert set(SEVERITY_RANK) == {"critical", "significant", "recommendation", "question"}


def test_basis_parsed_from_rule_text() -> None:
    rules = factory.ruleset()
    b = basis_from_rule({"basis": "№ 355, п. 33 (траншеи, шурфы)"}, rules)
    assert (
        (b.doc, b.status) == ("№ 355", "verified")
        and b.clause.startswith("п. 33")
        and b.url.startswith("https://")
    )
    c = basis_from_rule({"basis": "Правила ГПМ № 359 — сверить пункт; № 344"}, rules)
    assert c.status == "to_verify" and c.doc == "№ 359"
    assert basis_from_rule({"basis": "—"}, rules).status == "none"


def test_to_verify_basis_caps_critical_to_significant() -> None:
    rules = factory.ruleset()
    req = factory.request("GP", [])
    from aicheck.engine.context import build_context

    ctx = build_context(req, rules, factory.catalog())
    capped = make_finding(
        ctx,
        {"id": "X", "severity": "Критично", "basis": "№ 359 — сверить", "message": "m"},
        Target(type="description"),
    )
    solid = make_finding(
        ctx,
        {"id": "X", "severity": "Критично", "basis": "№ 344", "message": "m"},
        Target(type="description"),
    )
    assert (capped.severity, solid.severity) == ("significant", "critical")


def test_engine_is_deterministic() -> None:
    rows = [m("5.1", "Тест"), m("5.3", "Использовать краги  сварщика;; тут")]
    first = [f.model_dump_json() for f in run(rows, category="GP", params=True)]
    assert first == [f.model_dump_json() for f in run(rows, category="GP", params=True)]


def test_every_rule_of_the_package_is_implemented_or_left_to_the_llm() -> None:
    from aicheck.engine.registry import RULES
    from aicheck.rules.loader import check_type

    rules = factory.ruleset()
    for code in (
        list(rules.syntax)
        + list(rules.inapplicability)
        + list(rules.category_rules)
        + list(rules.risk_rules)
    ):
        if code in RULES:
            continue
        rule = rules.rule(code)
        assert check_type(rule) in ("llm", "code_llm", "none") or code in {
            "GP-05",
            "ZR-07",
            "ZP-06",
            "GO-05",
        }, code
    assert not set(RULES) - {c for c in RULES if rules.has_rule(c)}
