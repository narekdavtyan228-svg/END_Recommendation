import pytest

from aicheck.engine.context import build_context, match_catalog
from tests import factory
from tests.helpers import m

pytestmark = pytest.mark.stage2


def ctx_for(**kw):
    req = factory.request(kw.pop("category", "GP"), kw.pop("measures", []), **kw)
    return build_context(req, factory.ruleset(), factory.catalog())


def test_answer_has_the_highest_priority() -> None:
    req = factory.with_answers(factory.request("GP"), {"F03": "no"})
    c = build_context(req, factory.ruleset(), factory.catalog())
    assert c.factors["F03"].value == "no" and c.factors["F03"].source == "answer"


def test_unknown_answer_falls_through_to_flag() -> None:
    c = ctx_for()  # gasAirControl flag is true in the factory
    assert c.factors["F03"].value == "yes" and c.factors["F03"].source == "flag"


def test_description_stems_set_single_factor_groups() -> None:
    c = ctx_for(
        description="Работы рядом с железнодорожными путями", flags={"gasAirControl": False}
    )
    assert c.factors["F10"].value == "yes" and c.factors["F10"].source == "description"


def test_profile_default_and_unknown() -> None:
    c = ctx_for(flags={"gasAirControl": False})
    assert c.factors["F10"].value == "no" and c.factors["F10"].source == "profile"
    assert c.factors["F02"].value == "unknown" and c.factors["F02"].source == "none"


def test_match_catalog_exact_fuzzy_manual() -> None:
    cat = factory.catalog()
    assert match_catalog("Установить заглушки на трубопроводе", "5.3", cat)[0] == "catalog"
    assert match_catalog("установить   ЗАГЛУШКИ на трубопроводе", "5.3", cat)[0] == "catalog"
    assert (
        match_catalog("Установить заглушки на трубопроводе насосной", "5.3", cat)[0]
        == "catalog_edited"
    )
    assert match_catalog("Совсем другой текст про кабель", "5.3", cat)[0] == "manual"
    origin, item = match_catalog("Установить заглушки на трубопроводе", "5.9", cat)
    assert (
        origin == "catalog" and item and item["section"] == "5.3"
    )  # exact match ignores the section
    assert match_catalog("Установить заглушки на трубопроводе насосной", "5.9", cat)[0] == "manual"


def test_row_flags_dash_and_empty() -> None:
    c = ctx_for(measures=[m("5.1", "—"), m("5.2", ""), m("5.3", "Оградить зону работ знаками")])
    assert [(r.dash, r.empty, r.live) for r in c.rows] == [
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ]
