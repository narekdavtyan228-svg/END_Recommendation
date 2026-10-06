"""N01-N06, N10-N12, N14 and the category matrix."""

import pytest

from tests import factory
from tests.helpers import by_rule, has, m, run

pytestmark = pytest.mark.stage2
NO_FLAGS = {"gasAirControl": False, "adjacentApproval": False, "fireService": False}


def test_n01_other_category_markers() -> None:
    f = run([m("5.3", "Использовать краги сварщика при работе")], category="GP")
    assert has(f, "N01", "m0")


def test_n01_allowed_by_category_or_factor() -> None:
    assert not has(run([m("5.3", "Использовать краги сварщика при работе")], category="OG"), "N01")
    f = run(
        [m("5.3", "Использовать краги сварщика при работе")], category="GP", answers={"F19": "yes"}
    )
    assert not has(f, "N01")


def test_n01_hint_exception() -> None:
    cat = factory.catalog(hints={"5.3": "Заглушки, строповка и краги по месту"})
    f = run([m("5.3", "Использовать краги сварщика при работе")], category="GP", catalog=cat)
    assert not has(f, "N01")


def test_n02_conditional_catalog_record_with_factor_no() -> None:
    f = run(
        [m("5.2", "Отключить электрооборудование в зоне работ")],
        category="GP",
        answers={"F02": "no", "F08": "no", "F09": "no"},
    )
    n02 = by_rule(f, "N02")
    assert n02 and n02[0].recommendation and n02[0].recommendation.mode == "not_applicable"


def test_n02_not_raised_for_manual_text_or_factor_yes() -> None:
    f = run(
        [m("5.2", "Отключить кабель питания насоса полностью")],
        answers={"F02": "no", "F08": "no", "F09": "no"},
    )
    assert not has(f, "N02")
    f = run([m("5.2", "Отключить электрооборудование в зоне работ")], answers={"F09": "yes"})
    assert not has(f, "N02")


def test_n03_needs_the_season_parameter() -> None:
    text = m("5.10", "При морозе ниже −20 °C применять утеплённые перчатки и мероприятия")
    assert not has(run([text]), "N03")  # P09 is not set
    assert has(run([text], params=True), "N03")  # September: warm period


def test_n03_not_raised_in_cold_dates() -> None:
    text = m("5.10", "При морозе ниже −20 °C применять утеплённые перчатки и мероприятия")
    f = run(
        [text], params=True, startAt="2026-12-10T10:00:00+05:00", endAt="2026-12-12T10:00:00+05:00"
    )
    assert not has(f, "N03")


def test_n03_heat_measure_in_winter() -> None:
    f = run(
        [m("5.10", "При жаре выше +40 организовать питьевой режим бригады")],
        params=True,
        startAt="2026-12-10T10:00:00+05:00",
        endAt="2026-12-12T10:00:00+05:00",
    )
    assert has(f, "N03")


def test_n04_object_absent_in_unit_profile() -> None:
    f = run([m("5.8", "Выставить сигнальщика у железнодорожных путей на переезде")])
    assert has(f, "N04", "m0") and not has(f, "N01", "m0")


def test_n04_not_raised_when_factor_yes() -> None:
    f = run(
        [m("5.8", "Выставить сигнальщика у железнодорожных путей на переезде")],
        answers={"F10": "yes"},
    )
    assert not has(f, "N04")


def test_n05_record_in_another_section() -> None:
    f = run([m("5.2", "Установить заглушки на трубопроводе")])
    assert has(f, "N05", "m0")
    assert not has(run([m("5.3", "Установить заглушки на трубопроводе")]), "N05")


def test_n06_dash_in_core_section() -> None:
    f = run([m("5.5", "—")], category="GP")
    assert has(f, "N06", "m0")
    assert not has(run([m("5.5", "Оградить зону работ сигнальной лентой по периметру")]), "N06")


def test_n06_dash_in_conditional_section_with_factor_yes() -> None:
    assert has(run([m("5.4", "—")], category="ZR", answers={"F03": "yes"}), "N06")
    assert not has(run([m("5.4", "—")], category="ZR", answers={"F03": "no"}), "N06")


def test_n10_not_preparatory_actions() -> None:
    assert has(run([m("5.10", "При пожаре вызвать пожарную охрану немедленно")]), "N10")
    assert has(run([m("5.10", "По окончании работ сдать СИЗ и закрыть наряд")]), "N10")
    assert not has(run([m("5.10", "Подготовить пожарный щит на площадке работ")]), "N10")


def test_n11_foreign_norms() -> None:
    f = run([m("5.10", "Работы выполнять по требованиям Ростехнадзора на объекте")])
    n11 = by_rule(f, "N11")
    assert n11 and "Ростехнадзор" in n11[0].message.ru
    assert has(run([m("5.10", "Применять приказ № 782н при работе на высоте")]), "N11")
    assert not has(run([m("5.10", "Применять правила № 109 при работе на высоте")]), "N11")
    assert not has(run([m("5.10", "Выдать 528 касок на площадку работ")]), "N11")


def test_n12_flag_must_match_category() -> None:
    f = run([m("5.1", "Остановить технику")], category="GO", **{"flags": NO_FLAGS})
    n12 = by_rule(f, "N12")
    assert n12 and n12[0].severity == "critical" and n12[0].target.flag == "gasAirControl"
    assert not has(run([m("5.1", "Остановить технику")], category="GO"), "N12")


def test_n12_earthworks_need_neighbour_approval_and_fire_service_param() -> None:
    assert has(run([], category="ZR", flags=NO_FLAGS), "N12")
    assert has(run([], category="OG", params=True, flags=NO_FLAGS), "N12")
    assert not has(run([], category="OG", params=False, flags=NO_FLAGS), "N12")


def test_n14_unknown_conditional_factor_is_a_question() -> None:
    f = run([], category="GP")
    q = by_rule(f, "N14")
    assert q and all(x.kind == "question" and x.severity == "question" for x in q)
    assert {x.target.factorCode for x in q} >= {"F02", "F05"}


def test_n14_blocking_follows_severity_and_answers_close_it() -> None:
    f = run([], category="ZR")
    f27 = next(x for x in by_rule(f, "N14") if x.target.factorCode == "F27")
    assert f27.blocking  # section 5.2 of earthworks is critical when missing
    f = run([], category="ZR", answers={"F27": "no"})
    assert not any(x.target.factorCode == "F27" for x in by_rule(f, "N14"))


def test_matrix_missing_core_section_uses_severity_from_matrix() -> None:
    f = run([], category="ZR")
    mx = {x.target.section: x for x in by_rule(f, "MX")}
    assert "5.5" in mx and mx["5.5"].severity == "critical"
    assert mx["5.5"].evidence  # the minimal content expected


def test_matrix_conditional_section_follows_factors() -> None:
    f = run([], category="ZR", answers={"F03": "yes"})
    assert any(x.target.section == "5.4" for x in by_rule(f, "MX"))
    f = run([], category="ZR", answers={"F03": "no"})
    assert not any(x.target.section == "5.4" for x in by_rule(f, "MX"))


def test_matrix_not_raised_when_row_exists() -> None:
    f = run([m("5.5", "Оградить выемку сигнальной лентой не ниже одного метра")], category="ZR")
    assert not any(x.target.section == "5.5" for x in by_rule(f, "MX"))
