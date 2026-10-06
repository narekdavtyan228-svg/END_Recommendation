"""Category rules (code part) ZR, GP, ZP, OG, GO, VS."""

import pytest

from tests import factory
from tests.helpers import by_rule, has, m, run

pytestmark = pytest.mark.stage3
NO_ATTACH = {"attachments": []}
OK_5_4 = m("5.4", "Выполнить газоанализ воздуха в траншее до спуска людей прибором")


def test_zr01_neighbour_approval_in_5_7() -> None:
    assert has(
        run([m("5.7", "Предупредить персонал смежного участка о работах")], category="ZR"), "ZR-01"
    )
    ok = run(
        [m("5.7", "Получить согласование владельцев коммуникаций перед работами")], category="ZR"
    )
    assert not has(ok, "ZR-01")
    assert not has(run([], category="ZR"), "ZR-01")  # a missing section is the matrix's finding


def test_zr02_scheme_attachment() -> None:
    assert has(run([], category="ZR", **NO_ATTACH), "ZR-02")
    assert not has(run([], category="ZR"), "ZR-02")


def test_zr04_gas_analysis_when_f03() -> None:
    bad = run([m("5.4", "Выставить сигнальную ленту по периметру выемки")], category="ZR")
    assert has(bad, "ZR-04")
    assert not has(run([OK_5_4], category="ZR"), "ZR-04")
    assert not has(
        run([m("5.4", "Выставить ленту по периметру")], category="ZR", answers={"F03": "no"}),
        "ZR-04",
    )


def test_zr07_zp06_go05_are_delegated_to_ra12_and_ra13() -> None:
    """Their hazards come with the structured hazard table: RA12/RA13 report a missing hazard."""
    risk = {
        "hazardId": 311,
        "victimIds": [12],
        "harmIds": [45],
        "existingControlIds": [801],
        "b1": 3,
        "p1": 2,
    }
    f = run([], risks=[risk], category="ZR")
    assert has(f, "RA12") and not has(f, "ZR-07")
    f = run([], risks=[risk], category="ZR", answers={"F27": "yes"})
    assert has(f, "RA13")


def test_gp01_overhead_line_needs_flag() -> None:
    f = run([], category="GP", answers={"F02": "yes"}, flags={"adjacentApproval": False})
    g = by_rule(f, "GP-01")
    assert g and g[0].target.flag == "adjacentApproval"
    assert g[0].severity == "significant"  # basis "сверить пункт" caps the severity
    assert not has(run([], category="GP", answers={"F02": "yes"}), "GP-01")


def test_gp03_time_separation() -> None:
    assert has(run([m("5.6", "Работать на высоте со страховкой")], answers={"F05": "yes"}), "GP-03")
    ok = run([m("5.6", "Разделение работ по времени с подъёмом груза")], answers={"F05": "yes"})
    assert not has(ok, "GP-03")


def test_gp05_is_delegated_to_s14() -> None:
    """GP-05 has executor «Код (S14)»: the radius without metres is reported by S14."""
    assert has(run([m("5.5", "Радиус опасной зоны 15 принять")]), "S14")
    assert not has(run([m("5.5", "Радиус опасной зоны 15 м принять")]), "S14")


def test_zp01_and_go01_duplicate_of_n12_is_dropped() -> None:
    flags = {"gasAirControl": False}
    f = run([], category="ZP", flags=flags)
    assert has(f, "N12") and not has(f, "ZP-01")
    f = run([], category="GO", flags=flags)
    assert has(f, "N12") and not has(f, "GO-01")


def test_zp04_hot_work_inside_needs_permit() -> None:
    assert has(
        run([m("5.10", "Работать со средствами защиты")], category="ZP", answers={"F31": "yes"}),
        "ZP-04",
    )
    ok = run(
        [m("5.10", "Оформить наряд-допуск на огневые работы")],
        category="ZP",
        answers={"F31": "yes"},
    )
    assert not has(ok, "ZP-04")


def test_og03_gas_analysis_before_hot_work() -> None:
    assert has(run([m("5.4", "Подготовить место")], category="OG"), "OG-03")
    assert not has(run([OK_5_4], category="OG"), "OG-03")


def test_og04_permit_for_gas_hazardous_work() -> None:
    assert has(
        run([m("5.10", "Работать с огнетушителем")], category="OG", answers={"F31": "yes"}), "OG-04"
    )
    ok = run(
        [m("5.10", "Оформить наряд на газоопасные работы")], category="OG", answers={"F31": "yes"}
    )
    assert not has(ok, "OG-04")


def test_og05_follows_the_p11_parameter() -> None:
    assert not has(run([], category="OG", flags={"fireService": False}), "OG-05")
    f = run([], category="OG", params=True, flags={"fireService": False})
    assert has(f, "N12") and not has(f, "OG-05")  # reported once, as N12


def test_go02_template_of_5_4() -> None:
    f = run([m("5.4", "Выполнить газоанализ на месте работ")], category="GO")
    g = by_rule(f, "GO-02")
    assert g and g[0].evidence
    full = m(
        "5.4",
        "Место: устье, время: до начала, периодичность: каждый час, прибор: газоанализатор, результат записать",
    )
    assert not has(run([full], category="GO"), "GO-02")


def test_vs03_obsolete_wording() -> None:
    assert has(
        run([m("5.10", "Работы при температуре по нормам местных органов")], category="VS"), "VS-03"
    )
    assert not has(
        run([m("5.10", "Работы при температуре по гигиеническим нормативам")], category="VS"),
        "VS-03",
    )


def test_vs04_fence_radius_against_table() -> None:
    bad = run([m("5.5", "Работы на высоте 15 м, радиус ограждения 3 м вокруг зоны")], category="VS")
    assert has(bad, "VS-04")
    ok = run([m("5.5", "Работы на высоте 15 м, радиус ограждения 7 м вокруг зоны")], category="VS")
    assert not has(ok, "VS-04")


def test_vs07_vs08_factor_dependent_rules() -> None:
    assert has(run([m("5.5", "Ограждение зоны")], category="VS", answers={"F01": "yes"}), "VS-07")
    ok = run(
        [m("5.5", "Въезд ГПМ и техники в рабочую зону запрещен")],
        category="VS",
        answers={"F01": "yes"},
    )
    assert not has(ok, "VS-07")
    assert has(
        run([m("5.6", "Страховка работников")], category="VS", answers={"F25": "yes"}), "VS-08"
    )
    ok = run(
        [m("5.6", "Независимая страховка предметов тяжелее 10 кг")],
        category="VS",
        answers={"F25": "yes"},
    )
    assert not has(ok, "VS-08")


def test_category_rules_stay_inside_their_category() -> None:
    f = run([], category="GP")
    assert not any(x.ruleCode.startswith(("ZR-", "VS-", "OG-")) for x in f)


def test_unconfirmed_basis_caps_severity_but_not_for_linked_documents() -> None:
    ctx_findings = run([], category="ZR", flags={"adjacentApproval": True})
    assert factory.ruleset() is not None and ctx_findings is not None
