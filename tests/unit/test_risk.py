"""RA01-RA25 (code part)."""

import pytest

from tests.helpers import by_rule, has, run

pytestmark = pytest.mark.stage3
OK = {
    "hazardId": 311,
    "victimIds": [12],
    "harmIds": [45],
    "existingControlIds": [801],
    "b1": 3,
    "p1": 2,
}


def risk(**kw):
    return {**OK, **kw}


def ra(code, risks, category="ZR", params=True, **kw):
    return by_rule(run([], risks=risks, category=category, params=params, **kw), code)


def test_ra01_empty_table() -> None:
    assert has(run([], category="ZR"), "RA01")
    assert not has(run([], risks=[OK], category="ZR"), "RA01")


def test_ra02_missing_required_fields() -> None:
    f = ra("RA02", [risk(victimIds=[], b1=None)])
    assert {x.target.field for x in f} == {"victimIds", "b1"}
    assert not ra("RA02", [OK])


def test_ra03_scale_comes_from_p10() -> None:
    assert ra("RA03", [risk(b1=7)])
    assert not ra("RA03", [risk(b1=5)])
    assert not ra("RA03", [risk(b1=7)], params=False)  # no scale: nothing to check


def test_ra04_recomputes_r() -> None:
    f = ra("RA04", [risk(r1=7)])
    assert f and f[0].kind == "autofix" and f[0].autofix and f[0].autofix.after == "6"
    assert "3 × 2 = 6" in f[0].message.ru
    assert not ra("RA04", [risk(r1=6)])


def test_ra05_residual_higher_than_initial() -> None:
    assert ra("RA05", [risk(b2=4, p2=3, additionalControlIds=[915])])
    assert not ra("RA05", [risk(b2=1, p2=1, additionalControlIds=[915])])


def test_ra06_lowered_without_controls() -> None:
    assert ra("RA06", [risk(b2=1, p2=1)])
    assert not ra("RA06", [risk(b2=1, p2=1, additionalControlIds=[915])])
    assert not ra("RA06", [risk(b2=3, p2=2)])


def test_ra07_controls_without_residual() -> None:
    assert ra("RA07", [risk(additionalControlIds=[915])])
    assert not ra("RA07", [risk(additionalControlIds=[915], b2=1, p2=1)])


def test_ra08_additional_repeats_existing() -> None:
    assert ra("RA08", [risk(additionalControlIds=[801])])  # the same id
    assert ra("RA08", [risk(additionalControlIds=[917])])  # similarity >= 0.9 with 801
    assert not ra("RA08", [risk(additionalControlIds=[915])])


def test_ra09_severity_lowered_by_probability_only_measures() -> None:
    f = ra("RA09", [risk(b2=1, p2=2, additionalControlIds=[915])])
    assert f and "Инструктаж" in f[0].message.ru
    assert not ra("RA09", [risk(b2=1, p2=2, additionalControlIds=[802])])  # affects П+В


def test_ra10_ra11_zones_from_p10() -> None:
    assert ra("RA10", [risk(b2=5, p2=3, additionalControlIds=[915])])
    assert not ra("RA10", [risk(b2=2, p2=2, additionalControlIds=[915])])
    assert ra("RA11", [risk(b1=3, p1=3)])  # R=9 >= 6, no controls
    assert not ra("RA11", [risk(b1=3, p1=3, additionalControlIds=[915])])
    assert not ra("RA11", [risk(b1=3, p1=3)], params=False)


def test_ra12_required_hazard_missing_uses_catalog_severity() -> None:
    f = ra("RA12", [risk(hazardId=312)])
    names = {x.target.field: x.severity for x in f}
    assert names["Обрушение грунта стенок выемки"] == "critical"
    assert names["Падение в выемку"] == "significant"
    assert not any(
        x.target.field == "Повреждение подземных коммуникаций" for x in f
    )  # not "always"


def test_ra13_hazard_required_by_factor() -> None:
    assert ra("RA13", [risk()], answers={"F27": "yes"})
    assert not ra("RA13", [risk(), risk(hazardId=312)], answers={"F27": "yes"})
    assert not ra("RA13", [risk()], answers={"F27": "no"})


def test_ra14_duplicate_rows() -> None:
    f = ra("RA14", [risk(), risk(b1=1)])
    assert f and "1" in f[0].message.ru and "2" in f[0].message.ru
    assert not ra("RA14", [risk(), risk(victimIds=[13])])


def test_ra15_hazard_from_another_category() -> None:
    assert ra("RA15", [risk(hazardId=320)])  # "Падение груза" belongs to lifting works
    assert not ra("RA15", [risk()])


def test_ra16_victims_and_harms_must_match_the_hazard() -> None:
    f = ra("RA16", [risk(harmIds=[47])])
    assert f and "Ожоги" in f[0].message.ru
    assert ra("RA16", [risk(victimIds=[13])])
    assert not ra("RA16", [risk(harmIds=[45, 46])])


def test_ra17_controls_must_be_linked_to_the_hazard() -> None:
    f = ra("RA17", [risk(existingControlIds=[915])])
    assert f and "Инструктаж" in f[0].message.ru
    assert not ra("RA17", [risk(existingControlIds=[801, 802])])


def test_ra18_needs_a_measure_in_linked_sections() -> None:
    hot = risk(b1=3, p1=3)
    assert ra("RA18", [hot])
    assert not ra("RA18", [hot], params=False)
    found = by_rule(
        run(
            [{"section": "5.6", "text": "Установить крепление стенок выемки по проекту"}],
            risks=[hot],
            category="ZR",
            params=True,
        ),
        "RA18",
    )
    assert not found


def test_ra20_additional_control_must_be_reflected_in_section_5() -> None:
    assert ra("RA20", [risk(additionalControlIds=[801], existingControlIds=[802])])
    ok = run(
        [{"section": "5.5", "text": "Откосы по проекту"}],
        risks=[risk(additionalControlIds=[801], existingControlIds=[802])],
        category="ZR",
    )
    assert not has(ok, "RA20")


def test_ra21_minimum_severity_from_p13() -> None:
    assert ra("RA21", [risk(b1=2)])  # "Высокая" -> 4
    assert not ra("RA21", [risk(b1=4)])
    assert not ra("RA21", [risk(b1=2)], params=False)


def test_ra22_identical_scores_raise_a_question() -> None:
    f = ra("RA22", [risk(), risk(hazardId=312)])
    assert f and f[0].kind == "question"
    assert not ra("RA22", [risk(), risk(hazardId=312, b1=4)])
    assert not ra("RA22", [risk()])


def test_ra23_high_risk_needs_better_than_ppe() -> None:
    assert ra("RA23", [risk(b1=4, p1=4, additionalControlIds=[915, 916])])
    assert not ra("RA23", [risk(b1=4, p1=4, additionalControlIds=[802])])
    assert not ra("RA23", [risk(b1=2, p1=2, additionalControlIds=[915])])


def test_ra24_owner_and_deadline() -> None:
    assert ra("RA24", [risk(additionalControlIds=[915])])
    assert ra("RA24", [risk(additionalControlIds=[915], controlResponsibleRoleId=4)])
    assert not ra(
        "RA24", [risk(additionalControlIds=[915], controlResponsibleRoleId=4, implementWhenId=1)]
    )


def test_ra25_late_implementation_of_a_key_measure() -> None:
    late = risk(b1=4, p1=4, additionalControlIds=[915], implementWhenId=2)
    f = ra("RA25", [late])
    assert f and f[0].severity == "critical"
    assert not ra("RA25", [{**late, "implementWhenId": 1}])
    assert not ra("RA25", [{**late, "b1": 2, "p1": 2}])
