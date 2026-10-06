"""S01-S17: at least one positive and one negative case per rule."""

import pytest

from aicheck.engine.syntax import fix_latin, fix_punctuation, fix_repeats
from tests.helpers import by_rule, has, m, run

pytestmark = pytest.mark.stage2
GOOD = "Установить ограждение зоны работ и выставить знаки безопасности"


def one(text: str, **kw: object) -> list:
    return run([m("5.5", text, **kw)])


def test_s01_empty_row_is_critical() -> None:
    f = by_rule(one("   "), "S01")
    assert len(f) == 1 and f[0].severity == "critical" and f[0].target.rowId == "m0"


def test_s01_filled_and_dash_rows_pass() -> None:
    assert not has(one(GOOD), "S01")
    assert not has(one("—"), "S01")
    assert not has(one("", notApplicable=True), "S01")


@pytest.mark.parametrize(
    "text", ["Тест", "test123", "asdf", "xxx", "1111", "ok", "да", "не знаю", "ааааа", "???", "***"]
)
def test_s02_stub_values(text: str) -> None:
    f = by_rule(one(text), "S02")
    assert f and f[0].severity == "critical" and f[0].evidence == text


def test_s02_real_text_passes() -> None:
    assert not has(one(GOOD), "S02")


def test_s02_message_substitutes_value() -> None:
    assert "«Тест»" in by_rule(one("Тест"), "S02")[0].message.ru


def test_s03_hint_copy_is_found_and_text_passes() -> None:
    assert has(run([m("5.4", "Взять пробу воздушной среды")]), "S03")
    assert not has(
        run([m("5.4", "Взять пробу воздушной среды газоанализатором перед входом")]), "S03"
    )


def test_s04_too_short() -> None:
    assert has(one("Оградить зону"), "S04")
    assert not has(one(GOOD), "S04")


def test_s04_is_suppressed_by_stub_rule() -> None:
    findings = one("Тест")
    assert has(findings, "S02") and not has(findings, "S04")


def test_s05_no_letters() -> None:
    assert has(one("12345 67 89"), "S05")
    assert not has(one(GOOD), "S05")


def test_s06_unfilled_template() -> None:
    assert has(one("Установить заглушки на ___ трубопроводе"), "S06")
    assert has(one("Выставить пост на отметке [ ]"), "S06")
    assert not has(one(GOOD), "S06")


def test_s07_punctuation_artifacts_have_autofix() -> None:
    f = by_rule(one("Оградить зону работ.;  Выставить знаки безопасности вокруг"), "S07")
    assert f and f[0].kind == "autofix" and f[0].autofix
    assert ".;" not in f[0].autofix.after and "  " not in f[0].autofix.after


def test_s07_clean_text_passes() -> None:
    assert not has(one(GOOD), "S07")


def test_fix_punctuation_removes_leading_fragment() -> None:
    assert (
        fix_punctuation("маршрут; Маршруты движения согласовать") == "Маршруты движения согласовать"
    )
    assert fix_punctuation("; текст;; дальше") == "текст; дальше"


def test_s08_unbalanced_brackets_and_quotes() -> None:
    assert has(one("Выставить знаки (по схеме объекта"), "S08")
    assert has(one("Выставить знаки «по схеме объекта"), "S08")
    assert has(one('Выставить знаки "по схеме объекта'), "S08")
    assert not has(one("Выставить знаки (по схеме) «объекта»"), "S08")


def test_s09_kazakh_letters_in_russian_text() -> None:
    assert has(one("Пройти медосмотр (ауысым алдындағы медтексеру) перед работой"), "S09")
    assert not has(one(GOOD), "S09")


def test_s09_skipped_for_kazakh_locale() -> None:
    req_findings = run([m("5.5", "Ауысым алдындағы медтексеру өткізу қажет")])
    assert has(req_findings, "S09")


def test_s10_latin_lookalikes_autofix() -> None:
    f = by_rule(one("Оградить зоHу работ"), "S10")
    assert (
        f
        and f[0].autofix
        and f[0].autofix.after == "Оградить зону работ".replace("н", "Н", 0).replace("зону", "зоНу")
    )
    assert fix_latin("Hа месте OK") == "На месте OK"


def test_s10_pure_cyrillic_passes() -> None:
    assert not has(one(GOOD), "S10")


def test_s11_duplicate_in_one_row_and_across_rows() -> None:
    f = run([m("5.1", "Остановить технику в зоне работ; остановить технику в зоне работ")])
    assert has(f, "S11")
    f = run(
        [m("5.1", "Остановить технику в зоне работ"), m("5.2", "Остановить технику в зоне работ")]
    )
    d = by_rule(f, "S11")
    assert d and "5.1" in d[0].message.ru and "5.2" in d[0].message.ru


def test_s11_different_measures_pass() -> None:
    f = run([m("5.1", "Остановить технику в зоне работ"), m("5.2", "Отключить кабель питания")])
    assert not has(f, "S11")


def test_s12_repeated_word_autofix() -> None:
    f = by_rule(one("Оградить зону зону работ знаками"), "S12")
    assert f and f[0].autofix and f[0].autofix.after == "Оградить зону работ знаками"
    assert fix_repeats("в в здании") == "в здании"
    assert not has(one(GOOD), "S12")


def test_s13_is_service_only_and_normalises_dashes() -> None:
    for dash in ("-", "–", "--", "н/п", "не требуется", "Не предусмотрено"):
        f = one(dash)
        assert not has(f, "S13") and not has(f, "S01") and not has(f, "S02")


def test_s14_number_without_unit() -> None:
    f = by_rule(one("Расстояние до линии электропередачи 30 обеспечить"), "S14")
    assert f and "30" in f[0].message.ru


def test_s14_number_with_unit_or_reference_passes() -> None:
    assert not has(one("Расстояние до линии 30 м обеспечить всегда"), "S14")
    assert not has(one("Радиус зоны по п. 77 правил определить"), "S14")


def test_s15_emoji_is_found_and_removed() -> None:
    f = by_rule(one("Оградить зону работ 😀 знаками безопасности"), "S15")
    assert f and f[0].autofix and "😀" not in f[0].autofix.after


def test_s15_plain_text_passes() -> None:
    assert not has(one(GOOD), "S15")


def test_s16_long_record() -> None:
    assert has(one("Оградить зону работ. " * 80), "S16")
    assert not has(one(GOOD), "S16")


def test_s17_values_out_of_range() -> None:
    assert has(one("Работы запрещены при ветре 80 м/с на площадке"), "S17")
    assert has(one("Температура воздуха 90 °C на площадке контролируется"), "S17")
    assert has(one("Глубина выемки 45 м перед работами проверяется"), "S17")


def test_s17_plausible_values_pass() -> None:
    assert not has(one("Работы запрещены при ветре 15 м/с на площадке"), "S17")
    assert not has(one("Температура воздуха -30 °C на площадке контролируется"), "S17")
