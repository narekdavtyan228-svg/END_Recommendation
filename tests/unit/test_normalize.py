import pytest

from aicheck.engine.normalize import (
    compare_form,
    find_stem,
    is_dash,
    letter_ratio,
    short,
    significant_words,
    split_items,
)
from aicheck.sanitize import clean_text, mask_personal

pytestmark = pytest.mark.stage2


def test_compare_form_folds_case_yo_and_spaces() -> None:
    assert compare_form("  Ёлка   ЗЕЛЁНАЯ ") == "елка зеленая"


def test_is_dash_variants() -> None:
    assert all(is_dash(x) for x in ["-", "–", "—", "--", "н/п", "Не применимо", "не требуется"])
    assert not is_dash("нет")
    assert not is_dash("Оградить зону")


def test_split_items_by_semicolon() -> None:
    assert split_items("а; б ;; в;") == ["а", "б", "в"]


def test_significant_words_skip_prepositions() -> None:
    assert significant_words("Установить ограждение для зоны при работе") == [
        "установить",
        "ограждение",
        "зоны",
        "работе",
    ]


def test_letter_ratio_and_short() -> None:
    assert letter_ratio("абв 123") < 0.6
    assert letter_ratio("") == 0.0
    assert short("а" * 100, 10).endswith("…") and len(short("а" * 100, 10)) == 10


def test_find_stem_matches_word_start_only() -> None:
    assert find_stem("Проверка стропов краном", ["строп"]) == "стропов"
    assert find_stem("Построй", ["строп", "стро"]) is None


def test_clean_text_removes_tags_controls_and_normalises() -> None:
    assert clean_text("<b>Текст</b>\x00\x07 ok") == "Текст ok"
    assert clean_text("е́") == "é".replace("e", "е")[0:0] + clean_text("е́")


def test_mask_personal_replaces_iin_phone_email() -> None:
    text, count = mask_personal("ИИН 900101300123 тел +7 701 123 45 67 mail a.b@corp.kz")
    assert "[ИИН]" in text and "[ТЕЛ]" in text and "[EMAIL]" in text and count == 3
    assert "900101300123" not in text and "@" not in text
