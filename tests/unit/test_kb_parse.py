"""Stage 6: splitting documents into clauses (PDF, DOCX, TXT, MD)."""

import pytest

from aicheck.kb.parse import NO_TEXT_LAYER, ParseError, extract_text, parse_document, split_clauses
from tests import kbfiles

pytestmark = pytest.mark.stage6


def numbers(result) -> list[str]:
    return [c.clause_no for c in result.clauses]


def test_clauses_subclauses_and_headings_from_text() -> None:
    result = split_clauses(kbfiles.LAW)
    assert numbers(result) == ["1", "2", "33", "33.1)", "33.2)", "128"]
    first, last = result.clauses[0], result.clauses[-1]
    assert first.heading.startswith("Глава 1") and last.heading.startswith("Глава 2")
    assert "50 метров" in first.body and result.report["clauses"] == 6
    assert [c.position for c in result.clauses] == [1, 2, 3, 4, 5, 6]


def test_decimal_numbers_and_continuation_lines() -> None:
    text = "5.2.1. Первый абзац пункта\nпродолжение пункта\n5.2.2) Второй пункт\n"
    result = split_clauses(text)
    assert numbers(result) == ["5.2.1", "5.2.2"]
    assert result.clauses[0].body == "Первый абзац пункта\nпродолжение пункта"


def test_text_before_the_first_number_is_counted_not_lost() -> None:
    result = split_clauses("Вводный текст без номера\n1. Пункт номер один\n")
    assert numbers(result) == ["1"] and result.report["unnumbered_chars"] == len(
        "Вводный текст без номера"
    )


def test_text_without_numbers_gives_no_clauses() -> None:
    result = split_clauses("Просто текст\nбез нумерации")
    assert (
        result.clauses == []
        and result.report["clauses"] == 0
        and result.report["unnumbered_chars"] > 0
    )


def test_long_clause_is_split_by_paragraphs() -> None:
    paragraph = "Очень длинный абзац пункта. " * 60  # about 1700 chars
    text = "33. Начало\n" + "\n".join([paragraph] * 5)
    result = split_clauses(text)
    assert numbers(result) == ["33/1", "33/2", "33/3"]
    assert all(len(c.body) <= 4000 for c in result.clauses) and result.report["long_clauses"] == 1


def test_docx_with_table_rows_as_cells_joined_by_bars() -> None:
    data = kbfiles.docx(["1. Пункт с таблицей"], [["Параметр", "Значение"], ["Радиус", "4 м"]])
    text = extract_text("law.docx", data)
    assert "Параметр | Значение" in text and "Радиус | 4 м" in text
    assert numbers(parse_document("law.docx", data)) == ["1"]


def test_docx_and_txt_and_md_give_the_same_clauses() -> None:
    expected = numbers(split_clauses(kbfiles.LAW))
    assert numbers(parse_document("a.docx", kbfiles.docx())) == expected
    assert numbers(parse_document("a.txt", kbfiles.txt())) == expected
    assert numbers(parse_document("a.md", kbfiles.txt())) == expected


def test_pdf_with_a_text_layer_is_parsed() -> None:
    result = parse_document("law.pdf", kbfiles.pdf())
    assert {"1", "2", "33", "128"} <= set(numbers(result))


def test_pdf_without_a_text_layer_is_an_error() -> None:
    with pytest.raises(ParseError, match=NO_TEXT_LAYER):
        parse_document("scan.pdf", kbfiles.pdf_without_text())


def test_broken_files_are_errors_not_crashes() -> None:
    for name, data in (
        ("a.pdf", b"%PDF-1.4 garbage"),
        ("a.docx", b"PK\x03\x04junk"),
        ("a.txt", b"\xff\xfe\x00bad"),
    ):
        with pytest.raises(ParseError):
            parse_document(name, data)
