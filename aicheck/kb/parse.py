"""Document text -> numbered clauses (PDF, DOCX, TXT, MD)."""

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

from docx import Document
from docx.oxml.ns import qn
from pypdf import PdfReader
from pypdf.errors import PyPdfError

CLAUSE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){0,3})[.)]\s+")
SUBCLAUSE = re.compile(r"^\s*(\d{1,2})\)\s+")
HEADING = re.compile(r"^(Глава|Параграф|Раздел)\s+\d+")
MAX_CLAUSE_CHARS = 4000
NO_TEXT_LAYER = "нет текстового слоя, распознавание не поддерживается"


class ParseError(Exception):
    pass


@dataclass
class ParsedClause:
    clause_no: str
    heading: str | None
    body: str
    position: int = 0


@dataclass
class ParseResult:
    clauses: list[ParsedClause] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)


def _pdf_text(data: bytes) -> str:
    try:
        pages = [(page.extract_text() or "") for page in PdfReader(io.BytesIO(data)).pages]
    except (PyPdfError, ValueError, KeyError) as exc:
        raise ParseError("PDF cannot be read") from exc
    text = "\n".join(pages)
    if not text.strip():
        raise ParseError(NO_TEXT_LAYER)
    return text


def _docx_text(data: bytes) -> str:
    try:
        document = Document(io.BytesIO(data))
    except (zipfile.BadZipFile, KeyError, ValueError) as exc:
        raise ParseError("DOCX cannot be read") from exc
    lines: list[str] = []
    for element in document.element.body.iterchildren():
        if element.tag == qn("w:p"):
            lines.append("".join(t.text or "" for t in element.iter(qn("w:t"))))
        elif element.tag == qn("w:tbl"):
            for row in element.iter(qn("w:tr")):
                cells = [
                    "".join(t.text or "" for t in c.iter(qn("w:t"))) for c in row.iter(qn("w:tc"))
                ]
                lines.append(" | ".join(cells))
    return "\n".join(lines)


def extract_text(file_name: str, data: bytes) -> str:
    name = file_name.lower()
    if name.endswith(".pdf"):
        return _pdf_text(data)
    if name.endswith(".docx"):
        return _docx_text(data)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("text file must be UTF-8") from exc


def _split_long(clause: ParsedClause) -> list[ParsedClause]:
    """A clause above 4000 characters is cut by paragraphs into `no/1`, `no/2`..."""
    if len(clause.body) <= MAX_CLAUSE_CHARS:
        return [clause]
    parts: list[str] = [""]
    for paragraph in clause.body.split("\n"):
        if parts[-1] and len(parts[-1]) + len(paragraph) + 1 > MAX_CLAUSE_CHARS:
            parts.append("")
        parts[-1] = (parts[-1] + "\n" + paragraph).strip("\n")
    return [
        ParsedClause(f"{clause.clause_no}/{i}", clause.heading, p) for i, p in enumerate(parts, 1)
    ]


def split_clauses(text: str) -> ParseResult:
    clauses: list[ParsedClause] = []
    current: ParsedClause | None = None
    parent = ""
    heading: str | None = None
    unnumbered = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        sub, main = SUBCLAUSE.match(raw), CLAUSE.match(raw)
        if HEADING.match(line):
            heading, current = line, None
        elif sub and parent:
            current = ParsedClause(f"{parent}.{sub.group(1)})", heading, raw[sub.end() :].strip())
            clauses.append(current)
        elif main:
            parent = main.group(1)
            current = ParsedClause(parent, heading, raw[main.end() :].strip())
            clauses.append(current)
        elif current:
            current.body += "\n" + line
        else:
            unnumbered += len(line)
    result = [part for c in clauses for part in _split_long(c)]
    for position, clause in enumerate(result, 1):
        clause.position = position
    long_count = sum(1 for c in clauses if len(c.body) > MAX_CLAUSE_CHARS)
    report = {"clauses": len(result), "unnumbered_chars": unnumbered, "long_clauses": long_count}
    return ParseResult(result, report)


def parse_document(file_name: str, data: bytes) -> ParseResult:
    return split_clauses(extract_text(file_name, data))
