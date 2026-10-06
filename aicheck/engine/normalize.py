"""Text normalisation shared by the rules (originals are never modified)."""

import re
import unicodedata

SPACES = re.compile(r"\s+")
WORD = re.compile(r"[^\W\d_]+(?:-[^\W\d_]+)*", re.UNICODE)
DASH_FORMS = {"-", "–", "—", "--", "н/п", "нп", "не применимо", "не требуется", "не предусмотрено"}
DASH = "—"
# Prepositions and conjunctions that do not count as meaningful words (rule S04).
STOPWORDS = frozenset(
    [
        "при",
        "для",
        "над",
        "под",
        "что",
        "как",
        "или",
        "без",
        "про",
        "через",
        "между",
        "перед",
        "после",
        "около",
        "чтобы",
        "если",
        "также",
        "его",
        "ее",
        "их",
        "она",
        "они",
        "это",
        "эти",
        "той",
        "тот",
        "так",
        "там",
        "все",
        "всех",
        "всю",
        "при",
        "из",
        "от",
        "до",
        "по",
        "на",
        "об",
        "обо",
        "где",
        "когда",
        "либо",
        "еще",
        "уже",
        "только",
        "лишь",
    ]
)


def collapse(text: str) -> str:
    return SPACES.sub(" ", text).strip()


def compare_form(text: str) -> str:
    """NFC, lower case, `ё` -> `е`, collapsed spaces: the form used for comparisons."""
    return collapse(unicodedata.normalize("NFC", text).lower().replace("ё", "е"))


def is_dash(text: str) -> bool:
    return compare_form(text) in DASH_FORMS


def split_items(text: str) -> list[str]:
    """A row may hold several measures separated by `;`."""
    return [part.strip() for part in text.split(";") if part.strip()]


def significant_words(text: str) -> list[str]:
    return [w for w in WORD.findall(compare_form(text)) if len(w) >= 3 and w not in STOPWORDS]


def letter_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isalpha()) / len(text)


def short(text: str, limit: int = 60) -> str:
    text = collapse(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def stem_regex(stem: str) -> re.Pattern[str]:
    """Marker match by the beginning of a word, case-insensitive (spec section 6)."""
    return re.compile(r"\b" + re.escape(stem), re.IGNORECASE)


def find_stem(text: str, stems: tuple[str, ...] | list[str]) -> str | None:
    """First matched fragment (the whole word) or None."""
    for stem in stems:
        match = stem_regex(stem).search(text)
        if match:
            tail = re.match(r"\S*", text[match.start() :])
            return tail.group(0) if tail else stem
    return None
