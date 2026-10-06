"""Input sanitisation: NFC, control characters, HTML tags, personal data masking."""

import re
import unicodedata

from aicheck.logging import EMAIL, IIN, PHONE

CONTROL = re.compile(r"[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]")
TAG = re.compile(r"<[^>]*>")


def clean_text(value: str) -> str:
    """NFC, no control characters, no HTML tags (kept: tab, LF, CR)."""
    value = unicodedata.normalize("NFC", value)
    return CONTROL.sub("", TAG.sub("", value))


def mask_personal(value: str) -> tuple[str, int]:
    """Replace IIN, phone and e-mail; returns the text and the number of replacements."""
    total = 0
    for pattern, mask in ((EMAIL, "[EMAIL]"), (PHONE, "[ТЕЛ]"), (IIN, "[ИИН]")):
        value, count = pattern.subn(mask, value)
        total += count
    return value, total
