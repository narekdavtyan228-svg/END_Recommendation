"""Nothing may crash on arbitrary Unicode (S02, S05, S10 and the rest of the syntax rules)."""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aicheck.engine.syntax import fix_latin, fix_punctuation, fix_repeats
from tests.helpers import run

pytestmark = pytest.mark.stage2
TEXT = st.text(max_size=400)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(TEXT)
def test_rules_never_crash_on_random_text(text: str) -> None:
    findings = run([{"section": "5.5", "text": text}])
    assert all(f.ruleCode for f in findings)


@settings(max_examples=150, deadline=None)
@given(TEXT)
def test_autofixes_are_total_and_idempotent(text: str) -> None:
    assert fix_punctuation(fix_punctuation(text)) == fix_punctuation(text)
    assert fix_repeats(fix_repeats(text)).count("  ") <= fix_repeats(text).count("  ")
    assert len(fix_latin(text)) == len(text)


@settings(max_examples=100, deadline=None)
@given(st.text(alphabet=st.characters(min_codepoint=0x400, max_codepoint=0x4FF), max_size=60))
def test_cyrillic_text_is_not_flagged_as_latin(text: str) -> None:
    assert fix_latin(text) == text
