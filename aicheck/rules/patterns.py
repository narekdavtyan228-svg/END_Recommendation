"""Regex pieces of the rule package.

The rules JSON keeps regexes inside the human-readable `detect` field. To keep the JSON the
single source of logic, every piece below must appear verbatim in the `detect` text of its
rule; the loader checks this and compiles each piece once.
"""

PATTERNS: dict[str, list[str]] = {
    "S02": [
        r"^(test\w*|тест\w*|asdf\w*|qwe\w*|йцук\w*|xxx+|ххх+|ааа+|zzz+|1+|123\w*|0+|\.+|\?+|!+"
        r"|,+|\++|=+|_+|ok|ок|да|нет\s*данных|не\s*знаю|todo|tbd|\*+)$",
        r"^(.)\1{2,}$",
    ],
    "S06": [r"_{2,}", r"\[\s*\]", r"\{\s*\}", r"<\s*>", r"\.{3,}\s*$", r"…\s*$"],
    "S07": [r"\.;", r";;", r";\s*;", r"^\s*[;,.]", r"^\s*\S+;\s*[А-ЯЁ]", r"\s{2,}"],
    "S10": [r"[А-Яа-яЁё][AaBCcEeHKMOoPpTXxy]", r"[AaBCcEeHKMOoPpTXxy][А-Яа-яЁё]"],
    "S12": [r"\b(\w+)\s+\1\b"],
    "S15": [r"<[^>]+>", r"[\u0000-\u0008\u000B\u000C\u000E-\u001F]", r"[\U0001F300-\U0001FAFF]"],
    "S09": [r"[әғқңөұүһіӘҒҚҢӨҰҮҺІ]"],
    "S14": [r"\b\d+([.,]\d+)?\b"],
}
