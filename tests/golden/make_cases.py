"""Generates tests/golden/{catalog.json,params.json,cases/*.json}.

Expected findings are written by hand below (rule, target, severity); the engine output is
only compared with them by `make golden` and by tests/integration/test_golden.py.
Run: python tests/golden/make_cases.py
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aicheck.contracts import CheckRequest  # noqa: E402
from aicheck.hashing import content_hash  # noqa: E402
from aicheck.rules.loader import DATA_FILE  # noqa: E402

OUT = Path(__file__).parent
RULES = json.loads(DATA_FILE.read_text(encoding="utf-8"))
CAT_NAMES = {m["code"]: m["category"] for m in RULES["matrix"]}
ALL_FACTORS = [f["code"] for f in RULES["factors"]]
from tests.factory import PARAMS  # noqa: E402

GOOD_TEXT = {
    "5.1": "Остановить технику и оборудование в зоне проведения работ до начала подготовки",
    "5.2": "Отключить и обесточить оборудование в зоне работ с вывешиванием запрещающих плакатов",
    "5.3": "Установить заглушки на трубопроводах и перекрыть запорную арматуру перед работами",
    "5.4": "Выполнить анализ воздушной среды перед началом работ и после перерывов в работе",
    "5.5": "Оградить место проведения работ сигнальной лентой и выставить знаки безопасности",
    "5.6": "Организовать страховку работников и допуск на рабочие места строго по списку",
    "5.7": "Предупредить персонал смежных участков о начале работ и согласовать порядок взаимодействия",
    "5.9": "Определить и довести до бригады безопасные маршруты движения к месту проведения работ",
    "5.10": "Провести целевой инструктаж бригады и проверить наличие средств защиты на месте",
}
FIRE_55 = (
    "Оградить место работ сигнальной лентой, выставить знаки, подготовить первичные средства "
    "пожаротушения (огнетушители) и убрать ЛВЖ не ближе 50 м"
)
STOP_510 = "Работы на высоте запрещены при сильном ветре, грозе, осадках и плохой видимости"
GAS_54 = (
    "Выполнить газоанализ: место отбора, время замера, периодичность контроля, прибор и "
    "результат записать в наряд"
)
CORE = {
    "ZR": ["5.5", "5.7", "5.9"],
    "GP": ["5.3", "5.5", "5.7", "5.9", "5.10"],
    "ZP": ["5.1", "5.2", "5.3", "5.4", "5.5", "5.7", "5.9", "5.10"],
    "DR": ["5.5", "5.9"],
    "OG": ["5.1", "5.2", "5.5", "5.7", "5.9", "5.10"],
    "GO": ["5.1", "5.2", "5.3", "5.4", "5.5", "5.7", "5.9", "5.10"],
    "VS": ["5.3", "5.5", "5.6", "5.9", "5.10"],
}
ALL_FLAGS = {
    "adjacentApproval": True,
    "gasAirControl": True,
    "fireService": True,
    "contractorStaff": False,
}


LEVEL = {"Высокая": "high", "Средняя": "medium"}


def catalog() -> tuple[dict[str, Any], dict[str, int]]:
    hazards: list[dict[str, Any]] = []
    ids: dict[str, int] = {}
    for i, h in enumerate(RULES["hazards"], start=100):
        code = next(c for c, n in CAT_NAMES.items() if n == h["category"])
        ids[h["hazard"]] = i
        always = h["required_when"] == "Всегда"
        hazards.append(
            {
                "id": i,
                "category": code,
                "required": "always" if always else "factor",
                "name": h["hazard"] if "≥" not in h["hazard"] else "Опасность по описанию работ",
                "factors": [] if always else re.findall(r"F\d+", h["required_when"]),
                "min_severity_level": LEVEL.get(h["min_severity_level"]),
                "victim_ids": [1, 2],
                "harm_ids": [1, 2],
                "typical_existing_control_ids": [1, 2, 3, 4],
                "typical_additional_control_ids": [5],
                "linked_sections": [
                    s.strip() for s in h["linked_sections"].split(",") if s.strip().startswith("5.")
                ],
                "severity_if_missing": "critical"
                if h["severity_if_missing"] == "Критично"
                else "significant",
            }
        )
    controls = [
        {
            "id": 1,
            "name": "Инструктаж бригады перед началом работ",
            "hierarchy_level": "administrative",
            "affects": "P",
        },
        {
            "id": 2,
            "name": "Ограждение опасной зоны",
            "hierarchy_level": "engineering",
            "affects": "P",
        },
        {
            "id": 3,
            "name": "Применение средств индивидуальной защиты",
            "hierarchy_level": "ppe",
            "affects": "B",
        },
        {
            "id": 4,
            "name": "Исключение опасной операции из технологии",
            "hierarchy_level": "elimination",
            "affects": "PB",
        },
        {
            "id": 5,
            "name": "Страховка работников второй линией",
            "hierarchy_level": "engineering",
            "affects": "B",
            "linked_section": "5.6",
        },
    ]
    body = {
        "version": "golden-cat-1",
        "orgCode": "OMG",
        "hints": {"5.4": "Взять пробу воздушной среды"},
        "hazards": hazards,
        "controls": controls,
        "measures": [],
        "victims": [{"id": 1, "name": "Работник"}, {"id": 2, "name": "Посторонний"}],
        "harms": [{"id": 1, "name": "Травма"}, {"id": 2, "name": "Отравление"}],
        "roles": [{"id": 1, "name": "Производитель работ"}],
        "implement_when": [{"id": 1, "name": "До начала работ"}, {"id": 2, "name": "В ходе работ"}],
        "profiles": [{"unitCode": "NGDU-2", "objects": [], "factor_defaults": {"F10": "no"}}],
    }
    return body, ids


CATALOG, HAZARD_ID = catalog()


def good_risks(category: str) -> list[dict[str, Any]]:
    """One row per always-required hazard; rows alternate so that the scores differ (RA22)."""
    risks = []
    always = [
        h
        for h in RULES["hazards"]
        if h["category"] == CAT_NAMES[category] and h["required_when"] == "Всегда"
    ]
    for i, h in enumerate(always):
        high = h["min_severity_level"] == "Высокая"
        row: dict[str, Any] = {
            "rowId": f"r{i}",
            "hazardId": HAZARD_ID[h["hazard"]],
            "victimIds": [1],
            "harmIds": [1],
            "existingControlIds": [1],
            "b1": 4 if high else 3,
            "p1": 1,
            "additionalControlIds": [],
            "b2": None,
            "p2": None,
            "controlResponsibleRoleId": None,
            "implementWhenId": None,
        }
        if high and i % 2 == 1:  # R = 5: needs a control, implemented before the work
            row.update(
                b1=5,
                additionalControlIds=[2],
                b2=5,
                p2=1,
                controlResponsibleRoleId=1,
                implementWhenId=1,
            )
        risks.append(row)
    return risks


def good(category: str, **over: Any) -> dict[str, Any]:
    measures = []
    for n, section in enumerate(f"5.{i}" for i in range(1, 11)):
        if section in CORE[category]:
            text = GAS_54 if (section == "5.4" and category == "GO") else GOOD_TEXT[section]
            if section == "5.5" and category == "OG":
                text = FIRE_55
            if section == "5.10" and category == "VS":
                text = STOP_510
            measures.append(
                {
                    "rowId": f"m{n}",
                    "section": section,
                    "text": text,
                    "catalogItemId": None,
                    "origin": "manual",
                    "notApplicable": False,
                }
            )
    ctx = {
        "workType": "RPO",
        "categoryCode": category,
        "unitCode": "NGDU-2",
        "shopCode": None,
        "description": "Плановые работы на скважине",
        "startAt": "2026-09-18T10:41:00+05:00",
        "endAt": "2026-09-19T10:41:00+05:00",
        "flags": dict(ALL_FLAGS),
        "attachments": [{"kind": "scheme", "count": 1}],
        "catalogVersion": "golden-cat-1",
    }
    request = {
        "schemaVersion": "1.0",
        "tenant": {"orgCode": "OMG"},
        "end": {
            "endRef": "end_golden",
            "snapshotVersion": 1,
            "contentHash": "sha256:" + "0" * 64,
            "mode": "full",
        },
        "context": ctx,
        "measures": measures,
        "risks": good_risks(category),
        "factorAnswers": dict.fromkeys(ALL_FACTORS, "no"),
        "locale": "ru",
        "requestedBy": {"userRef": "u_golden", "role": "issuer"},
    }
    request.update(over)
    return request


def rid(request: dict[str, Any], section: str, index: int = 0) -> str:
    return [m for m in request["measures"] if m["section"] == section][index]["rowId"]


def edit(request: dict[str, Any], section: str, text: str, index: int = 0) -> None:
    for m in [m for m in request["measures"] if m["section"] == section][index : index + 1]:
        m["text"] = text


def drop(request: dict[str, Any], section: str) -> None:
    request["measures"] = [m for m in request["measures"] if m["section"] != section]


def add(request: dict[str, Any], section: str, text: str, row: str, **extra: Any) -> str:
    request["measures"].append(
        {
            "rowId": row,
            "section": section,
            "text": text,
            "catalogItemId": None,
            "origin": "manual",
            "notApplicable": False,
            **extra,
        }
    )
    return row


def answers(request: dict[str, Any], **values: str) -> None:
    request["factorAnswers"].update(values)


def flags(request: dict[str, Any], **values: bool) -> None:
    request["context"]["flags"].update(values)


# --- expected findings: tuples (rule, target, severity) -------------------------------------------


def target(request: dict[str, Any], spec: str) -> dict[str, Any]:
    kind, _, rest = spec.partition(":")
    if kind == "row":
        row = next(m for m in request["measures"] if m["rowId"] == rest)
        return {"type": "measure", "section": row["section"], "rowId": rest}
    if kind == "sec":
        return {"type": "section", "section": rest}
    if kind == "flag":
        return {"type": "flag", "field": rest}
    if kind == "factor":
        return {"type": "factor", "factorCode": rest}
    if kind == "risk":
        row, _, field = rest.partition(":")
        return {"type": "risk", "rowId": row, **({"field": field} if field else {})}
    if kind == "risks":
        return {"type": "risk", **({"field": rest} if rest else {})}
    return {"type": "description"}


def save(
    case_id: str,
    title: str,
    request: dict[str, Any],
    expected: list[tuple[str, str, str]],
    params: bool = True,
    **extra: Any,
) -> None:
    request["end"]["contentHash"] = content_hash(CheckRequest.model_validate(request))
    body = {
        "id": case_id,
        "title": title,
        "params": params,
        "request": request,
        "expected": [
            {"rule": r, "target": target(request, t), "severity": s} for r, t, s in expected
        ],
        **extra,
    }
    (OUT / "cases" / f"{case_id}.json").write_text(
        json.dumps(body, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )


def categories() -> None:
    names = {
        "ZR": "земляные",
        "GP": "грузоподъёмные",
        "ZP": "замкнутое пространство",
        "DR": "другие",
        "OG": "огневые",
        "GO": "газоопасные",
        "VS": "высота",
    }
    for code in CORE:
        save(f"cat_{code}_1_good", f"{names[code]}: хороший ЭНД", good(code), [])
    bad_and_border()


def bad_and_border() -> None:
    # ZR bad: stub in 5.5, no 5.7, F27=yes without 5.2, neighbour flag off, no scheme, gas without analysis
    r = good("ZR")
    edit(r, "5.5", "Тест")
    drop(r, "5.7")
    answers(r, F27="yes", F03="yes")
    add(r, "5.4", "Выставить сигнальную ленту по периметру выемки", "x4")
    flags(r, adjacentApproval=False)
    r["context"]["attachments"] = []
    save(
        "cat_ZR_2_bad",
        "земляные: плохой ЭНД",
        r,
        [
            ("S02", f"row:{rid(r, '5.5')}", "critical"),
            ("MX", "sec:5.7", "critical"),
            ("MX", "sec:5.2", "critical"),
            ("N12", "flag:adjacentApproval", "critical"),
            ("ZR-02", "desc", "significant"),
            ("ZR-04", "sec:5.4", "critical"),
            ("RA13", "risks:Повреждение подземных коммуникаций", "significant"),
            ("RA13", "risks:Загазованность выемки", "significant"),
        ],
    )
    # ZR borderline: an unknown factor only -> a question, nothing else
    r = good("ZR")
    r["factorAnswers"].pop("F27")
    save(
        "cat_ZR_3_border",
        "земляные: пограничный (неизвестный фактор)",
        r,
        [("N14", "factor:F27", "question")],
    )

    # GP bad: dash in a core section, other-category markers, VL near the crane without approval flag
    r = good("GP")
    edit(r, "5.5", "—")
    edit(r, "5.3", "Использовать краги сварщика и электроды при подготовке стропов")
    answers(r, F02="yes")
    flags(r, adjacentApproval=False)
    add(r, "5.2", "Отключить линию электропередачи на время работ", "x2")
    save(
        "cat_GP_2_bad",
        "грузоподъёмные: плохой ЭНД",
        r,
        [
            ("N06", f"row:{rid(r, '5.5')}", "critical"),
            ("N01", f"row:{rid(r, '5.3')}", "significant"),
            ("GP-01", "flag:adjacentApproval", "significant"),
            ("N13", "flag:adjacentApproval", "critical"),
            ("RA13", "risks:Поражение током при приближении к ВЛ", "significant"),
        ],
    )
    # GP borderline: radius written with units, number with unit, exactly the plausible limit
    r = good("GP")
    edit(r, "5.5", "Радиус опасной зоны 15 м, ветер до 15 м/с, ограждение оградить лентой")
    save("cat_GP_3_border", "грузоподъёмные: пограничный (числа с единицами)", r, [])

    # ZP bad: a gas flag off, a core section missing, hot work inside without permit
    r = good("ZP")
    flags(r, gasAirControl=False)
    drop(r, "5.3")
    answers(r, F31="yes")
    save(
        "cat_ZP_2_bad",
        "замкнутое пространство: плохой ЭНД",
        r,
        [
            ("N12", "flag:gasAirControl", "critical"),
            ("MX", "sec:5.3", "significant"),
            ("ZP-04", "desc", "significant"),
            ("N13", "flag:gasAirControl", "critical"),
        ],
    )
    # ZP borderline: same gap but the permit is mentioned
    r = good("ZP")
    answers(r, F31="yes")
    edit(r, "5.10", "Оформить наряд-допуск на огневые работы и провести целевой инструктаж бригады")
    save("cat_ZP_3_border", "замкнутое пространство: пограничный (наряд указан)", r, [])

    # DR bad: only stub text and no risks; borderline: description-dependent sections left to the LLM
    r = good("DR")
    edit(r, "5.5", "test")
    r["risks"] = []
    save(
        "cat_DR_2_bad",
        "другие: плохой ЭНД",
        r,
        [("S02", f"row:{rid(r, '5.5')}", "critical"), ("RA01", "risks", "critical")],
    )
    r = good("DR")
    r["factorAnswers"] = {}
    save("cat_DR_3_border", "другие: пограничный (условные пункты по описанию)", r, [])

    # OG bad: fire service off, ok text but markers of another group, analysis missing with F03
    r = good("OG")
    flags(r, fireService=False)
    answers(r, F03="yes")
    add(r, "5.4", "Подготовить место для проведения огневых работ", "x4")
    save(
        "cat_OG_2_bad",
        "огневые: плохой ЭНД",
        r,
        [("N12", "flag:fireService", "significant"), ("OG-03", "sec:5.4", "critical")],
    )
    # OG borderline: F35 (electric welding) unknown -> a question for the hazard
    r = good("OG")
    r["factorAnswers"].pop("F35")
    save(
        "cat_OG_3_border",
        "огневые: пограничный (вид сварки неизвестен)",
        r,
        [("N14", "factor:F35", "question")],
    )

    # GO bad: 5.4 lacks the template elements; gas flag off
    r = good("GO")
    edit(r, "5.4", "Выполнить газоанализ на месте работ")
    flags(r, gasAirControl=False)
    save(
        "cat_GO_2_bad",
        "газоопасные: плохой ЭНД",
        r,
        [
            ("GO-02", "sec:5.4", "significant"),
            ("N12", "flag:gasAirControl", "critical"),
            ("N13", "flag:gasAirControl", "critical"),
        ],
    )
    r = good("GO")
    edit(r, "5.4", GAS_54 + ", повторять после каждого перерыва")
    save("cat_GO_3_border", "газоопасные: пограничный (полный шаблон 5.4)", r, [])

    # VS bad: obsolete wording, fence radius under the table, heavy objects without independent belay
    r = good("VS")
    edit(r, "5.5", "Работы на высоте 15 м, радиус ограждения 3 м вокруг зоны работ")
    edit(r, "5.10", "Температурные ограничения принять по нормам местных органов")
    answers(r, F25="yes")
    save(
        "cat_VS_2_bad",
        "высота: плохой ЭНД",
        r,
        [
            ("VS-04", f"row:{rid(r, '5.5')}", "significant"),
            ("VS-03", f"row:{rid(r, '5.10')}", "recommendation"),
            ("VS-08", "desc", "significant"),
            ("VS-02", "desc", "significant"),
        ],
    )
    r = good("VS")
    edit(r, "5.5", "Работы на высоте 15 м, радиус ограждения 7 м вокруг зоны работ")
    save("cat_VS_3_border", "высота: пограничный (радиус ровно по таблице)", r, [])


def general() -> None:
    r = good("GP")
    edit(r, "5.5", "")
    edit(r, "5.3", "Установить заглушки на ___ трубопроводе")
    edit(r, "5.7", "Тест")
    edit(r, "5.9", "12345 6789")
    edit(r, "5.10", "Провести инструктаж")
    save(
        "gen_01_syntax_critical",
        "синтаксис: пустой, шаблон, заглушка, цифры, коротко",
        r,
        [
            ("S01", f"row:{rid(r, '5.5')}", "critical"),
            ("S06", f"row:{rid(r, '5.3')}", "critical"),
            ("S02", f"row:{rid(r, '5.7')}", "critical"),
            ("S05", f"row:{rid(r, '5.9')}", "critical"),
            ("S04", f"row:{rid(r, '5.10')}", "significant"),
        ],
    )
    r = good("GP")
    edit(r, "5.5", "Оградить зону работ.;  выставить знаки безопасности вокруг зоны")
    edit(r, "5.7", "Предупредить персонал персонал смежных участков о начале работ")
    edit(r, "5.9", "Определить безопасные маршруты к мecту работ для бригады и водителей")
    edit(r, "5.10", "Провести инструктаж бригады 😀 и проверить наличие средств защиты")
    save(
        "gen_02_autofix",
        "автоисправления: S07, S12, S10, S15",
        r,
        [
            ("S07", f"row:{rid(r, '5.5')}", "recommendation"),
            ("S12", f"row:{rid(r, '5.7')}", "recommendation"),
            ("S10", f"row:{rid(r, '5.9')}", "recommendation"),
            ("S15", f"row:{rid(r, '5.10')}", "recommendation"),
        ],
    )
    r = good("ZR")
    edit(r, "5.5", "—")
    edit(r, "5.9", "не требуется")
    answers(r, F03="no")
    add(r, "5.4", "-", "x4")
    save(
        "gen_03_dashes",
        "прочерки: ядро и условный пункт",
        r,
        [("N06", f"row:{rid(r, '5.5')}", "critical"), ("N06", f"row:{rid(r, '5.9')}", "critical")],
    )
    r = good("GP")
    r["factorAnswers"] = {}
    save(
        "gen_04_questions",
        "неизвестные факторы: вопросы",
        r,
        [
            ("N14", "factor:F02", "question"),
            ("N14", "factor:F08", "question"),
            ("N14", "factor:F09", "question"),
            ("N14", "factor:F05", "question"),
            ("N14", "factor:F14", "question"),
            ("N14", "factor:F07", "question"),
            ("N14", "factor:F11", "question"),
            ("N14", "factor:F12", "question"),
            ("MX", "sec:5.4", "critical"),
        ],
    )  # F03 is "yes" through the gas control flag
    r = good("GP")
    add(r, "5.2", "Отключить электрооборудование в зоне работ", "x2")
    save("gen_05_conditional_no", "условный пункт при факторе «нет»", r, [])
    r = good("GP")
    add(r, "5.3", "Использовать краги сварщика", "x3")
    add(r, "5.4", "Сигнальщик у железнодорожных путей на переезде", "x4")
    r["factorAnswers"].pop("F10")  # the unit profile says "no": the object is absent
    save(
        "gen_06_other_markers",
        "маркеры другой категории и отсутствующий объект",
        r,
        [("N01", "row:x3", "significant"), ("N04", "row:x4", "recommendation")],
    )
    r = good("GP")
    add(r, "5.10", "При морозе ниже −20 °C применять утеплённые перчатки и мероприятия", "x10")
    save("gen_07_season", "сезонность при тёплых датах", r, [("N03", "row:x10", "recommendation")])
    r = good("GP")
    add(r, "5.10", "При пожаре вызвать пожарную охрану немедленно", "x1")
    add(r, "5.7", "Работы выполнять по требованиям Ростехнадзора и приказа № 782н", "x7")
    save(
        "gen_08_foreign_norms",
        "N10 и N11",
        r,
        [("N10", "row:x1", "recommendation"), ("N11", "row:x7", "significant")],
    )
    r = good("GO")
    flags(r, gasAirControl=False)
    save(
        "gen_09_flags",
        "флаг противоречит категории",
        r,
        [("N12", "flag:gasAirControl", "critical"), ("N13", "flag:gasAirControl", "critical")],
    )
    r = good("ZR")
    drop(r, "5.5")
    drop(r, "5.7")
    drop(r, "5.9")
    save(
        "gen_10_matrix",
        "матрица: нет ядра",
        r,
        [
            ("MX", "sec:5.5", "critical"),
            ("MX", "sec:5.7", "critical"),
            ("MX", "sec:5.9", "significant"),
        ],
    )
    r = good("GP")
    add(r, "5.1", "Остановить технику в зоне работ на площадке", "d1")
    add(r, "5.10", "остановить технику в зоне работ на площадке", "d2")
    save("gen_11_duplicates", "дубли мероприятий", r, [("S11", "row:d2", "significant")])
    r = good("GP")
    add(r, "5.1", "Радиус опасной зоны 15 принять до начала работ", "n1")
    add(r, "5.2", "Скорость ветра 80 м/с учитывать при работе", "n2")
    save(
        "gen_12_numbers",
        "числа без единиц и вне диапазона",
        r,
        [("S14", "row:n1", "significant"), ("S17", "row:n2", "significant")],
    )
    r = good("GP")
    r["risks"][0].update(b1=9, r1=3, b2=1, p2=1)
    save(
        "gen_13_arithmetic",
        "арифметика рисков",
        r,
        [
            ("RA03", "risk:r0:b1", "critical"),
            ("RA04", "risk:r0:r1", "critical"),
            ("RA06", "risk:r0", "critical"),
            ("RA11", "risk:r0", "significant"),
        ],
    )
    r = good("GP")
    r["risks"][0].update(
        b1=5,
        p1=3,
        additionalControlIds=[1],
        b2=4,
        p2=4,
        controlResponsibleRoleId=None,
        implementWhenId=2,
    )
    save(
        "gen_14_zones",
        "зоны риска и срок внедрения",
        r,
        [
            ("RA05", "risk:r0", "critical"),
            ("RA10", "risk:r0", "critical"),
            ("RA24", "risk:r0", "significant"),
            ("RA25", "risk:r0:implementWhenId", "critical"),
            ("RA08", "risk:r0:additionalControlIds", "critical"),
            ("RA09", "risk:r0:b2", "significant"),
            ("RA23", "risk:r0", "recommendation"),
        ],
    )
    r = good("ZR")
    r["risks"] = r["risks"][:1] + [dict(r["risks"][0], rowId="r9")]
    answers(r, F27="yes")
    save(
        "gen_15_risk_composition",
        "состав рисков: обязательные и дубли",
        r,
        [
            ("MX", "sec:5.2", "critical"),
            ("RA12", "risks:Падение в выемку", "significant"),
            ("RA13", "risks:Повреждение подземных коммуникаций", "significant"),
            ("RA14", "risk:r9", "significant"),
            ("RA22", "risks", "question"),
        ],
    )
    r = good("GP")
    r["risks"][0].update(harmIds=[2], victimIds=[2])
    save(
        "gen_16_llm_unavailable",
        "кейс «LLM недоступна»: кодовые находки сохраняются",
        r,
        [],
        llm="unavailable",
    )
    r = good("GP")
    r["risks"][0].update(
        hazardId=HAZARD_ID["Обрушение грунта стенок выемки"],
        b1=2,
        additionalControlIds=[5],
        existingControlIds=[1, 9],
    )
    save(
        "gen_17_risk_links",
        "связи рисков: чужая опасность, мера, тяжесть",
        r,
        [
            ("RA15", "risk:r0:hazardId", "recommendation"),
            ("RA17", "risk:r0", "significant"),
            ("RA20", "risk:r0:additionalControlIds", "recommendation"),
            ("RA21", "risk:r0:b1", "significant"),
            ("RA07", "risk:r0", "significant"),
            ("RA24", "risk:r0", "significant"),
            ("RA12", "risks:Падение груза", "critical"),
        ],
    )
    r = good("ZR")
    r["context"]["attachments"] = []
    save(
        "gen_18_attachments",
        "вложения: нет схемы коммуникаций",
        r,
        [("ZR-02", "desc", "significant")],
    )


def llm_cases() -> None:
    """Cases for compare-models and smoke-llm: the first rule of the task and the first residue row."""
    for n, category in enumerate(("GP", "ZR", "VS"), start=1):
        r = good(category)
        first = r["measures"][0]
        save(
            f"llm_0{n}_{category}",
            f"оценка модели: {category}",
            r,
            [],
            expected_ai=[
                {
                    "rule": "N07",
                    "target": {
                        "type": "measure",
                        "section": first["section"],
                        "rowId": first["rowId"],
                    },
                }
            ],
        )


def main() -> None:
    (OUT / "cases").mkdir(exist_ok=True)
    for old in (OUT / "cases").glob("*.json"):
        old.unlink()
    (OUT / "catalog.json").write_text(
        json.dumps(CATALOG, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    (OUT / "params.json").write_text(
        json.dumps(PARAMS, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    categories()
    general()
    llm_cases()


if __name__ == "__main__":
    main()
