# Сервис ИИ-проверки раздела 2 ЭНД

Микросервис проверяет подготовительные мероприятия (пп. 5.1–5.10) и оценку рисков наряда-допуска по правилам
`aicheck/rules/data/omg_ai_check_rules.json`, с опорой на базу нормативных документов и локальную LLM.
Код-этап (правила S, N, матрица, категории, RA01–RA25) отвечает синхронно за доли секунды; LLM-этап — асинхронно,
через очередь в PostgreSQL. Все прогоны, находки и действия пишутся в неизменяемый журнал.

Один пакет `aicheck`, синхронный код (FastAPI + SQLAlchemy Core + psycopg 3), один процесс API и один процесс воркера.

## Быстрый старт (docker compose, заглушка LLM)

```bash
make dev-secrets          # секреты для разработки в ./secrets (ключи, пароли)
docker compose up --build # postgres, fake-llm, миграции + пакет правил, api (8000), worker
TOKEN=$(python scripts/dev_token.py hse-backend)      # PyJWT нужен локально: pip install pyjwt cryptography
curl -s localhost:8000/v1/ready
```

Загрузить справочник (пример формата — `tests/golden/catalog.json`) под ролью администратора с MFA:

```bash
ADMIN=$(python scripts/dev_token.py ai-admin)
curl -s -X POST localhost:8000/v1/admin/catalog -H "Authorization: Bearer $ADMIN" \
     -H 'Content-Type: application/json' --data @tests/golden/catalog.json
```

Дальше `POST /v1/checks` с телом из `tests/golden/cases/*.json` (поле `request`) и заголовком
`Idempotency-Key: <end.contentHash>`.

## Запуск с локальной моделью (DeepSeek V4 Flash и др.)

Сервис говорит с любым OpenAI-совместимым шлюзом (vLLM, Ollama, LM Studio…): `POST {LLM_BASE_URL}/v1/chat/completions`
с заголовком `Authorization: Bearer <ключ>`. Задайте в `.env` (образец — `.env.example`):

```
LLM_BASE_URL=http://localhost:8000          # http:// допустим только для loopback (или ALLOW_INSECURE_LLM=true на стенде)
LLM_API_KEY_FILE=./secrets/llm_api_key      # либо LLM_API_KEY=... для локального запуска
LLM_MODEL=<имя модели на шлюзе>
LLM_JSON_MODE=true                          # false, если шлюз не принимает response_format
ALLOWED_OUTBOUND_HOSTS=localhost,hse.internal.example
```

В `docker compose` укажите `LLM_BASE_URL=http://host.docker.internal:8000`, `ALLOWED_OUTBOUND_HOSTS=host.docker.internal,…`,
`ALLOW_INSECURE_LLM=true`. Блоки `<think>…</think>` и ограждения ```` ```json ```` в ответе модели удаляются сервисом.
Для vLLM рекомендуется `--enable-prefix-caching`: промпт строится так, что стабильная часть идёт первой.

Проверка модели на реальных данных (не в CI): `make smoke-llm` (5 эталонных ЭНД, время и доля отброшенных находок) и
`make compare-models` (`LLM_MODEL` против `LLM_MODEL_ALT`, отчёт `reports/models.md`).

## Запуск без Docker

```bash
uv venv --python 3.12 .venv && . .venv/bin/activate
uv pip install -r requirements-dev.lock
python -m aicheck.cli migrate --owner-url postgresql://owner:***@host/aicheck   # роль-владелец, только для миграций
python -m aicheck.cli import-rules --activate                                  # загрузка и активация пакета правил
uvicorn --factory aicheck.api.server:build --port 8000                         # API
python -m aicheck.jobs.worker                                                  # воркер LLM, callback, разбор документов
```

## Переменные окружения

Сервис не стартует, если обязательная переменная не задана или секрет не читается. Образец — `.env.example`.

| Переменная | Обяз. | По умолчанию | Назначение | Кто задаёт |
| --- | --- | --- | --- | --- |
| `DATABASE_URL_FILE` | да | — | файл со строкой подключения PostgreSQL (роль `aicheck_app`) | DevOps |
| `ORG_CODE` | да | — | `OMG` | разработка |
| `LLM_BASE_URL` | да | — | адрес OpenAI-совместимого шлюза | DevOps |
| `LLM_API_KEY_FILE` (или `LLM_API_KEY`) | да | — | ключ модели | ИБ / DevOps |
| `LLM_MODEL` | да | — | имя модели на шлюзе | разработка |
| `LLM_TIMEOUT_S` | нет | 12 | таймаут вызова | разработка |
| `LLM_JSON_MODE` | нет | true | передавать `response_format` | разработка |
| `LLM_JSON_SCHEMA_MODE` | нет | false | JSON Schema в `response_format` | разработка |
| `LLM_MIN_CONFIDENCE` | нет | 0.6 | порог «предложения» | разработка |
| `LLM_CA_BUNDLE` | нет | системный | корневой сертификат шлюза | ИБ |
| `LLM_MODEL_ALT` | нет | — | вторая модель (только `compare-models`) | разработка |
| `PROMPT_VERSION` | нет | v1 | версия файлов промптов | разработка |
| `HSE_CALLBACK_URL` | да (режим Б) | — | callback в HSE; пусто — HSE забирает результат через `GET` | DevOps |
| `CALLBACK_HMAC_SECRET_FILE` | при callback | — | секрет подписи | ИБ |
| `HSE_CATALOG_EXPORT_URL` | да | — | экспорт справочников HSE | DevOps |
| `JWT_ISSUER`, `JWT_AUDIENCE` | да, `ai-check` | — | проверка сервисного токена | ИБ |
| `JWT_PUBLIC_KEY_FILE` | да | — | публичный ключ издателя (RS256) | ИБ |
| `ALLOWED_OUTBOUND_HOSTS` | да | — | хосты LLM, HSE и IdP через запятую | ИБ / DevOps |
| `MAX_BODY_KB` | нет | 256 | лимит тела запроса | разработка |
| `POLL_INTERVAL_S` | нет | 1 | пауза воркера | разработка |
| `LOG_LEVEL` | нет | INFO | уровень логов (события ИБ — всегда) | DevOps |
| `IDP_JWKS_URL`, `IDP_ISSUER`, `IDP_AUDIENCE` | режим А | — | ключи и параметры токена корпоративного IdP | ИБ |
| `CORS_ALLOWED_ORIGINS` | режим А | — | адрес веб-интерфейса HSE | DevOps |
| `USER_RUNS_PER_HOUR` | нет | 30 | лимит прогонов на пользователя | разработка |
| `KB_MAX_FILE_MB` / `KB_CONTEXT_CHARS` / `KB_FTS_LIMIT` | нет | 20 / 12000 / 8 | база документов | разработка |
| `ALLOW_INSECURE_LLM` | нет | false | `http://` для не-loopback хоста (только стенд) | разработка |

## Требования к размещению

База данных и локальная LLM размещаются на серверах на **территории Республики Казахстан** (Закон № 94-V, ст. 12).
Сервис не хранит ИИН, телефоны и e-mail: они заменяются на `[ИИН]`, `[ТЕЛ]`, `[EMAIL]` до записи и до вызова модели.
Журнал проверок хранится не менее 3 лет (удаления в коде нет), логи — в stdout. Подробности — `docs/security.md`.

## Параметры правил

Пакет `omg_ai_check_rules.json` (v1.3) содержит пилотные значения параметров P09–P15: человекочитаемое `value` и
машиночитаемое `data`. Правила читают только `data`, поэтому значения меняются новой версией пакета (без выпуска кода):
`POST /v1/admin/rulesets` + `…/activate`, откат — активация предыдущей версии. Значения помечены «пилотное — утвердить HSE ОМГ».

| Параметр | Правила | Что в `data` |
| --- | --- | --- |
| P09 | N03 | `warm`, `cold` — периоды `from`/`to` (`MM-DD`); правило работает, только если обе даты работ лежат в одном периоде |
| P10 | RA03, RA10, RA11, RA23 | `scale` (B, P), `zones` (acceptable / needs_controls / unacceptable), `residual_if_no_additional_controls`, `high_zone_for_RA23` |
| P11 | N12, OG-05 | флаг противопожарной службы обязателен для огневых работ, если любой из факторов `when_any_factor_yes` = да; критичность — `severity` |
| P13 | RA21 | минимальная тяжесть по уровню опасности (`high`, `medium`, `low`) |
| P14 | RA18 | `min_R` — порог Р для обязательной связи с разделом 5 |
| P15 | RA25 | `implement_before_start_ids` — ID значений «Когда внедрить» = «до начала работ» (из справочника HSE; пока пусто — RA25 молчит) |

## Справочник HSE

Формат — как у `tests/golden/official/test_catalog.json` (`POST /v1/admin/catalog`, схема — `contracts/catalog.py`): мероприятия
(`text_ru`, `category`, `section`, `item_type`, `factors`, `key_elements`, `active`), опасности (`required`, `factors`,
`min_severity_level`, связи с «кто/как/мерами», `linked_sections`, `severity_if_missing`), меры (`hierarchy_level`, `affects`,
`hazard_ids`, `linked_section`), роли, сроки внедрения и профили подразделений (`factor_defaults`). Неизвестные поля игнорируются.
Версии неизменяемы; синхронизация `POST /v1/sync` забирает дельту (`active: false` — деактивация записи).

## API

Все эндпоинты — под `/v1`, контракт — `openapi.json` (тест сравнивает его с генерируемым; обновление — `make openapi`).
Роли: `hse-backend`, `ai-admin` (с MFA), в режиме А — пользовательский токен IdP. Коды ошибок: 400 `schema_invalid`,
401, 403, 409 `catalog_version_unknown`, 413, 422 `validation_failed` / `content_hash_mismatch`, 429 (`Retry-After`).
Каждый ответ содержит `X-Request-Id`.

| Эндпоинт | Назначение |
| --- | --- |
| `POST /v1/checks` | запуск прогона (`Idempotency-Key` = `contentHash`); ответ — находки кода, статус LLM |
| `GET /v1/checks/{runId}` | полный результат (в том числе находки LLM) |
| `POST /v1/checks/{runId}/answers` | новый прогон с ответами на вопросы-факторы |
| `POST /v1/findings/{findingId}/actions` | `accept`, `edit`, `reject` (нужен `reasonCode`), `answer`, `hide`, `reopen` |
| `GET /v1/gate?endRef=&contentHash=` | вердикт для шлюза отправки |
| `POST /v1/sync`, `GET /v1/catalog/version` | синхронизация справочников |
| `POST /v1/admin/catalog` | загрузка справочников и профилей одним файлом |
| `POST /v1/admin/rulesets`, `…/{id}/activate` | пакеты правил |
| `/v1/admin/kb/*`, `GET /v1/kb/clauses/{code}/{no}` | база нормативных документов |
| `GET /v1/health`, `/v1/ready`, `/metrics` | живость, готовность, метрики |

## Канонический хеш и проверка подписи callback для HSE

`contentHash` считается по правилам раздела 16 ТЗ; 10 контрольных входов и ожидаемых значений — `tests/golden/hash_vectors.json`
(поле `canonical` — байты до хеширования). Callback приходит с заголовками `X-Timestamp` (Unix-время) и
`X-Signature: sha256=<hex>` — HMAC-SHA256 от `timestamp + "." + тело` секретом `CALLBACK_HMAC_SECRET`. Проверка на стороне HSE:

```python
import hashlib, hmac, time

def verify_callback(secret: bytes, body: bytes, timestamp: str, signature: str) -> bool:
    if abs(time.time() - int(timestamp)) > 300:        # окно 5 минут
        return False
    expected = "sha256=" + hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)    # сравнение в постоянное время
```

## База нормативных документов

Загрузка (`POST /v1/admin/kb/documents`, multipart: `file` + `meta` JSON) → разбор воркером → правка пунктов → активация.
Правило ссылается на пункт по коду документа и номеру (`PUT /v1/admin/kb/rule-refs`), поэтому связь переживает смену версии;
`GET /v1/admin/kb/documents/{id}/diff` показывает добавленные, удалённые и изменённые пункты и затронутые правила;
`GET /v1/admin/kb/rule-refs/broken` — ссылки на несуществующие пункты. Поддерживаются PDF с текстовым слоем, DOCX, TXT, MD.

## Проверки и тесты

```bash
make lint typecheck sec        # ruff, mypy, bandit, pip-audit, scripts/check_code.py
make test-stage N=7            # тесты этапов 0…N параллельно (pytest -n auto) + пороги покрытия
make test-serial               # те же тесты в одном процессе (результат обязан совпасть)
make golden                    # reports/golden.md: 42 собственных кейса + 16 кейсов приёмки (кодовый этап)
make perf                      # 20 параллельных прогонов, p95 код-этапа ≤ 1 с
scripts/ci.sh                  # порядок CI: lint → typecheck → sec → test-stage → golden
```

Для тестов нужен PostgreSQL (по умолчанию `postgresql://postgres:postgres@localhost:5432/postgres`, переменная
`TEST_DB_ADMIN_URL`); у каждого процесса pytest своя база `aicheck_test_<worker>`, каждый тест — в транзакции с откатом.
Реальная LLM в тестах не вызывается: `tests/fakes/fake_llm.py` (сценарии `ok`, `invalid_json`, `schema_mismatch`, `timeout`,
`http_500_then_ok`, `unknown_rule_code`, `foreign_markers`, `rf_norms`, `low_confidence`, `injection_echo`).

## Эксплуатация

- Миграции: `python -m aicheck.cli migrate --owner-url …` (роль-владелец только для Alembic; приложение работает под `aicheck_app`).
- Пакет правил: `cli import-rules --file … --activate` или админ-API. Каждый прогон хранит версию пакета и справочников.
- Кеш LLM: `cli purge-cache --days 30`. Журнал: `cli retention-report`.
- Метрики `/metrics`: `llm_findings_dropped_total{reason}`, `callback_undelivered_total`, `pii_detected_total`, `checks_total`,
  `code_stage_seconds`, `llm_call_seconds`, `llm_calls_total`, `auth_denied_total`.
- Резервное копирование, инциденты, сроки хранения — `docs/security.md`. Допущения и отступления от ТЗ — `DECISIONS.md`.
