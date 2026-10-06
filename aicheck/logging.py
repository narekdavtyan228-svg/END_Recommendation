"""JSON logging with a scrubber for secrets and personal data."""

import json
import logging
import re
import sys
from datetime import UTC, datetime

IIN = re.compile(r"(?<!\d)\d{12}(?!\d)")
PHONE = re.compile(r"(?<!\w)(?:\+7|8)[\s\-()]*\d{3}[\s\-()]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
SECRET = re.compile(
    r"(?i)(authorization|api[_-]?key|secret|token|password)(['\"]?\s*[:=]\s*['\"]?)"
    r"(bearer\s+)?[^\s,'\"}]+"
)
BEARER = re.compile(r"(?i)bearer\s+[\w.\-~+/=]+")
MASKS = ((EMAIL, "[EMAIL]"), (PHONE, "[ТЕЛ]"), (IIN, "[ИИН]"))
_STD = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


def mask_pii(text: str) -> str:
    for pattern, replacement in MASKS:
        text = pattern.sub(replacement, text)
    return text


def scrub(text: str) -> str:
    text = SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    return mask_pii(BEARER.sub("Bearer ***", text))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": scrub(record.getMessage()),
        }
        data.update({k: scrub(str(v)) for k, v in record.__dict__.items() if k not in _STD})
        if record.exc_info and record.exc_info[0]:
            data["exc_type"] = record.exc_info[0].__name__
        return json.dumps(data, ensure_ascii=False)


def configure(level: str = "INFO") -> None:
    """Root logs follow `level`; security events are always emitted (INFO)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    security = logging.getLogger("aicheck.security")
    security.handlers[:] = [handler]
    security.setLevel(logging.INFO)
    security.propagate = False


def security_event(event: str, **fields: object) -> None:
    logging.getLogger("aicheck.security").info(event, extra=fields)
