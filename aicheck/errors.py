"""Domain errors; the API layer maps them to HTTP codes (see api/app.py)."""


class AppError(Exception):
    status = 500
    code = "internal_error"

    def __init__(self, message: str, field: str | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field
        if code:
            self.code = code


class ValidationError(AppError):
    status = 422
    code = "business_invalid"


class NotFound(AppError):
    status = 404
    code = "not_found"


class Conflict(AppError):
    status = 409
    code = "conflict"


class Unavailable(AppError):
    status = 503
    code = "unavailable"


class Unauthorized(AppError):
    status = 401
    code = "unauthorized"


class Forbidden(AppError):
    status = 403
    code = "forbidden"


class PayloadTooLarge(AppError):
    status = 413
    code = "payload_too_large"


class TooManyRequests(AppError):
    status = 429
    code = "rate_limited"
