"""ASGI glue: request-size limit and X-Request-Id.

This is the only module with `async def`: both features need the raw ASGI stream, which a
synchronous route cannot see. `scripts/check_code.py` allows `async def` in this file only.
"""

import re
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

SAFE_ID = re.compile(r"^[A-Za-z0-9._\-]{1,100}$")
TOO_LARGE = (
    b'{"error":{"code":"payload_too_large","message":"request body is too large","field":null}}'
)


class _Stream:
    """State of one request: counts the received bytes and answers 413 once over the limit."""

    def __init__(self, receive: Receive, send: Send, limit: int, request_id: str) -> None:
        self.receive_next, self.send_next = receive, send
        self.limit, self.request_id = limit, request_id
        self.received = 0
        self.exceeded = False
        self.responded = False

    async def receive(self) -> Message:
        message = await self.receive_next()
        if message["type"] == "http.request":
            self.received += len(message.get("body", b""))
            if self.received > self.limit:
                self.exceeded = True
                return {"type": "http.request", "body": b"", "more_body": False}
        return message

    async def send(self, message: Message) -> None:
        if self.exceeded:
            if not self.responded:
                self.responded = True
                await self.reject()
            return
        await self.forward(message)

    async def forward(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            message.setdefault("headers", []).append((b"x-request-id", self.request_id.encode()))
        await self.send_next(message)

    async def reject(self) -> None:
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(TOO_LARGE)).encode()),
        ]
        await self.forward({"type": "http.response.start", "status": 413, "headers": headers})
        await self.forward({"type": "http.response.body", "body": TOO_LARGE})


class RequestGuard:
    def __init__(
        self, app: ASGIApp, default_limit: int, upload_prefix: str, upload_limit: int
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.upload_prefix = upload_prefix
        self.upload_limit = upload_limit

    def limit_for(self, scope: Scope) -> int:
        if scope["method"] == "POST" and scope["path"].startswith(self.upload_prefix):
            return self.upload_limit
        return self.default_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        given = headers.get("x-request-id", "")
        request_id = given if SAFE_ID.match(given) else str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        stream = _Stream(receive, send, self.limit_for(scope), request_id)
        declared = headers.get("content-length", "")
        if declared.isdigit() and int(declared) > stream.limit:
            await stream.reject()
            return
        await self.app(scope, stream.receive, stream.send)
