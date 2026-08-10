from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyLimitMiddleware:
    """Reject HTTP request bodies that exceed a fixed number of bytes.

    The complete body is validated before the downstream application is called,
    so JSON parsing and route handlers cannot observe a partially validated body.
    """

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        if not isinstance(max_body_bytes, int) or isinstance(max_body_bytes, bool) or max_body_bytes < 0:
            raise ValueError("max_body_bytes must be a non-negative integer")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        try:
            declared_length = _content_length(scope)
        except ValueError:
            await _error_response(400, "Invalid Content-Length")(scope, receive, send)
            return

        if declared_length is not None and declared_length > self.max_body_bytes:
            await _error_response(413, "Request body too large")(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await _error_response(400, "Invalid request body")(scope, receive, send)
                return

            chunk = message.get("body", b"")
            if not isinstance(chunk, bytes):
                await _error_response(400, "Invalid request body")(scope, receive, send)
                return
            if len(chunk) > self.max_body_bytes - len(body):
                await _error_response(413, "Request body too large")(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        if declared_length is not None and declared_length != len(body):
            await _error_response(400, "Content-Length mismatch")(scope, receive, send)
            return

        replay = _replay_body(bytes(body), receive)
        await self.app(scope, replay, send)


def _content_length(scope: Scope) -> int | None:
    raw_values = [value for name, value in scope.get("headers", []) if name.lower() == b"content-length"]
    if not raw_values:
        return None

    values: list[int] = []
    for raw_value in raw_values:
        try:
            parts = raw_value.decode("ascii").split(",")
        except UnicodeDecodeError as exc:
            raise ValueError("Content-Length must be ASCII") from exc
        for part in parts:
            normalized = part.strip()
            if not normalized or not normalized.isascii() or not normalized.isdecimal():
                raise ValueError("Content-Length must be a non-negative decimal integer")
            values.append(int(normalized))

    if not values or any(value != values[0] for value in values[1:]):
        raise ValueError("Conflicting Content-Length values")
    return values[0]


def _replay_body(body: bytes, upstream_receive: Receive) -> Receive:
    delivered = False

    async def receive() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await upstream_receive()

    return receive


def _error_response(status_code: int, detail: str) -> ASGIApp:
    return JSONResponse({"detail": detail}, status_code=status_code)
