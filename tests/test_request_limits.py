from collections.abc import Sequence
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.types import Message, Scope

from ai_firewall.request_limits import RequestBodyLimitMiddleware


def _app(max_body_bytes: int = 16) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=max_body_bytes)

    @app.post("/echo")
    async def echo(body: dict[str, Any]) -> dict[str, Any]:
        return body

    return app


def test_rejects_oversized_declared_length_before_json_parsing() -> None:
    with TestClient(_app()) as client:
        response = client.post(
            "/echo",
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "17"},
        )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


def test_rejects_malformed_content_length() -> None:
    with TestClient(_app()) as client:
        response = client.post(
            "/echo",
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "invalid"},
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid Content-Length"}


@pytest.mark.asyncio
async def test_rejects_oversized_stream_without_content_length() -> None:
    downstream_called = False

    async def downstream(scope: Scope, receive: Any, send: Any) -> None:
        nonlocal downstream_called
        downstream_called = True

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=5)
    messages: Sequence[Message] = (
        {"type": "http.request", "body": b"abc", "more_body": True},
        {"type": "http.request", "body": b"def", "more_body": False},
    )
    iterator = iter(messages)
    sent: list[Message] = []

    async def receive() -> Message:
        return next(iterator)

    async def send(message: Message) -> None:
        sent.append(message)

    await middleware(
        {"type": "http", "method": "POST", "path": "/", "headers": []}, receive, send
    )

    assert downstream_called is False
    assert sent[0]["status"] == 413


def test_allows_body_at_exact_limit_and_replays_it() -> None:
    body = b'{"value":"ok"}'
    with TestClient(_app(max_body_bytes=len(body))) as client:
        response = client.post("/echo", content=body, headers={"content-type": "application/json"})

    assert response.status_code == 200
    assert response.json() == {"value": "ok"}


def test_rejects_content_length_mismatch() -> None:
    with TestClient(_app()) as client:
        response = client.post(
            "/echo",
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "3"},
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Content-Length mismatch"}

