from dataclasses import dataclass

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from ai_firewall.auth import APIKeyAuthenticator


@dataclass
class AuthSettings:
    api_key: str | None


def _app(settings: AuthSettings) -> FastAPI:
    app = FastAPI(dependencies=[Depends(APIKeyAuthenticator(settings))])

    @app.get("/protected")
    async def protected() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_accepts_matching_api_key_header() -> None:
    with TestClient(_app(AuthSettings(api_key="synthetic-test-key"))) as client:
        response = client.get(
            "/protected", headers={"x-ai-firewall-api-key": "synthetic-test-key"}
        )

    assert response.status_code == 200


def test_rejects_missing_or_incorrect_api_key_without_echoing_values() -> None:
    supplied = "synthetic-wrong-key"
    expected = "synthetic-expected-key"
    with TestClient(_app(AuthSettings(api_key=expected))) as client:
        missing = client.get("/protected")
        incorrect = client.get("/protected", headers={"x-ai-firewall-api-key": supplied})

    assert missing.status_code == 401
    assert incorrect.status_code == 401
    assert supplied not in incorrect.text
    assert expected not in incorrect.text


def test_rejects_query_string_api_key() -> None:
    with TestClient(_app(AuthSettings(api_key="synthetic-test-key"))) as client:
        response = client.get("/protected?api_key=synthetic-test-key")

    assert response.status_code == 401


def test_fails_closed_when_server_api_key_is_unconfigured() -> None:
    with TestClient(_app(AuthSettings(api_key=None))) as client:
        response = client.get("/protected", headers={"x-ai-firewall-api-key": "anything"})

    assert response.status_code == 503
    assert "anything" not in response.text


def test_rejects_duplicate_api_key_headers() -> None:
    with TestClient(_app(AuthSettings(api_key="synthetic-test-key"))) as client:
        response = client.get(
            "/protected",
            headers=[
                ("x-ai-firewall-api-key", "synthetic-test-key"),
                ("x-ai-firewall-api-key", "synthetic-test-key"),
            ],
        )

    assert response.status_code == 401
