from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient

from ai_firewall.config import settings
from ai_firewall.main import app
from ai_firewall.proxy import ValidatedDestination

AUTH_HEADERS = {"x-ai-firewall-api-key": "synthetic-local-client-key"}


@pytest.fixture(autouse=True)
def configure_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "api_key", AUTH_HEADERS["x-ai-firewall-api-key"])


def test_health(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_local_console_is_available_without_exposing_configuration(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "AI Firewall · Local review workspace" in response.text
    assert AUTH_HEADERS["x-ai-firewall-api-key"] not in response.text


def test_ready_when_auth_and_audit_storage_are_usable(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_ready_fails_generically_when_auth_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "api_key", None)
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        readiness = client.get("/ready")
        liveness = client.get("/health")

    assert readiness.status_code == 503
    assert readiness.json() == {"detail": "Service unavailable"}
    assert liveness.status_code == 200
    assert liveness.json() == {"status": "ok"}


def test_ready_fails_generically_when_audit_storage_is_unusable(tmp_path: Path) -> None:
    settings.audit_path = tmp_path
    with TestClient(app) as client:
        readiness = client.get("/ready")
        liveness = client.get("/health")

    assert readiness.status_code == 503
    assert readiness.json() == {"detail": "Service unavailable"}
    assert str(tmp_path) not in readiness.text
    assert liveness.status_code == 200


def test_rejects_untrusted_host_header(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        response = client.get("/health", headers={"host": "untrusted.invalid"})

    assert response.status_code == 400


def test_interactive_api_docs_are_disabled(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_scan_does_not_expose_blocked_payload(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        response = client.post(
            "/v1/scan",
            headers=AUTH_HEADERS,
            json={"payload": "password=supersecretvalue"},
        )
    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    assert response.json()["payload"] is None
    assert "supersecretvalue" not in settings.audit_path.read_text()


def test_scan_requires_authentication(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        response = client.post("/v1/scan", json={"payload": "public text"})

    assert response.status_code == 401
    assert not settings.audit_path.exists()


def test_policy_summary_is_authenticated_and_does_not_expose_patterns(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    with TestClient(app) as client:
        unauthorized = client.get("/v1/policy")
        response = client.get("/v1/policy", headers=AUTH_HEADERS)

    assert unauthorized.status_code == 401
    assert response.status_code == 200
    payload = response.json()
    assert payload["default_action"] == "block"
    assert payload["rules"]
    assert all("pattern" not in rule for rule in payload["rules"])


def test_scan_rejects_oversized_body_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(settings, "max_payload_bytes", 1)
    # Middleware configuration is fixed at app construction, so exercise its shipped limit.
    oversized = b'{"payload":"' + b"x" * 1_000_001 + b'"}'
    with TestClient(app) as client:
        response = client.post(
            "/v1/scan",
            headers={**AUTH_HEADERS, "content-type": "application/json"},
            content=oversized,
        )

    assert response.status_code == 413
    assert not settings.audit_path.exists()


def test_proxy_uses_validated_destination_and_strips_caller_headers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(settings, "proxy_enabled", True)
    validated = ValidatedDestination(
        url="https://api.openai.com/v1/responses",
        hostname="api.openai.com",
        port=443,
        resolved_addresses=(),
    )
    validate = AsyncMock(return_value=validated)
    monkeypatch.setattr("ai_firewall.main.validate_destination", validate)

    with TestClient(app) as client:
        request = AsyncMock(
            return_value=httpx.Response(
                200,
                content=b'{"ok":true}',
                headers={"content-type": "application/json"},
            )
        )
        client.app.state.http.request = request
        response = client.post(
            "/v1/proxy",
            headers=AUTH_HEADERS,
            json={
                "url": "https://api.openai.com/v1/responses",
                "headers": {
                    "authorization": "Bearer synthetic-provider-token",
                    "content-type": "application/json",
                },
                "payload": {"input": "Contact synthetic.user@example.com"},
            },
        )

    assert response.status_code == 200
    assert request.await_args.kwargs["headers"] == {}
    assert request.await_args.kwargs["json"] == {"input": "Contact [REDACTED:email]"}
    assert "synthetic-provider-token" not in settings.audit_path.read_text()


def test_proxy_is_disabled_by_default(tmp_path: Path) -> None:
    settings.audit_path = tmp_path / "audit.jsonl"
    settings.proxy_enabled = False

    with TestClient(app) as client:
        response = client.post(
            "/v1/proxy",
            headers=AUTH_HEADERS,
            json={
                "url": "https://api.openai.com/v1/responses",
                "headers": {},
                "payload": {"input": "public text"},
            },
        )

    assert response.status_code == 503
    assert not settings.audit_path.exists()
