from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .audit import audit_storage_usable, write_audit_event
from .auth import APIKeyAuthenticator, authentication_ready
from .config import settings
from .models import Action, PolicySummary, ProxyRequest, RuleSummary, ScanRequest, ScanResponse
from .policy import Policy, load_policy
from .proxy import (
    DestinationValidationError,
    HeaderValidationError,
    sanitize_caller_headers,
    validate_destination,
)
from .request_limits import RequestBodyLimitMiddleware
from .scanner import scan_payload
from .web_ui import CONSOLE_CSS, CONSOLE_HTML, CONSOLE_JS


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.policy = load_policy(settings.policy_path)
    async with httpx.AsyncClient(
        timeout=settings.request_timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        app.state.http = client
        yield


app = FastAPI(
    title="AI Firewall",
    version="0.1.1",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=settings.max_payload_bytes)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))
authenticate = APIKeyAuthenticator(settings)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
        "object-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _policy(request: Request) -> Policy:
    return request.app.state.policy


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def local_console() -> str:
    return CONSOLE_HTML


@app.get("/assets/console.css", include_in_schema=False)
async def console_css() -> Response:
    return Response(CONSOLE_CSS, media_type="text/css")


@app.get("/assets/console.js", include_in_schema=False)
async def console_js() -> Response:
    return Response(CONSOLE_JS, media_type="text/javascript")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> dict[str, Any]:
    if not authentication_ready(settings) or not audit_storage_usable(settings.audit_path):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable",
        )
    return {"status": "ready"}


@app.get(
    "/v1/policy",
    response_model=PolicySummary,
    dependencies=[Depends(authenticate)],
)
async def policy_summary(request: Request) -> PolicySummary:
    """Return inspectable policy metadata without exposing regex definitions."""

    policy = _policy(request)
    return PolicySummary(
        version=policy.version,
        default_action=policy.default_action,
        allowed_hosts=sorted(policy.allowed_hosts),
        rules=[
            RuleSummary(
                id=rule.id,
                description=rule.description,
                action=rule.action,
                severity=rule.severity,
            )
            for rule in policy.rules
        ],
    )


@app.post("/v1/scan", response_model=ScanResponse, dependencies=[Depends(authenticate)])
async def scan(body: ScanRequest, request: Request) -> ScanResponse:
    result = scan_payload(body.payload, _policy(request))
    write_audit_event(settings.audit_path, result)
    return result


@app.post("/v1/proxy", dependencies=[Depends(authenticate)])
async def proxy(body: ProxyRequest, request: Request) -> Response:
    if not settings.proxy_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Proxy forwarding unavailable",
        )

    policy = _policy(request)
    method = body.method.upper()
    if method not in {"POST", "PUT", "PATCH"}:
        raise HTTPException(status_code=405, detail="Only POST, PUT, and PATCH are supported")

    try:
        destination = await validate_destination(str(body.url), policy.allowed_hosts)
        upstream_headers = sanitize_caller_headers(body.headers)
    except (DestinationValidationError, HeaderValidationError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Destination not allowed")

    result = scan_payload(body.payload, policy)
    write_audit_event(settings.audit_path, result, destination.hostname)
    if result.decision == Action.BLOCK:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Sensitive data blocked", "findings": [f.model_dump() for f in result.findings]},
        )

    try:
        upstream = await request.app.state.http.request(
            method,
            destination.url,
            headers=upstream_headers,
            json=result.payload,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Upstream request failed") from exc
    safe_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() in {"content-type", "request-id", "x-request-id"}
    }
    return Response(content=upstream.content, status_code=upstream.status_code, headers=safe_headers)
