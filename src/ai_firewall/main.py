import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .audit import audit_storage_usable
from .auth import APIKeyAuthenticator, authentication_ready
from .config import settings
from .models import Action, PolicySummary, ProxyRequest, RuleSummary, ScanRequest, ScanResponse
from .policy import Policy, load_policy
from .privacy import (
    InspectionOutcome,
    LocalModelRegistry,
    PrivacyDatabase,
    PrivacyOrchestrator,
    load_model_manifest,
)
from .privacy.events import PrivacyEvent
from .proxy import (
    DestinationValidationError,
    HeaderValidationError,
    sanitize_caller_headers,
    validate_destination,
)
from .request_limits import RequestBodyLimitMiddleware
from .web_ui import CONSOLE_CSS, CONSOLE_HTML, CONSOLE_JS


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.policy = load_policy(settings.policy_path)
    app.state.model_registry = LocalModelRegistry(load_model_manifest(settings.models_path))
    app.state.privacy_database = PrivacyDatabase(settings.database_path)
    app.state.privacy_database.initialize()
    app.state.orchestrator = PrivacyOrchestrator(
        policy=app.state.policy,
        audit_path=settings.audit_path,
        database=app.state.privacy_database,
        models=app.state.model_registry,
    )
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
async def ready(request: Request) -> dict[str, Any]:
    dependencies_ready = (
        audit_storage_usable(settings.audit_path)
        and request.app.state.privacy_database.usable()
        and request.app.state.model_registry.ready()
    )
    if not authentication_ready(settings) or not dependencies_ready:
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
    outcome = await request.app.state.orchestrator.inspect(body.payload)
    return outcome.response


@app.post(
    "/v1/privacy/inspect/stream",
    dependencies=[Depends(authenticate)],
)
async def inspect_stream(body: ScanRequest, request: Request) -> StreamingResponse:
    """Stream metadata-only graph events, then the local scan response."""

    async def stream():
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=32)
        sentinel = object()

        async def run_graph() -> None:
            try:
                outcome = await request.app.state.orchestrator.inspect(body.payload, queue.put)
                await queue.put(outcome)
            finally:
                await queue.put(sentinel)

        task = asyncio.create_task(run_graph())
        try:
            while True:
                item = await queue.get()
                if item is sentinel:
                    break
                if isinstance(item, PrivacyEvent):
                    yield f"event: privacy\ndata: {item.model_dump_json()}\n\n"
                elif isinstance(item, InspectionOutcome):
                    result = {
                        "request_id": item.request_id,
                        "result": item.response.model_dump(mode="json"),
                    }
                    yield f"event: result\ndata: {json.dumps(result, separators=(',', ':'))}\n\n"
                else:
                    raise TypeError("privacy stream received an invalid item")
            await task
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@app.get(
    "/v1/privacy/topology",
    dependencies=[Depends(authenticate)],
)
async def privacy_topology(request: Request) -> dict[str, Any]:
    return request.app.state.orchestrator.topology()


@app.get(
    "/v1/privacy/history",
    dependencies=[Depends(authenticate)],
)
async def privacy_history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    summaries = await asyncio.to_thread(request.app.state.privacy_database.recent, limit)
    return {
        "storage": "local_metadata_only",
        "items": [
            {
                "request_id": summary.request_id,
                "timestamp": summary.timestamp,
                "decision": summary.decision.value,
                "finding_count": summary.finding_count,
                "rule_ids": summary.rule_ids,
                "model_ids": summary.model_ids,
                "duration_ms": summary.duration_ms,
                "policy_version": summary.policy_version,
            }
            for summary in summaries
        ],
    }


@app.delete(
    "/v1/privacy/history",
    dependencies=[Depends(authenticate)],
)
async def clear_privacy_history(request: Request) -> dict[str, Any]:
    deleted = await asyncio.to_thread(request.app.state.privacy_database.clear)
    return {"storage": "local_metadata_only", "deleted": deleted}


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

    outcome = await request.app.state.orchestrator.inspect(body.payload)
    result = outcome.response
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
