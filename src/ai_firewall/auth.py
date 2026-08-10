import re
import secrets
from typing import Protocol

from fastapi import HTTPException, Request, status

DEFAULT_API_KEY_HEADER = "x-ai-firewall-api-key"
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")


class APIKeySettings(Protocol):
    """Minimum settings interface required by ``APIKeyAuthenticator``."""

    api_key: str | None


def authentication_ready(settings: APIKeySettings) -> bool:
    """Return whether server-side authentication has usable key material."""

    return isinstance(settings.api_key, str) and bool(settings.api_key)


class APIKeyAuthenticator:
    """FastAPI dependency that authenticates a single dedicated header."""

    def __init__(
        self,
        settings: APIKeySettings,
        *,
        header_name: str = DEFAULT_API_KEY_HEADER,
    ) -> None:
        normalized_header = header_name.lower()
        if not _HEADER_NAME.fullmatch(normalized_header):
            raise ValueError("header_name must be a valid HTTP field name")
        self._settings = settings
        self._header_name = normalized_header.encode("ascii")

    async def __call__(self, request: Request) -> None:
        expected = self._settings.api_key
        if not authentication_ready(self._settings):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication unavailable",
            )
        assert isinstance(expected, str)

        supplied_values = [
            value
            for name, value in request.scope.get("headers", [])
            if name.lower() == self._header_name
        ]
        if len(supplied_values) != 1 or not secrets.compare_digest(
            supplied_values[0], expected.encode("utf-8")
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "ApiKey"},
            )
