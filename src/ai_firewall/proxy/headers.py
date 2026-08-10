"""Caller-header filtering for outbound proxy requests."""

import re
from collections.abc import Collection, Mapping


class HeaderValidationError(ValueError):
    """Raised when header input or allowlist configuration is malformed."""


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

_FORBIDDEN_HEADERS = frozenset(
    {
        "accept-encoding",
        "authorization",
        "connection",
        "content-encoding",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
    }
)

_FORWARDING_HEADERS = frozenset(
    {
        "cf-connecting-ip",
        "forwarded",
        "true-client-ip",
        "x-client-ip",
        "x-cluster-client-ip",
        "x-real-ip",
    }
)


def _normalize_header_name(name: str) -> str:
    if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
        raise HeaderValidationError("Header name is invalid")
    return name.lower()


def _is_forbidden(name: str, connection_headers: frozenset[str]) -> bool:
    return (
        name in _FORBIDDEN_HEADERS
        or name in _FORWARDING_HEADERS
        or name in connection_headers
        or name.startswith(("x-forwarded-", "proxy-"))
    )


def sanitize_caller_headers(
    headers: Mapping[str, str],
    *,
    allowed_headers: Collection[str] = frozenset(),
) -> dict[str, str]:
    """Copy only explicitly allowed semantic headers, using lowercase names.

    Transport, credential, authority, compression, and forwarding headers are
    always stripped even if they appear in ``allowed_headers``.
    """

    try:
        allowed = frozenset(_normalize_header_name(name) for name in allowed_headers)
    except (TypeError, AttributeError) as exc:
        raise HeaderValidationError("Allowed header names are invalid") from exc

    normalized: list[tuple[str, str]] = []
    connection_headers: set[str] = set()
    for raw_name, value in headers.items():
        name = _normalize_header_name(raw_name)
        if not isinstance(value, str) or any(char in value for char in ("\r", "\n", "\0")):
            raise HeaderValidationError("Header value is invalid")
        normalized.append((name, value))
        if name == "connection":
            for token in value.split(","):
                token = token.strip()
                if token:
                    connection_headers.add(_normalize_header_name(token))

    dynamic_forbidden = frozenset(connection_headers)
    return {
        name: value
        for name, value in normalized
        if name in allowed and not _is_forbidden(name, dynamic_forbidden)
    }
