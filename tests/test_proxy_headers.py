import pytest

from ai_firewall.proxy.headers import HeaderValidationError, sanitize_caller_headers


def test_copies_only_explicitly_allowed_headers() -> None:
    result = sanitize_caller_headers(
        {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Unapproved": "synthetic-value",
        },
        allowed_headers={"content-type", "accept"},
    )

    assert result == {"content-type": "application/json", "accept": "application/json"}


def test_default_allowlist_discards_all_caller_headers() -> None:
    assert sanitize_caller_headers({"Content-Type": "application/json"}) == {}


def test_always_strips_security_sensitive_and_forwarding_headers() -> None:
    headers = {
        "Authorization": "Bearer synthetic-provider-token",
        "Host": "internal.invalid",
        "Content-Length": "999",
        "Content-Encoding": "gzip",
        "Accept-Encoding": "gzip",
        "Transfer-Encoding": "chunked",
        "Forwarded": "for=192.0.2.10",
        "X-Forwarded-For": "192.0.2.10",
        "X-Real-IP": "192.0.2.10",
        "Via": "synthetic-proxy",
        "Proxy-Authorization": "Basic synthetic-value",
    }

    result = sanitize_caller_headers(headers, allowed_headers=set(headers))

    assert result == {}


def test_connection_nominated_headers_are_stripped() -> None:
    result = sanitize_caller_headers(
        {"Connection": "X-Remove, keep-alive", "X-Remove": "synthetic-value", "Accept": "json"},
        allowed_headers={"x-remove", "accept"},
    )

    assert result == {"accept": "json"}


@pytest.mark.parametrize(
    ("headers", "allowed_headers"),
    [
        ({"Bad Header": "value"}, {"bad-header"}),
        ({"X-Safe": "value\r\nInjected: yes"}, {"x-safe"}),
        ({"X-Safe": "value"}, {"bad header"}),
    ],
)
def test_rejects_malformed_header_input(
    headers: dict[str, str], allowed_headers: set[str]
) -> None:
    with pytest.raises(HeaderValidationError):
        sanitize_caller_headers(headers, allowed_headers=allowed_headers)
