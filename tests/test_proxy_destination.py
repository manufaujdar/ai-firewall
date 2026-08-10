import ipaddress
from collections.abc import Sequence

import pytest

from ai_firewall.proxy.destination import (
    DestinationValidationError,
    validate_destination,
)


class FakeResolver:
    def __init__(self, addresses: Sequence[str]) -> None:
        self.addresses = addresses
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        self.calls.append((hostname, port))
        return self.addresses


@pytest.mark.asyncio
async def test_normalizes_exact_host_and_resolves_all_addresses() -> None:
    resolver = FakeResolver(("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"))

    result = await validate_destination(
        "HTTPS://EXAMPLE.COM./v1/messages?stream=false",
        {"example.com"},
        resolver=resolver,
    )

    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.resolved_addresses == (
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"),
    )
    assert resolver.calls == [("example.com", 443)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/v1",
        "https://user@example.com/v1",
        "https://user:pass@example.com/v1",
        "https://example.com/v1#fragment",
        "https://example.com/v1#",
        "https://example.com:444/v1",
        "https://sub.example.com/v1",
    ],
)
async def test_rejects_unapproved_url_forms_before_dns(url: str) -> None:
    resolver = FakeResolver(("93.184.216.34",))

    with pytest.raises(DestinationValidationError):
        await validate_destination(url, {"example.com"}, resolver=resolver)

    assert resolver.calls == []


@pytest.mark.asyncio
async def test_accepts_an_explicitly_allowed_non_default_port() -> None:
    resolver = FakeResolver(("93.184.216.34",))

    result = await validate_destination(
        "https://example.com:8443/v1",
        {"example.com"},
        allowed_ports={443, 8443},
        resolver=resolver,
    )

    assert result.port == 8443
    assert resolver.calls == [("example.com", 8443)]


@pytest.mark.asyncio
async def test_compares_idna_hostnames_in_normalized_form() -> None:
    resolver = FakeResolver(("93.184.216.34",))

    result = await validate_destination(
        "https://bücher.example/v1",
        {"xn--bcher-kva.example"},
        resolver=resolver,
    )

    assert result.hostname == "xn--bcher-kva.example"
    assert resolver.calls == [("xn--bcher-kva.example", 443)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.23.4.5",
        "169.254.169.254",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "::1",
        "fd00::1",
        "fe80::1",
        "ff02::1",
        "::",
    ],
)
async def test_rejects_non_global_ipv4_and_ipv6(address: str) -> None:
    with pytest.raises(DestinationValidationError, match="not globally routable"):
        await validate_destination(
            "https://example.com/v1",
            {"example.com"},
            resolver=FakeResolver((address,)),
        )


@pytest.mark.asyncio
async def test_rejects_entire_resolution_if_any_address_is_unsafe() -> None:
    resolver = FakeResolver(("93.184.216.34", "127.0.0.1"))

    with pytest.raises(DestinationValidationError, match="not globally routable"):
        await validate_destination("https://example.com/v1", {"example.com"}, resolver=resolver)


@pytest.mark.asyncio
async def test_fails_closed_when_resolution_is_empty() -> None:
    with pytest.raises(DestinationValidationError, match="did not resolve"):
        await validate_destination(
            "https://example.com/v1",
            {"example.com"},
            resolver=FakeResolver(()),
        )
