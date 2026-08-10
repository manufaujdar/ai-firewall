"""Fail-closed validation of outbound proxy destinations."""

import asyncio
import ipaddress
import re
import socket
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class DestinationValidationError(ValueError):
    """Raised when an outbound URL is not safe and explicitly approved."""


class AddressResolver(Protocol):
    """Resolver contract used by destination validation."""

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        """Return every address currently associated with ``hostname``."""


class SystemResolver:
    """Resolve addresses without blocking the application's async event loop."""

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        return tuple(dict.fromkeys(result[4][0] for result in results))


@dataclass(frozen=True, slots=True)
class ValidatedDestination:
    """A normalized destination and the complete address set checked for it."""

    url: str
    hostname: str
    port: int
    resolved_addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]


def normalize_hostname(hostname: str) -> str:
    """Return the canonical comparison form for an IP address or DNS hostname."""

    candidate = hostname.rstrip(".").lower()
    if not candidate:
        raise DestinationValidationError("Destination hostname is missing")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass

    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DestinationValidationError("Destination hostname is invalid") from exc
    if len(normalized) > 253 or any(
        _DNS_LABEL.fullmatch(label) is None for label in normalized.split(".")
    ):
        raise DestinationValidationError("Destination hostname is invalid")
    return normalized


def _parse_url(url: str) -> tuple[SplitResult, str, int]:
    if not isinstance(url, str) or not url or any(ord(char) < 32 for char in url):
        raise DestinationValidationError("Destination URL is invalid")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise DestinationValidationError("Destination URL is invalid") from exc

    if parsed.scheme.lower() != "https":
        raise DestinationValidationError("Destination must use HTTPS")
    if not parsed.netloc or hostname is None:
        raise DestinationValidationError("Destination hostname is missing")
    if parsed.username is not None or parsed.password is not None:
        raise DestinationValidationError("Destination userinfo is not allowed")
    if "#" in url:
        raise DestinationValidationError("Destination fragments are not allowed")
    if "\\" in parsed.netloc:
        raise DestinationValidationError("Destination authority is invalid")
    return parsed, normalize_hostname(hostname), port or 443


def _normalize_allowed_ports(allowed_ports: Collection[int]) -> frozenset[int]:
    ports = frozenset(allowed_ports)
    if not ports or any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        for port in ports
    ):
        raise DestinationValidationError("Allowed destination ports are invalid")
    return ports


def _validate_address(raw_address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError as exc:
        raise DestinationValidationError("DNS returned an invalid address") from exc

    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        raise DestinationValidationError("Destination address is not globally routable")
    return address


async def validate_destination(
    url: str,
    allowed_hosts: Collection[str],
    *,
    allowed_ports: Collection[int] = frozenset({443}),
    resolver: AddressResolver | None = None,
) -> ValidatedDestination:
    """Validate an HTTPS URL against exact hosts, ports, and all resolved addresses.

    The returned addresses are validation evidence. The forwarding layer must pin its
    connection to one of them and must repeat validation for every redirect or retry.
    """

    _parsed, hostname, port = _parse_url(url)
    try:
        normalized_allowed_hosts = frozenset(normalize_hostname(host) for host in allowed_hosts)
    except (TypeError, AttributeError) as exc:
        raise DestinationValidationError("Allowed destination hosts are invalid") from exc
    if hostname not in normalized_allowed_hosts:
        raise DestinationValidationError("Destination hostname is not allowed")
    if port not in _normalize_allowed_ports(allowed_ports):
        raise DestinationValidationError("Destination port is not allowed")

    active_resolver = resolver or SystemResolver()
    try:
        raw_addresses = await active_resolver.resolve(hostname, port)
    except (OSError, socket.gaierror) as exc:
        raise DestinationValidationError("Destination resolution failed") from exc
    if not raw_addresses:
        raise DestinationValidationError("Destination did not resolve")

    resolved = tuple(dict.fromkeys(_validate_address(address) for address in raw_addresses))
    return ValidatedDestination(
        url=url,
        hostname=hostname,
        port=port,
        resolved_addresses=resolved,
    )
