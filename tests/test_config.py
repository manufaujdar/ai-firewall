import pytest
from pydantic import ValidationError

from ai_firewall.config import Settings


def test_proxy_transport_cannot_be_enabled_before_security_boundary_is_complete() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, proxy_enabled=True)


def test_api_key_requires_minimum_length() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, api_key="synthetic-short-key")


def test_safe_runtime_defaults() -> None:
    configured = Settings(_env_file=None)

    assert configured.proxy_enabled is False
    assert configured.fail_closed is True
    assert "*" not in configured.trusted_hosts
