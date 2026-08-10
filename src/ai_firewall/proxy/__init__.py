"""Security boundaries for outbound proxy requests."""

from .destination import (
    AddressResolver,
    DestinationValidationError,
    SystemResolver,
    ValidatedDestination,
    normalize_hostname,
    validate_destination,
)
from .headers import HeaderValidationError, sanitize_caller_headers

__all__ = [
    "AddressResolver",
    "DestinationValidationError",
    "HeaderValidationError",
    "SystemResolver",
    "ValidatedDestination",
    "normalize_hostname",
    "sanitize_caller_headers",
    "validate_destination",
]
