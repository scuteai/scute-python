from __future__ import annotations

import ipaddress

HEADER = "X-Scute-Client-IP"


def clean_client_ip(value: object) -> str | None:
    """One IPv4 or IPv6 address, trimmed; None for anything else (blank, a
    range, a list, a hostname, an address with a zone)."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or "%" in value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def client_ip_argument(value: str | None) -> str | None:
    """A client IP the developer passed: None or blank sends none, anything
    that isn't one address raises ValueError."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    ip = clean_client_ip(value)
    if ip is None:
        raise ValueError(f"client_ip must be one IPv4 or IPv6 address, got {value!r}")
    return ip
