"""
Validation helpers for reconnaissance targets.

Supports validation and normalization of domains, URLs, IPv4/IPv6
addresses, and CIDR ranges.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def is_valid_domain(value: str) -> bool:
    """Check whether ``value`` is a syntactically valid domain name.

    Args:
        value: The candidate domain string.

    Returns:
        ``True`` if the string looks like a valid domain, ``False``
        otherwise.
    """
    if not value or len(value) > 253:
        return False
    return bool(_DOMAIN_PATTERN.match(value.strip().rstrip(".")))


def is_valid_url(value: str) -> bool:
    """Check whether ``value`` is a syntactically valid HTTP(S) URL.

    Args:
        value: The candidate URL string.

    Returns:
        ``True`` if the string has a valid scheme and network location.
    """
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    hostname = parsed.hostname or ""
    return is_valid_domain(hostname) or is_valid_ipv4(hostname) or is_valid_ipv6(hostname)


def is_valid_ipv4(value: str) -> bool:
    """Check whether ``value`` is a valid IPv4 address.

    Args:
        value: The candidate IPv4 address string.

    Returns:
        ``True`` if valid, ``False`` otherwise.
    """
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Check whether ``value`` is a valid IPv6 address.

    Args:
        value: The candidate IPv6 address string.

    Returns:
        ``True`` if valid, ``False`` otherwise.
    """
    try:
        ipaddress.IPv6Address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_cidr(value: str) -> bool:
    """Check whether ``value`` is a valid IPv4 or IPv6 CIDR range.

    Args:
        value: The candidate CIDR string, e.g. ``"192.168.1.0/24"``.

    Returns:
        ``True`` if valid, ``False`` otherwise.
    """
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


def normalize_target(value: str) -> str:
    """Normalize a user-supplied target into a bare hostname or address.

    Strips whitespace, URL schemes, paths, ports, and trailing dots so
    that downstream modules receive a consistent target string.

    Args:
        value: The raw target string supplied by the user.

    Returns:
        The normalized target (domain, IPv4, IPv6, or CIDR).

    Raises:
        ValueError: If the target does not match any supported format.
    """
    candidate = value.strip()

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    else:
        # Strip a path/query if present without a scheme, e.g. example.com/foo
        candidate = candidate.split("/", 1)[0]
        # Strip a port if present, but keep IPv6 addresses in brackets intact.
        if not candidate.startswith("["):
            candidate = candidate.split(":", 1)[0]

    candidate = candidate.strip().rstrip(".").strip("[]")

    if is_valid_cidr(candidate) and "/" in candidate:
        return candidate
    if is_valid_ipv4(candidate) or is_valid_ipv6(candidate):
        return candidate
    if is_valid_domain(candidate):
        return candidate.lower()

    raise ValueError(f"'{value}' is not a valid domain, URL, IP address, or CIDR range")


def classify_target(value: str) -> str:
    """Classify a normalized target string.

    Args:
        value: A normalized target (see :func:`normalize_target`).

    Returns:
        One of ``"domain"``, ``"ipv4"``, ``"ipv6"``, or ``"cidr"``.

    Raises:
        ValueError: If the target does not match any known category.
    """
    if "/" in value and is_valid_cidr(value):
        return "cidr"
    if is_valid_ipv4(value):
        return "ipv4"
    if is_valid_ipv6(value):
        return "ipv6"
    if is_valid_domain(value):
        return "domain"
    raise ValueError(f"Unable to classify target '{value}'")
