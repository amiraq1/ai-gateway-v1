"""Admin IP rules and client address resolution.

Forwarded headers are honored only when the direct TCP peer is an explicitly
trusted proxy (TRUSTED_PROXIES). Everything else is ignored, so a client cannot
change its apparent address by sending headers.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_MAX_RULE_INPUT_LENGTH = 64
_IPV4_MAPPED_PREFIX = 96


def normalize_address(address: IPAddress) -> IPAddress:
    """Map ::ffff:a.b.c.d to a.b.c.d so IPv4 rules match IPv4-mapped peers."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def parse_address(value: str | None) -> IPAddress | None:
    if value is None:
        return None
    try:
        return normalize_address(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def parse_ip_or_cidr(value: str) -> IPNetwork:
    """Parse an IP address or CIDR. Host bits must be zero, and IPv4-mapped IPv6 networks become IPv4."""
    if not isinstance(value, str):
        raise ValueError("Invalid IP address or CIDR")
    text = value.strip()
    if not text or len(text) > _MAX_RULE_INPUT_LENGTH:
        raise ValueError("Invalid IP address or CIDR")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise ValueError("Invalid IP address or CIDR") from None
    if (isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= _IPV4_MAPPED_PREFIX
            and network.network_address.ipv4_mapped is not None):
        mapped = ipaddress.ip_network(
            f"{network.network_address.ipv4_mapped}/{network.prefixlen - _IPV4_MAPPED_PREFIX}", strict=True)
        return mapped
    return network


def parse_trusted_proxies(raw: str) -> tuple[IPNetwork, ...]:
    """Parse a comma-separated list such as "10.0.0.5, 192.0.2.0/24". Empty input trusts no proxy."""
    entries = [item.strip() for item in raw.split(",") if item.strip()]
    return tuple(parse_ip_or_cidr(item) for item in entries)


def _is_trusted(address: IPAddress, trusted: Sequence[IPNetwork]) -> bool:
    return any(address in network for network in trusted)


def resolve_client_ip(peer: str | None, forwarded_for: Iterable[str], trusted_proxies: Sequence[IPNetwork]) -> IPAddress | None:
    """Return the client address for policy checks, or None when it cannot be determined safely.

    A forwarded chain is walked from the right. Trusted proxies are skipped, and
    the first untrusted address is the client. An invalid entry makes the result None.
    """
    peer_address = parse_address(peer)
    if peer_address is None:
        return None
    headers = [value for value in forwarded_for]
    if not trusted_proxies or not _is_trusted(peer_address, trusted_proxies) or not headers:
        return peer_address

    chain: list[IPAddress] = []
    for header in headers:
        for item in header.split(","):
            parsed = parse_address(item) if item.strip() else None
            if parsed is None:
                return None
            chain.append(parsed)
    if not chain:
        return None
    for candidate in reversed(chain):
        if not _is_trusted(candidate, trusted_proxies):
            return candidate
    return chain[0]


@dataclass(frozen=True)
class IpRule:
    rule_id: int
    rule_type: str
    network: IPNetwork
    is_active: bool


def is_request_allowed(address: IPAddress, rules: Iterable[IpRule]) -> bool:
    """Deny rules always win. When any active allow rule exists, only matching addresses pass."""
    active = [rule for rule in rules if rule.is_active]
    if any(rule.rule_type == "deny" and address in rule.network for rule in active):
        return False
    allows = [rule for rule in active if rule.rule_type == "allow"]
    if not allows:
        return True
    return any(address in rule.network for rule in allows)
