"""Outbound destination policy for AI provider connections.

Every connection to a provider is checked at connect time, not only when the
configuration is loaded:

* The host is resolved once. Every returned address is validated, and one bad
  address rejects the whole result.
* Only addresses validated in that same call are connected to. The request URL
  is rewritten to the validated IP, the original host is kept in the Host header,
  and TLS verifies the original name through the sni_hostname extension. A second
  DNS answer cannot redirect the connection (DNS rebinding).
* Redirects are never followed.

Address tiers:
* denied: cloud metadata, link-local, multicast, unspecified, and reserved ranges.
  Never allowed.
* internal: loopback, private, shared (CGNAT), documentation, and other non-global
  ranges. Allowed only for a provider that lists them in trusted_internal_networks.
* public: globally routable addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .ip_access import IPAddress, IPNetwork, normalize_address

Resolver = Callable[[str, int], Awaitable[list[str]]]

DNS_TIMEOUT_SECONDS = 5.0
HTTPS_PORT = 443
HTTP_PORT = 80

TIER_DENIED = "denied"
TIER_INTERNAL = "internal"
TIER_PUBLIC = "public"

_ALWAYS_DENIED: tuple[IPNetwork, ...] = tuple(ipaddress.ip_network(item) for item in (
    "0.0.0.0/8",           # "this network", including unspecified
    "169.254.0.0/16",      # link-local, includes the 169.254.169.254 metadata service
    "224.0.0.0/4",         # multicast
    "240.0.0.0/4",         # reserved, includes the broadcast address
    "100.100.100.200/32",  # Alibaba Cloud metadata service (inside CGNAT space)
    "::/128",              # IPv6 unspecified
    "ff00::/8",            # IPv6 multicast
    "fe80::/10",           # IPv6 link-local
    "fd00:ec2::254/128",   # AWS IPv6 metadata service
))
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPATIBLE_PREFIX = ipaddress.ip_network("::/96")
_IPV6_LOOPBACK = ipaddress.ip_address("::1")


class DestinationBlockedError(Exception):
    """A provider destination failed the egress policy. The message never includes the address."""


def classify_address(value: str | IPAddress) -> str:
    """Return the tier of one address. Raises ValueError if the text is not an IP address."""
    address = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(value.strip())
    address = normalize_address(address)
    if isinstance(address, ipaddress.IPv6Address):
        if address in _NAT64_PREFIX:
            return classify_address(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
        if address.sixtofour is not None:
            return TIER_DENIED if classify_address(address.sixtofour) == TIER_DENIED else TIER_INTERNAL
        if address.teredo is not None:
            return TIER_DENIED if classify_address(address.teredo[1]) == TIER_DENIED else TIER_INTERNAL
        if address in _IPV4_COMPATIBLE_PREFIX and address != _IPV6_LOOPBACK:
            return TIER_DENIED
    if any(address in network for network in _ALWAYS_DENIED):
        return TIER_DENIED
    return TIER_PUBLIC if address.is_global else TIER_INTERNAL


def _contained(address: IPAddress, networks: Iterable[IPNetwork]) -> bool:
    return any(address in network for network in networks)


def validate_trusted_networks(networks: Sequence[IPNetwork]) -> tuple[IPNetwork, ...]:
    """Reject trust entries that overlap a range that is never allowed."""
    for network in networks:
        for denied in _ALWAYS_DENIED:
            if network.version == denied.version and network.overlaps(denied):
                raise ValueError("trusted internal network overlaps a blocked address range")
    return tuple(networks)


def validate_provider_endpoint(api_base: str, trusted_networks: Sequence[IPNetwork]) -> str:
    """Config-time checks on a provider base URL. DNS names are checked again at connect time."""
    try:
        parts = urlsplit(api_base)
        port = parts.port
    except ValueError:
        raise ValueError("api_base must be an absolute URL with a valid port") from None
    scheme = parts.scheme.lower()
    trusted = bool(trusted_networks)
    if scheme not in {"https", "http"} or not parts.netloc or not parts.hostname:
        raise ValueError("api_base must be an absolute HTTP(S) URL")
    if scheme == "http" and not trusted:
        raise ValueError("api_base must use HTTPS unless trusted_internal_networks is set")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("api_base cannot contain credentials, query, or fragment")
    if port is not None and port != HTTPS_PORT and not trusted:
        raise ValueError("api_base port is not allowed without trusted_internal_networks")
    host = parts.hostname.lower()
    if host == "localhost" or host.endswith(".localhost"):
        if not trusted:
            raise ValueError("api_base host is not allowed without trusted_internal_networks")
    else:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            tier = classify_address(literal)
            if tier == TIER_DENIED or (tier == TIER_INTERNAL and not _contained(literal, trusted_networks)):
                raise ValueError("api_base address is not allowed")
    return api_base.rstrip("/")


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


@dataclass(frozen=True)
class EgressPolicy:
    trusted_networks: tuple[IPNetwork, ...] = ()

    @property
    def allows_internal(self) -> bool:
        return bool(self.trusted_networks)

    def check_url(self, url: httpx.URL) -> int:
        """Check scheme and port before any lookup. Returns the effective port."""
        if url.scheme not in {"https", "http"}:
            raise DestinationBlockedError("unsupported destination scheme")
        if url.scheme == "http" and not self.allows_internal:
            raise DestinationBlockedError("plain HTTP is not allowed for this provider")
        port = url.port or (HTTPS_PORT if url.scheme == "https" else HTTP_PORT)
        if port != HTTPS_PORT and not self.allows_internal:
            raise DestinationBlockedError("destination port is not allowed for this provider")
        return port

    async def resolve_allowed(self, host: str, port: int, resolver: Resolver) -> list[IPAddress]:
        """Resolve once and return only addresses that passed every check. Any failing address rejects all."""
        try:
            literal: IPAddress | None = normalize_address(ipaddress.ip_address(host))
        except ValueError:
            literal = None
        if literal is not None:
            candidates = [str(literal)]
        else:
            try:
                candidates = await asyncio.wait_for(resolver(host, port), DNS_TIMEOUT_SECONDS)
            except (OSError, asyncio.TimeoutError):
                raise httpx.ConnectError("provider host could not be resolved") from None
        allowed: list[IPAddress] = []
        for candidate in candidates:
            try:
                address = normalize_address(ipaddress.ip_address(candidate.strip()))
            except ValueError:
                raise DestinationBlockedError("destination resolved to an invalid address") from None
            tier = classify_address(address)
            if tier == TIER_DENIED:
                raise DestinationBlockedError("destination address is not allowed")
            if tier == TIER_INTERNAL and not _contained(address, self.trusted_networks):
                raise DestinationBlockedError("destination address is internal and not trusted")
            if address not in allowed:
                allowed.append(address)
        if not allowed:
            raise httpx.ConnectError("provider host could not be resolved")
        return allowed


class PinnedDestinationTransport(httpx.AsyncBaseTransport):
    """Connects only to addresses validated in the same request. One instance serves one provider URL."""

    def __init__(self, policy: EgressPolicy, resolver: Resolver = system_resolver) -> None:
        self._policy = policy
        self._resolver = resolver
        self._transports: dict[str, httpx.AsyncHTTPTransport] = {}

    def _transport_for(self, address: str) -> httpx.AsyncHTTPTransport:
        transport = self._transports.get(address)
        if transport is None:
            transport = httpx.AsyncHTTPTransport(retries=0)
            self._transports[address] = transport
        return transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        port = self._policy.check_url(url)
        addresses = await self._policy.resolve_allowed(url.host, port, self._resolver)
        last_error: httpx.TransportError | None = None
        for address in addresses:
            pinned = httpx.Request(
                request.method,
                url.copy_with(host=str(address)),
                headers=request.headers,
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": url.host},
            )
            try:
                return await self._transport_for(str(address)).handle_async_request(pinned)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_error = exc
                continue
        if last_error is not None:
            raise last_error
        raise httpx.ConnectError("provider host could not be reached")

    async def aclose(self) -> None:
        for transport in self._transports.values():
            await transport.aclose()
        self._transports.clear()
