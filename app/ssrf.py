from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, Callable, Coroutine
from urllib.parse import urlsplit

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend


class SSRFProtectionError(ValueError):
    """Raised when a URL or host violates SSRF protection rules."""
    pass


_ALWAYS_FORBIDDEN_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 Carrier-Grade NAT (Shared Address Space)
    ipaddress.ip_network("169.254.0.0/16"),    # RFC 3927 Link-local / Cloud metadata (e.g. 169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),         # RFC 1122 'This host on this network'
    ipaddress.ip_network("192.0.0.0/24"),      # RFC 6890 IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # RFC 5737 Documentation (TEST-NET-1)
    ipaddress.ip_network("198.51.100.0/24"),   # RFC 5737 Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),    # RFC 5737 Documentation (TEST-NET-3)
    ipaddress.ip_network("240.0.0.0/4"),       # RFC 1112 Reserved for Future Use
    ipaddress.ip_network("224.0.0.0/4"),       # RFC 5771 Multicast
    ipaddress.ip_network("fe80::/10"),         # RFC 4291 IPv6 Link-Local
    ipaddress.ip_network("::/128"),            # RFC 4291 IPv6 Unspecified
    ipaddress.ip_network("ff00::/8"),          # RFC 4291 IPv6 Multicast
    ipaddress.ip_network("100::/64"),          # RFC 6666 IPv6 Discard-Only prefix
    ipaddress.ip_network("2001:db8::/32"),     # RFC 3849 IPv6 Documentation
    ipaddress.ip_network("fd00:ec2::254/128"), # AWS EC2 IPv6 Instance Metadata (IMDSv2)
)

_EXPLICIT_FORBIDDEN_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),       # RFC 1122 Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private-Use
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private-Use
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private-Use
    ipaddress.ip_network("198.18.0.0/15"),     # RFC 2544 Network Interconnect Device Benchmark
    ipaddress.ip_network("fc00::/7"),          # RFC 4193 IPv6 Unique Local Address (ULA)
    ipaddress.ip_network("::1/128"),           # RFC 4291 IPv6 Loopback
)

_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")


def _extract_embedded_ipv4s(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """Extract any IPv4 addresses embedded inside transitional IPv6 mechanisms."""
    embedded: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        embedded.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        embedded.append(ip.sixtofour)
    if ip.teredo is not None:
        embedded.extend(ip.teredo)

    val = int(ip)
    if ip in _IPV4_COMPATIBLE and val > 1:
        embedded.append(ipaddress.IPv4Address(val & 0xFFFFFFFF))
    if ip in _NAT64_WELL_KNOWN:
        embedded.append(ipaddress.IPv4Address(val & 0xFFFFFFFF))
    elif ip in _NAT64_LOCAL_USE:
        # RFC 6052 prefix lengths (/96, /64, /56, /48) with u-octet at bits 64..71 == 0
        if ((val >> 32) & 0xFFFFFFFFFFFF) == 0:
            embedded.append(ipaddress.IPv4Address(val & 0xFFFFFFFF))
        elif ((val >> 56) & 0xFFFFFF) == 0 and (val & 0xFFFFFF) == 0:
            embedded.append(ipaddress.IPv4Address((val >> 24) & 0xFFFFFFFF))
        elif ((val >> 72) & 0xFF) == 0 and ((val >> 56) & 0xFF) == 0 and (val & 0xFFFFFFFF) == 0:
            embedded.append(ipaddress.IPv4Address((((val >> 64) & 0xFF) << 24) | ((val >> 32) & 0xFFFFFF)))
        elif ((val >> 56) & 0xFF) == 0 and (val & 0xFFFFFFFFFF) == 0:
            embedded.append(ipaddress.IPv4Address((((val >> 64) & 0xFFFF) << 16) | ((val >> 40) & 0xFFFF)))
    return embedded


def is_ip_forbidden(ip_obj_or_str: ipaddress.IPv4Address | ipaddress.IPv6Address | str,
                    allow_private_hosts: bool = False) -> bool:
    """Check if an IP address is forbidden.

    When allow_private_hosts is False (default): forbids all non-global, private, loopback,
    link-local, cloud metadata, multicast, and reserved addresses.
    When allow_private_hosts is True: permits loopback and RFC 1918 private addresses,
    while strictly and unconditionally forbidding cloud metadata (169.254.169.254),
    CGNAT (100.64.0.0/10), multicast, link-local, and reserved networks.
    """
    try:
        if isinstance(ip_obj_or_str, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = ip_obj_or_str
        else:
            cleaned = str(ip_obj_or_str).strip()
            if cleaned.startswith("[") and cleaned.endswith("]"):
                cleaned = cleaned[1:-1]
            ip = ipaddress.ip_address(cleaned)

        if isinstance(ip, ipaddress.IPv6Address):
            for embedded_v4 in _extract_embedded_ipv4s(ip):
                if is_ip_forbidden(embedded_v4, allow_private_hosts=allow_private_hosts):
                    return True
            if ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped

        # Unconditionally forbidden networks (Cloud Metadata, CGNAT, Multicast, etc.)
        for net in _ALWAYS_FORBIDDEN_NETWORKS:
            if ip in net:
                return True

        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return True

        # When private hosts are not explicitly allowed, forbid loopback & private spaces
        if not allow_private_hosts:
            if not ip.is_global or ip.is_private or ip.is_loopback:
                return True
            for net in _EXPLICIT_FORBIDDEN_NETWORKS:
                if ip in net:
                    return True

        return False
    except ValueError:
        return True


def validate_ssrf_url(url: str, provider_name: str = "provider", allow_private_hosts: bool = False) -> str:
    """
    Canonically parse and strictly validate an api_base URL for SSRF vulnerabilities.
    Rejects userinfo, queries, fragments, non-standard IP formats, and cloud metadata.
    When allow_private_hosts=False (default), also rejects plain HTTP, local domains,
    private IPs, and loopbacks.
    When allow_private_hosts=True, allows HTTP and local/private networks, but strictly
    retains protections against cloud metadata (169.254.169.254) and CGNAT.
    """
    parts = urlsplit(url)

    if allow_private_hosts:
        if parts.scheme not in {"http", "https"}:
            raise ValueError(f"Provider {provider_name!r} api_base must use HTTP or HTTPS")
    else:
        if parts.scheme != "https":
            raise ValueError(f"Provider {provider_name!r} api_base must use HTTPS")

    if not parts.netloc:
        raise ValueError(f"Provider {provider_name!r} api_base must be an absolute URL")
    if parts.username or parts.password:
        raise ValueError(f"Provider {provider_name!r} api_base cannot contain userinfo (username/password)")
    if parts.query or parts.fragment:
        raise ValueError(f"Provider {provider_name!r} api_base cannot contain query or fragment")
    if parts.port is not None and not (1 <= parts.port <= 65535):
        raise ValueError(f"Provider {provider_name!r} api_base has invalid port")

    raw_host = parts.hostname or ""
    if not raw_host:
        raise ValueError(f"Provider {provider_name!r} api_base has no valid hostname")

    if "%" in raw_host or "%" in url:
        raise ValueError(f"Provider {provider_name!r} api_base contains forbidden zone identifier")

    host_lower = raw_host.lower().rstrip(".")
    if not host_lower:
        raise ValueError(f"Provider {provider_name!r} api_base has no valid hostname")

    if not allow_private_hosts:
        forbidden_suffixes = (".localhost", ".local", ".internal", ".lan", ".home", ".corp")
        if host_lower == "localhost" or host_lower.endswith(forbidden_suffixes):
            raise ValueError(f"Provider {provider_name!r} api_base targets forbidden local domain: {raw_host!r}")

    if host_lower.isdigit():
        raise ValueError(f"Provider {provider_name!r} api_base targets non-standard integer IP notation: {raw_host!r}")

    dot_parts = host_lower.split(".")
    if 1 <= len(dot_parts) <= 4 and all(p.isdigit() or p.startswith(("0x", "0X")) for p in dot_parts):
        if any(p.startswith(("0x", "0X")) or (p.startswith("0") and len(p) > 1) for p in dot_parts):
            raise ValueError(f"Provider {provider_name!r} api_base targets non-standard octal/hex IP notation: {raw_host!r}")
        if len(dot_parts) < 4:
            raise ValueError(f"Provider {provider_name!r} api_base targets non-standard shorthand IP notation: {raw_host!r}")

    try:
        ip = ipaddress.ip_address(host_lower)
        if is_ip_forbidden(ip, allow_private_hosts=allow_private_hosts):
            raise ValueError(f"Provider {provider_name!r} api_base targets forbidden IP address: {ip}")
    except ValueError as e:
        if "targets forbidden" in str(e):
            raise

    return url.rstrip("/")


class SafeSSRFNetworkBackend(AutoBackend):
    """
    Network backend that intercepts connect_tcp to prevent SSRF and DNS Rebinding.
    1. Resolves all A and AAAA records before connection.
    2. Rejects if ANY resolved address is forbidden (fail-closed).
    3. Pins the TCP connection to the first verified safe IP.
    """

    def __init__(self, dns_resolver: Callable[[str, int], list[str] | Coroutine[Any, Any, list[str]]] | None = None,
                 allow_private_hosts: bool = False):
        super().__init__()
        self.dns_resolver = dns_resolver
        self.allow_private_hosts = allow_private_hosts
        self.last_connected_ip: str | None = None

    async def _resolve(self, host: str, port: int) -> list[str]:
        if self.dns_resolver is not None:
            res = self.dns_resolver(host, port)
            if asyncio.iscoroutine(res):
                res = await res
            return list(res)

        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        return [info[4][0] for info in addr_info]

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            resolved_ips = await self._resolve(host, port)
        except Exception as exc:
            raise httpcore.ConnectError(f"DNS resolution failed for {host}: {exc}") from exc

        if not resolved_ips:
            raise httpcore.ConnectError(f"DNS resolution returned no addresses for {host}")

        for ip_str in resolved_ips:
            if is_ip_forbidden(ip_str, allow_private_hosts=self.allow_private_hosts):
                raise httpcore.ConnectError(
                    f"SSRF protection blocked target: {host} resolved to forbidden IP {ip_str}"
                )

        pinned_ip = resolved_ips[0]
        self.last_connected_ip = pinned_ip

        return await super().connect_tcp(
            pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class SafeSSRFTransport(httpx.AsyncHTTPTransport):
    """
    HTTPX Async Transport hardened against SSRF:
    - trust_env=False (ignores HTTP_PROXY, HTTPS_PROXY, ALL_PROXY from environment)
    - Uses SafeSSRFNetworkBackend for DNS resolution safety and IP pinning
    """

    def __init__(
        self,
        dns_resolver: Any = None,
        allow_private_hosts: bool = False,
        max_connections: int = 64,
        **kwargs: Any,
    ):
        super().__init__(trust_env=False, **kwargs)
        self.network_backend = SafeSSRFNetworkBackend(dns_resolver=dns_resolver, allow_private_hosts=allow_private_hosts)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self._pool._ssl_context,
            network_backend=self.network_backend,
            max_connections=max_connections,
            max_keepalive_connections=min(20, max_connections),
            retries=0,
            http1=True,
            http2=False,
        )


def create_safe_transport(
    dns_resolver: Any = None,
    allow_private_hosts: bool = False,
    max_connections: int = 64,
) -> httpx.AsyncBaseTransport:
    """Create a safe SSRF-hardened transport instance."""
    return SafeSSRFTransport(
        dns_resolver=dns_resolver,
        allow_private_hosts=allow_private_hosts,
        max_connections=max_connections,
    )
