"""SSRF protection — block connections to private/reserved IP ranges.

Provides ``is_private_ip()`` to check whether an IP address falls within
RFC 1918 private ranges, loopback, link-local, or IPv6 ULA/link-local
networks.  Use ``check_url_ssrf()`` as a convenience to resolve a URL's
hostname and check all returned addresses.

This module is the first line of defence against DNS-rebinding SSRF attacks
where an attacker submits a seed domain that initially resolves to a public
IP (passing the DNS filter) but later rebinds to an internal address.
Collectors should call ``is_private_ip()`` on the resolved IP *at connect
time* to catch rebind attempts that slip past the seed-phase filter.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is a private or reserved IP address.

    Covers RFC 1918, loopback, link-local, IPv6 ULA, and IPv6 link-local.
    Returns False for unparseable strings (safe default: allow).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return False


def check_url_ssrf(url: str) -> bool:
    """Return True if *url*'s host resolves to any private IP (SSRF risk).

    Performs a synchronous DNS lookup.  Intended for pre-flight checks in
    non-async contexts; async callers should resolve via ``getaddrinfo`` in
    an executor and call ``is_private_ip()`` on each result directly.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    try:
        results = socket.getaddrinfo(hostname, None)
        return any(is_private_ip(r[4][0]) for r in results)
    except OSError:
        return False


__all__ = ["check_url_ssrf", "is_private_ip"]
