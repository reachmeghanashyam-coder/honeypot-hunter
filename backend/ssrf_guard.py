"""
SSRF, DNS Rebinding, and Egress Security Guard for Honeypot Hunter.

Strictly validates URLs and resolved IP addresses before any navigation or
sub-request is permitted inside the browser sandbox.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

# Local internal honeypot trap endpoints are explicitly permitted ONLY when
# targeting the controlled local trap server port during sandbox demonstrations.
CONTROLLED_TRAP_HOSTS = {"127.0.0.1", "localhost", "host.docker.internal"}


@dataclass(frozen=True)
class URLValidationResult:
    allowed: bool
    normalized_url: str
    hostname: str
    resolved_ips: list[str]
    blocked_reason: Optional[str] = None
    is_controlled_trap: bool = False
    is_unreachable: bool = False


def is_ip_forbidden(ip_str: str) -> tuple[bool, Optional[str]]:
    """
    Check if an IPv4 or IPv6 address falls within private, loopback, link-local,
    cloud metadata (169.254.169.254), multicast, or reserved address spaces.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    if str(ip_obj) == "169.254.169.254":
        return True, "Blocked Cloud Metadata Endpoint (169.254.169.254)"
    if ip_obj.is_loopback:
        return True, f"Blocked Loopback Address ({ip_obj})"
    if ip_obj.is_link_local:
        return True, f"Blocked Link-Local Address ({ip_obj})"
    if ip_obj.is_private:
        return True, f"Blocked RFC1918 / Private Network Address ({ip_obj})"
    if ip_obj.is_multicast:
        return True, f"Blocked Multicast Address ({ip_obj})"
    if ip_obj.is_reserved or ip_obj.is_unspecified:
        return True, f"Blocked Reserved/Unspecified Address ({ip_obj})"

    # Explicit carrier-grade NAT check (100.64.0.0/10)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip_obj in cgnat:
            return True, f"Blocked Carrier-Grade NAT / Internal Range ({ip_obj})"

    return False, None


def validate_target_url(
    raw_url: str,
    allow_controlled_trap_port: Optional[int] = None,
) -> URLValidationResult:
    """
    Validate a user-supplied or page-redirected URL against SSRF, scheme abuse,
    and DNS rebinding to private IP ranges.
    """
    if not raw_url or not isinstance(raw_url, str):
        return URLValidationResult(
            allowed=False,
            normalized_url="",
            hostname="",
            resolved_ips=[],
            blocked_reason="Empty or non-string URL input.",
        )

    cleaned = raw_url.strip()
    if len(cleaned) > 2048:
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned[:128],
            hostname="",
            resolved_ips=[],
            blocked_reason="URL exceeds maximum safe length (2048 chars).",
        )

    # Reject control characters or null bytes
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        return URLValidationResult(
            allowed=False,
            normalized_url="",
            hostname="",
            resolved_ips=[],
            blocked_reason="URL contains illegal control characters.",
        )

    # Auto-prepend https:// if user typed a bare domain like "example.com"
    if "://" not in cleaned and not cleaned.startswith(("javascript:", "file:", "data:", "ftp:", "gopher:", "ws:", "wss:")):
        cleaned = f"https://{cleaned}"

    try:
        parsed = urlparse(cleaned)
    except Exception as exc:
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned,
            hostname="",
            resolved_ips=[],
            blocked_reason=f"Malformed URL syntax: {exc}",
        )

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned,
            hostname="",
            resolved_ips=[],
            blocked_reason=f"Forbidden URL scheme '{scheme}://'. Only HTTP/HTTPS allowed.",
        )

    if parsed.username or parsed.password:
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned,
            hostname=parsed.hostname or "",
            resolved_ips=[],
            blocked_reason="Embedded credentials in URL authority are forbidden.",
        )

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned,
            hostname="",
            resolved_ips=[],
            blocked_reason="Missing hostname in URL.",
        )

    # Check if this is an explicit built-in sandbox trap route on our controlled trap port
    if (
        allow_controlled_trap_port is not None
        and hostname in CONTROLLED_TRAP_HOSTS
        and parsed.port == allow_controlled_trap_port
        and parsed.path.startswith("/traps/")
        and not parsed.path.startswith("/traps/ssrf-")
    ):
        return URLValidationResult(
            allowed=True,
            normalized_url=cleaned,
            hostname=hostname,
            resolved_ips=["127.0.0.1"],
            blocked_reason=None,
            is_controlled_trap=True,
        )

    # Block obvious internal hostnames immediately
    if hostname in {"localhost", "metadata.google.internal", "instance-data", "host.docker.internal"} or hostname.endswith(".internal") or hostname.endswith(".local"):
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned,
            hostname=hostname,
            resolved_ips=[],
            blocked_reason=f"Blocked internal/reserved hostname '{hostname}'.",
        )

    # If hostname is already a literal IP, validate it directly
    try:
        ipaddress.ip_address(hostname)
        forbidden, reason = is_ip_forbidden(hostname)
        if forbidden:
            return URLValidationResult(
                allowed=False,
                normalized_url=cleaned,
                hostname=hostname,
                resolved_ips=[hostname],
                blocked_reason=reason,
            )
        return URLValidationResult(
            allowed=True,
            normalized_url=cleaned,
            hostname=hostname,
            resolved_ips=[hostname],
        )
    except ValueError:
        pass

    # Resolve DNS and check ALL returned A/AAAA records to prevent DNS rebinding
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned,
            hostname=hostname,
            resolved_ips=[],
            blocked_reason=f"DNS resolution failed for '{hostname}': {exc}",
            is_unreachable=True,
        )

    resolved_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = str(sockaddr[0])
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)
        forbidden, reason = is_ip_forbidden(ip_str)
        if forbidden:
            return URLValidationResult(
                allowed=False,
                normalized_url=cleaned,
                hostname=hostname,
                resolved_ips=resolved_ips,
                blocked_reason=f"DNS rebinding / SSRF protection triggered for '{hostname}': {reason}",
            )

    if not resolved_ips:
        return URLValidationResult(
            allowed=False,
            normalized_url=cleaned,
            hostname=hostname,
            resolved_ips=[],
            blocked_reason=f"No valid public IP records returned for '{hostname}'.",
        )

    return URLValidationResult(
        allowed=True,
        normalized_url=cleaned,
        hostname=hostname,
        resolved_ips=resolved_ips,
    )
