import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class TargetValidationResult:
    is_valid: bool
    target_url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: List[str]
    error_message: Optional[str] = None
    is_private_or_loopback: bool = False


# Obvious internal/local domain suffixes that should be rejected without DNS lookup
BLOCKED_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".test",
    ".invalid",
    ".example",
    ".localhost"
)

# Known cloud metadata hostnames
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc"
}


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """
    Evaluate if an IP address falls into any blocked or unsafe ranges:
    - Loopback (127.0.0.0/8, ::1)
    - Private networks (RFC 1918: 10/8, 172.16/12, 192.168/16; RFC 4193: fc00::/7)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Cloud Metadata (169.254.169.254, 100.100.100.200)
    - Carrier-grade NAT (100.64.0.0/10)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Unspecified / Broadcast (0.0.0.0/8, ::, 255.255.255.255)
    - Reserved addresses (240.0.0.0/4)
    """
    if ip.is_loopback:
        return True, f"Loopback address ({ip}) is strictly prohibited."
    if ip.is_private:
        return True, f"Private/internal network address ({ip}) is strictly prohibited."
    if ip.is_link_local:
        return True, f"Link-local network address ({ip}) is strictly prohibited."
    if ip.is_multicast:
        return True, f"Multicast address ({ip}) is strictly prohibited."
    if ip.is_unspecified:
        return True, f"Unspecified address ({ip}) is strictly prohibited."
    if ip.is_reserved:
        return True, f"Reserved address ({ip}) is strictly prohibited."

    # Explicit check for AWS/GCP/Azure/Alibaba cloud metadata IP (169.254.169.254, 100.100.100.200)
    ip_str = str(ip)
    if ip_str in {"169.254.169.254", "100.100.100.200"}:
        return True, "Cloud metadata endpoint is strictly prohibited."

    # Carrier-grade NAT (100.64.0.0/10) check
    if isinstance(ip, ipaddress.IPv4Address):
        cgnat_network = ipaddress.IPv4Network("100.64.0.0/10")
        if ip in cgnat_network:
            return True, f"Carrier-Grade NAT address ({ip}) is prohibited."

    return False, ""


def resolve_all_ips(hostname: str, port: int = 443) -> List[str]:
    """
    Resolve both IPv4 and IPv6 addresses for a hostname using socket.getaddrinfo.
    Returns unique list of resolved IP strings.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        ips = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for hostname '{hostname}': {e.strerror}")
    except Exception as e:
        raise ValueError(f"DNS lookup error for hostname '{hostname}': {str(e)}")


def validate_target(target_url: str) -> TargetValidationResult:
    """
    Comprehensive target URL and destination safety validator.
    Validates:
    - URL structure & scheme (http/https only)
    - Hostname presence & FQDN syntax
    - Blocks localhost, internal TLDs, and metadata hostnames
    - Resolves all destination IPs (IPv4/IPv6)
    - Inspects every resolved IP against loopback, private, link-local, and cloud metadata ranges
    """
    raw_url = str(target_url).strip()
    if not raw_url:
        return TargetValidationResult(
            is_valid=False,
            target_url="",
            scheme="",
            hostname="",
            port=0,
            resolved_ips=[],
            error_message="Target URL cannot be empty."
        )

    # Prepend https:// only if scheme delimiter '://' is completely missing
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception as e:
        return TargetValidationResult(
            is_valid=False,
            target_url=raw_url,
            scheme="",
            hostname="",
            port=0,
            resolved_ips=[],
            error_message=f"Malformed URL structure: {str(e)}"
        )

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return TargetValidationResult(
            is_valid=False,
            target_url=raw_url,
            scheme=scheme,
            hostname="",
            port=0,
            resolved_ips=[],
            error_message=f"Unsupported protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted."
        )

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return TargetValidationResult(
            is_valid=False,
            target_url=raw_url,
            scheme=scheme,
            hostname="",
            port=0,
            resolved_ips=[],
            error_message="Target URL does not contain a valid hostname."
        )

    # 1. Reject localhost and explicit loopback hostnames
    if hostname in ("localhost", "localhost.localdomain", "127.0.0.1", "::1", "0.0.0.0"):
        return TargetValidationResult(
            is_valid=False,
            target_url=raw_url,
            scheme=scheme,
            hostname=hostname,
            port=parsed.port or (443 if scheme == "https" else 80),
            resolved_ips=["127.0.0.1" if "127" in hostname or "local" in hostname else "0.0.0.0"],
            error_message=f"Access to '{hostname}' is rejected: localhost and loopback targets are prohibited.",
            is_private_or_loopback=True
        )

    # 2. Reject known metadata hostnames
    if hostname in BLOCKED_HOSTNAMES:
        return TargetValidationResult(
            is_valid=False,
            target_url=raw_url,
            scheme=scheme,
            hostname=hostname,
            port=parsed.port or (443 if scheme == "https" else 80),
            resolved_ips=[],
            error_message="Cloud metadata endpoint is strictly prohibited.",
            is_private_or_loopback=True
        )

    # 3. Reject internal TLD suffixes
    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if hostname.endswith(suffix):
            return TargetValidationResult(
                is_valid=False,
                target_url=raw_url,
                scheme=scheme,
                hostname=hostname,
                port=parsed.port or (443 if scheme == "https" else 80),
                resolved_ips=[],
                error_message=f"Internal domain suffix '{suffix}' is prohibited.",
                is_private_or_loopback=True
            )

    port = parsed.port or (443 if scheme == "https" else 80)
    if port < 1 or port > 65535:
        return TargetValidationResult(
            is_valid=False,
            target_url=raw_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            resolved_ips=[],
            error_message=f"Invalid TCP port {port}. Must be between 1 and 65535."
        )

    # 4. Check if hostname is directly an IP literal
    try:
        direct_ip = ipaddress.ip_address(hostname)
        blocked, reason = is_ip_blocked(direct_ip)
        if blocked:
            return TargetValidationResult(
                is_valid=False,
                target_url=raw_url,
                scheme=scheme,
                hostname=hostname,
                port=port,
                resolved_ips=[str(direct_ip)],
                error_message=reason,
                is_private_or_loopback=True
            )
        resolved_ips = [str(direct_ip)]
    except ValueError:
        # Not a raw IP literal; resolve domain via DNS
        try:
            resolved_ips = resolve_all_ips(hostname, port)
        except ValueError as dns_err:
            return TargetValidationResult(
                is_valid=False,
                target_url=raw_url,
                scheme=scheme,
                hostname=hostname,
                port=port,
                resolved_ips=[],
                error_message=str(dns_err)
            )

    if not resolved_ips:
        return TargetValidationResult(
            is_valid=False,
            target_url=raw_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            resolved_ips=[],
            error_message=f"No IP addresses resolved for '{hostname}'."
        )

    # 5. Inspect EVERY resolved IP
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            blocked, reason = is_ip_blocked(ip_obj)
            if blocked:
                return TargetValidationResult(
                    is_valid=False,
                    target_url=raw_url,
                    scheme=scheme,
                    hostname=hostname,
                    port=port,
                    resolved_ips=resolved_ips,
                    error_message=f"Security Policy Violation: Hostname '{hostname}' resolves to blocked destination {ip_str}. {reason}",
                    is_private_or_loopback=True
                )
        except ValueError:
            return TargetValidationResult(
                is_valid=False,
                target_url=raw_url,
                scheme=scheme,
                hostname=hostname,
                port=port,
                resolved_ips=resolved_ips,
                error_message=f"Invalid resolved IP format '{ip_str}'."
            )

    # Normalized clean URL
    clean_url = urllib.parse.urlunparse((
        scheme,
        f"{hostname}:{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else hostname,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""  # strip fragment
    ))

    return TargetValidationResult(
        is_valid=True,
        target_url=clean_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_ips=resolved_ips,
        error_message=None,
        is_private_or_loopback=False
    )
