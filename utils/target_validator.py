import ipaddress
import os
import socket
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}


def validate_target_url(target: str) -> tuple[bool, str]:
    """
    Validate a scan target before any network request is made.

    Development mode:
        Allows localhost/private IPs for local testing.

    Production mode:
        Blocks localhost, loopback, private, link-local,
        multicast, reserved and unspecified IP addresses.
    """

    if not isinstance(target, str) or not target.strip():
        return False, "Target URL is required."

    target = target.strip()

    try:
        parsed = urlparse(target)
    except Exception:
        return False, "Invalid target URL."

    # ---------------------------------------------------------
    # Scheme validation
    # ---------------------------------------------------------
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, "Only HTTP and HTTPS targets are allowed."

    # ---------------------------------------------------------
    # Hostname validation
    # ---------------------------------------------------------
    hostname = parsed.hostname

    if not hostname:
        return False, "Target URL must contain a valid hostname."

    hostname = hostname.lower().rstrip(".")

    # ---------------------------------------------------------
    # Block credentials inside URL
    # Example:
    # http://user:password@example.com
    # ---------------------------------------------------------
    if parsed.username or parsed.password:
        return False, "Credentials in target URLs are not allowed."

    # ---------------------------------------------------------
    # Development mode
    # ---------------------------------------------------------
    environment = os.getenv(
        "VULNHAWK_ENV",
        "development"
    ).lower()

    if environment != "production":
        return True, "Target accepted in development mode."

    # ---------------------------------------------------------
    # Production hostname restrictions
    # ---------------------------------------------------------
    blocked_hostnames = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }

    if hostname in blocked_hostnames:
        return False, "Localhost targets are blocked in production."

    # ---------------------------------------------------------
    # Resolve hostname
    # ---------------------------------------------------------
    try:
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (
                443 if parsed.scheme.lower() == "https"
                else 80
            ),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        return False, "Target hostname could not be resolved."
    except Exception:
        return False, "Unable to resolve target hostname."

    resolved_ips = {
        address[4][0]
        for address in addresses
        if address and address[4]
    }

    if not resolved_ips:
        return False, "Target hostname resolved to no usable address."

    # ---------------------------------------------------------
    # SSRF protection
    # ---------------------------------------------------------
    for ip_string in resolved_ips:

        try:
            ip = ipaddress.ip_address(ip_string)
        except ValueError:
            return False, "Target resolved to an invalid IP address."

        if ip.is_loopback:
            return False, "Loopback targets are blocked in production."

        if ip.is_private:
            return False, "Private network targets are blocked in production."

        if ip.is_link_local:
            return False, "Link-local targets are blocked in production."

        if ip.is_multicast:
            return False, "Multicast targets are blocked in production."

        if ip.is_reserved:
            return False, "Reserved IP targets are blocked in production."

        if ip.is_unspecified:
            return False, "Unspecified IP targets are blocked in production."

    return True, "Target accepted."