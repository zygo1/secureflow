"""Local-only target validation shared by config, reachability and ZAP."""

from ipaddress import ip_address
from urllib.parse import urlsplit


def validate_local_target(url: str) -> None:
    """Allow HTTP on loopback IPs at any explicit or default port."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port  # Validate malformed ports early.
        address = ip_address(host or "")
    except (ValueError, TypeError) as error:
        raise ValueError("Target must use a loopback IP address") from error

    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port == 0
    ):
        raise ValueError("Only HTTP loopback targets are allowed")
