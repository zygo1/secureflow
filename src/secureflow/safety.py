"""HTTP reachability checks with same-origin redirect enforcement."""

from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from secureflow.target_validation import validate_local_target

MAX_REDIRECTS = 5


def origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname or "", parsed.port or 80


class SameOriginRedirectHandler(HTTPRedirectHandler):
    """Follow at most five redirects without leaving the initial origin."""

    max_redirections = MAX_REDIRECTS
    max_repeats = MAX_REDIRECTS

    def __init__(self, target_url: str):
        super().__init__()
        validate_local_target(target_url)
        self.allowed_origin = origin(target_url)
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urljoin(req.full_url, newurl)
        validate_local_target(destination)
        if origin(destination) != self.allowed_origin:
            raise ValueError("Redirect blocked: destination is outside target origin")
        self.redirect_count += 1
        if self.redirect_count > MAX_REDIRECTS:
            raise ValueError("Redirect blocked: too many redirects")
        return super().redirect_request(req, fp, code, msg, headers, destination)


def check_target_reachable(url: str) -> int:
    validate_local_target(url)
    opener = build_opener(ProxyHandler({}), SameOriginRedirectHandler(url))
    request = Request(url, method="GET", headers={"User-Agent": "SecureFlow/0.1"})
    try:
        with opener.open(request, timeout=5) as response:
            return response.status
    except HTTPError as error:
        if 300 <= error.code < 400:
            raise ValueError(f"Redirect blocked: HTTP {error.code}") from error
        raise ValueError(f"Target returned HTTP {error.code}") from error
