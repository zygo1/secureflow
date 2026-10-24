from urllib.error import HTTPError

from secureflow.target_validation import validate_local_target
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


def check_target_reachable(url: str) -> int:
    validate_local_target(url)
    opener = build_opener(ProxyHandler({}), NoRedirectHandler)

    request = Request(
        url,
        method="GET",
        headers={"User-Agent": "SecureFlow/0.1"},
    )

    try:
        with opener.open(request, timeout=5) as response:
            return response.status

    except HTTPError as error:
        if 300 <= error.code < 400:
            raise ValueError(
                f"Redirect blocked: HTTP {error.code}"
            ) from error

        raise ValueError(
            f"Target returned HTTP {error.code}"
        ) from error
