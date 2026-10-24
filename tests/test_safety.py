from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request

import pytest

from secureflow.safety import SameOriginRedirectHandler, check_target_reachable

BASE = "http://127.0.0.1:3000/"


def redirect(handler, destination, source=BASE):
    request = Request(source)
    return handler.redirect_request(
        req=request,
        fp=None,
        code=302,
        msg="Found",
        headers={},
        newurl=destination,
    )


@pytest.mark.parametrize("destination", [
    "/az", "/login", "http://127.0.0.1:3000/az",
])
def test_same_origin_redirect_allowed(destination):
    request = redirect(SameOriginRedirectHandler(BASE), destination)
    assert request.full_url == "http://127.0.0.1:3000" + (
        destination if destination.startswith("/") else "/az"
    )


@pytest.mark.parametrize("destination", [
    "http://127.0.0.1:8080/admin",
    "https://127.0.0.1:3000/",
    "http://192.168.1.1/",
    "https://example.com/",
    "http://127.0.0.2:3000/",
])
def test_cross_origin_redirect_blocked(destination):
    with pytest.raises(ValueError):
        redirect(SameOriginRedirectHandler(BASE), destination)


def test_redirect_limit():
    handler = SameOriginRedirectHandler(BASE)
    for _ in range(5):
        redirect(handler, "/az")
    with pytest.raises(ValueError, match="too many redirects"):
        redirect(handler, "/az")


def test_target_reachable():
    with patch("secureflow.safety.build_opener") as mock_opener:
        response = mock_opener.return_value.open.return_value
        response.__enter__.return_value.status = 200
        assert check_target_reachable(BASE) == 200


def test_network_failure():
    with patch("secureflow.safety.build_opener") as mock_opener:
        mock_opener.return_value.open.side_effect = URLError("Connection refused")
        with pytest.raises(URLError):
            check_target_reachable(BASE)
