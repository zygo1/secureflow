from unittest.mock import patch

import pytest

from secureflow.safety import (
    NoRedirectHandler,
    check_target_reachable,
)


def test_redirects_are_disabled():
    handler = NoRedirectHandler()

    result = handler.redirect_request(
        req=None,
        fp=None,
        code=302,
        msg="Found",
        headers={},
        newurl="https://example.com",
    )

    assert result is None


def test_target_reachable():
    with patch("secureflow.safety.build_opener") as mock_opener:
        response = mock_opener.return_value.open.return_value
        response.__enter__.return_value.status = 200

        status = check_target_reachable(
            "http://127.0.0.1:3000"
        )

        assert status == 200


def test_network_failure():
    from urllib.error import URLError

    with patch("secureflow.safety.build_opener") as mock_opener:
        mock_opener.return_value.open.side_effect = URLError(
            "Connection refused"
        )

        with pytest.raises(URLError):
            check_target_reachable(
                "http://127.0.0.1:3000"
            )
