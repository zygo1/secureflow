import pytest
from pydantic import ValidationError

from secureflow.models import TargetConfig
from secureflow.target_validation import validate_local_target


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.2:8080",
    "http://[::1]:8000",
])
def test_allows_loopback_on_multiple_ports(url):
    validate_local_target(url)
    target = TargetConfig(name="Local App", base_url=url)
    assert target.environment == "local-lab"


@pytest.mark.parametrize("url", [
    "http://example.com:3000",
    "https://127.0.0.1:3000",
    "http://192.168.1.10:3000",
    "http://169.254.169.254/",
    "http://localhost:3000",
    "http://127.0.0.1:bad",
    "http://127.0.0.1:3000/#fragment",
    "http://user:pass@127.0.0.1:3000",
])
def test_rejects_non_loopback_or_invalid_targets(url):
    with pytest.raises(ValueError):
        validate_local_target(url)
    with pytest.raises(ValidationError):
        TargetConfig(name="Rejected", base_url=url)


def test_reachability_rejects_external_url_before_network():
    from unittest.mock import patch

    from secureflow.safety import check_target_reachable

    with patch("secureflow.safety.build_opener") as opener:
        with pytest.raises(ValueError):
            check_target_reachable("http://example.com")
        opener.assert_not_called()


def test_zap_rejects_external_url_before_docker(tmp_path):
    from unittest.mock import patch

    from secureflow.scanners.zap import run_zap

    with patch("secureflow.scanners.zap.subprocess.run") as run:
        with pytest.raises(ValueError):
            run_zap("http://example.com", tmp_path / "zap.json")
        run.assert_not_called()
