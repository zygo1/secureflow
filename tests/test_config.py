import pytest

from secureflow.config import load_config
from secureflow.models import TargetConfig


def test_load_valid_config():
    config = load_config("config/targets.yaml")

    assert config.version == 1
    assert config.targets["juice-shop"].name == "OWASP Juice Shop"
    assert config.profiles["baseline"].scanners["zap"].mode == "passive"


def test_missing_config_file():
    with pytest.raises(FileNotFoundError):
        load_config("config/does-not-exist.yaml")


def test_invalid_target_url():
    with pytest.raises(ValueError):
        TargetConfig(
            name="Unsafe Target",
            base_url="https://example.com",
            environment="local-lab",
        )


def test_invalid_scan_mode(tmp_path):
    invalid_config = """
version: 1

targets:
  juice-shop:
    name: OWASP Juice Shop
    base_url: http://127.0.0.1:3000
    environment: local-lab

profiles:
  baseline:
    scanners:
      zap:
        enabled: true
        mode: aggressive

reporting:
  formats:
    - json
  output_dir: output
"""

    config_file = tmp_path / "invalid.yaml"
    config_file.write_text(invalid_config, encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(str(config_file))


def test_unknown_target_field():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TargetConfig(
            name="OWASP Juice Shop",
            base_url="http://127.0.0.1:3000",
            environment="local-lab",
            unknown_field="unexpected",
        )


def test_empty_config_file(tmp_path):
    config_file = tmp_path / "empty.yaml"
    config_file.write_text("", encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(str(config_file))
