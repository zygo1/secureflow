import json
import pytest
from secureflow.config import load_config
from secureflow.runner import create_assessment

@pytest.fixture
def config(tmp_path):
    settings = load_config("config/targets.yaml")

    settings.reporting.output_dir = str(tmp_path)

    return settings


def test_create_assessment(config):
    run_dir = create_assessment(
        config=config,
        target_id="juice-shop",
        profile_id="baseline",
    )

    assert run_dir.exists()
    assert (run_dir / "metadata.json").exists()
    assert (run_dir / "summary.md").exists()


def test_assessment_metadata(config):
    run_dir = create_assessment(
        config=config,
        target_id="juice-shop",
        profile_id="baseline",
    )

    metadata_path = run_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())

    assert metadata["target_id"] == "juice-shop"
    assert metadata["profile"] == "baseline"
    assert metadata["status"] == "initialized"
    assert metadata["findings"] == []

    assert "semgrep" in metadata["scanners"]
    assert "zap" in metadata["scanners"]


def test_unknown_target(config):
    with pytest.raises(ValueError, match="Unknown target"):
        create_assessment(
            config=config,
            target_id="unknown",
            profile_id="baseline",
        )


def test_unknown_profile(config):
    with pytest.raises(ValueError, match="Unknown profile"):
        create_assessment(
            config=config,
            target_id="juice-shop",
            profile_id="unknown",
        )


def test_unique_run_ids(config):
    first_run = create_assessment(
        config=config,
        target_id="juice-shop",
        profile_id="baseline",
    )

    second_run = create_assessment(
        config=config,
        target_id="juice-shop",
        profile_id="baseline",
    )

    assert first_run != second_run
