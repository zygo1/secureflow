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


def test_record_scanner_failure(config):
    from secureflow.runner import record_scanner_failure, finalize_assessment

    run_dir = create_assessment(config, "juice-shop", "baseline")
    record_scanner_failure(run_dir, "osv", "RuntimeError")

    metadata = json.loads((run_dir / "metadata.json").read_text())
    assert metadata["scanner_results"]["osv"] == {
        "status": "failed",
        "error_type": "RuntimeError",
    }
    assert finalize_assessment(run_dir, failed=True) == "failed"


def test_successful_assessment(config):
    from secureflow.runner import update_scanner_result, finalize_assessment

    run_dir = create_assessment(config, "juice-shop", "baseline")
    for name in ("semgrep", "osv", "gitleaks", "zap"):
        update_scanner_result(run_dir, name, 0, f"{name}.json")

    assert finalize_assessment(run_dir) == "completed"
