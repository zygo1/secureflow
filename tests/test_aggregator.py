import json

import pytest

from secureflow.reporting.aggregator import aggregate_findings


def create_assessment(tmp_path, scanner_results):
    metadata = {"scanner_results": scanner_results}
    (tmp_path / "metadata.json").write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )
    return tmp_path


def test_aggregate_semgrep_findings(tmp_path):
    assessment_dir = create_assessment(
        tmp_path,
        {
            "semgrep": {
                "status": "completed",
                "output_file": "semgrep.json",
            }
        },
    )

    report = {
        "results": [
            {
                "check_id": "test-rule",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "message": "Potential vulnerability",
                    "severity": "ERROR",
                },
            }
        ]
    }

    (assessment_dir / "semgrep.json").write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    findings = aggregate_findings(assessment_dir)

    assert len(findings) == 1
    assert findings[0].scanner == "semgrep"
    assert findings[0].severity == "high"


def test_aggregate_skips_failed_scanners(tmp_path):
    assessment_dir = create_assessment(
        tmp_path,
        {
            "semgrep": {
                "status": "failed",
                "error_type": "RuntimeError",
            }
        },
    )

    assert aggregate_findings(assessment_dir) == []


def test_aggregate_missing_report(tmp_path):
    assessment_dir = create_assessment(
        tmp_path,
        {
            "semgrep": {
                "status": "completed",
                "output_file": "semgrep.json",
            }
        },
    )

    with pytest.raises(FileNotFoundError):
        aggregate_findings(assessment_dir)


def test_aggregate_unsupported_scanner(tmp_path):
    assessment_dir = create_assessment(
        tmp_path,
        {
            "unknown-scanner": {
                "status": "completed",
                "output_file": "unknown.json",
            }
        },
    )

    with pytest.raises(ValueError, match="Unsupported scanner"):
        aggregate_findings(assessment_dir)


def test_aggregate_invalid_json(tmp_path):
    assessment_dir = create_assessment(
        tmp_path,
        {
            "zap": {
                "status": "completed",
                "output_file": "zap.json",
            }
        },
    )

    (assessment_dir / "zap.json").write_text(
        "{invalid json}",
        encoding="utf-8",
    )

    with pytest.raises(json.JSONDecodeError):
        aggregate_findings(assessment_dir)
