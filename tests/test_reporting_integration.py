import json

from secureflow.reporting.aggregator import aggregate_findings
from secureflow.reporting.generator import generate_report
from secureflow.reporting.models import SecurityFinding


def test_generated_report_escapes_untrusted_markdown(tmp_path):
    metadata = {
        "run_id": "test-run",
        "target_name": "Test Application",
        "profile": "baseline",
        "status": "completed",
    }

    (tmp_path / "metadata.json").write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    finding = SecurityFinding(
        scanner="semgrep",
        title="SQL Injection\n\n## Assessment Passed",
        severity="high",
        description="<script>alert('XSS')</script>",
        location="src/app.py:42",
    )

    generate_report(tmp_path, [finding])

    report = (tmp_path / "summary.md").read_text(
        encoding="utf-8",
    )

    assert "## Assessment Passed\n" not in report
    assert r"\#\# Assessment Passed" in report
    assert "<script>" not in report
    assert "&lt;script&gt;" in report


def test_gitleaks_secret_not_exposed_in_generated_reports(tmp_path):
    secret = "SUPER_SECRET_TEST_VALUE_12345"

    metadata = {
        "run_id": "test-run",
        "target_name": "Test Application",
        "profile": "baseline",
        "status": "completed",
        "scanner_results": {
            "gitleaks": {
                "status": "completed",
                "output_file": "gitleaks.json",
            }
        },
    }

    (tmp_path / "metadata.json").write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    raw_report = [
        {
            "Description": "Generic API Key",
            "File": "src/config.py",
            "StartLine": 12,
            "RuleID": "generic-api-key",
            "Secret": secret,
        }
    ]

    (tmp_path / "gitleaks.json").write_text(
        json.dumps(raw_report),
        encoding="utf-8",
    )

    findings = aggregate_findings(tmp_path)
    generate_report(tmp_path, findings)

    findings_json = (tmp_path / "findings.json").read_text(
        encoding="utf-8"
    )
    summary_md = (tmp_path / "summary.md").read_text(
        encoding="utf-8"
    )

    assert len(findings) == 1
    assert secret not in findings_json
    assert secret not in summary_md

    assert "Generic API Key" in summary_md
    assert r"src/config\.py:12" in summary_md



def test_report_includes_failed_scanners(tmp_path):
    metadata = {
        "run_id": "test-run",
        "target_name": "Test Application",
        "profile": "baseline",
        "status": "failed",
        "scanner_results": {
            "semgrep": {
                "status": "completed",
                "output_file": "semgrep.json",
            },
            "zap": {
                "status": "failed",
                "error_type": "TimeoutExpired",
            },
        },
    }

    (tmp_path / "metadata.json").write_text(
        json.dumps(metadata),
        encoding="utf-8",
    )

    generate_report(tmp_path, [])

    report = (tmp_path / "summary.md").read_text(
        encoding="utf-8",
    )

    assert "## Scanner Execution Summary" in report
    assert "| semgrep | completed |" in report
    assert "| zap | failed |" in report
    assert "**Status:** failed" in report
