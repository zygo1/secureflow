import json
from pathlib import Path

from secureflow.reporting.models import SecurityFinding
from secureflow.reporting.normalizer import (
    normalize_gitleaks,
    normalize_osv,
    normalize_semgrep,
    normalize_zap,
)

NORMALIZERS = {
    "semgrep": normalize_semgrep,
    "osv": normalize_osv,
    "gitleaks": normalize_gitleaks,
    "zap": normalize_zap,
}


def aggregate_findings(assessment_dir: Path) -> list[SecurityFinding]:
    metadata_path = assessment_dir / "metadata.json"

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    findings = []

    scanner_results = metadata.get("scanner_results", {})

    assessment_root = assessment_dir.resolve()

    for scanner_name, result in scanner_results.items():
        if result.get("status") != "completed":
            continue

        normalizer = NORMALIZERS.get(scanner_name)

        if normalizer is None:
            raise ValueError(f"Unsupported scanner: {scanner_name}")

        output_file = result.get("output_file")

        if not output_file:
            raise ValueError(f"Missing output file for {scanner_name}")

        report_path = (assessment_dir / output_file).resolve()

        if report_path.parent != assessment_root:
            raise ValueError(
                f"Invalid report path for scanner: {scanner_name}"
            )

        data = json.loads(report_path.read_text(encoding="utf-8"))

        findings.extend(normalizer(data))

    return findings
