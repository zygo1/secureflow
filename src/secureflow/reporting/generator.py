import json
from collections import Counter
from pathlib import Path

from secureflow.reporting.models import SecurityFinding


SEVERITY_ORDER = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
)


def generate_report(
    assessment_dir: Path,
    findings: list[SecurityFinding],
) -> None:
    metadata_path = assessment_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    # Machine-readable report
    findings_path = assessment_dir / "findings.json"
    findings_path.write_text(
        json.dumps(
            [finding.model_dump(mode="json") for finding in findings],
            indent=2,
        ),
        encoding="utf-8",
    )

    # Statistics
    severity_counts = Counter(
        finding.severity for finding in findings
    )
    scanner_counts = Counter(
        finding.scanner for finding in findings
    )

    lines = [
        "# SecureFlow Security Assessment",
        "",
        f"**Run ID:** {metadata['run_id']}",
        f"**Target:** {metadata['target_name']}",
        f"**Profile:** {metadata['profile']}",
        f"**Status:** {metadata['status']}",
        "",
        "## Executive Summary",
        "",
        f"**Total findings:** {len(findings)}",
        "",
        "## Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]

    for severity in SEVERITY_ORDER:
        lines.append(
            f"| {severity.capitalize()} | "
            f"{severity_counts[severity]} |"
        )

    lines.extend([
        "",
        "## Scanner Breakdown",
        "",
        "| Scanner | Findings |",
        "|---------|---------:|",
    ])

    for scanner, count in sorted(scanner_counts.items()):
        lines.append(f"| {scanner} | {count} |")

    lines.extend([
        "",
        "## Findings",
        "",
    ])

    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### {index}. {finding.title}",
            "",
            f"- **Scanner:** {finding.scanner}",
            f"- **Severity:** {finding.severity}",
            f"- **Location:** {finding.location or 'N/A'}",
            f"- **Rule ID:** {finding.rule_id or 'N/A'}",
            "",
            finding.description,
            "",
        ])

    summary_path = assessment_dir / "summary.md"
    summary_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
