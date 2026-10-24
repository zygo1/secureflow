
import json
from collections import Counter
from pathlib import Path

from secureflow.reporting.markdown import escape_markdown
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
    scanner_results = metadata.get("scanner_results", {})

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
        f"**Run ID:** {escape_markdown(metadata['run_id'])}",
        f"**Target:** {escape_markdown(metadata['target_name'])}",
        f"**Profile:** {escape_markdown(metadata['profile'])}",
        f"**Status:** {escape_markdown(metadata['status'])}",
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

    # Findings grouped by scanner
    lines.extend([
        "",
        "## Scanner Breakdown",
        "",
        "| Scanner | Findings |",
        "|---------|---------:|",
    ])

    for scanner, count in sorted(scanner_counts.items()):
        lines.append(
            f"| {escape_markdown(scanner)} | {count} |"
        )

    # Scanner execution status
    lines.extend([
        "",
        "## Scanner Execution Summary",
        "",
        "| Scanner | Status |",
        "|---------|--------|",
    ])

    for scanner_name, result in sorted(scanner_results.items()):
        name = escape_markdown(scanner_name)
        status = escape_markdown(result.get("status", "unknown"))
        lines.append(f"| {name} | {status} |")

    # Detailed findings
    lines.extend([
        "",
        "## Findings",
        "",
    ])

    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### {index}. {escape_markdown(finding.title)}",
            "",
            f"- **Scanner:** {escape_markdown(finding.scanner)}",
            f"- **Severity:** {escape_markdown(finding.severity)}",
            f"- **Location:** {escape_markdown(finding.location or 'N/A')}",
            f"- **Rule ID:** {escape_markdown(finding.rule_id or 'N/A')}",
            "",
            escape_markdown(finding.description),
            "",
        ])

    # Write Markdown report
    summary_path = assessment_dir / "summary.md"
    summary_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
