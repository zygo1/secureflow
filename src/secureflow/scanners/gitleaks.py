import json
import subprocess
from pathlib import Path


def run_gitleaks(source_path: Path, output_path: Path) -> int:
    source_path = source_path.resolve(strict=True)
    output_path = output_path.resolve()

    if not source_path.is_dir():
        raise ValueError("Gitleaks source path must be a directory")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "docker",
        "run",
        "--rm",
        "--mount",
        f"type=bind,source={source_path},target=/src,readonly",
        "--mount",
        f"type=bind,source={output_path.parent},target=/reports",
        "ghcr.io/gitleaks/gitleaks:v8.24.3",
        "dir",
        "/src",
        "--report-format",
        "json",
        "--report-path",
        "/reports/gitleaks.json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    # Exit 0: No secrets found
    # Exit 1: Potential secrets found
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Gitleaks failed (exit {result.returncode}): "
            f"{result.stderr[-2000:]}"
        )

    report_path = output_path.parent / "gitleaks.json"

    # Gitleaks may not create a report when no findings exist.
    if not report_path.exists() and result.returncode == 0:
        report_path.write_text("[]", encoding="utf-8")

    if not report_path.exists():
        raise RuntimeError("Gitleaks report was not created")

    try:
        findings = json.loads(
            report_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Gitleaks returned invalid JSON"
        ) from error

    if not isinstance(findings, list):
        raise RuntimeError("Unexpected Gitleaks report format")

    if report_path != output_path:
        output_path.write_text(
            json.dumps(findings, indent=2),
            encoding="utf-8",
        )
        report_path.unlink()

    return len(findings)
