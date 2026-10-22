import json
import subprocess
from pathlib import Path


def run_semgrep(source_path: Path, output_path: Path) -> int:
    source_path = source_path.resolve(strict=True)

    if not source_path.is_dir():
        raise ValueError("Semgrep source path must be a directory")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{source_path}:/src:ro",
        "semgrep/semgrep:latest",
        "semgrep",
        "scan",
        "--config",
        "p/owasp-top-ten",
        "--json",
        "/src",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Semgrep failed (exit {result.returncode}): "
            f"{result.stderr[-2000:]}"
        )

    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Semgrep returned invalid JSON"
        ) from error

    output_path.write_text(
        json.dumps(findings, indent=2),
        encoding="utf-8",
    )

    return len(findings.get("results", []))
