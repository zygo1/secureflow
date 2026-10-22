import json
import subprocess
from pathlib import Path


def run_osv(source_path: Path, output_path: Path) -> int:
    source_path = source_path.resolve(strict=True)

    lockfile = source_path / "package-lock.json"

    if not lockfile.is_file():
        raise FileNotFoundError(
            f"package-lock.json not found: {lockfile}"
        )

    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{source_path}:/src:ro",
        "ghcr.io/google/osv-scanner:v2.6.0",
        "scan",
        "source",
        "--lockfile=/src/package-lock.json",
        "--format=json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    # OSV-Scanner can return 1 when vulnerabilities are found.
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"OSV-Scanner failed (exit {result.returncode}): "
            f"{result.stderr[-2000:]}"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "OSV-Scanner returned invalid JSON"
        ) from error

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    # Count individual vulnerability entries.
    findings_count = 0

    for result_group in data.get("results", []):
        for package in result_group.get("packages", []):
            findings_count += len(
                package.get("vulnerabilities", [])
            )

    return findings_count
