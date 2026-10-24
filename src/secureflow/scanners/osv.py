
import json
import os
import subprocess
from pathlib import Path


SUPPORTED_LOCKFILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}

EXCLUDED_DIRECTORIES = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
}


def detect_lockfiles(source_path: Path) -> list[Path]:
    """Find supported lockfiles recursively, excluding generated directories."""
    lockfiles = []

    for root, directories, files in os.walk(
        source_path,
        followlinks=False,
    ):
        directories[:] = [
            directory
            for directory in directories
            if directory not in EXCLUDED_DIRECTORIES
            and not (Path(root) / directory).is_symlink()
        ]

        for filename in files:
            if filename not in SUPPORTED_LOCKFILES:
                continue

            lockfile = Path(root) / filename

            if lockfile.is_symlink():
                continue

            if lockfile.is_file():
                lockfiles.append(lockfile)

    if not lockfiles:
        raise FileNotFoundError(
            f"No supported lockfiles found in {source_path}"
        )

    return sorted(lockfiles)


def run_osv(source_path: Path, output_path: Path) -> int:
    source_path = source_path.resolve(strict=True)

    if not source_path.is_dir():
        raise ValueError("OSV source path must be a directory")

    lockfiles = detect_lockfiles(source_path)

    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{source_path}:/src:ro",
        "ghcr.io/google/osv-scanner:v2.6.0",
        "scan",
        "source",
    ]

    for lockfile in lockfiles:
        relative_path = lockfile.relative_to(source_path)
        container_path = (
            "/src/" + relative_path.as_posix()
        )

        command.append(
            f"--lockfile={container_path}"
        )

    command.append("--format=json")

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
