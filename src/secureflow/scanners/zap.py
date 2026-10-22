import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse


def run_zap(target_url: str, output_path: Path) -> int:
    parsed_url = urlparse(target_url)

    # Temporary restriction for our local Juice Shop lab.
    if (
        parsed_url.scheme != "http"
        or parsed_url.hostname != "127.0.0.1"
        or parsed_url.port != 3000
    ):
        raise ValueError("ZAP target is outside the allowed local lab")

    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists():
        raise FileExistsError(
            f"ZAP report already exists: {output_path}"
        )

    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-v",
        f"{output_path.parent}:/zap/wrk:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py",
        "-t",
        target_url,
        "-J",
        output_path.name,
        "-m",
        "1",
        "-I",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    # ZAP Baseline exit codes:
    # 0 = No findings requiring a non-zero exit
    # 1 = At least one FAIL alert
    # 2 = At least one WARN alert (unless -I is used)
    # 3 = Execution error
    if result.returncode not in (0, 1, 2):
        raise RuntimeError(
            f"ZAP failed (exit {result.returncode}): "
            f"{result.stderr[-2000:]}"
        )

    if not output_path.is_file():
        raise RuntimeError("ZAP JSON report was not created")

    try:
        data = json.loads(
            output_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "ZAP returned invalid JSON"
        ) from error

    if not isinstance(data, dict) or not isinstance(
        data.get("site"), list
    ):
        raise RuntimeError("Unexpected ZAP JSON report structure")

    findings_count = sum(
        len(site.get("alerts", []))
        for site in data["site"]
    )

    return findings_count
