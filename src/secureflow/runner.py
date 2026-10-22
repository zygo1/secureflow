import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from secureflow.scanners.semgrep import run_semgrep
from secureflow.models import SecureFlowConfig


def create_assessment(
    config: SecureFlowConfig,
    target_id: str,
    profile_id: str,
) -> Path:

    if target_id not in config.targets:
        raise ValueError(f"Unknown target: {target_id}")

    if profile_id not in config.profiles:
        raise ValueError(f"Unknown profile: {profile_id}")

    target = config.targets[target_id]
    profile = config.profiles[profile_id]

    now = datetime.now(timezone.utc)
    run_id = f"{now:%Y%m%dT%H%M%SZ}-{uuid4().hex[:8]}"

    output_dir = Path(config.reporting.output_dir)
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    metadata = {
        "run_id": run_id,
        "created_at": now.isoformat(),
        "target_id": target_id,
        "target_name": target.name,
        "target_url": str(target.base_url),
        "profile": profile_id,
        "status": "initialized",
        "scanners": [
            name
            for name, scanner in profile.scanners.items()
            if scanner.enabled
        ],
        "findings": [],
    }

    metadata_path = run_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    summary = f"""# SecureFlow Assessment

**Run ID:** {run_id}

**Target:** {target.name}

**URL:** {target.base_url}

**Profile:** {profile_id}

**Status:** Initialized

No security scans have been executed yet.
"""

    (run_dir / "summary.md").write_text(
        summary,
        encoding="utf-8",
    )

    return run_dir


def run_semgrep_assessment(
    source_path: Path,
    assessment_dir: Path,
) -> int:
    output_path = assessment_dir / "semgrep.json"

    findings_count = run_semgrep(
        source_path=source_path,
        output_path=output_path,
    )

    return findings_count


def update_scanner_result(
    assessment_dir: Path,
    scanner_name: str,
    findings_count: int,
    output_file: str,
) -> None:
    metadata_path = assessment_dir / "metadata.json"

    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )

    metadata.setdefault("scanner_results", {})[scanner_name] = {
        "status": "completed",
        "findings_count": findings_count,
        "output_file": output_file,
    }

    metadata["status"] = "running"

    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )
