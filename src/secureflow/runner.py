import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from secureflow.scanners.semgrep import run_semgrep
from secureflow.models import SecureFlowConfig
from secureflow.scanners.osv import run_osv
from secureflow.scanners.gitleaks import run_gitleaks
from secureflow.scanners.zap import run_zap


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


def run_osv_assessment(
    source_path: Path,
    assessment_dir: Path,
) -> int:
    output_path = assessment_dir / "osv.json"

    findings_count = run_osv(
        source_path=source_path,
        output_path=output_path,
    )

    return findings_count


def run_gitleaks_assessment(
    source_path: Path,
    assessment_dir: Path,
) -> int:
    output_path = assessment_dir / "gitleaks.json"

    findings_count = run_gitleaks(
        source_path=source_path,
        output_path=output_path,
    )

    return findings_count


def run_zap_assessment(
    target_url: str,
    assessment_dir: Path,
) -> int:
    output_path = assessment_dir / "zap.json"

    findings_count = run_zap(
        target_url=target_url,
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


def finalize_assessment(
    assessment_dir: Path,
    failed: bool = False,
) -> str:
    metadata_path = assessment_dir / "metadata.json"

    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )

    expected_scanners = set(metadata["scanners"])
    scanner_results = metadata.get("scanner_results", {})

    all_completed = all(
        scanner_results.get(name, {}).get("status") == "completed"
        for name in expected_scanners
    )

    metadata["status"] = (
        "failed"
        if failed or not all_completed
        else "completed"
    )

    metadata["completed_at"] = (
        datetime.now(timezone.utc).isoformat()
    )

    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    return metadata["status"]
