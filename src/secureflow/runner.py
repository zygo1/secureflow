import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from secureflow.models import SecureFlowConfig
from secureflow.reporting.aggregator import aggregate_findings
from secureflow.reporting.generator import generate_report
from secureflow.scanners.gitleaks import run_gitleaks
from secureflow.scanners.osv import run_osv
from secureflow.scanners.semgrep import run_semgrep
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

    now = datetime.now(UTC)
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
        datetime.now(UTC).isoformat()
    )

    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    return metadata["status"]


def record_scanner_failure(
    assessment_dir: Path,
    scanner_name: str,
    error_type: str,
) -> None:
    """Record a failed scanner without persisting sensitive error output."""
    metadata_path = assessment_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    metadata.setdefault("scanner_results", {})[scanner_name] = {
        "status": "failed",
        "error_type": error_type,
    }
    metadata["status"] = "running"
    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )


def finalize_reporting(assessment_dir: Path) -> tuple[bool, int]:
    """Generate reports; record failures without exposing exception details."""
    metadata_path = assessment_dir / "metadata.json"

    try:
        findings = aggregate_findings(assessment_dir)
        generate_report(assessment_dir, findings)
    except (OSError, ValueError, TypeError, KeyError) as error:
        # Reporting can fail after scanners have completed successfully.
        # Keep the assessment status accurate and avoid logging raw data.
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["status"] = "failed"
            metadata["report_error"] = type(error).__name__
            metadata_path.write_text(
                json.dumps(metadata, indent=2), encoding="utf-8"
            )
        except (OSError, ValueError, TypeError):
            # The metadata file itself may be unwritable (e.g. disk full).
            return False, 0
        return False, 0

    return True, len(findings)
