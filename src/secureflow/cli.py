import shutil
import subprocess
from pathlib import Path
from urllib.error import URLError

import typer

from secureflow.config import load_config
from secureflow.runner import (
    create_assessment,
    finalize_assessment,
    finalize_reporting,
    record_scanner_failure,
    run_gitleaks_assessment,
    run_osv_assessment,
    run_semgrep_assessment,
    run_zap_assessment,
    update_scanner_result,
)
from secureflow.safety import check_target_reachable

app = typer.Typer(
    help="SecureFlow - Application Security Assessment CLI",
    no_args_is_help=True,
)

DEFAULT_CONFIG = Path("config/targets.yaml")


@app.command()
def doctor(
    config: Path = typer.Option(
        DEFAULT_CONFIG,
        "--config",
        help="Path to the configuration file.",
    ),
):
    """Check if the SecureFlow environment is ready."""

    typer.echo("SecureFlow Environment Check\n")

    try:
        load_config(str(config))
        typer.secho(
            "[PASS] Configuration valid",
            fg=typer.colors.GREEN,
        )
    except (FileNotFoundError, ValueError) as error:
        typer.secho(
            f"[FAIL] Configuration: {error}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    if shutil.which("docker") is None:
        typer.secho(
            "[FAIL] Docker not installed",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        typer.secho(
            "[PASS] Docker Compose available",
            fg=typer.colors.GREEN,
        )
    except (subprocess.SubprocessError, OSError):
        typer.secho(
            "[FAIL] Docker Compose unavailable",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    typer.secho(
        "\nEnvironment checks passed.",
        fg=typer.colors.GREEN,
    )


@app.command()
def targets(
    config: Path = typer.Option(
        DEFAULT_CONFIG,
        "--config",
        help="Path to the configuration file.",
    ),
):
    """List configured assessment targets."""

    try:
        settings = load_config(str(config))
    except (FileNotFoundError, ValueError) as error:
        typer.secho(
            f"Configuration error: {error}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    typer.echo("Configured targets:\n")

    for target_id, target in settings.targets.items():
        typer.echo(
            f"{target_id} | {target.name} | "
            f"{target.environment} | {target.base_url}"
        )


@app.command()
def scan(
    target: str = typer.Option(
        ...,
        "--target",
        help="Target ID from configuration.",
    ),
    profile: str = typer.Option(
        "baseline",
        "--profile",
        help="Scan profile ID.",
    ),
    config: Path = typer.Option(
        DEFAULT_CONFIG,
        "--config",
        help="Path to configuration file.",
    ),
):
    """Run a security assessment."""

    # ----------------------------------------
    # 1. Initialize assessment
    # ----------------------------------------

    try:
        settings = load_config(str(config))

        if target not in settings.targets:
            raise ValueError(f"Unknown target: {target}")

        if profile not in settings.profiles:
            raise ValueError(f"Unknown profile: {profile}")

        target_config = settings.targets[target]

        typer.echo(f"Checking {target_config.base_url} ...")

        status = check_target_reachable(
            str(target_config.base_url)
        )

        typer.echo(f"Target reachable (HTTP {status})")

        run_dir = create_assessment(
            config=settings,
            target_id=target,
            profile_id=profile,
        )

    except (
        FileNotFoundError,
        ValueError,
        URLError,
        TimeoutError,
    ) as error:
        typer.secho(
            f"Assessment initialization failed: {error}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    typer.secho(
        f"Assessment initialized: {run_dir}",
        fg=typer.colors.GREEN,
    )

    # ----------------------------------------
    # 2. Execute scanners
    # ----------------------------------------

    assessment_failed = True
    final_status = "failed"

    try:
        # SEMGREP
        semgrep_config = settings.profiles[profile].scanners.get(
            "semgrep"
        )

        if semgrep_config is not None and semgrep_config.enabled:
            source_path = target_config.source_path

            if not source_path:
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="semgrep",
                    error_type="ConfigurationError",
                )
                typer.secho(
                    "Semgrep requires a source_path.",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.echo("Running Semgrep SAST scan...")

            try:
                findings_count = run_semgrep_assessment(
                    source_path=Path(source_path),
                    assessment_dir=run_dir,
                )

                update_scanner_result(
                    assessment_dir=run_dir,
                    scanner_name="semgrep",
                    findings_count=findings_count,
                    output_file="semgrep.json",
                )

            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="semgrep",
                    error_type=type(error).__name__,
                )
                typer.secho(
                    f"Semgrep scan failed: {error}",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.secho(
                f"Semgrep completed: {findings_count} findings",
                fg=typer.colors.GREEN,
            )

        # OSV-SCANNER
        osv_config = settings.profiles[profile].scanners.get(
            "osv"
        )

        if osv_config is not None and osv_config.enabled:
            source_path = target_config.source_path

            if not source_path:
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="osv",
                    error_type="ConfigurationError",
                )
                typer.secho(
                    "OSV-Scanner requires a source_path.",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.echo("Running OSV-Scanner SCA scan...")

            try:
                findings_count = run_osv_assessment(
                    source_path=Path(source_path),
                    assessment_dir=run_dir,
                )

                update_scanner_result(
                    assessment_dir=run_dir,
                    scanner_name="osv",
                    findings_count=findings_count,
                    output_file="osv.json",
                )

            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="osv",
                    error_type=type(error).__name__,
                )
                typer.secho(
                    f"OSV-Scanner failed: {error}",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.secho(
                f"OSV-Scanner completed: {findings_count} findings",
                fg=typer.colors.GREEN,
            )

        # GITLEAKS
        gitleaks_config = settings.profiles[profile].scanners.get(
            "gitleaks"
        )

        if gitleaks_config is not None and gitleaks_config.enabled:
            source_path = target_config.source_path

            if not source_path:
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="gitleaks",
                    error_type="ConfigurationError",
                )
                typer.secho(
                    "Gitleaks requires a source_path.",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.echo("Running Gitleaks secret detection...")

            try:
                findings_count = run_gitleaks_assessment(
                    source_path=Path(source_path),
                    assessment_dir=run_dir,
                )

                update_scanner_result(
                    assessment_dir=run_dir,
                    scanner_name="gitleaks",
                    findings_count=findings_count,
                    output_file="gitleaks.json",
                )

            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="gitleaks",
                    error_type=type(error).__name__,
                )
                typer.secho(
                    f"Gitleaks scan failed: {error}",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.secho(
                f"Gitleaks completed: {findings_count} findings",
                fg=typer.colors.GREEN,
            )

        # OWASP ZAP
        zap_config = settings.profiles[profile].scanners.get(
            "zap"
        )

        if zap_config is not None and zap_config.enabled:
            if zap_config.mode != "passive":
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="zap",
                    error_type="ConfigurationError",
                )
                typer.secho(
                    "Only passive ZAP mode is supported.",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.echo("Running OWASP ZAP Baseline scan...")

            try:
                findings_count = run_zap_assessment(
                    target_url=str(target_config.base_url),
                    assessment_dir=run_dir,
                )

                update_scanner_result(
                    assessment_dir=run_dir,
                    scanner_name="zap",
                    findings_count=findings_count,
                    output_file="zap.json",
                )

            except (
                OSError,
                RuntimeError,
                ValueError,
                subprocess.SubprocessError,
            ) as error:
                record_scanner_failure(
                    assessment_dir=run_dir,
                    scanner_name="zap",
                    error_type=type(error).__name__,
                )
                typer.secho(
                    f"ZAP scan failed: {error}",
                    fg=typer.colors.RED,
                )
                raise typer.Exit(code=1)

            typer.secho(
                f"ZAP completed: {findings_count} alerts",
                fg=typer.colors.GREEN,
            )

        # All enabled scanners finished.
        assessment_failed = False

    
    finally:
        # Finalize assessment metadata first.
        final_status = finalize_assessment(
            assessment_dir=run_dir,
            failed=assessment_failed,
        )

        report_success, findings_count = finalize_reporting(run_dir)
        if report_success:
            typer.secho(
                f"Report generated: {findings_count} findings",
                fg=typer.colors.GREEN,
            )
        else:
            final_status = "failed"
            typer.secho(
                "Report generation failed; check assessment metadata.",
                fg=typer.colors.RED,
            )

        color = (
            typer.colors.GREEN
            if final_status == "completed"
            else typer.colors.RED
        )

        typer.secho(
            f"Assessment {final_status}: {run_dir}",
            fg=color,
        )


    if final_status != "completed":
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
