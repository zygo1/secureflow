from pathlib import Path
import shutil
import subprocess
import typer
from secureflow.config import load_config
from urllib.error import URLError
from secureflow.safety import check_target_reachable
from secureflow.runner import create_assessment

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
        typer.secho("[PASS] Configuration valid", fg=typer.colors.GREEN)
    except (FileNotFoundError, ValueError) as error:
        typer.secho(f"[FAIL] Configuration: {error}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if shutil.which("docker") is None:
        typer.secho("[FAIL] Docker not installed", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        typer.secho("[PASS] Docker Compose available", fg=typer.colors.GREEN)
    except (subprocess.SubprocessError, OSError):
        typer.secho("[FAIL] Docker Compose unavailable", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho("\nEnvironment checks passed.", fg=typer.colors.GREEN)


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
        typer.secho(f"Configuration error: {error}", fg=typer.colors.RED)
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
    """Initialize a security assessment run."""

    try:
        settings = load_config(str(config))

        if target not in settings.targets:
            raise ValueError(f"Unknown target: {target}")

        if profile not in settings.profiles:
            raise ValueError(f"Unknown profile: {profile}")

        target_config = settings.targets[target]

        typer.echo(f"Checking {target_config.base_url} ...")

        status = check_target_reachable(str(target_config.base_url))
        typer.echo(f"Target reachable (HTTP {status})")

        run_dir = create_assessment(
            config=settings,
            target_id=target,
            profile_id=profile,
        )

    except (FileNotFoundError, ValueError, URLError, TimeoutError) as error:
        typer.secho(
            f"Assessment initialization failed: {error}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    typer.secho(
        f"Assessment initialized: {run_dir}",
        fg=typer.colors.GREEN,
    )


if __name__ == "__main__":
    app()
