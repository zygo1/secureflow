import json
from subprocess import CompletedProcess
from unittest.mock import patch

from secureflow.scanners.semgrep import run_semgrep


def test_semgrep_success(tmp_path):
    # Create a temporary source directory
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    output_path = tmp_path / "semgrep.json"

    # Fake Semgrep response
    fake_response = {
        "results": [
            {"check_id": "test-rule-1"},
            {"check_id": "test-rule-2"},
        ]
    }

    fake_process = CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(fake_response),
        stderr="",
    )

    # Replace the real subprocess.run with a mock
    with patch(
        "secureflow.scanners.semgrep.subprocess.run",
        return_value=fake_process,
    ) as mock_run:
        findings_count = run_semgrep(
            source_path=source_dir,
            output_path=output_path,
        )

    assert findings_count == 2
    assert output_path.exists()

    saved_data = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert saved_data == fake_response

    # Verify subprocess.run was called exactly once
    mock_run.assert_called_once()

    command = mock_run.call_args.args[0]

    assert command[0:3] == ["docker", "run", "--rm"]
    assert "--json" in command
    assert f"{source_dir.resolve()}:/src:ro" in command
