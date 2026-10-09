import sys
import time
from pathlib import Path

import pytest

from app.process_runner import (
    ProcessAbortedError,
    ProcessTimeoutError,
    minimal_env,
    run_limited,
)

# Subprocessos Python controlados pelo teste (nenhum código de terceiros).
PYTHON = sys.executable


def run(code: str, tmp_path: Path, **kwargs: object) -> object:
    options: dict[str, object] = {
        "cwd": tmp_path,
        "env": minimal_env(),
        "timeout_seconds": 10,
        "max_output_bytes": 1024,
        "poll_interval_seconds": 0.05,
    }
    options.update(kwargs)
    return run_limited([PYTHON, "-I", "-c", code], **options)  # type: ignore[arg-type]


def test_captures_stdout_stderr_and_returncode(tmp_path: Path) -> None:
    code = "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"

    result = run(code, tmp_path, capture_stdout=True)

    assert result.returncode == 3  # type: ignore[attr-defined]
    assert result.stdout.strip() == b"out"  # type: ignore[attr-defined]
    assert result.stderr_text == "err"  # type: ignore[attr-defined]


def test_stdout_not_captured_by_default(tmp_path: Path) -> None:
    result = run("print('out')", tmp_path)

    assert result.stdout == b""  # type: ignore[attr-defined]
    assert result.stdout_truncated is False  # type: ignore[attr-defined]


def test_output_is_bounded(tmp_path: Path) -> None:
    code = "import sys; sys.stdout.write('A' * 200000); sys.stderr.write('B' * 200000)"

    result = run(code, tmp_path, capture_stdout=True, max_output_bytes=100)

    assert result.returncode == 0  # type: ignore[attr-defined]
    assert result.stdout == b"A" * 100  # type: ignore[attr-defined]
    assert result.stderr == b"B" * 100  # type: ignore[attr-defined]
    assert result.stdout_truncated is True  # type: ignore[attr-defined]
    assert result.stderr_truncated is True  # type: ignore[attr-defined]


def test_timeout_kills_process(tmp_path: Path) -> None:
    started = time.monotonic()

    with pytest.raises(ProcessTimeoutError):
        run("import time; time.sleep(30)", tmp_path, timeout_seconds=0.3)

    assert time.monotonic() - started < 10


def test_abort_check_kills_process(tmp_path: Path) -> None:
    with pytest.raises(ProcessAbortedError):
        run("import time; time.sleep(30)", tmp_path, abort_check=lambda: True)


def test_environment_is_minimal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "supersecret")
    code = "import os; print(os.environ.get('GITHUB_TOKEN', 'absent'), os.environ['EXTRA'])"

    result = run(code, tmp_path, capture_stdout=True, env=minimal_env({"EXTRA": "ok"}))

    assert result.stdout.split() == [b"absent", b"ok"]  # type: ignore[attr-defined]


def test_minimal_env_only_inherits_allowed_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "supersecret")

    env = minimal_env()

    assert set(env) <= {"PATH", "SYSTEMROOT"}


def test_start_failure_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        run_limited(
            [str(tmp_path / "does-not-exist.exe")],
            cwd=tmp_path,
            env=minimal_env(),
            timeout_seconds=5,
            max_output_bytes=10,
        )
