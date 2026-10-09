import io
import os
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app import process_runner, repository_clone
from app.repository_clone import (
    CloneFailedError,
    CloneLimits,
    CloneSizeLimitError,
    CloneTimeoutError,
    GitNotAvailableError,
    cloned_repository,
)
from app.repository_url import GitHubRepository, parse_github_repository_url

FAKE_GIT = "/usr/bin/git"
REPO = parse_github_repository_url("https://github.com/psf/requests")
FAST_LIMITS = CloneLimits(timeout_seconds=5, poll_interval_seconds=0.01)


class FakeProcess:
    """Simula ``subprocess.Popen`` sem executar o Git."""

    def __init__(
        self,
        command: list[str],
        *,
        returncode: int = 0,
        stderr: bytes = b"",
        hang: bool = False,
        on_wait: Callable[[Path], None] | None = None,
    ) -> None:
        self.destination = Path(command[-1])
        self.returncode = returncode
        self.stderr = io.BytesIO(stderr)
        self.hang = hang
        self.on_wait = on_wait
        self.killed = False
        self.pid = 4242

    def wait(self, timeout: float | None = None) -> int:
        if self.on_wait is not None:
            self.on_wait(self.destination)
        if self.killed:
            return -9
        if self.hang:
            time.sleep(min(timeout or 0, 0.01))
            raise subprocess.TimeoutExpired("git", timeout or 0)
        return self.returncode

    def kill(self) -> None:
        self.killed = True


class PopenSpy:
    def __init__(self, **process_kwargs: Any) -> None:
        self.process_kwargs = process_kwargs
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.process: FakeProcess | None = None

    def __call__(self, command: list[str], **kwargs: Any) -> FakeProcess:
        self.calls.append((command, kwargs))
        self.process = FakeProcess(command, **self.process_kwargs)
        return self.process


def write_file(destination: Path, size: int = 10, name: str = "README.md") -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / name).write_bytes(b"x" * size)


@pytest.fixture
def fake_git(monkeypatch: pytest.MonkeyPatch) -> Callable[..., PopenSpy]:
    monkeypatch.setattr(repository_clone.shutil, "which", lambda _name: FAKE_GIT)

    def install(**process_kwargs: Any) -> PopenSpy:
        spy = PopenSpy(**process_kwargs)
        monkeypatch.setattr(process_runner.subprocess, "Popen", spy)
        return spy

    return install


def assert_no_leftovers(base_dir: Path) -> None:
    assert list(base_dir.iterdir()) == []


# --- Sucesso -----------------------------------------------------------------


def test_clone_success_yields_directory_and_cleans_up(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    fake_git(on_wait=write_file)

    with cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path) as path:
        assert (path / "README.md").is_file()
        assert path.parent.parent == tmp_path
        assert path.parent.name.startswith("codeguardian-")

    assert not path.exists()
    assert_no_leftovers(tmp_path)


def test_each_clone_uses_exclusive_directory(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    fake_git(on_wait=write_file)

    with (
        cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path) as first,
        cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path) as second,
    ):
        assert first != second

    assert_no_leftovers(tmp_path)


def test_command_uses_separated_arguments_without_shell(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    spy = fake_git(on_wait=write_file)

    with cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path) as path:
        pass

    command, kwargs = spy.calls[0]
    assert isinstance(command, list)
    assert kwargs["shell"] is False
    assert command[0] == FAKE_GIT
    # "--" encerra as opções: a URL e o destino nunca são lidos como flags.
    separator = command.index("--")
    assert command[separator + 1 :] == ["https://github.com/psf/requests", str(path)]
    assert command.index("clone") < separator
    for option in ("--depth=1", "--no-recurse-submodules", "--template=", "--no-tags"):
        assert option in command[:separator]


def test_command_hardens_git_configuration(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    spy = fake_git(on_wait=write_file)

    with cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path):
        pass

    command, _ = spy.calls[0]
    configs = {command[i + 1] for i, arg in enumerate(command) if arg == "-c"}
    assert {
        "protocol.allow=never",
        "protocol.https.allow=always",
        "http.followRedirects=false",
        "credential.helper=",
        "core.symlinks=false",
        "transfer.fsckObjects=true",
    } <= configs


def test_environment_does_not_leak_secrets(
    fake_git: Callable[..., PopenSpy], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "supersecret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "supersecret")
    spy = fake_git(on_wait=write_file)

    with cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path):
        pass

    _, kwargs = spy.calls[0]
    env = kwargs["env"]
    assert "supersecret" not in env.values()
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert kwargs["stdin"] is subprocess.DEVNULL


# --- Falhas ------------------------------------------------------------------


def test_clone_failure_raises_safe_error_and_cleans_up(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    fake_git(returncode=128, stderr=b"fatal: repository 'https://github.com/x/y/' not found\n")

    with (
        pytest.raises(CloneFailedError) as exc_info,
        cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path),
    ):
        pytest.fail("o bloco não deve executar após falha de clonagem")

    assert exc_info.value.message == "Repositório não encontrado ou inacessível."
    assert "not found" in exc_info.value.detail
    assert_no_leftovers(tmp_path)


def test_unknown_failure_does_not_expose_git_output(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    fake_git(returncode=1, stderr=b"fatal: internal detail /home/server/secret-path\n")

    with (
        pytest.raises(CloneFailedError) as exc_info,
        cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path),
    ):
        pass

    assert exc_info.value.message == "Falha ao clonar o repositório."
    assert "secret-path" not in str(exc_info.value)
    assert_no_leftovers(tmp_path)


def test_git_output_is_bounded(fake_git: Callable[..., PopenSpy], tmp_path: Path) -> None:
    fake_git(returncode=1, stderr=b"A" * 1_000_000)
    limits = CloneLimits(timeout_seconds=5, poll_interval_seconds=0.01, max_output_bytes=100)

    with (
        pytest.raises(CloneFailedError) as exc_info,
        cloned_repository(REPO, limits=limits, base_dir=tmp_path),
    ):
        pass

    assert len(exc_info.value.detail) <= 100


def test_failure_to_start_git_is_handled(
    fake_git: Callable[..., PopenSpy], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_git()

    def broken_popen(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("exec format error")

    monkeypatch.setattr(process_runner.subprocess, "Popen", broken_popen)

    with (
        pytest.raises(CloneFailedError, match="iniciar o Git"),
        cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path),
    ):
        pass

    assert_no_leftovers(tmp_path)


def test_missing_git_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(repository_clone.shutil, "which", lambda _name: None)

    with (
        pytest.raises(GitNotAvailableError),
        cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path),
    ):
        pass

    assert_no_leftovers(tmp_path)


# --- Timeout e tamanho -------------------------------------------------------


def test_timeout_kills_git_and_cleans_up(fake_git: Callable[..., PopenSpy], tmp_path: Path) -> None:
    spy = fake_git(hang=True, on_wait=write_file)
    limits = CloneLimits(timeout_seconds=0.05, poll_interval_seconds=0.01)

    with (
        pytest.raises(CloneTimeoutError, match="tempo limite"),
        cloned_repository(REPO, limits=limits, base_dir=tmp_path),
    ):
        pass

    assert spy.process is not None and spy.process.killed
    assert_no_leftovers(tmp_path)


def test_size_limit_during_clone_kills_git(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    spy = fake_git(hang=True, on_wait=lambda dest: write_file(dest, size=2048))
    limits = CloneLimits(timeout_seconds=5, poll_interval_seconds=0.01, max_repository_bytes=1024)

    with (
        pytest.raises(CloneSizeLimitError),
        cloned_repository(REPO, limits=limits, base_dir=tmp_path),
    ):
        pass

    assert spy.process is not None and spy.process.killed
    assert_no_leftovers(tmp_path)


def test_size_limit_checked_after_completion(
    fake_git: Callable[..., PopenSpy], tmp_path: Path
) -> None:
    fake_git(on_wait=lambda dest: write_file(dest, size=2048))
    limits = CloneLimits(timeout_seconds=5, poll_interval_seconds=0.01, max_repository_bytes=1024)

    with (
        pytest.raises(CloneSizeLimitError),
        cloned_repository(REPO, limits=limits, base_dir=tmp_path),
    ):
        pass

    assert_no_leftovers(tmp_path)


# --- Validação da entrada e limpeza --------------------------------------------


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        ("--upload-pack=touch pwned", "repo"),
        ("psf", "-oProxyCommand=evil"),
        ("psf", "../../etc"),
        ("127.0.0.1", "repo"),
    ],
)
def test_rejects_unvalidated_repository(
    fake_git: Callable[..., PopenSpy], tmp_path: Path, owner: str, name: str
) -> None:
    spy = fake_git()
    tampered = GitHubRepository(owner=owner, name=name)

    with (
        pytest.raises(CloneFailedError, match="inválido"),
        cloned_repository(tampered, limits=FAST_LIMITS, base_dir=tmp_path),
    ):
        pass

    assert spy.calls == []
    assert_no_leftovers(tmp_path)


def test_rejects_raw_string(fake_git: Callable[..., PopenSpy], tmp_path: Path) -> None:
    spy = fake_git()

    with (
        pytest.raises(TypeError),
        cloned_repository("https://github.com/psf/requests", base_dir=tmp_path),  # type: ignore[arg-type]
    ):
        pass

    assert spy.calls == []


def test_cleans_up_when_analysis_raises(fake_git: Callable[..., PopenSpy], tmp_path: Path) -> None:
    fake_git(on_wait=write_file)

    with (
        pytest.raises(RuntimeError, match="analysis failed"),
        cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path),
    ):
        raise RuntimeError("analysis failed")

    assert_no_leftovers(tmp_path)


def test_cleans_up_read_only_files(fake_git: Callable[..., PopenSpy], tmp_path: Path) -> None:
    def create_read_only_object(destination: Path) -> None:
        objects = destination / ".git" / "objects" / "ab"
        objects.mkdir(parents=True, exist_ok=True)
        target = objects / "cdef"
        target.write_bytes(b"blob")
        target.chmod(stat.S_IREAD)

    fake_git(on_wait=create_read_only_object)

    with cloned_repository(REPO, limits=FAST_LIMITS, base_dir=tmp_path):
        pass

    assert_no_leftovers(tmp_path)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        {"timeout_seconds": 10_000},
        {"max_repository_bytes": 0},
        {"max_output_bytes": -5},
    ],
)
def test_clone_limits_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CloneLimits(**kwargs)
