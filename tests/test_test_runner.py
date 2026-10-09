"""Orquestração da execução isolada de testes, com comandos Docker simulados.

Nenhum teste aqui executa Docker ou código de repositórios: ``run_limited`` é
substituído por um simulador que registra os comandos e devolve respostas
programadas.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app import test_runner
from app.analysis_report import CheckName, CheckStatus, OverallStatus
from app.process_runner import ProcessResult, ProcessTimeoutError
from app.test_runner import (
    TestCounts,
    TestExecutionSettings,
    TestRunReport,
    TestRunStatus,
    build_run_command,
    run_repository_tests,
)
from tests.test_analysis_report import build, structure_report

DOCKER = "/usr/bin/docker"
IMAGE = "codeguardian/pytest-runner:0.1.0"
ENABLED = TestExecutionSettings(enabled=True, image=IMAGE)
# tmpfs dentro do container, não um diretório do host.
CONTAINER_TMP = "/tmp"  # noqa: S108

Response = ProcessResult | Exception


def result(returncode: int = 0, stdout: bytes = b"", *, truncated: bool = False) -> ProcessResult:
    return ProcessResult(
        returncode=returncode,
        stdout=stdout,
        stderr=b"",
        stdout_truncated=truncated,
        stderr_truncated=False,
    )


class FakeDocker:
    """Simula a CLI do Docker respondendo por subcomando."""

    def __init__(self, **responses: Response) -> None:
        self.responses: dict[str, Response] = {
            "version": result(0, b"linux 29.8.2\n"),
            "image": result(0, b"sha256:abc\n"),
            "run": result(0, b"..\n2 passed in 0.10s\n"),
            "kill": result(0),
            "rm": result(0),
        }
        self.responses.update(responses)
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> ProcessResult:
        self.calls.append((command, kwargs))
        response = self.responses[command[1]]
        if isinstance(response, Exception):
            raise response
        return response

    def subcommands(self) -> list[str]:
        return [command[1] for command, _ in self.calls]

    def run_call(self) -> tuple[list[str], dict[str, Any]]:
        return next(call for call in self.calls if call[0][1] == "run")


@pytest.fixture
def fake_docker(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FakeDocker]:
    monkeypatch.setattr(test_runner.shutil, "which", lambda _name: DOCKER)

    def install(**responses: Response) -> FakeDocker:
        fake = FakeDocker(**responses)
        monkeypatch.setattr(test_runner, "run_limited", fake)
        return fake

    return install


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    (path / "tests").mkdir(parents=True)
    (path / "tests" / "test_x.py").write_text("def test_x(): pass\n", encoding="utf-8")
    return path


# --- Configuração explícita ----------------------------------------------------


def test_disabled_by_default(fake_docker: Callable[..., FakeDocker], repo: Path) -> None:
    fake = fake_docker()

    report = run_repository_tests(repo, TestExecutionSettings())

    assert report.status is TestRunStatus.DISABLED
    assert fake.calls == []


def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEGUARDIAN_TEST_EXECUTION", "enabled")
    monkeypatch.setenv("CODEGUARDIAN_TEST_IMAGE", IMAGE)

    settings = TestExecutionSettings.from_env()

    assert (settings.enabled, settings.image) == (True, IMAGE)


@pytest.mark.parametrize("value", ["", "1", "true", "yes", "ENABLED-ish"])
def test_only_explicit_value_enables(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("CODEGUARDIAN_TEST_EXECUTION", value)

    assert TestExecutionSettings.from_env().enabled is False


@pytest.mark.parametrize(
    "image",
    ["--privileged", "img --privileged", "img;rm -rf /", "-v/:/host", "Upper/case", ""],
)
def test_rejects_unsafe_image_reference(image: str) -> None:
    with pytest.raises(ValidationError):
        TestExecutionSettings(enabled=True, image=image)


@pytest.mark.parametrize(
    "kwargs",
    [{"timeout_seconds": 0}, {"memory_mb": 16}, {"pids_limit": 1}, {"cpus": 0}, {"tmpfs_mb": 1}],
)
def test_rejects_invalid_limits(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TestExecutionSettings(enabled=True, image=IMAGE, **kwargs)


# --- Ambiente seguro indisponível: etapa ignorada --------------------------------


def test_missing_image_setting(fake_docker: Callable[..., FakeDocker], repo: Path) -> None:
    fake = fake_docker()

    report = run_repository_tests(repo, TestExecutionSettings(enabled=True))

    assert report.status is TestRunStatus.SKIPPED_UNAVAILABLE
    assert "não configurada" in (report.message or "")
    assert fake.calls == []


def test_docker_not_installed(
    fake_docker: Callable[..., FakeDocker], repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_docker()
    monkeypatch.setattr(test_runner.shutil, "which", lambda _name: None)

    report = run_repository_tests(repo, ENABLED)

    assert report.status is TestRunStatus.SKIPPED_UNAVAILABLE
    assert fake.calls == []


@pytest.mark.parametrize(
    "version",
    [
        result(1, b""),  # daemon parado
        OSError("not found"),
        ProcessTimeoutError(),
        result(0, b"windows 29.8.2\n"),  # containers Windows
        result(0, b"\n"),
    ],
)
def test_daemon_unavailable(
    fake_docker: Callable[..., FakeDocker], repo: Path, version: Response
) -> None:
    fake = fake_docker(version=version)

    report = run_repository_tests(repo, ENABLED)

    assert report.status is TestRunStatus.SKIPPED_UNAVAILABLE
    assert "run" not in fake.subcommands()


def test_image_not_built(fake_docker: Callable[..., FakeDocker], repo: Path) -> None:
    fake = fake_docker(image=result(1, b""))

    report = run_repository_tests(repo, ENABLED)

    assert report.status is TestRunStatus.SKIPPED_UNAVAILABLE
    assert "Imagem" in (report.message or "")
    assert fake.subcommands() == ["version", "image"]  # nunca tenta baixar a imagem


def test_unsafe_mount_path_is_not_used(
    fake_docker: Callable[..., FakeDocker], tmp_path: Path
) -> None:
    fake = fake_docker()
    path = tmp_path / "repo,readonly=false"
    path.mkdir()

    report = run_repository_tests(path, ENABLED)

    assert report.status is TestRunStatus.SKIPPED_UNAVAILABLE
    assert fake.calls == []


# --- Isolamento do container ---------------------------------------------------


def test_run_command_isolation_flags(
    fake_docker: Callable[..., FakeDocker], repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "supersecret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "supersecret")
    fake = fake_docker()

    run_repository_tests(repo, ENABLED)

    command, kwargs = fake.run_call()
    joined = " ".join(command)
    pairs = {(command[i], command[i + 1]) for i in range(len(command) - 1)}
    assert command[:3] == [DOCKER, "run", "--rm"]
    assert {
        ("--network", "none"),
        ("--user", "65534:65534"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--pull", "never"),
        ("--cpus", "1.0"),
        ("--memory", "512m"),
        ("--memory-swap", "512m"),
        ("--pids-limit", "128"),
        ("--tmpfs", f"{CONTAINER_TMP}:rw,noexec,nosuid,nodev,size=64m"),
    } <= pairs
    assert "--read-only" in command
    mount = command[command.index("--mount") + 1]
    assert mount == f"type=bind,source={repo.resolve()},target=/workspace,readonly"
    # Nada do host além do repositório: sem socket do Docker, sem outros volumes,
    # sem privilégios extras e sem variáveis herdadas.
    for forbidden in ("docker.sock", "--privileged", "-v", "--volume", "--env-file", "host"):
        assert forbidden not in command
    assert "supersecret" not in joined
    envs = [command[i + 1] for i, arg in enumerate(command) if arg == "--env"]
    assert envs == [
        f"HOME={CONTAINER_TMP}",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
    ]
    assert all("=" in env for env in envs)  # "--env NOME" sem valor herdaria do host
    # A imagem é seguida apenas do comando do pytest; nada de pip install.
    image_index = command.index(IMAGE)
    assert command[image_index + 1 : image_index + 4] == ["python", "-m", "pytest"]
    assert "pip" not in command[image_index:]
    assert "supersecret" not in kwargs["env"].values()


def test_custom_limits_are_applied(tmp_path: Path) -> None:
    settings = TestExecutionSettings(
        enabled=True, image=IMAGE, cpus=0.5, memory_mb=256, pids_limit=64, tmpfs_mb=16
    )

    command = build_run_command(DOCKER, IMAGE, settings, tmp_path, "c1")

    pairs = {(command[i], command[i + 1]) for i in range(len(command) - 1)}
    assert {
        ("--cpus", "0.5"),
        ("--memory", "256m"),
        ("--memory-swap", "256m"),
        ("--pids-limit", "64"),
        ("--tmpfs", f"{CONTAINER_TMP}:rw,noexec,nosuid,nodev,size=16m"),
    } <= pairs


def test_container_is_always_removed(fake_docker: Callable[..., FakeDocker], repo: Path) -> None:
    fake = fake_docker()

    run_repository_tests(repo, ENABLED)

    run_command, _ = fake.run_call()
    name = run_command[run_command.index("--name") + 1]
    assert name.startswith("codeguardian-tests-")
    assert fake.calls[-1][0] == [DOCKER, "rm", "--force", name]


# --- Classificação dos resultados ----------------------------------------------


@pytest.mark.parametrize(
    ("returncode", "stdout", "status", "counts"),
    [
        (0, b"...\n3 passed, 1 skipped in 0.52s\n", TestRunStatus.PASSED, (3, 0, 0, 1)),
        (
            1,
            b"F..\n=== short test summary info ===\nFAILED t.py::a\n1 failed, 2 passed in 1.0s\n",
            TestRunStatus.FAILED,
            (2, 1, 0, 0),
        ),
        (
            2,
            b"ERROR t.py\n1 error in 0.20s\n",
            TestRunStatus.COLLECTION_ERROR,
            (0, 0, 1, 0),
        ),
        (5, b"no tests ran in 0.01s\n", TestRunStatus.NO_TESTS, (0, 0, 0, 0)),
        (3, b"INTERNALERROR>\n", TestRunStatus.PYTEST_ERROR, None),
        (4, b"ERROR: usage\n", TestRunStatus.PYTEST_ERROR, None),
        (137, b"", TestRunStatus.RESOURCE_LIMIT, None),
        (125, b"", TestRunStatus.INFRASTRUCTURE_ERROR, None),
        (127, b"", TestRunStatus.INFRASTRUCTURE_ERROR, None),
        (42, b"", TestRunStatus.INFRASTRUCTURE_ERROR, None),
    ],
)
def test_result_classification(
    fake_docker: Callable[..., FakeDocker],
    repo: Path,
    returncode: int,
    stdout: bytes,
    status: TestRunStatus,
    counts: tuple[int, int, int, int] | None,
) -> None:
    fake_docker(run=result(returncode, stdout))

    report = run_repository_tests(repo, ENABLED)

    assert report.status is status
    assert report.exit_code == returncode
    assert report.docker_version == "29.8.2"
    assert report.image == IMAGE
    if counts is None:
        assert report.counts is None
    else:
        assert report.counts is not None
        c = report.counts
        assert (c.passed, c.failed, c.errors, c.skipped) == counts


def test_timeout_kills_and_removes_container(
    fake_docker: Callable[..., FakeDocker], repo: Path
) -> None:
    fake = fake_docker(run=ProcessTimeoutError())

    report = run_repository_tests(repo, ENABLED)

    assert report.status is TestRunStatus.TIMEOUT
    run_command, _ = fake.run_call()
    name = run_command[run_command.index("--name") + 1]
    assert fake.subcommands()[-3:] == ["run", "kill", "rm"]
    assert fake.calls[-2][0] == [DOCKER, "kill", name]


def test_failure_to_start_docker(fake_docker: Callable[..., FakeDocker], repo: Path) -> None:
    fake = fake_docker(run=OSError("exec format error"))

    report = run_repository_tests(repo, ENABLED)

    assert report.status is TestRunStatus.INFRASTRUCTURE_ERROR
    assert fake.subcommands()[-1] == "rm"


def test_raw_output_is_not_kept(fake_docker: Callable[..., FakeDocker], repo: Path) -> None:
    fake_docker(run=result(1, b"secret-token-from-test-output\n1 failed in 0.1s\n"))

    report = run_repository_tests(repo, ENABLED)

    assert "secret-token" not in report.model_dump_json()


def test_truncated_output_still_uses_exit_code(
    fake_docker: Callable[..., FakeDocker], repo: Path
) -> None:
    fake_docker(run=result(1, b"F" * 100, truncated=True))

    report = run_repository_tests(repo, ENABLED)

    assert report.status is TestRunStatus.FAILED
    assert report.counts is None


def test_structure_without_tests_skips_container(
    fake_docker: Callable[..., FakeDocker], repo: Path
) -> None:
    fake = fake_docker()
    structure = structure_report().model_copy(
        update={"tests": structure_report().tests.model_copy(update={"has_tests": False})}
    )

    report = run_repository_tests(repo, ENABLED, structure=structure)

    assert report.status is TestRunStatus.NO_TESTS
    assert fake.calls == []


# --- Efeito no relatório consolidado -------------------------------------------


def make_tests_report(status: TestRunStatus, failed: int = 0) -> TestRunReport:
    counts = None
    if status in {TestRunStatus.PASSED, TestRunStatus.FAILED}:
        counts = TestCounts(passed=3, failed=failed)
    return TestRunReport(
        status=status, message=None, counts=counts, image=IMAGE, docker_version="29.8.2"
    )


def test_report_disabled_does_not_affect_result() -> None:
    report = build(tests=TestRunReport(status=TestRunStatus.DISABLED, message="desabilitada"))

    assert report.overall_status is OverallStatus.NO_ISSUES_FOUND
    assert report.approved is True
    check = next(c for c in report.checks if c.name is CheckName.TESTS)
    assert (check.status, check.tool_status) == (CheckStatus.SKIPPED, "disabled")
    assert report.errors == []


def test_report_passed_tests() -> None:
    report = build(tests=make_tests_report(TestRunStatus.PASSED))

    assert report.overall_status is OverallStatus.NO_ISSUES_FOUND
    assert report.approved is True
    assert report.finding_counts.test_failures == 0
    assert report.tools.docker == "29.8.2"


def test_report_failed_tests_are_issues() -> None:
    report = build(tests=make_tests_report(TestRunStatus.FAILED, failed=2))

    assert report.overall_status is OverallStatus.ISSUES_FOUND
    assert report.approved is False
    assert report.finding_counts.test_failures == 2


@pytest.mark.parametrize(
    "status",
    [
        TestRunStatus.SKIPPED_UNAVAILABLE,
        TestRunStatus.COLLECTION_ERROR,
        TestRunStatus.TIMEOUT,
        TestRunStatus.RESOURCE_LIMIT,
        TestRunStatus.INFRASTRUCTURE_ERROR,
    ],
)
def test_report_enabled_but_not_completed_is_incomplete(status: TestRunStatus) -> None:
    report = build(tests=TestRunReport(status=status, message="motivo"))

    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.approved is False
    assert report.finding_counts.test_failures is None


def test_report_no_tests_is_not_applicable() -> None:
    report = build(tests=TestRunReport(status=TestRunStatus.NO_TESTS))

    check = next(c for c in report.checks if c.name is CheckName.TESTS)
    assert check.status is CheckStatus.NOT_APPLICABLE
    assert report.overall_status is OverallStatus.NO_ISSUES_FOUND


def test_report_unexpected_test_runner_error() -> None:
    report = build(tests_error="Erro interno na execução isolada de testes.")

    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.errors == ["Erro interno na execução isolada de testes."]
