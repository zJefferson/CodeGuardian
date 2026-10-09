"""Execução opcional e isolada dos testes de um repositório com pytest.

O código do repositório (testes, ``conftest.py``, módulos importados) só é
executado dentro de um container descartável; nunca no processo da API. Se não
houver ambiente isolado disponível, a etapa é ignorada; não existe alternativa
de execução local.

Controles do container (ver ``docs/testes-isolados.md``):
sem rede, sistema de arquivos somente leitura (repositório montado ``readonly``
e ``/tmp`` em tmpfs limitado), usuário sem privilégios, sem capabilities, com
``no-new-privileges``, limites de CPU, memória, processos e tempo, nenhuma
variável de ambiente ou volume do host além do repositório, e nenhuma imagem
baixada ou dependência instalada durante a execução.
"""

import logging
import os
import re
import shutil
import uuid
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.process_runner import ProcessResult, ProcessTimeoutError, minimal_env, run_limited
from app.structure_analyzer import StructureReport

logger = logging.getLogger(__name__)

ENV_ENABLED = "CODEGUARDIAN_TEST_EXECUTION"
ENV_IMAGE = "CODEGUARDIAN_TEST_IMAGE"

_CONTAINER_USER = "65534:65534"  # nobody
_CONTAINER_WORKDIR = "/workspace"
# tmpfs dentro do container (não é um diretório do host).
_CONTAINER_TMP = "/tmp"  # noqa: S108
_CONTAINER_LABEL = "codeguardian.role=test-runner"
_DOCKER_COMMAND_TIMEOUT = 30
# Referência de imagem: sem espaços e sem começar com "-" (não vira opção).
# Âncoras explícitas: o "pattern" do Pydantic procura em qualquer posição.
_IMAGE_REFERENCE = r"^[a-z0-9][A-Za-z0-9._/:@-]{0,254}$"
# Variáveis que a CLI do Docker usa para encontrar o daemon. São passadas
# apenas ao processo da CLI no host, nunca ao container.
_DOCKER_CLI_ENV_VARS = (
    "USERPROFILE",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
)
_SUMMARY_LINE = re.compile(r"\bin [0-9.]+s\b")
_SUMMARY_COUNT = re.compile(
    r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed|deselected|warnings?)"
)


class TestExecutionSettings(BaseModel):
    """Configuração da execução isolada. Desabilitada por padrão."""

    __test__ = False  # não é uma classe de teste do pytest
    model_config = ConfigDict(frozen=True)

    enabled: bool = False
    image: str | None = Field(default=None, pattern=_IMAGE_REFERENCE)
    timeout_seconds: float = Field(default=300.0, gt=0, le=1800)
    cpus: float = Field(default=1.0, gt=0, le=8)
    memory_mb: int = Field(default=512, ge=64, le=8192)
    pids_limit: int = Field(default=128, ge=16, le=4096)
    tmpfs_mb: int = Field(default=64, ge=8, le=1024)
    max_output_bytes: int = Field(default=1024 * 1024, gt=0)

    @classmethod
    def from_env(cls) -> "TestExecutionSettings":
        """Lê a configuração explícita das variáveis de ambiente."""
        return cls(
            enabled=os.environ.get(ENV_ENABLED, "").strip().lower() == "enabled",
            image=os.environ.get(ENV_IMAGE, "").strip() or None,
        )


class TestRunStatus(StrEnum):
    __test__ = False  # não é uma classe de teste do pytest

    DISABLED = "disabled"  # não configurado: etapa opcional desligada
    SKIPPED_UNAVAILABLE = "skipped_unavailable"  # sem ambiente isolado
    NO_TESTS = "no_tests"  # ausência de testes
    PASSED = "passed"
    FAILED = "failed"  # testes reprovados
    COLLECTION_ERROR = "collection_error"  # ex.: dependências ausentes no container
    PYTEST_ERROR = "pytest_error"  # erro interno/uso do pytest (config do repositório)
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"  # container encerrado (ex.: memória)
    INFRASTRUCTURE_ERROR = "infrastructure_error"  # falha do Docker/ambiente


class TestCounts(BaseModel):
    __test__ = False

    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    xfailed: int = 0
    xpassed: int = 0


class TestRunReport(BaseModel):
    """Resultado da execução. A saída bruta do pytest não é incluída."""

    __test__ = False

    status: TestRunStatus
    message: str | None = None
    exit_code: int | None = None
    counts: TestCounts | None = None
    image: str | None = None
    docker_version: str | None = None


# Códigos de saída do pytest e do Docker.
_EXIT_STATUS = {
    0: TestRunStatus.PASSED,
    1: TestRunStatus.FAILED,
    2: TestRunStatus.COLLECTION_ERROR,
    3: TestRunStatus.PYTEST_ERROR,
    4: TestRunStatus.PYTEST_ERROR,
    5: TestRunStatus.NO_TESTS,
    125: TestRunStatus.INFRASTRUCTURE_ERROR,  # docker run falhou
    126: TestRunStatus.INFRASTRUCTURE_ERROR,  # comando não executável
    127: TestRunStatus.INFRASTRUCTURE_ERROR,  # comando não encontrado
    137: TestRunStatus.RESOURCE_LIMIT,  # SIGKILL (ex.: falta de memória)
}

_MESSAGES = {
    TestRunStatus.PASSED: None,
    TestRunStatus.FAILED: "Há testes reprovados.",
    TestRunStatus.COLLECTION_ERROR: (
        "Erro ao coletar os testes; provavelmente faltam dependências do projeto, "
        "que não são instaladas no ambiente isolado."
    ),
    TestRunStatus.PYTEST_ERROR: "O pytest terminou com erro de uso ou erro interno.",
    TestRunStatus.NO_TESTS: "Nenhum teste foi coletado.",
    TestRunStatus.RESOURCE_LIMIT: "O container foi encerrado por exceder limites de recursos.",
    TestRunStatus.INFRASTRUCTURE_ERROR: "Falha no ambiente isolado de execução.",
}


class _Unavailable(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def run_repository_tests(
    repository_path: Path,
    settings: TestExecutionSettings,
    *,
    structure: StructureReport | None = None,
) -> TestRunReport:
    """Executa os testes de ``repository_path`` em um container isolado."""
    if not settings.enabled:
        return TestRunReport(
            status=TestRunStatus.DISABLED, message="Execução de testes desabilitada."
        )
    if structure is not None and structure.complete and not structure.tests.has_tests:
        return TestRunReport(
            status=TestRunStatus.NO_TESTS, message=_MESSAGES[TestRunStatus.NO_TESTS]
        )

    try:
        docker, image, docker_version = _check_environment(settings, repository_path)
    except _Unavailable as exc:
        return TestRunReport(
            status=TestRunStatus.SKIPPED_UNAVAILABLE, message=exc.message, image=settings.image
        )

    container = f"codeguardian-tests-{uuid.uuid4().hex[:12]}"
    command = build_run_command(docker, image, settings, Path(repository_path), container)
    try:
        result = run_limited(
            command,
            cwd=Path(repository_path),
            env=_docker_cli_env(),
            timeout_seconds=settings.timeout_seconds,
            max_output_bytes=settings.max_output_bytes,
            capture_stdout=True,
        )
    except ProcessTimeoutError:
        # Encerrar o cliente não encerra o container: é preciso matá-lo.
        _docker_quiet(docker, ["kill", container])
        return _report(
            TestRunStatus.TIMEOUT,
            settings,
            docker_version,
            message="Os testes excederam o tempo limite.",
        )
    except OSError:
        return _report(
            TestRunStatus.INFRASTRUCTURE_ERROR,
            settings,
            docker_version,
            message="Não foi possível iniciar o Docker.",
        )
    finally:
        _docker_quiet(docker, ["rm", "--force", container])

    status = _EXIT_STATUS.get(result.returncode, TestRunStatus.INFRASTRUCTURE_ERROR)
    counts = _parse_counts(result)
    return _report(status, settings, docker_version, exit_code=result.returncode, counts=counts)


def build_run_command(
    docker: str,
    image: str,
    settings: TestExecutionSettings,
    repository_path: Path,
    container: str,
) -> list[str]:
    """Monta o ``docker run`` com todos os controles de isolamento."""
    source = str(repository_path.resolve())
    return [
        docker,
        "run",
        "--rm",
        "--name",
        container,
        "--label",
        _CONTAINER_LABEL,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        _CONTAINER_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--init",
        "--cpus",
        str(settings.cpus),
        "--memory",
        f"{settings.memory_mb}m",
        "--memory-swap",
        f"{settings.memory_mb}m",
        "--pids-limit",
        str(settings.pids_limit),
        "--ulimit",
        "nofile=256:256",
        "--tmpfs",
        f"{_CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={settings.tmpfs_mb}m",
        "--mount",
        f"type=bind,source={source},target={_CONTAINER_WORKDIR},readonly",
        "--workdir",
        _CONTAINER_WORKDIR,
        # Somente variáveis com valor explícito: nada é herdado do host.
        "--env",
        f"HOME={_CONTAINER_TMP}",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        image,
        "python",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        "--color=no",
        # Ignora addopts do repositório (ex.: plugins não instalados na imagem).
        "-o",
        "addopts=",
        f"--basetemp={_CONTAINER_TMP}/pytest",
        "--rootdir",
        _CONTAINER_WORKDIR,
    ]


def _check_environment(
    settings: TestExecutionSettings, repository_path: Path
) -> tuple[str, str, str]:
    """Retorna (docker, imagem, versão do servidor) ou lança ``_Unavailable``."""
    if settings.image is None:
        raise _Unavailable(f"Imagem de execução não configurada ({ENV_IMAGE}).")
    docker = shutil.which("docker")
    if docker is None:
        raise _Unavailable("Docker não encontrado no servidor.")
    # "," e "=" alterariam as opções de --mount.
    if any(char in str(Path(repository_path).resolve()) for char in ",="):
        raise _Unavailable("Caminho do repositório incompatível com montagem segura.")

    info = _docker(docker, ["version", "--format", "{{.Server.Os}} {{.Server.Version}}"])
    if info is None or info.returncode != 0:
        raise _Unavailable("O daemon do Docker não está disponível.")
    server = info.stdout.decode("utf-8", errors="replace").strip().split()
    if len(server) != 2 or server[0] != "linux":
        raise _Unavailable("O Docker não está em modo de containers Linux.")

    image = _docker(docker, ["image", "inspect", "--format", "{{.Id}}", settings.image])
    if image is None or image.returncode != 0:
        raise _Unavailable("Imagem de execução não encontrada localmente; construa-a antes.")
    return docker, settings.image, server[1][:64]


def _docker(docker: str, args: list[str]) -> ProcessResult | None:
    try:
        return run_limited(
            [docker, *args],
            cwd=Path.cwd(),
            env=_docker_cli_env(),
            timeout_seconds=_DOCKER_COMMAND_TIMEOUT,
            max_output_bytes=4096,
            capture_stdout=True,
        )
    except (OSError, ProcessTimeoutError):
        return None


def _docker_quiet(docker: str, args: list[str]) -> None:
    result = _docker(docker, args)
    if result is None:
        logger.warning("Comando docker %s não concluído.", args[0])


def _docker_cli_env() -> dict[str, str]:
    return minimal_env(
        {name: os.environ[name] for name in _DOCKER_CLI_ENV_VARS if name in os.environ}
    )


def _parse_counts(result: ProcessResult) -> TestCounts | None:
    """Lê as contagens da linha final de resumo do pytest, se houver."""
    text = result.stdout.decode("utf-8", errors="replace")
    summary = next(
        (line for line in reversed(text.splitlines()) if _SUMMARY_LINE.search(line)), None
    )
    if summary is None:
        return None
    counts = TestCounts()
    for number, kind in _SUMMARY_COUNT.findall(summary):
        field = {"error": "errors", "errors": "errors"}.get(kind, kind)
        if field in TestCounts.model_fields:
            setattr(counts, field, int(number))
    return counts


def _report(
    status: TestRunStatus,
    settings: TestExecutionSettings,
    docker_version: str,
    *,
    message: str | None = None,
    exit_code: int | None = None,
    counts: TestCounts | None = None,
) -> TestRunReport:
    return TestRunReport(
        status=status,
        message=message or _MESSAGES.get(status),
        exit_code=exit_code,
        counts=counts,
        image=settings.image,
        docker_version=docker_version,
    )
