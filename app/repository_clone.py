"""Clonagem controlada de repositórios previamente validados.

O conteúdo clonado é tratado como dado não confiável: nenhum código do
repositório é executado e nenhuma dependência é instalada. Os riscos restantes
e os controles exigidos para implantação pública estão em ``docs/clonagem.md``.
"""

import logging
import os
import shutil
import stat
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.process_runner import (
    ProcessAbortedError,
    ProcessTimeoutError,
    minimal_env,
    run_limited,
)
from app.repository_url import (
    GitHubRepository,
    InvalidRepositoryURLError,
    parse_github_repository_url,
)

logger = logging.getLogger(__name__)

_WORKDIR_PREFIX = "codeguardian-"
_CLONE_DIRNAME = "repo"

# Configurações aplicadas via "-c", com precedência sobre qualquer outra fonte.
_GIT_CONFIG: tuple[tuple[str, str], ...] = (
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("http.followRedirects", "false"),
    ("credential.helper", ""),
    ("core.askPass", ""),
    ("core.symlinks", "false"),
    ("core.protectNTFS", "true"),
    ("core.protectHFS", "true"),
    ("core.fsmonitor", "false"),
    ("transfer.fsckObjects", "true"),
    ("submodule.recurse", "false"),
)


class CloneLimits(BaseModel):
    """Limites aplicados a uma clonagem."""

    model_config = ConfigDict(frozen=True)

    timeout_seconds: float = Field(default=120.0, gt=0, le=900)
    max_repository_bytes: int = Field(default=200 * 1024 * 1024, gt=0)
    max_output_bytes: int = Field(default=64 * 1024, gt=0)
    poll_interval_seconds: float = Field(default=0.5, gt=0)


class CloneError(Exception):
    """Falha de clonagem. ``message`` é segura para exibir ao usuário.

    ``detail`` guarda a saída de erro do Git (limitada) para diagnóstico em logs;
    não deve ser repassada ao usuário.
    """

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class GitNotAvailableError(CloneError):
    """O executável do Git não foi encontrado."""


class CloneFailedError(CloneError):
    """O Git terminou com erro ou não pôde ser iniciado."""


class CloneTimeoutError(CloneError):
    """A clonagem excedeu o tempo limite."""


class CloneSizeLimitError(CloneError):
    """O repositório excedeu o tamanho máximo permitido."""


@contextmanager
def cloned_repository(
    repository: GitHubRepository,
    *,
    limits: CloneLimits | None = None,
    base_dir: Path | None = None,
) -> Iterator[Path]:
    """Clona ``repository`` em um diretório temporário exclusivo.

    O diretório é removido ao sair do bloco ``with``, inclusive em caso de erro::

        with cloned_repository(repo) as path:
            ...  # analisar arquivos em ``path`` sem executá-los

    Raises:
        CloneError: se a clonagem não puder ser concluída.
    """
    limits = limits or CloneLimits()
    url = _trusted_clone_url(repository)
    git = shutil.which("git")
    if git is None:
        raise GitNotAvailableError("O Git não está disponível no servidor.")

    workdir = Path(tempfile.mkdtemp(prefix=_WORKDIR_PREFIX, dir=base_dir))
    try:
        destination = workdir / _CLONE_DIRNAME
        _clone(git, url, destination, workdir, limits)
        yield destination
    finally:
        _remove_tree(workdir)


def _trusted_clone_url(repository: GitHubRepository) -> str:
    """Revalida o repositório.

    ``GitHubRepository`` pode ser instanciado diretamente sem passar pela
    validação de URL; revalidar garante que owner/nome não carregam opções
    de linha de comando ou caminhos inesperados.
    """
    if not isinstance(repository, GitHubRepository):
        raise TypeError("repository deve ser um GitHubRepository.")
    try:
        validated = parse_github_repository_url(repository.url)
    except InvalidRepositoryURLError as exc:
        raise CloneFailedError("O repositório informado é inválido.") from exc
    if validated != repository:
        raise CloneFailedError("O repositório informado é inválido.")
    return validated.url


def _build_command(git: str, url: str, destination: Path) -> list[str]:
    config = list(_GIT_CONFIG)
    if os.name == "nt":
        # O backend TLS do Git for Windows vem da configuração de sistema, que é
        # ignorada; schannel usa o repositório de certificados do Windows.
        config.append(("http.sslBackend", "schannel"))
    command = [git]
    for key, value in config:
        command += ["-c", f"{key}={value}"]
    command += [
        "clone",
        "--quiet",
        "--depth=1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--template=",
        "--",
        url,
        str(destination),
    ]
    return command


def _build_env(home: Path) -> dict[str, str]:
    return minimal_env(
        {
            # Ignora configurações de sistema e do usuário (ex.: credential.helper).
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "HOME": str(home),
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "LC_ALL": "C",
        }
    )


def _clone(git: str, url: str, destination: Path, workdir: Path, limits: CloneLimits) -> None:
    command = _build_command(git, url, destination)
    try:
        result = run_limited(
            command,
            cwd=workdir,
            env=_build_env(workdir),
            timeout_seconds=limits.timeout_seconds,
            max_output_bytes=limits.max_output_bytes,
            poll_interval_seconds=limits.poll_interval_seconds,
            abort_check=lambda: _directory_size(destination) > limits.max_repository_bytes,
        )
    except OSError as exc:
        raise CloneFailedError("Não foi possível iniciar o Git.") from exc
    except ProcessTimeoutError:
        raise CloneTimeoutError("A clonagem excedeu o tempo limite.") from None
    except ProcessAbortedError:
        raise CloneSizeLimitError("O repositório excede o tamanho máximo permitido.") from None

    if result.returncode != 0:
        detail = result.stderr_text
        raise CloneFailedError(_failure_message(detail), detail=detail)
    if _directory_size(destination) > limits.max_repository_bytes:
        raise CloneSizeLimitError("O repositório excede o tamanho máximo permitido.")


def _failure_message(stderr: str) -> str:
    lowered = stderr.lower()
    if "not found" in lowered or "could not read username" in lowered:
        return "Repositório não encontrado ou inacessível."
    if "redirect" in lowered:
        return "O repositório redireciona para outro endereço; informe a URL atual."
    if "could not resolve host" in lowered or "unable to access" in lowered:
        return "Não foi possível conectar ao GitHub."
    return "Falha ao clonar o repositório."


def _directory_size(path: Path) -> int:
    """Soma o tamanho dos arquivos sem seguir links simbólicos."""
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue  # diretório ainda não criado ou removido durante a clonagem
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                else:
                    total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    return total


def _remove_tree(path: Path, attempts: int = 3) -> None:
    """Remove ``path`` sem propagar erros, para não mascarar a exceção original."""

    def make_writable_and_retry(func: Callable[[str], object], target: str, _exc: object) -> None:
        # Objetos do Git são somente leitura; no Windows isso impede a remoção.
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        func(target)

    for attempt in range(1, attempts + 1):
        try:
            shutil.rmtree(path, onexc=make_writable_and_retry)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == attempts:
                logger.warning("Não foi possível remover o diretório temporário %s.", path)
                return
            time.sleep(0.2 * attempt)
