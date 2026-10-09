"""Execução de ferramentas externas com limites de tempo e de saída.

Os comandos são sempre listas de argumentos executadas sem shell, com
ambiente mínimo (sem segredos do processo da API) e sem entrada padrão.
"""

import logging
import os
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

logger = logging.getLogger(__name__)

_READ_CHUNK_BYTES = 4096
_KILL_WAIT_SECONDS = 5

# Variáveis do ambiente herdadas pelas ferramentas. Todo o resto
# (tokens, chaves de API etc.) é descartado.
_INHERITED_ENV_VARS = ("PATH", "SYSTEMROOT")


class ProcessTimeoutError(Exception):
    """O processo excedeu o tempo limite e foi encerrado."""


class ProcessAbortedError(Exception):
    """O processo foi encerrado porque ``abort_check`` retornou verdadeiro."""


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace").strip()


def minimal_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Ambiente mínimo para subprocessos, acrescido de ``extra``."""
    env = {name: os.environ[name] for name in _INHERITED_ENV_VARS if name in os.environ}
    env.update(extra or {})
    return env


def run_limited(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    poll_interval_seconds: float = 0.5,
    capture_stdout: bool = False,
    abort_check: Callable[[], bool] | None = None,
) -> ProcessResult:
    """Executa ``command`` e aguarda seu término dentro dos limites.

    Guarda no máximo ``max_output_bytes`` de cada saída; o excedente é lido e
    descartado para que o processo não bloqueie com o pipe cheio.

    Raises:
        OSError: se o processo não puder ser iniciado.
        ProcessTimeoutError: se exceder ``timeout_seconds``.
        ProcessAbortedError: se ``abort_check`` retornar verdadeiro.
    """
    process = subprocess.Popen(  # noqa: S603 - lista de argumentos, sem shell
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=dict(env),
        shell=False,
    )
    readers = [_BoundedReader(process.stderr, max_output_bytes)]
    if capture_stdout:
        readers.append(_BoundedReader(process.stdout, max_output_bytes))
    for reader in readers:
        reader.start()

    try:
        returncode = _wait(process, timeout_seconds, poll_interval_seconds, abort_check)
    finally:
        for reader in readers:
            reader.join(timeout=poll_interval_seconds * 4)

    stderr = readers[0]
    stdout = readers[1] if capture_stdout else _BoundedReader(None, 0)
    return ProcessResult(
        returncode=returncode,
        stdout=stdout.data,
        stderr=stderr.data,
        stdout_truncated=stdout.truncated,
        stderr_truncated=stderr.truncated,
    )


def _wait(
    process: subprocess.Popen[bytes],
    timeout_seconds: float,
    poll_interval_seconds: float,
    abort_check: Callable[[], bool] | None,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            return process.wait(timeout=poll_interval_seconds)
        except subprocess.TimeoutExpired:
            pass
        if time.monotonic() >= deadline:
            _kill(process)
            raise ProcessTimeoutError
        if abort_check is not None and abort_check():
            _kill(process)
            raise ProcessAbortedError


def _kill(process: subprocess.Popen[bytes]) -> None:
    process.kill()
    try:
        process.wait(timeout=_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        logger.warning("Processo não terminou após kill (pid=%s).", process.pid)


class _BoundedReader(threading.Thread):
    """Lê um stream até o fim, guardando no máximo ``limit`` bytes."""

    def __init__(self, stream: IO[bytes] | None, limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._buffer = bytearray()
        self.truncated = False

    def run(self) -> None:
        if self._stream is None:
            return
        try:
            while chunk := self._stream.read(_READ_CHUNK_BYTES):
                remaining = self._limit - len(self._buffer)
                if len(chunk) > remaining:
                    self.truncated = True
                if remaining > 0:
                    self._buffer += chunk[:remaining]
        except (OSError, ValueError):
            pass  # stream fechado após kill
        finally:
            self._stream.close()

    @property
    def data(self) -> bytes:
        return bytes(self._buffer)
