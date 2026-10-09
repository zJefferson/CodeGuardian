"""Análise estática de repositórios com Ruff.

O Ruff apenas lê e analisa os arquivos; nenhum código do repositório é
importado ou executado. Ele roda com ``--isolated``, ignorando qualquer
configuração presente no repositório analisado (``pyproject.toml``,
``ruff.toml``), pois essa configuração é controlada por terceiros e poderia,
por exemplo, apontar ``extend`` ou ``cache-dir`` para fora do diretório.
"""

import json
import re
import shutil
from enum import StrEnum
from importlib import metadata
from pathlib import Path, PurePath

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.process_runner import ProcessTimeoutError, minimal_env, run_limited
from app.structure_analyzer import StructureReport, analyze_structure

# Regras padrão do Ruff (E4, E7, E9, F) + flake8-bugbear (B) + flake8-bandit (S).
DEFAULT_RULES = ("E4", "E7", "E9", "F", "B", "S")
_RULE_SELECTOR = re.compile(r"[A-Z]{1,4}[0-9]{0,4}")
_MAX_TEXT_LENGTH = 500

# Códigos de saída do Ruff: 0 sem achados, 1 com achados, 2 erro.
_EXIT_OK = 0
_EXIT_FINDINGS = 1


class RuffSettings(BaseModel):
    """Regras e limites da análise com Ruff."""

    model_config = ConfigDict(frozen=True)

    rules: tuple[str, ...] = DEFAULT_RULES
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    max_output_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    # Achados truncados tornam a pontuação da análise estática indisponível.
    max_findings: int = Field(default=5000, gt=0)
    poll_interval_seconds: float = Field(default=0.2, gt=0)

    @field_validator("rules")
    @classmethod
    def _validate_rules(cls, rules: tuple[str, ...]) -> tuple[str, ...]:
        if not rules:
            raise ValueError("Ao menos uma regra deve ser selecionada.")
        for rule in rules:
            if not _RULE_SELECTOR.fullmatch(rule):
                raise ValueError("Seletor de regra inválido.")
        return rules


class RuffStatus(StrEnum):
    COMPLETED = "completed"  # Ruff executou; findings pode estar vazio
    NO_PYTHON_FILES = "no_python_files"  # nada a analisar
    TIMEOUT = "timeout"  # análise incompleta
    OUTPUT_LIMIT = "output_limit"  # análise incompleta
    FAILED = "failed"  # falha da ferramenta


class RuffFinding(BaseModel):
    file: str
    line: int
    column: int
    end_line: int | None
    end_column: int | None
    rule: str | None
    message: str
    suggestion: str | None
    url: str | None


class RuffReport(BaseModel):
    """Resultado da análise com Ruff.

    ``status`` diferencia análise concluída sem achados (``completed`` com
    ``findings`` vazio), ausência de arquivos Python, análise incompleta
    (``timeout``/``output_limit``) e falha (``failed``).
    """

    status: RuffStatus
    tool_version: str | None
    rules: list[str]
    findings: list[RuffFinding]
    finding_count: int
    findings_truncated: bool
    error: str | None = None

    @property
    def complete(self) -> bool:
        return self.status in {RuffStatus.COMPLETED, RuffStatus.NO_PYTHON_FILES}


# --- Formato bruto da saída JSON do Ruff --------------------------------------


class _RawLocation(BaseModel):
    row: int
    column: int


class _RawFix(BaseModel):
    message: str | None = None


class _RawDiagnostic(BaseModel):
    filename: str
    code: str | None = None
    message: str
    location: _RawLocation
    end_location: _RawLocation | None = None
    fix: _RawFix | None = None
    url: str | None = None


class RuffNotAvailableError(Exception):
    """O executável do Ruff não foi encontrado."""


def analyze_with_ruff(
    root: Path,
    *,
    settings: RuffSettings | None = None,
    structure: StructureReport | None = None,
) -> RuffReport:
    """Executa o Ruff sobre ``root`` e retorna os achados estruturados.

    ``structure`` pode ser informado para reaproveitar uma análise estrutural
    já feita; caso contrário, ela é executada para detectar arquivos Python.
    """
    settings = settings or RuffSettings()
    root = Path(root)
    structure = structure or analyze_structure(root)
    if structure.complete and not structure.python_files:
        return _report(settings, RuffStatus.NO_PYTHON_FILES)

    try:
        ruff = _find_ruff()
    except RuffNotAvailableError:
        return _report(settings, RuffStatus.FAILED, error="O Ruff não está disponível no servidor.")

    try:
        result = run_limited(
            _build_command(ruff, settings),
            cwd=root,
            env=minimal_env(),
            timeout_seconds=settings.timeout_seconds,
            max_output_bytes=settings.max_output_bytes,
            poll_interval_seconds=settings.poll_interval_seconds,
            capture_stdout=True,
        )
    except ProcessTimeoutError:
        return _report(settings, RuffStatus.TIMEOUT, error="O Ruff excedeu o tempo limite.")
    except OSError:
        return _report(settings, RuffStatus.FAILED, error="Não foi possível iniciar o Ruff.")

    if result.stdout_truncated:
        return _report(
            settings, RuffStatus.OUTPUT_LIMIT, error="A saída do Ruff excedeu o limite permitido."
        )
    if result.returncode not in {_EXIT_OK, _EXIT_FINDINGS}:
        return _report(settings, RuffStatus.FAILED, error="O Ruff terminou com erro.")

    try:
        diagnostics = _parse_output(result.stdout)
    except ValueError:
        return _report(
            settings, RuffStatus.FAILED, error="A saída do Ruff está em formato inesperado."
        )

    findings = [_to_finding(d, root) for d in diagnostics]
    findings.sort(key=lambda f: (f.file, f.line, f.column, f.rule or ""))
    return _report(
        settings,
        RuffStatus.COMPLETED,
        findings=findings[: settings.max_findings],
        finding_count=len(findings),
    )


def _find_ruff() -> str:
    try:
        from ruff.__main__ import find_ruff_bin

        return str(find_ruff_bin())
    except (ImportError, FileNotFoundError):
        pass
    ruff = shutil.which("ruff")
    if ruff is None:
        raise RuffNotAvailableError
    return ruff


def _build_command(ruff: str, settings: RuffSettings) -> list[str]:
    return [
        ruff,
        "check",
        "--isolated",
        "--no-cache",
        "--no-fix",
        "--quiet",
        "--output-format=json",
        f"--select={','.join(settings.rules)}",
        "--",
        ".",
    ]


def _parse_output(stdout: bytes) -> list[_RawDiagnostic]:
    try:
        data = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError from exc
    if not isinstance(data, list):
        raise ValueError
    try:
        return [_RawDiagnostic.model_validate(item) for item in data]
    except ValidationError as exc:
        raise ValueError from exc


def _to_finding(diagnostic: _RawDiagnostic, root: Path) -> RuffFinding:
    end = diagnostic.end_location
    return RuffFinding(
        file=_relative_path(diagnostic.filename, root),
        line=diagnostic.location.row,
        column=diagnostic.location.column,
        end_line=end.row if end else None,
        end_column=end.column if end else None,
        rule=_truncate(diagnostic.code),
        message=_truncate(diagnostic.message) or "",
        suggestion=_truncate(diagnostic.fix.message if diagnostic.fix else None),
        url=diagnostic.url if diagnostic.url and diagnostic.url.startswith("https://") else None,
    )


def _relative_path(filename: str, root: Path) -> str:
    """Caminho relativo ao repositório; nunca expõe caminhos do servidor."""
    path = Path(filename)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return PurePath(filename).name


def _truncate(text: str | None) -> str | None:
    if text is None or len(text) <= _MAX_TEXT_LENGTH:
        return text
    return text[: _MAX_TEXT_LENGTH - 1] + "…"


def _tool_version() -> str | None:
    try:
        return metadata.version("ruff")
    except metadata.PackageNotFoundError:
        return None


def _report(
    settings: RuffSettings,
    status: RuffStatus,
    *,
    findings: list[RuffFinding] | None = None,
    finding_count: int = 0,
    error: str | None = None,
) -> RuffReport:
    findings = findings or []
    return RuffReport(
        status=status,
        tool_version=_tool_version(),
        rules=list(settings.rules),
        findings=findings,
        finding_count=finding_count,
        findings_truncated=finding_count > len(findings),
        error=error,
    )
