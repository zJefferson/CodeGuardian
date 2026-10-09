"""Verificação de vulnerabilidades conhecidas com pip-audit.

O pip-audit nunca recebe os arquivos do repositório analisado. Um arquivo
``requirements`` sanitizado, contendo apenas linhas ``nome==versão`` extraídas
por ``app.dependency_files``, é gerado em um diretório temporário próprio.

Com ``--no-deps --disable-pip`` o pip-audit não instala nada nem resolve
dependências (o que executaria ``setup.py`` de terceiros): apenas consulta a
fonte de vulnerabilidades (PyPI ou OSV) para cada versão declarada.

A análise depende das dependências declaradas com versão exata e das
informações disponíveis na fonte de vulnerabilidades: dependências transitivas
não declaradas, versões não fixadas e vulnerabilidades ainda não publicadas
não aparecem no resultado.
"""

import json
import shutil
import sys
import tempfile
import time
from enum import StrEnum
from importlib import metadata
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.dependency_files import (
    CollectionLimits,
    DeclaredDependency,
    DependencyCollection,
    DependencyFile,
    UnauditedDependency,
    collect_dependencies,
)
from app.process_runner import ProcessTimeoutError, minimal_env, run_limited
from app.structure_analyzer import StructureReport

_WORKDIR_PREFIX = "codeguardian-audit-"
_MAX_ID_LENGTH = 100

# Indícios de que a fonte de vulnerabilidades está inacessível.
_SOURCE_UNAVAILABLE_MARKERS = (
    "connectionerror",
    "proxyerror",
    "maxretryerror",
    "connecttimeout",
    "readtimeout",
    "nameresolutionerror",
    "sslerror",
    "serviceerror",
    "temporary failure in name resolution",
)


class AuditStatus(StrEnum):
    NO_VULNERABILITIES = "no_vulnerabilities"  # concluída, sem achados
    VULNERABILITIES_FOUND = "vulnerabilities_found"  # concluída, com achados
    NO_DEPENDENCY_FILES = "no_dependency_files"
    NO_AUDITABLE_DEPENDENCIES = "no_auditable_dependencies"  # nada com versão exata
    SOURCE_UNAVAILABLE = "source_unavailable"  # fonte de vulnerabilidades inacessível
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    FAILED = "failed"  # falha de execução


_COMPLETED_STATUSES = frozenset(
    {
        AuditStatus.NO_VULNERABILITIES,
        AuditStatus.VULNERABILITIES_FOUND,
        AuditStatus.NO_DEPENDENCY_FILES,
        AuditStatus.NO_AUDITABLE_DEPENDENCIES,
    }
)


class AuditSettings(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability_service: Literal["pypi", "osv"] = "pypi"
    timeout_seconds: float = Field(default=180.0, gt=0, le=1800)
    request_timeout_seconds: int = Field(default=15, gt=0, le=120)
    max_output_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    max_packages: int = Field(default=500, gt=0)
    poll_interval_seconds: float = Field(default=0.2, gt=0)
    # Interpretador com pip-audit instalado. Em produção, pode apontar para um
    # ambiente virtual dedicado à ferramenta, separado do ambiente da API.
    python_executable: str = sys.executable


class Vulnerability(BaseModel):
    id: str
    aliases: list[str]
    fix_versions: list[str]


class AuditedPackage(BaseModel):
    name: str
    version: str
    sources: list[str]
    vulnerabilities: list[Vulnerability]


class DependencyAuditReport(BaseModel):
    """Resultado da auditoria de dependências.

    ``status`` diferencia análise concluída sem achados, concluída com
    vulnerabilidades, nada a auditar e falhas (fonte indisponível, timeout,
    limite de saída ou erro da ferramenta). ``unaudited`` lista o que não pôde
    ser verificado (versão não fixada, URL, pacote fora do PyPI...).
    """

    status: AuditStatus
    tool: str = "pip-audit"
    tool_version: str | None
    vulnerability_service: str
    dependency_files: list[DependencyFile]
    packages: list[AuditedPackage]
    unaudited: list[UnauditedDependency]
    collection_errors: list[str]
    vulnerable_package_count: int
    vulnerability_count: int
    error: str | None = None

    @property
    def complete(self) -> bool:
        return self.status in _COMPLETED_STATUSES


# --- Formato bruto da saída JSON do pip-audit ---------------------------------


class _RawVulnerability(BaseModel):
    id: str
    fix_versions: list[str] = []
    aliases: list[str] = []


class _RawDependency(BaseModel):
    name: str
    version: str | None = None
    vulns: list[_RawVulnerability] = []
    skip_reason: str | None = None


class _RawOutput(BaseModel):
    dependencies: list[_RawDependency]


class _AuditFailure(Exception):
    def __init__(self, status: AuditStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def audit_dependencies(
    root: Path,
    *,
    settings: AuditSettings | None = None,
    structure: StructureReport | None = None,
    collection_limits: CollectionLimits | None = None,
) -> DependencyAuditReport:
    """Audita as dependências declaradas no repositório em ``root``."""
    settings = settings or AuditSettings()
    collection = collect_dependencies(root, structure=structure, limits=collection_limits)
    unaudited = list(collection.unaudited)

    if not collection.files:
        return _report(settings, collection, AuditStatus.NO_DEPENDENCY_FILES, unaudited)
    dependencies = collection.dependencies
    if len(dependencies) > settings.max_packages:
        unaudited += [
            UnauditedDependency(
                source=dep.sources[0],
                line=None,
                requirement=f"{dep.name}=={dep.version}",
                reason=f"Limite de {settings.max_packages} pacotes por análise atingido.",
            )
            for dep in dependencies[settings.max_packages :]
        ]
        dependencies = dependencies[: settings.max_packages]
    if not dependencies:
        return _report(settings, collection, AuditStatus.NO_AUDITABLE_DEPENDENCIES, unaudited)

    packages: list[AuditedPackage] = []
    try:
        _run_batches(dependencies, settings, packages, unaudited)
    except _AuditFailure as failure:
        return _report(
            settings, collection, failure.status, unaudited, packages, error=failure.message
        )

    vulnerable = any(p.vulnerabilities for p in packages)
    status = AuditStatus.VULNERABILITIES_FOUND if vulnerable else AuditStatus.NO_VULNERABILITIES
    return _report(settings, collection, status, unaudited, packages)


def _batches(dependencies: list[DeclaredDependency]) -> list[list[DeclaredDependency]]:
    """Agrupa sem nomes repetidos: o pip-audit rejeita o mesmo pacote duas vezes."""
    batches: list[list[DeclaredDependency]] = []
    for dep in dependencies:
        for batch in batches:
            if all(other.name != dep.name for other in batch):
                batch.append(dep)
                break
        else:
            batches.append([dep])
    return batches


def _run_batches(
    dependencies: list[DeclaredDependency],
    settings: AuditSettings,
    packages: list[AuditedPackage],
    unaudited: list[UnauditedDependency],
) -> None:
    deadline = time.monotonic() + settings.timeout_seconds
    workdir = Path(tempfile.mkdtemp(prefix=_WORKDIR_PREFIX))
    try:
        for index, batch in enumerate(_batches(dependencies)):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _AuditFailure(AuditStatus.TIMEOUT, "A auditoria excedeu o tempo limite.")
            requirements = workdir / f"requirements-{index}.txt"
            requirements.write_text(
                "".join(f"{dep.name}=={dep.version}\n" for dep in batch), encoding="utf-8"
            )
            output = _run_pip_audit(requirements, workdir, settings, remaining)
            _merge(output, batch, packages, unaudited)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _build_command(requirements: Path, workdir: Path, settings: AuditSettings) -> list[str]:
    return [
        settings.python_executable,
        "-I",
        "-m",
        "pip_audit",
        "--requirement",
        str(requirements),
        "--no-deps",
        "--disable-pip",
        "--format",
        "json",
        "--progress-spinner",
        "off",
        "--aliases",
        "on",
        "--desc",
        "off",
        "--vulnerability-service",
        settings.vulnerability_service,
        "--timeout",
        str(settings.request_timeout_seconds),
        "--cache-dir",
        str(workdir / "cache"),
    ]


def _run_pip_audit(
    requirements: Path, workdir: Path, settings: AuditSettings, timeout: float
) -> _RawOutput:
    # Diretório pessoal e de dados apontam para o diretório temporário: o
    # pip-audit precisa deles (Path.home() usa USERPROFILE no Windows), mas não
    # deve ler nem gravar nos diretórios reais do usuário do servidor.
    env = minimal_env(
        {
            "HOME": str(workdir),
            "USERPROFILE": str(workdir),
            "APPDATA": str(workdir),
            "LOCALAPPDATA": str(workdir),
            "PIP_NO_INPUT": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    try:
        result = run_limited(
            _build_command(requirements, workdir, settings),
            cwd=workdir,
            env=env,
            timeout_seconds=timeout,
            max_output_bytes=settings.max_output_bytes,
            poll_interval_seconds=settings.poll_interval_seconds,
            capture_stdout=True,
        )
    except ProcessTimeoutError:
        raise _AuditFailure(AuditStatus.TIMEOUT, "A auditoria excedeu o tempo limite.") from None
    except OSError:
        raise _AuditFailure(AuditStatus.FAILED, "Não foi possível iniciar o pip-audit.") from None

    if result.stdout_truncated:
        raise _AuditFailure(
            AuditStatus.OUTPUT_LIMIT, "A saída do pip-audit excedeu o limite permitido."
        )
    # pip-audit retorna 1 tanto para "vulnerabilidades encontradas" quanto para
    # erros; a saída JSON é o que diferencia os casos.
    try:
        return _RawOutput.model_validate(json.loads(result.stdout.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
        pass

    stderr = result.stderr_text.lower()
    if any(marker in stderr for marker in _SOURCE_UNAVAILABLE_MARKERS):
        raise _AuditFailure(
            AuditStatus.SOURCE_UNAVAILABLE,
            "A fonte de vulnerabilidades está indisponível; tente novamente mais tarde.",
        )
    raise _AuditFailure(AuditStatus.FAILED, "O pip-audit terminou com erro.")


def _merge(
    output: _RawOutput,
    batch: list[DeclaredDependency],
    packages: list[AuditedPackage],
    unaudited: list[UnauditedDependency],
) -> None:
    declared = {dep.name: dep for dep in batch}
    answered: set[str] = set()
    for raw in output.dependencies:
        dep = declared.get(raw.name)
        if dep is None:
            continue  # o pip-audit só deveria devolver o que foi enviado
        answered.add(dep.name)
        if raw.skip_reason is not None:
            unaudited.append(
                UnauditedDependency(
                    source=dep.sources[0],
                    line=None,
                    requirement=f"{dep.name}=={dep.version}",
                    reason="Pacote não encontrado na fonte de vulnerabilidades.",
                )
            )
            continue
        packages.append(
            AuditedPackage(
                name=dep.name,
                version=dep.version,
                sources=dep.sources,
                vulnerabilities=_unique_vulnerabilities(raw.vulns),
            )
        )
    for dep in batch:
        if dep.name not in answered:
            unaudited.append(
                UnauditedDependency(
                    source=dep.sources[0],
                    line=None,
                    requirement=f"{dep.name}=={dep.version}",
                    reason="O pip-audit não retornou resultado para este pacote.",
                )
            )


def _unique_vulnerabilities(raw: list[_RawVulnerability]) -> list[Vulnerability]:
    """pip-audit pode repetir a mesma vulnerabilidade; agrupa por identificador."""
    merged: dict[str, Vulnerability] = {}
    for vuln in raw:
        key = vuln.id[:_MAX_ID_LENGTH]
        current = merged.setdefault(key, Vulnerability(id=key, aliases=[], fix_versions=[]))
        for alias in vuln.aliases:
            alias = alias[:_MAX_ID_LENGTH]
            if alias not in current.aliases and alias != key:
                current.aliases.append(alias)
        for version in vuln.fix_versions:
            version = version[:_MAX_ID_LENGTH]
            if version not in current.fix_versions:
                current.fix_versions.append(version)
    for vuln in merged.values():
        vuln.aliases.sort()
    return sorted(merged.values(), key=lambda v: v.id)


def _tool_version(settings: AuditSettings) -> str | None:
    """Versão do pip-audit do interpretador atual; desconhecida se for outro."""
    if settings.python_executable != sys.executable:
        return None
    try:
        return metadata.version("pip-audit")
    except metadata.PackageNotFoundError:
        return None


def _report(
    settings: AuditSettings,
    collection: DependencyCollection,
    status: AuditStatus,
    unaudited: list[UnauditedDependency],
    packages: list[AuditedPackage] | None = None,
    *,
    error: str | None = None,
) -> DependencyAuditReport:
    packages = sorted(packages or [], key=lambda p: (p.name, p.version))
    return DependencyAuditReport(
        status=status,
        tool_version=_tool_version(settings),
        vulnerability_service=settings.vulnerability_service,
        dependency_files=collection.files,
        packages=packages,
        unaudited=unaudited,
        collection_errors=collection.errors,
        vulnerable_package_count=sum(1 for p in packages if p.vulnerabilities),
        vulnerability_count=sum(len(p.vulnerabilities) for p in packages),
        error=error,
    )
