"""Coleta de dependências declaradas em arquivos de um repositório.

Os arquivos são lidos apenas como dados (TOML/JSON/texto); nada é instalado,
importado ou executado. Só dependências com versão exata (``==``) podem ser
auditadas sem instalar o projeto; as demais são registradas como não auditadas.

Opções de arquivos ``requirements`` (``-r``, ``-e``, ``--index-url`` etc.) e
requisitos por URL ou caminho local nunca são seguidos: poderiam apontar para
arquivos fora do repositório ou para serviços internos.
"""

import json
import re
import tomllib
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from pydantic import BaseModel, ConfigDict, Field

from app.structure_analyzer import ConfigKind, StructureReport, analyze_structure


class DependencyFileKind(StrEnum):
    REQUIREMENTS = "requirements"
    PYPROJECT = "pyproject"
    PIPFILE_LOCK = "pipfile.lock"
    POETRY_LOCK = "poetry.lock"
    UV_LOCK = "uv.lock"


_LOCKFILE_KINDS = {
    "pipfile.lock": DependencyFileKind.PIPFILE_LOCK,
    "poetry.lock": DependencyFileKind.POETRY_LOCK,
    "uv.lock": DependencyFileKind.UV_LOCK,
}

# Opções por requisito, como "--hash=sha256:..." após o especificador.
_INLINE_OPTION = re.compile(r"\s--?[A-Za-z]")
_COMMENT = re.compile(r"(^|\s)#.*$")
_PINNED_OPERATORS = frozenset({"==", "==="})


class CollectionLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_files: int = Field(default=50, gt=0)
    max_file_bytes: int = Field(default=5 * 1024 * 1024, gt=0)


class DependencyFile(BaseModel):
    path: str
    kind: DependencyFileKind


class DeclaredDependency(BaseModel):
    """Dependência com versão exata, pronta para auditoria."""

    name: str
    version: str
    sources: list[str]


class UnauditedDependency(BaseModel):
    """Entrada que não pôde ser auditada, com o motivo."""

    source: str
    line: int | None
    requirement: str
    reason: str


class DependencyCollection(BaseModel):
    files: list[DependencyFile]
    dependencies: list[DeclaredDependency]
    unaudited: list[UnauditedDependency]
    errors: list[str]


def collect_dependencies(
    root: Path,
    *,
    structure: StructureReport | None = None,
    limits: CollectionLimits | None = None,
) -> DependencyCollection:
    """Localiza os arquivos de dependências suportados e extrai as dependências."""
    root = Path(root)
    limits = limits or CollectionLimits()
    structure = structure or analyze_structure(root)
    collector = _Collector(root, limits)

    for config in structure.config_files:
        kind = _dependency_kind(config.path, config.kind)
        if kind is None:
            continue
        if len(collector.files) >= limits.max_files:
            collector.errors.append(
                f"Limite de {limits.max_files} arquivos de dependências atingido."
            )
            break
        collector.collect(config.path, kind)
    return collector.result()


def _dependency_kind(path: str, kind: ConfigKind) -> DependencyFileKind | None:
    name = PurePosixPath(path).name.lower()
    if kind is ConfigKind.REQUIREMENTS and name.endswith(".txt"):
        return DependencyFileKind.REQUIREMENTS
    if kind is ConfigKind.PYPROJECT:
        return DependencyFileKind.PYPROJECT
    if kind in {ConfigKind.LOCKFILE, ConfigKind.PIPFILE}:
        return _LOCKFILE_KINDS.get(name)
    return None


class _Collector:
    def __init__(self, root: Path, limits: CollectionLimits) -> None:
        self.root = root
        self.limits = limits
        self.files: list[DependencyFile] = []
        self.pinned: dict[tuple[str, str], list[str]] = {}
        self.unaudited: list[UnauditedDependency] = []
        self.errors: list[str] = []

    def collect(self, relative: str, kind: DependencyFileKind) -> None:
        text = self._read(relative)
        if text is None:
            return
        self.files.append(DependencyFile(path=relative, kind=kind))
        try:
            if kind is DependencyFileKind.REQUIREMENTS:
                self._parse_requirements_txt(relative, text)
            elif kind is DependencyFileKind.PYPROJECT:
                self._parse_pyproject(relative, tomllib.loads(text))
            elif kind is DependencyFileKind.PIPFILE_LOCK:
                self._parse_pipfile_lock(relative, json.loads(text))
            else:
                self._parse_package_lock(relative, tomllib.loads(text))
        except (tomllib.TOMLDecodeError, json.JSONDecodeError, TypeError, AttributeError):
            self.errors.append(f"{relative}: arquivo inválido ou em formato inesperado.")

    def _read(self, relative: str) -> str | None:
        path = self.root / relative
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.root.resolve())
            if path.is_symlink() or not resolved.is_file():
                raise ValueError
            if resolved.stat().st_size > self.limits.max_file_bytes:
                self.errors.append(f"{relative}: arquivo excede o tamanho máximo permitido.")
                return None
            return resolved.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            self.errors.append(f"{relative}: arquivo não está em UTF-8.")
        except (OSError, ValueError):
            self.errors.append(f"{relative}: arquivo não pôde ser lido.")
        return None

    # --- Formatos ----------------------------------------------------------

    def _parse_requirements_txt(self, source: str, text: str) -> None:
        for line_number, line in _logical_lines(text):
            if line.startswith("-"):
                self._skip(source, line_number, line, "Opção de requirements não suportada.")
                continue
            spec = _INLINE_OPTION.split(line, maxsplit=1)[0].strip()
            self._add_requirement(source, line_number, spec)

    def _parse_pyproject(self, source: str, data: dict[str, Any]) -> None:
        project = data.get("project", {})
        for spec in _as_list(project.get("dependencies", [])):
            self._add_requirement(source, None, spec)
        for specs in project.get("optional-dependencies", {}).values():
            for spec in _as_list(specs):
                self._add_requirement(source, None, spec)
        for specs in data.get("dependency-groups", {}).values():
            for spec in _as_list(specs):
                if isinstance(spec, str):  # {include-group = "..."} já é coberto
                    self._add_requirement(source, None, spec)

    def _parse_pipfile_lock(self, source: str, data: dict[str, Any]) -> None:
        for section in ("default", "develop"):
            for name, entry in data.get(section, {}).items():
                version = entry.get("version") if isinstance(entry, dict) else None
                if isinstance(version, str) and version.startswith("=="):
                    self._add_pinned(source, name, version[2:])
                else:
                    self._skip(source, None, str(name), "Dependência sem versão do PyPI.")

    def _parse_package_lock(self, source: str, data: dict[str, Any]) -> None:
        """poetry.lock e uv.lock: tabelas [[package]] com name/version."""
        for package in _as_list(data.get("package", [])):
            if not isinstance(package, dict):
                raise TypeError
            name, version = package.get("name"), package.get("version")
            origin = package.get("source")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            if _is_non_registry_source(origin):
                self._skip(source, None, name, "Dependência fora do PyPI (git, caminho ou URL).")
                continue
            self._add_pinned(source, name, version)

    # --- Registro ------------------------------------------------------------

    def _add_requirement(self, source: str, line: int | None, spec: object) -> None:
        if not isinstance(spec, str):
            raise TypeError
        try:
            requirement = Requirement(spec)
        except InvalidRequirement:
            self._skip(source, line, spec, "Requisito inválido.")
            return
        if requirement.url:
            self._skip(source, line, spec, "Requisito por URL ou caminho não é auditado.")
            return
        specifiers = list(requirement.specifier)
        if (
            len(specifiers) != 1
            or specifiers[0].operator not in _PINNED_OPERATORS
            or "*" in specifiers[0].version
        ):
            self._skip(source, line, spec, "Versão não fixada (use ==).")
            return
        self._add_pinned(source, requirement.name, specifiers[0].version)

    def _add_pinned(self, source: str, name: str, version: str) -> None:
        key = (canonicalize_name(name), version.strip())
        sources = self.pinned.setdefault(key, [])
        if source not in sources:
            sources.append(source)

    def _skip(self, source: str, line: int | None, requirement: str, reason: str) -> None:
        self.unaudited.append(
            UnauditedDependency(
                source=source, line=line, requirement=requirement[:200], reason=reason
            )
        )

    def result(self) -> DependencyCollection:
        return DependencyCollection(
            files=self.files,
            dependencies=[
                DeclaredDependency(name=name, version=version, sources=sources)
                for (name, version), sources in sorted(self.pinned.items())
            ],
            unaudited=self.unaudited,
            errors=self.errors,
        )


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Linhas sem comentários, com continuações (``\\``) unidas."""
    lines: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        line = _COMMENT.sub("", buffer + stripped).strip()
        buffer = ""
        if line:
            lines.append((start, line))
    if buffer.strip():
        lines.append((start, _COMMENT.sub("", buffer).strip()))
    return lines


def _is_non_registry_source(origin: object) -> bool:
    """Pacotes do PyPI não têm ``source`` (poetry.lock) ou têm ``registry`` (uv.lock).

    Git, caminhos, URLs, projetos editáveis e índices privados não são auditados:
    o nome poderia coincidir com um pacote diferente no PyPI.
    """
    if origin is None:
        return False
    return not (isinstance(origin, dict) and "registry" in origin)


def _as_list(value: object) -> list[Any]:
    """Garante que um campo do arquivo é lista (uma string seria iterada letra a letra)."""
    if not isinstance(value, list):
        raise TypeError
    return value
