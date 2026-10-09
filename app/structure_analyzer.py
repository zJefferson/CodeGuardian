"""Análise estrutural de repositórios clonados.

Examina apenas metadados do sistema de arquivos (nomes, tipos e caminhos).
Nenhum arquivo é aberto, importado ou executado, e nenhuma dependência é
instalada. Links simbólicos e junções nunca são seguidos, de modo que a
varredura não sai do diretório analisado.
"""

import os
from collections import deque
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

# Dependências, caches, ambientes virtuais e controle de versão.
IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        "env",
        "node_modules",
        "site-packages",
        ".tox",
        ".nox",
        ".eggs",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
        ".ipynb_checkpoints",
        ".idea",
        ".vscode",
    }
)
_IGNORED_DIRECTORY_SUFFIXES = (".egg-info", ".dist-info")

_PYTHON_SUFFIXES = (".py",)
_TEST_DIRECTORY_NAMES = frozenset({"tests", "test", "testing"})
_DOCS_DIRECTORY_NAMES = frozenset({"docs", "doc", "documentation"})
_SOURCE_DIRECTORY_NAMES = frozenset({"src", "lib"})
_README_STEMS = frozenset({"readme"})


class ConfigKind(StrEnum):
    PYPROJECT = "pyproject"
    REQUIREMENTS = "requirements"
    SETUP_PY = "setup.py"
    SETUP_CFG = "setup.cfg"
    PYTEST_INI = "pytest.ini"
    TOX_INI = "tox.ini"
    PIPFILE = "pipfile"
    LOCKFILE = "lockfile"
    LINTER = "linter"
    TYPE_CHECKER = "type-checker"
    PRE_COMMIT = "pre-commit"


_CONFIG_FILES: dict[str, ConfigKind] = {
    "pyproject.toml": ConfigKind.PYPROJECT,
    "setup.py": ConfigKind.SETUP_PY,
    "setup.cfg": ConfigKind.SETUP_CFG,
    "pytest.ini": ConfigKind.PYTEST_INI,
    "tox.ini": ConfigKind.TOX_INI,
    "pipfile": ConfigKind.PIPFILE,
    "pipfile.lock": ConfigKind.LOCKFILE,
    "poetry.lock": ConfigKind.LOCKFILE,
    "uv.lock": ConfigKind.LOCKFILE,
    "pdm.lock": ConfigKind.LOCKFILE,
    "ruff.toml": ConfigKind.LINTER,
    ".ruff.toml": ConfigKind.LINTER,
    ".flake8": ConfigKind.LINTER,
    ".pylintrc": ConfigKind.LINTER,
    "mypy.ini": ConfigKind.TYPE_CHECKER,
    ".mypy.ini": ConfigKind.TYPE_CHECKER,
    ".pre-commit-config.yaml": ConfigKind.PRE_COMMIT,
}


class DirectoryKind(StrEnum):
    SOURCE = "source"
    PACKAGE = "package"
    TESTS = "tests"
    DOCS = "docs"


class StructureLimits(BaseModel):
    """Limites da varredura."""

    model_config = ConfigDict(frozen=True)

    max_depth: int = Field(default=12, ge=0, le=64)
    max_files: int = Field(default=20_000, gt=0)


class ConfigFile(BaseModel):
    path: str
    kind: ConfigKind


class RelevantDirectory(BaseModel):
    path: str
    kind: DirectoryKind


class TestsInfo(BaseModel):
    has_tests: bool
    test_file_count: int
    test_directories: list[str]


class DocumentationInfo(BaseModel):
    has_documentation: bool
    readme_files: list[str]
    docs_directories: list[str]


class StructureReport(BaseModel):
    """Resultado da análise estrutural.

    ``complete=False`` indica análise incompleta (limite atingido ou diretório
    ilegível); os motivos ficam em ``limitations``. Listas vazias com
    ``complete=True`` indicam ausência real do item.
    """

    complete: bool
    limitations: list[str]
    files_examined: int
    python_files: list[str]
    config_files: list[ConfigFile]
    relevant_directories: list[RelevantDirectory]
    tests: TestsInfo
    documentation: DocumentationInfo
    ignored_directories: list[str]
    skipped_links: int


class StructureAnalysisError(Exception):
    """A análise não pôde ser realizada. ``message`` é segura para o usuário."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def analyze_structure(root: Path, limits: StructureLimits | None = None) -> StructureReport:
    """Analisa a estrutura do repositório em ``root`` sem executar nada.

    Raises:
        StructureAnalysisError: se ``root`` não for um diretório real.
    """
    limits = limits or StructureLimits()
    root = Path(root)
    _validate_root(root)
    return _Scanner(root, limits).scan()


def _validate_root(root: Path) -> None:
    if root.is_symlink() or _is_junction(root):
        raise StructureAnalysisError("O diretório analisado não pode ser um link.")
    if not root.is_dir():
        raise StructureAnalysisError("O diretório analisado não existe.")


def _is_junction(path: Path) -> bool:
    return hasattr(path, "is_junction") and path.is_junction()


def _display(relative: PurePosixPath) -> str:
    """Caminho relativo em formato POSIX, seguro para serialização JSON."""
    text = relative.as_posix()
    return text.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")


def _is_ignored_directory(name: str) -> bool:
    lowered = name.lower()
    return lowered in IGNORED_DIRECTORIES or lowered.endswith(_IGNORED_DIRECTORY_SUFFIXES)


def _config_kind(name: str) -> ConfigKind | None:
    lowered = name.lower()
    if lowered in _CONFIG_FILES:
        return _CONFIG_FILES[lowered]
    if lowered.startswith("requirements") and lowered.endswith((".txt", ".in")):
        return ConfigKind.REQUIREMENTS
    return None


def _is_test_file(name: str) -> bool:
    lowered = name.lower()
    if not lowered.endswith(".py"):
        return False
    return lowered.startswith("test_") or lowered.endswith("_test.py") or lowered == "conftest.py"


def _is_readme(name: str) -> bool:
    return name.lower().split(".", 1)[0] in _README_STEMS


class _Scanner:
    def __init__(self, root: Path, limits: StructureLimits) -> None:
        self.root = root
        self.limits = limits
        self.files_examined = 0
        self.skipped_links = 0
        self.unreadable_directories = 0
        self.depth_limited = False
        self.file_limit_reached = False
        self.python_files: list[str] = []
        self.config_files: list[ConfigFile] = []
        self.relevant: list[RelevantDirectory] = []
        self.test_files = 0
        self.test_directories: list[str] = []
        self.readme_files: list[str] = []
        self.docs_directories: list[str] = []
        self.ignored: list[str] = []
        self.packages: set[PurePosixPath] = set()

    def scan(self) -> StructureReport:
        # Busca em largura: arquivos da raiz são examinados antes dos internos.
        queue: deque[tuple[Path, PurePosixPath, bool]] = deque(
            [(self.root, PurePosixPath(), False)]
        )
        while queue and not self.file_limit_reached:
            directory, relative, inside_tests = queue.popleft()
            self._scan_directory(directory, relative, inside_tests, queue)
        return self._report()

    def _scan_directory(
        self,
        directory: Path,
        relative: PurePosixPath,
        inside_tests: bool,
        queue: deque[tuple[Path, PurePosixPath, bool]],
    ) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            self.unreadable_directories += 1
            return

        depth = len(relative.parts)
        files = [e for e in entries if not self._is_link(e) and not self._is_dir(e)]
        if relative.parts and not inside_tests and any(e.name == "__init__.py" for e in files):
            self._register_package(relative)

        for entry in entries:
            if self._is_link(entry):
                self.skipped_links += 1
                continue
            child = relative / entry.name
            if self._is_dir(entry):
                self._handle_directory(entry, child, depth, inside_tests, queue)
                continue
            if self.files_examined >= self.limits.max_files:
                self.file_limit_reached = True
                return
            self.files_examined += 1
            self._handle_file(entry.name, child, depth, inside_tests)

    def _handle_directory(
        self,
        entry: os.DirEntry[str],
        child: PurePosixPath,
        depth: int,
        inside_tests: bool,
        queue: deque[tuple[Path, PurePosixPath, bool]],
    ) -> None:
        name = entry.name.lower()
        if _is_ignored_directory(entry.name):
            self.ignored.append(_display(child))
            return
        if depth + 1 > self.limits.max_depth:
            self.depth_limited = True
            return

        is_tests = name in _TEST_DIRECTORY_NAMES
        if is_tests:
            self.test_directories.append(_display(child))
            self.relevant.append(RelevantDirectory(path=_display(child), kind=DirectoryKind.TESTS))
        elif name in _DOCS_DIRECTORY_NAMES:
            self.docs_directories.append(_display(child))
            self.relevant.append(RelevantDirectory(path=_display(child), kind=DirectoryKind.DOCS))
        elif name in _SOURCE_DIRECTORY_NAMES:
            self.relevant.append(RelevantDirectory(path=_display(child), kind=DirectoryKind.SOURCE))
        queue.append((Path(entry.path), child, inside_tests or is_tests))

    def _handle_file(self, name: str, child: PurePosixPath, depth: int, inside_tests: bool) -> None:
        if name.lower().endswith(_PYTHON_SUFFIXES):
            self.python_files.append(_display(child))
            if _is_test_file(name) or (inside_tests and name != "__init__.py"):
                self.test_files += 1
        kind = _config_kind(name)
        if kind is not None:
            self.config_files.append(ConfigFile(path=_display(child), kind=kind))
        if depth == 0 and _is_readme(name):
            self.readme_files.append(_display(child))

    def _register_package(self, relative: PurePosixPath) -> None:
        self.packages.add(relative)
        # Registra apenas pacotes de nível mais alto (cujo pai não é pacote).
        if relative.parent not in self.packages:
            self.relevant.append(
                RelevantDirectory(path=_display(relative), kind=DirectoryKind.PACKAGE)
            )

    @staticmethod
    def _is_link(entry: os.DirEntry[str]) -> bool:
        try:
            return entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction())
        except OSError:
            return True

    @staticmethod
    def _is_dir(entry: os.DirEntry[str]) -> bool:
        try:
            return entry.is_dir(follow_symlinks=False)
        except OSError:
            return False

    def _report(self) -> StructureReport:
        limitations: list[str] = []
        if self.file_limit_reached:
            limitations.append(
                f"Limite de {self.limits.max_files} arquivos atingido; "
                "a varredura foi interrompida."
            )
        if self.depth_limited:
            limitations.append(
                f"Diretórios além da profundidade {self.limits.max_depth} não foram examinados."
            )
        if self.unreadable_directories:
            limitations.append(f"{self.unreadable_directories} diretório(s) não puderam ser lidos.")

        return StructureReport(
            complete=not limitations,
            limitations=limitations,
            files_examined=self.files_examined,
            python_files=sorted(self.python_files),
            config_files=sorted(self.config_files, key=lambda c: c.path),
            relevant_directories=sorted(self.relevant, key=lambda d: (d.path, d.kind)),
            tests=TestsInfo(
                has_tests=self.test_files > 0,
                test_file_count=self.test_files,
                test_directories=sorted(self.test_directories),
            ),
            documentation=DocumentationInfo(
                has_documentation=bool(self.readme_files or self.docs_directories),
                readme_files=sorted(self.readme_files),
                docs_directories=sorted(self.docs_directories),
            ),
            ignored_directories=sorted(self.ignored),
            skipped_links=self.skipped_links,
        )
