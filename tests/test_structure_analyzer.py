import json
import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from app import structure_analyzer
from app.structure_analyzer import (
    ConfigFile,
    ConfigKind,
    DirectoryKind,
    RelevantDirectory,
    StructureAnalysisError,
    StructureLimits,
    analyze_structure,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_project(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def create_dir_link(link: Path, target: Path) -> None:
    """Cria link simbólico; no Windows sem privilégio, usa junction."""
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        if sys.platform != "win32":
            pytest.skip("Sem permissão para criar links simbólicos.")
        import _winapi

        _winapi.CreateJunction(str(target), str(link))


# --- Projetos de exemplo -----------------------------------------------------


@pytest.fixture
def src_layout_project(tmp_path: Path) -> Path:
    return make_project(
        tmp_path / "project",
        {
            "pyproject.toml": "[project]\nname = 'demo'\n",
            "requirements.txt": "requests==2.0\n",
            "requirements-dev.txt": "pytest\n",
            "setup.cfg": "",
            "pytest.ini": "",
            "README.md": "# Demo\n",
            "src/demo/__init__.py": "",
            "src/demo/core.py": "",
            "src/demo/sub/__init__.py": "",
            "src/demo/sub/helpers.py": "",
            "tests/__init__.py": "",
            "tests/conftest.py": "",
            "tests/test_core.py": "",
            "tests/unit/test_helpers.py": "",
            "docs/index.md": "",
            ".git/config": "",
            ".git/hooks/pre-commit.py": "",
            ".venv/lib/site.py": "",
            "node_modules/pkg/index.js": "",
            "src/demo/__pycache__/core.cpython-312.pyc": "",
            "demo.egg-info/PKG-INFO": "",
            ".pytest_cache/v/cache.py": "",
        },
    )


def test_src_layout_project(src_layout_project: Path) -> None:
    report = analyze_structure(src_layout_project)

    assert report.complete is True
    assert report.limitations == []
    assert report.python_files == [
        "src/demo/__init__.py",
        "src/demo/core.py",
        "src/demo/sub/__init__.py",
        "src/demo/sub/helpers.py",
        "tests/__init__.py",
        "tests/conftest.py",
        "tests/test_core.py",
        "tests/unit/test_helpers.py",
    ]
    assert report.config_files == [
        ConfigFile(path="pyproject.toml", kind=ConfigKind.PYPROJECT),
        ConfigFile(path="pytest.ini", kind=ConfigKind.PYTEST_INI),
        ConfigFile(path="requirements-dev.txt", kind=ConfigKind.REQUIREMENTS),
        ConfigFile(path="requirements.txt", kind=ConfigKind.REQUIREMENTS),
        ConfigFile(path="setup.cfg", kind=ConfigKind.SETUP_CFG),
    ]
    assert report.relevant_directories == [
        RelevantDirectory(path="docs", kind=DirectoryKind.DOCS),
        RelevantDirectory(path="src", kind=DirectoryKind.SOURCE),
        RelevantDirectory(path="src/demo", kind=DirectoryKind.PACKAGE),
        RelevantDirectory(path="tests", kind=DirectoryKind.TESTS),
    ]
    assert report.tests.has_tests is True
    assert report.tests.test_file_count == 3  # conftest, test_core, unit/test_helpers
    assert report.tests.test_directories == ["tests"]
    assert report.documentation.has_documentation is True
    assert report.documentation.readme_files == ["README.md"]
    assert report.documentation.docs_directories == ["docs"]


def test_ignores_dependencies_caches_and_vcs(src_layout_project: Path) -> None:
    report = analyze_structure(src_layout_project)

    assert report.ignored_directories == [
        ".git",
        ".pytest_cache",
        ".venv",
        "demo.egg-info",
        "node_modules",
        "src/demo/__pycache__",
    ]
    assert not any(".git" in p or ".venv" in p or "cache" in p for p in report.python_files)


def test_flat_project_without_tests_or_docs(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"main.py": "", "utils.py": "", "data.csv": ""})

    report = analyze_structure(root)

    assert report.complete is True
    assert report.files_examined == 3
    assert report.python_files == ["main.py", "utils.py"]
    assert report.config_files == []
    assert report.tests.has_tests is False
    assert report.tests.test_file_count == 0
    assert report.documentation.has_documentation is False


def test_flat_layout_package_and_test_patterns(tmp_path: Path) -> None:
    root = make_project(
        tmp_path,
        {
            "setup.py": "",
            "tox.ini": "",
            "Pipfile": "",
            "poetry.lock": "",
            "ruff.toml": "",
            ".pre-commit-config.yaml": "",
            "README.rst": "",
            "mylib/__init__.py": "",
            "mylib/api.py": "",
            "mylib/api_test.py": "",
            "test/test_api.py": "",
        },
    )

    report = analyze_structure(root)

    kinds = {c.path: c.kind for c in report.config_files}
    assert kinds == {
        ".pre-commit-config.yaml": ConfigKind.PRE_COMMIT,
        "Pipfile": ConfigKind.PIPFILE,
        "poetry.lock": ConfigKind.LOCKFILE,
        "ruff.toml": ConfigKind.LINTER,
        "setup.py": ConfigKind.SETUP_PY,
        "tox.ini": ConfigKind.TOX_INI,
    }
    assert RelevantDirectory(path="mylib", kind=DirectoryKind.PACKAGE) in (
        report.relevant_directories
    )
    assert report.tests.test_file_count == 2  # mylib/api_test.py e test/test_api.py
    assert report.tests.test_directories == ["test"]
    assert report.documentation.readme_files == ["README.rst"]
    # setup.py é detectado como configuração e também como arquivo Python.
    assert "setup.py" in report.python_files


def test_non_python_project(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"package.json": "{}", "index.js": "", "README": ""})

    report = analyze_structure(root)

    assert report.complete is True
    assert report.python_files == []
    assert report.config_files == []
    assert report.documentation.readme_files == ["README"]


def test_empty_project(tmp_path: Path) -> None:
    report = analyze_structure(tmp_path)

    assert report.complete is True
    assert report.files_examined == 0
    assert report.python_files == []
    assert report.tests.has_tests is False


def test_analyzes_codeguardian_itself() -> None:
    report = analyze_structure(PROJECT_ROOT)

    assert "app/main.py" in report.python_files
    assert "tests/test_structure_analyzer.py" in report.python_files
    assert ConfigFile(path="pyproject.toml", kind=ConfigKind.PYPROJECT) in report.config_files
    assert report.tests.has_tests is True
    assert ".venv" in report.ignored_directories
    assert not any(p.startswith(".venv/") for p in report.python_files)


# --- Nenhum código é executado -----------------------------------------------


def test_does_not_execute_repository_code(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    payload = f"open({str(marker)!r}, 'w').write('pwned')\n"
    root = make_project(
        tmp_path / "project",
        {
            "setup.py": payload,
            "conftest.py": payload,
            "pkg/__init__.py": payload,
            "tests/test_x.py": payload,
        },
    )

    report = analyze_structure(root)

    assert report.tests.has_tests is True
    assert not marker.exists()
    assert "pkg" not in sys.modules


# --- Limites -----------------------------------------------------------------


def test_depth_limit_marks_report_incomplete(tmp_path: Path) -> None:
    root = make_project(
        tmp_path, {"top.py": "", "a/one.py": "", "a/b/two.py": "", "a/b/c/x.py": ""}
    )

    report = analyze_structure(root, StructureLimits(max_depth=2))

    assert report.python_files == ["a/b/two.py", "a/one.py", "top.py"]
    assert report.complete is False
    assert any("profundidade 2" in item for item in report.limitations)


def test_depth_zero_examines_only_root(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"top.py": "", "pkg/inner.py": ""})

    report = analyze_structure(root, StructureLimits(max_depth=0))

    assert report.python_files == ["top.py"]
    assert report.complete is False


def test_file_limit_stops_scan_and_keeps_root_files(tmp_path: Path) -> None:
    files = {f"deep/module_{i:02}.py": "" for i in range(20)}
    files["pyproject.toml"] = ""
    root = make_project(tmp_path, files)

    report = analyze_structure(root, StructureLimits(max_files=5))

    assert report.files_examined == 5
    assert report.complete is False
    assert any("Limite de 5 arquivos" in item for item in report.limitations)
    # Busca em largura: a configuração da raiz é examinada antes dos subdiretórios.
    assert ConfigFile(path="pyproject.toml", kind=ConfigKind.PYPROJECT) in report.config_files
    assert len(report.python_files) == 4


def test_exact_file_limit_is_complete(tmp_path: Path) -> None:
    root = make_project(tmp_path, {f"m{i}.py": "" for i in range(3)})

    report = analyze_structure(root, StructureLimits(max_files=3))

    assert report.files_examined == 3
    assert report.complete is True


@pytest.mark.parametrize(
    "kwargs", [{"max_depth": -1}, {"max_depth": 100}, {"max_files": 0}, {"max_files": -1}]
)
def test_limits_validation(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        StructureLimits(**kwargs)


# --- Links e erros -----------------------------------------------------------


def test_does_not_follow_links_outside_root(tmp_path: Path) -> None:
    outside = make_project(tmp_path / "outside", {"secret.py": "", "pyproject.toml": ""})
    root = make_project(tmp_path / "project", {"main.py": ""})
    create_dir_link(root / "escape", outside)

    report = analyze_structure(root)

    assert report.python_files == ["main.py"]
    assert report.config_files == []
    assert report.skipped_links == 1


def test_does_not_follow_file_symlinks(tmp_path: Path) -> None:
    outside = make_project(tmp_path / "outside", {"secret.py": ""})
    root = make_project(tmp_path / "project", {"main.py": ""})
    try:
        os.symlink(outside / "secret.py", root / "linked.py")
    except OSError:
        pytest.skip("Sem permissão para criar links simbólicos de arquivo.")

    report = analyze_structure(root)

    assert report.python_files == ["main.py"]
    assert report.skipped_links == 1


def test_rejects_root_link(tmp_path: Path) -> None:
    target = make_project(tmp_path / "real", {"main.py": ""})
    link = tmp_path / "link"
    create_dir_link(link, target)

    with pytest.raises(StructureAnalysisError, match="link"):
        analyze_structure(link)


def test_rejects_missing_root(tmp_path: Path) -> None:
    with pytest.raises(StructureAnalysisError, match="não existe"):
        analyze_structure(tmp_path / "missing")


def test_rejects_file_as_root(tmp_path: Path) -> None:
    file = tmp_path / "file.py"
    file.write_text("", encoding="utf-8")

    with pytest.raises(StructureAnalysisError):
        analyze_structure(file)


def test_unreadable_directory_marks_report_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_project(tmp_path, {"main.py": "", "locked/hidden.py": ""})
    real_scandir = os.scandir

    def scandir(path: Path) -> object:
        if Path(path).name == "locked":
            raise PermissionError("access denied")
        return real_scandir(path)

    monkeypatch.setattr(structure_analyzer.os, "scandir", scandir)

    report = analyze_structure(root)

    assert report.python_files == ["main.py"]
    assert report.complete is False
    assert any("não puderam ser lidos" in item for item in report.limitations)


# --- Serialização ------------------------------------------------------------


def test_report_serializes_to_json(src_layout_project: Path) -> None:
    report = analyze_structure(src_layout_project)

    data = json.loads(report.model_dump_json())

    assert data["complete"] is True
    assert data["config_files"][0] == {"path": "pyproject.toml", "kind": "pyproject"}
    assert data["relevant_directories"][0] == {"path": "docs", "kind": "docs"}
