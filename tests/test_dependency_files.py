import json
from pathlib import Path

import pytest

from app.dependency_files import (
    CollectionLimits,
    DeclaredDependency,
    DependencyFile,
    DependencyFileKind,
    collect_dependencies,
)


def make_project(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def pinned(collection: object) -> set[tuple[str, str]]:
    return {(d.name, d.version) for d in collection.dependencies}  # type: ignore[attr-defined]


def reasons(collection: object) -> dict[str, str]:
    return {u.requirement: u.reason for u in collection.unaudited}  # type: ignore[attr-defined]


# --- requirements.txt ----------------------------------------------------------


REQUIREMENTS = """\
# comentário
Flask==3.1.0
requests == 2.31.0  # comentário no fim
Jinja2[i18n]==2.4.1 ; python_version >= "3.8"
urllib3===2.0.0
numpy>=1.0
django
pandas==2.*
idna==3.7 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
-r ../../outside/secret.txt
-e .
--index-url https://internal.example/simple
-i https://internal.example/simple
--extra-index-url http://169.254.169.254/
pkg @ https://example.com/pkg.tar.gz
./local/package
not a valid requirement!!!
"""


def test_requirements_txt(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"requirements.txt": REQUIREMENTS})

    collection = collect_dependencies(root)

    assert collection.files == [
        DependencyFile(path="requirements.txt", kind=DependencyFileKind.REQUIREMENTS)
    ]
    assert pinned(collection) == {
        ("flask", "3.1.0"),
        ("requests", "2.31.0"),
        ("jinja2", "2.4.1"),
        ("urllib3", "2.0.0"),
        ("idna", "3.7"),
    }
    skipped = reasons(collection)
    assert skipped["numpy>=1.0"] == "Versão não fixada (use ==)."
    assert skipped["django"] == "Versão não fixada (use ==)."
    assert skipped["pandas==2.*"] == "Versão não fixada (use ==)."
    for option in ("-r ../../outside/secret.txt", "-e .", "-i https://internal.example/simple"):
        assert skipped[option] == "Opção de requirements não suportada."
    assert skipped["pkg @ https://example.com/pkg.tar.gz"].startswith("Requisito por URL")
    assert skipped["./local/package"] == "Requisito inválido."
    assert skipped["not a valid requirement!!!"] == "Requisito inválido."
    assert collection.errors == []


def test_requirements_line_numbers(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"requirements.txt": REQUIREMENTS})

    collection = collect_dependencies(root)

    lines = {u.requirement: u.line for u in collection.unaudited}
    assert lines["numpy>=1.0"] == 6
    assert lines["-r ../../outside/secret.txt"] == 12


def test_include_options_are_not_followed(tmp_path: Path) -> None:
    make_project(tmp_path / "outside", {"secret.txt": "leaked==1.0\n"})
    root = make_project(
        tmp_path / "repo",
        {"requirements.txt": "-r ../outside/secret.txt\n-c ../outside/secret.txt\n"},
    )

    collection = collect_dependencies(root)

    assert collection.dependencies == []
    assert len(collection.unaudited) == 2


def test_multiple_requirement_files_and_sources(tmp_path: Path) -> None:
    root = make_project(
        tmp_path,
        {
            "requirements.txt": "flask==3.1.0\n",
            "requirements-dev.txt": "flask==3.1.0\npytest==8.0.0\n",
            "docs/requirements.txt": "sphinx==7.0.0\n",
            "requirements.in": "flask\n",  # entrada do pip-tools: ignorada
        },
    )

    collection = collect_dependencies(root)

    assert [f.path for f in collection.files] == [
        "docs/requirements.txt",
        "requirements-dev.txt",
        "requirements.txt",
    ]
    assert (
        DeclaredDependency(
            name="flask", version="3.1.0", sources=["requirements-dev.txt", "requirements.txt"]
        )
        in collection.dependencies
    )
    assert pinned(collection) == {("flask", "3.1.0"), ("pytest", "8.0.0"), ("sphinx", "7.0.0")}


# --- pyproject.toml ------------------------------------------------------------


def test_pyproject(tmp_path: Path) -> None:
    root = make_project(
        tmp_path,
        {
            "pyproject.toml": """
[project]
name = "demo"
dependencies = ["fastapi==0.110.0", "pydantic>=2"]

[project.optional-dependencies]
dev = ["pytest==8.0.0"]

[dependency-groups]
lint = ["ruff==0.4.0", {include-group = "dev"}]

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.0.0"
""",
        },
    )

    collection = collect_dependencies(root)

    assert collection.files[0].kind is DependencyFileKind.PYPROJECT
    assert pinned(collection) == {
        ("fastapi", "0.110.0"),
        ("pytest", "8.0.0"),
        ("ruff", "0.4.0"),
    }
    assert reasons(collection) == {"pydantic>=2": "Versão não fixada (use ==)."}


@pytest.mark.parametrize(
    "content",
    [
        "[project\nname = 'x'",
        "[project]\ndependencies = 'requests==1.0'\n",
        "[project]\ndependencies = [1, 2]\n",
        "project = 'x'\n",
    ],
)
def test_invalid_pyproject_is_reported(tmp_path: Path, content: str) -> None:
    root = make_project(tmp_path, {"pyproject.toml": content})

    collection = collect_dependencies(root)

    assert collection.dependencies == []
    assert collection.errors == ["pyproject.toml: arquivo inválido ou em formato inesperado."]


# --- Lockfiles -----------------------------------------------------------------


def test_pipfile_lock(tmp_path: Path) -> None:
    lock = {
        "_meta": {"hash": {"sha256": "x"}},
        "default": {
            "requests": {"version": "==2.31.0", "hashes": []},
            "mylib": {"git": "https://github.com/x/mylib.git", "ref": "abc"},
        },
        "develop": {"pytest": {"version": "==8.0.0"}},
    }
    root = make_project(tmp_path, {"Pipfile": "", "Pipfile.lock": json.dumps(lock)})

    collection = collect_dependencies(root)

    assert [f.kind for f in collection.files] == [DependencyFileKind.PIPFILE_LOCK]
    assert pinned(collection) == {("requests", "2.31.0"), ("pytest", "8.0.0")}
    assert reasons(collection) == {"mylib": "Dependência sem versão do PyPI."}


def test_poetry_lock(tmp_path: Path) -> None:
    root = make_project(
        tmp_path,
        {
            "poetry.lock": """
[[package]]
name = "Requests"
version = "2.31.0"

[[package]]
name = "private-lib"
version = "1.0.0"
[package.source]
type = "git"
url = "https://github.com/x/private-lib.git"
""",
        },
    )

    collection = collect_dependencies(root)

    assert pinned(collection) == {("requests", "2.31.0")}
    assert reasons(collection) == {"private-lib": "Dependência fora do PyPI (git, caminho ou URL)."}


def test_uv_lock(tmp_path: Path) -> None:
    root = make_project(
        tmp_path,
        {
            "uv.lock": """
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "flask"
version = "3.1.0"
source = { registry = "https://pypi.org/simple" }
""",
        },
    )

    collection = collect_dependencies(root)

    assert pinned(collection) == {("flask", "3.1.0")}
    assert list(reasons(collection)) == ["demo"]


def test_invalid_lockfile_is_reported(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"Pipfile.lock": "{not json", "poetry.lock": "package = 3\n"})

    collection = collect_dependencies(root)

    assert sorted(collection.errors) == [
        "Pipfile.lock: arquivo inválido ou em formato inesperado.",
        "poetry.lock: arquivo inválido ou em formato inesperado.",
    ]


# --- Arquivos e limites --------------------------------------------------------


def test_no_dependency_files(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"main.py": "", "setup.cfg": "", "pdm.lock": ""})

    collection = collect_dependencies(root)

    assert collection.files == []
    assert collection.dependencies == []


def test_file_size_limit(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"requirements.txt": "flask==3.1.0\n" * 100})

    collection = collect_dependencies(root, limits=CollectionLimits(max_file_bytes=50))

    assert collection.files == []
    assert collection.errors == ["requirements.txt: arquivo excede o tamanho máximo permitido."]


def test_file_count_limit(tmp_path: Path) -> None:
    root = make_project(tmp_path, {f"requirements-{i}.txt": "" for i in range(5)})

    collection = collect_dependencies(root, limits=CollectionLimits(max_files=2))

    assert len(collection.files) == 2
    assert any("Limite de 2" in error for error in collection.errors)


def test_non_utf8_file(tmp_path: Path) -> None:
    root = tmp_path
    (root / "requirements.txt").write_bytes(b"flask==3.1.0\n\xff\xfe\n")

    collection = collect_dependencies(root)

    assert collection.errors == ["requirements.txt: arquivo não está em UTF-8."]


def test_does_not_execute_setup_py(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    root = make_project(
        tmp_path / "repo",
        {
            "setup.py": f"open({str(marker)!r}, 'w').write('pwned')\n",
            "requirements.txt": "-e .\n",
        },
    )

    collect_dependencies(root)

    assert not marker.exists()
