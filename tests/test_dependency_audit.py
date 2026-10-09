import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app import dependency_audit
from app.dependency_audit import (
    AuditSettings,
    AuditStatus,
    Vulnerability,
    audit_dependencies,
)
from app.process_runner import ProcessResult, ProcessTimeoutError

# Trechos reais da saída do pip-audit 2.10 (com ids repetidos, como ele emite).
JINJA2_VULNS = [
    {"id": "PYSEC-2019-217", "fix_versions": ["2.10.1"], "aliases": ["CVE-2019-10906"]},
    {
        "id": "PYSEC-2019-217",
        "fix_versions": ["2.10.1"],
        "aliases": ["GHSA-462w-v97r-4m45", "CVE-2019-10906"],
    },
    {"id": "PYSEC-2014-8", "fix_versions": ["2.7.2"], "aliases": ["CVE-2014-1402"]},
]

NETWORK_TRACEBACK = b"""\
Traceback (most recent call last):
  File "...requests/adapters.py", line 696, in send
requests.exceptions.ConnectionError: HTTPSConnectionPool(host='pypi.org', port=443):
Max retries exceeded with url: /pypi/flask/3.1.0/json
"""


def make_project(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def pip_audit_output(*dependencies: dict[str, Any]) -> bytes:
    return json.dumps({"dependencies": list(dependencies), "fixes": []}).encode()


def result(stdout: bytes = b"", *, returncode: int = 1, stderr: bytes = b"") -> ProcessResult:
    return ProcessResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=False,
        stderr_truncated=False,
    )


class RunSpy:
    """Substitui ``run_limited`` registrando o comando e o arquivo enviado."""

    def __init__(self, *responses: ProcessResult | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.requirements: list[str] = []

    def __call__(self, command: list[str], **kwargs: Any) -> ProcessResult:
        self.calls.append((command, kwargs))
        path = Path(command[command.index("--requirement") + 1])
        self.requirements.append(path.read_text(encoding="utf-8"))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


SpyInstaller = Callable[..., RunSpy]


@pytest.fixture
def spy_runner(monkeypatch: pytest.MonkeyPatch) -> SpyInstaller:
    def install(*responses: ProcessResult | Exception) -> RunSpy:
        spy = RunSpy(*responses)
        monkeypatch.setattr(dependency_audit, "run_limited", spy)
        return spy

    return install


@pytest.fixture
def project(tmp_path: Path) -> Path:
    return make_project(
        tmp_path / "repo",
        {
            "requirements.txt": "jinja2==2.4.1\nflask==3.1.0\nrequests>=2\n",
            "pyproject.toml": "[project]\ndependencies = ['flask==3.1.0']\n",
        },
    )


# --- Resultados simulados ------------------------------------------------------


def test_vulnerabilities_found(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(
        result(
            pip_audit_output(
                {"name": "flask", "version": "3.1.0", "vulns": []},
                {"name": "jinja2", "version": "2.4.1", "vulns": JINJA2_VULNS},
            )
        )
    )

    report = audit_dependencies(project)

    assert report.status is AuditStatus.VULNERABILITIES_FOUND
    assert report.complete is True
    assert report.tool == "pip-audit"
    assert report.tool_version is not None
    assert report.vulnerability_service == "pypi"
    assert report.vulnerable_package_count == 1
    assert report.vulnerability_count == 2  # ids repetidos agrupados

    flask, jinja2 = report.packages
    assert (flask.name, flask.version, flask.vulnerabilities) == ("flask", "3.1.0", [])
    assert flask.sources == ["pyproject.toml", "requirements.txt"]
    assert (jinja2.name, jinja2.version) == ("jinja2", "2.4.1")
    assert jinja2.vulnerabilities == [
        Vulnerability(id="PYSEC-2014-8", aliases=["CVE-2014-1402"], fix_versions=["2.7.2"]),
        Vulnerability(
            id="PYSEC-2019-217",
            aliases=["CVE-2019-10906", "GHSA-462w-v97r-4m45"],
            fix_versions=["2.10.1"],
        ),
    ]
    # Dependências sem versão fixa são registradas, não auditadas.
    assert [u.requirement for u in report.unaudited] == ["requests>=2"]


def test_no_vulnerabilities(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(
        result(
            pip_audit_output(
                {"name": "flask", "version": "3.1.0", "vulns": []},
                {"name": "jinja2", "version": "2.4.1", "vulns": []},
            ),
            returncode=0,
        )
    )

    report = audit_dependencies(project)

    assert report.status is AuditStatus.NO_VULNERABILITIES
    assert report.complete is True
    assert report.vulnerability_count == 0
    assert len(report.packages) == 2


def test_package_not_found_on_source(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(
        result(
            pip_audit_output(
                {"name": "flask", "version": "3.1.0", "vulns": []},
                {"name": "jinja2", "skip_reason": "Dependency not found on PyPI"},
            ),
            returncode=0,
        )
    )

    report = audit_dependencies(project)

    assert report.status is AuditStatus.NO_VULNERABILITIES
    assert [p.name for p in report.packages] == ["flask"]
    skipped = {u.requirement: u.reason for u in report.unaudited}
    assert skipped["jinja2==2.4.1"] == "Pacote não encontrado na fonte de vulnerabilidades."


def test_missing_package_in_output_is_unaudited(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(result(pip_audit_output({"name": "flask", "version": "3.1.0", "vulns": []})))

    report = audit_dependencies(project)

    assert "jinja2==2.4.1" in {u.requirement for u in report.unaudited}


def test_source_unavailable(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(result(b"", stderr=NETWORK_TRACEBACK))

    report = audit_dependencies(project)

    assert report.status is AuditStatus.SOURCE_UNAVAILABLE
    assert report.complete is False
    assert report.error is not None and "indisponível" in report.error
    assert "pypi.org" not in report.error


def test_tool_failure(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(result(b"", stderr=b"ERROR:pip_audit._cli:/srv/internal/secret failure"))

    report = audit_dependencies(project)

    assert report.status is AuditStatus.FAILED
    assert report.error == "O pip-audit terminou com erro."
    assert "secret" not in report.model_dump_json()


@pytest.mark.parametrize(
    "stdout",
    [b"not json", b"\xff", b'{"deps": []}', b'{"dependencies": [{"version": "1"}]}', b"[]"],
)
def test_unexpected_output(project: Path, spy_runner: SpyInstaller, stdout: bytes) -> None:
    spy_runner(result(stdout))

    report = audit_dependencies(project)

    assert report.status is AuditStatus.FAILED


def test_timeout(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(ProcessTimeoutError())

    report = audit_dependencies(project)

    assert report.status is AuditStatus.TIMEOUT
    assert report.complete is False


def test_failure_to_start(project: Path, spy_runner: SpyInstaller) -> None:
    spy_runner(OSError("not found"))

    report = audit_dependencies(project)

    assert report.status is AuditStatus.FAILED
    assert report.error == "Não foi possível iniciar o pip-audit."


def test_output_limit(project: Path, spy_runner: SpyInstaller) -> None:
    truncated = ProcessResult(
        returncode=1, stdout=b'{"dep', stderr=b"", stdout_truncated=True, stderr_truncated=False
    )
    spy_runner(truncated)

    report = audit_dependencies(project)

    assert report.status is AuditStatus.OUTPUT_LIMIT


# --- Nada a auditar ------------------------------------------------------------


def test_no_dependency_files(tmp_path: Path, spy_runner: SpyInstaller) -> None:
    spy = spy_runner()
    root = make_project(tmp_path, {"main.py": ""})

    report = audit_dependencies(root)

    assert report.status is AuditStatus.NO_DEPENDENCY_FILES
    assert report.complete is True
    assert spy.calls == []


def test_no_pinned_dependencies(tmp_path: Path, spy_runner: SpyInstaller) -> None:
    spy = spy_runner()
    root = make_project(tmp_path, {"requirements.txt": "flask\nrequests>=2\n"})

    report = audit_dependencies(root)

    assert report.status is AuditStatus.NO_AUDITABLE_DEPENDENCIES
    assert len(report.unaudited) == 2
    assert spy.calls == []


# --- Ambiente controlado -------------------------------------------------------


def test_command_environment_and_sanitized_input(
    project: Path,
    spy_runner: SpyInstaller,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "supersecret")
    monkeypatch.setenv("PIP_INDEX_URL", "http://internal.example/simple")
    spy = spy_runner(result(pip_audit_output(), returncode=0))

    audit_dependencies(project, settings=AuditSettings(vulnerability_service="osv"))

    command, kwargs = spy.calls[0]
    assert command[:4] == [sys.executable, "-I", "-m", "pip_audit"]
    for flag in ("--no-deps", "--disable-pip"):
        assert flag in command
    assert command[command.index("--format") + 1] == "json"
    assert command[command.index("--vulnerability-service") + 1] == "osv"

    requirements = Path(command[command.index("--requirement") + 1])
    workdir = kwargs["cwd"]
    assert requirements.parent == workdir
    assert project not in requirements.parents  # o arquivo do repositório nunca é usado
    assert spy.requirements == ["flask==3.1.0\njinja2==2.4.1\n"]

    env = kwargs["env"]
    assert "supersecret" not in env.values()
    assert "PIP_INDEX_URL" not in env
    for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
        assert env[name] == str(workdir)
    assert not workdir.exists()  # diretório temporário removido


def test_duplicate_names_run_in_separate_batches(tmp_path: Path, spy_runner: SpyInstaller) -> None:
    root = make_project(
        tmp_path,
        {"requirements.txt": "flask==3.1.0\n", "requirements-old.txt": "flask==2.0.0\n"},
    )
    spy = spy_runner(
        result(pip_audit_output({"name": "flask", "version": "2.0.0", "vulns": []}), returncode=0),
        result(pip_audit_output({"name": "flask", "version": "3.1.0", "vulns": []}), returncode=0),
    )

    report = audit_dependencies(root)

    assert spy.requirements == ["flask==2.0.0\n", "flask==3.1.0\n"]
    assert [(p.name, p.version) for p in report.packages] == [
        ("flask", "2.0.0"),
        ("flask", "3.1.0"),
    ]


def test_max_packages_limit(tmp_path: Path, spy_runner: SpyInstaller) -> None:
    root = make_project(tmp_path, {"requirements.txt": "a==1\nb==1\nc==1\n"})
    spy = spy_runner(result(pip_audit_output(), returncode=0))

    report = audit_dependencies(root, settings=AuditSettings(max_packages=2))

    assert spy.requirements == ["a==1\nb==1\n"]
    assert any("Limite de 2 pacotes" in u.reason for u in report.unaudited)


def test_custom_interpreter_has_unknown_version(project: Path, spy_runner: SpyInstaller) -> None:
    spy = spy_runner(result(pip_audit_output(), returncode=0))

    report = audit_dependencies(
        project, settings=AuditSettings(python_executable="/opt/tools/bin/python")
    )

    assert spy.calls[0][0][0] == "/opt/tools/bin/python"
    assert report.tool_version is None


def test_collection_errors_are_reported(tmp_path: Path, spy_runner: SpyInstaller) -> None:
    spy_runner()
    root = make_project(tmp_path, {"pyproject.toml": "[project\n"})

    report = audit_dependencies(root)

    assert report.status is AuditStatus.NO_AUDITABLE_DEPENDENCIES
    assert report.collection_errors == [
        "pyproject.toml: arquivo inválido ou em formato inesperado."
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"vulnerability_service": "evil"},
        {"timeout_seconds": 0},
        {"request_timeout_seconds": 0},
        {"max_packages": 0},
    ],
)
def test_settings_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AuditSettings(**kwargs)
