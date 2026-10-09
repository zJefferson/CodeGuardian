import json
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app import ruff_analyzer
from app.process_runner import ProcessResult, ProcessTimeoutError
from app.ruff_analyzer import (
    RuffFinding,
    RuffNotAvailableError,
    RuffSettings,
    RuffStatus,
    analyze_with_ruff,
)
from app.structure_analyzer import analyze_structure

SAMPLE_WITH_ISSUES = """\
import os
import subprocess


def f(x=[]):
    subprocess.call("ls", shell=True)
    return x == None
"""

CLEAN_SAMPLE = """\
def add(a: int, b: int) -> int:
    return a + b
"""


def make_project(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def rules_of(findings: list[RuffFinding]) -> set[str | None]:
    return {f.rule for f in findings}


# --- Exemplos conhecidos (Ruff real) -----------------------------------------


def test_detects_known_issues(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"sample.py": SAMPLE_WITH_ISSUES})

    report = analyze_with_ruff(root)

    assert report.status is RuffStatus.COMPLETED
    assert report.complete is True
    assert report.error is None
    assert {"F401", "B006", "S602", "E711"} <= rules_of(report.findings)
    assert report.finding_count == len(report.findings)
    assert report.tool_version is not None

    unused = next(f for f in report.findings if f.rule == "F401")
    assert unused.file == "sample.py"
    assert (unused.line, unused.column) == (1, 8)
    assert (unused.end_line, unused.end_column) == (1, 10)
    assert "`os` imported but unused" in unused.message
    assert unused.suggestion == "Remove unused import: `os`"
    assert unused.url is not None and unused.url.startswith("https://docs.astral.sh/ruff/")

    shell = next(f for f in report.findings if f.rule == "S602")
    assert shell.line == 6
    assert shell.suggestion is None


def test_clean_code_has_no_findings(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"clean.py": CLEAN_SAMPLE})

    report = analyze_with_ruff(root)

    assert report.status is RuffStatus.COMPLETED
    assert report.findings == []
    assert report.finding_count == 0
    assert report.findings_truncated is False


def test_reports_syntax_errors(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"broken.py": "def g(:\n    pass\n"})

    report = analyze_with_ruff(root)

    assert report.status is RuffStatus.COMPLETED
    assert "invalid-syntax" in rules_of(report.findings)
    assert all(f.file == "broken.py" for f in report.findings)


def test_nested_paths_are_relative(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"pkg/sub/mod.py": "import os\n"})

    report = analyze_with_ruff(root)

    assert [f.file for f in report.findings] == ["pkg/sub/mod.py"]


def test_ignores_repository_ruff_configuration(tmp_path: Path) -> None:
    outside = tmp_path / "outside.toml"
    outside.write_text("[lint]\nignore = ['ALL']\n", encoding="utf-8")
    root = make_project(
        tmp_path / "repo",
        {
            "pyproject.toml": (
                "[tool.ruff]\n"
                "extend = '../outside.toml'\n"
                "cache-dir = '../stolen-cache'\n"
                "[tool.ruff.lint]\nignore = ['F401']\n"
            ),
            "ruff.toml": "[lint]\nignore = ['ALL']\n",
            "mod.py": "import os\n",
        },
    )

    report = analyze_with_ruff(root)

    assert report.status is RuffStatus.COMPLETED
    assert "F401" in rules_of(report.findings)
    assert not (tmp_path / "stolen-cache").exists()
    assert not (root / ".ruff_cache").exists()


def test_does_not_execute_repository_code(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    payload = f"open({str(marker)!r}, 'w').write('pwned')\n"
    root = make_project(
        tmp_path / "repo",
        {"setup.py": payload, "conftest.py": payload, "pkg/__init__.py": payload},
    )

    report = analyze_with_ruff(root)

    assert report.status is RuffStatus.COMPLETED
    assert not marker.exists()


def test_custom_rule_selection(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"sample.py": SAMPLE_WITH_ISSUES})

    report = analyze_with_ruff(root, settings=RuffSettings(rules=("F",)))

    assert report.rules == ["F"]
    assert rules_of(report.findings) == {"F401"}


def test_findings_are_capped(tmp_path: Path) -> None:
    source = "".join(f"import mod{i}\n" for i in range(5))
    root = make_project(tmp_path, {"many.py": source})

    report = analyze_with_ruff(root, settings=RuffSettings(rules=("F",), max_findings=2))

    assert report.finding_count == 5
    assert len(report.findings) == 2
    assert report.findings_truncated is True
    assert [f.line for f in report.findings] == [1, 2]


def test_reuses_structure_report(tmp_path: Path) -> None:
    root = make_project(tmp_path, {"mod.py": "import os\n"})
    structure = analyze_structure(root)

    report = analyze_with_ruff(root, structure=structure)

    assert rules_of(report.findings) == {"F401"}


# --- Sem arquivos Python -----------------------------------------------------


def fail_if_called(*_args: Any, **_kwargs: Any) -> None:
    pytest.fail("O Ruff não deveria ser executado.")


def test_no_python_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = make_project(tmp_path, {"index.js": "", "README.md": ""})
    monkeypatch.setattr(ruff_analyzer, "run_limited", fail_if_called)

    report = analyze_with_ruff(root)

    assert report.status is RuffStatus.NO_PYTHON_FILES
    assert report.complete is True
    assert report.findings == []


def test_empty_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ruff_analyzer, "run_limited", fail_if_called)

    report = analyze_with_ruff(tmp_path)

    assert report.status is RuffStatus.NO_PYTHON_FILES


# --- Respostas simuladas -----------------------------------------------------


class RunSpy:
    def __init__(self, result: ProcessResult | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> ProcessResult:
        self.calls.append((command, kwargs))
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def simulated(
    stdout: bytes = b"[]",
    *,
    returncode: int = 0,
    stderr: bytes = b"",
    stdout_truncated: bool = False,
) -> ProcessResult:
    return ProcessResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=False,
    )


@pytest.fixture
def py_project(tmp_path: Path) -> Path:
    return make_project(tmp_path, {"mod.py": "x = 1\n"})


def install(monkeypatch: pytest.MonkeyPatch, spy: RunSpy) -> RunSpy:
    monkeypatch.setattr(ruff_analyzer, "run_limited", spy)
    return spy


def test_command_and_environment(py_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "supersecret")
    spy = install(monkeypatch, RunSpy(simulated()))

    analyze_with_ruff(py_project, settings=RuffSettings(timeout_seconds=7, max_output_bytes=99))

    command, kwargs = spy.calls[0]
    assert command[1] == "check"
    for flag in ("--isolated", "--no-cache", "--no-fix", "--output-format=json"):
        assert flag in command
    assert "--select=E4,E7,E9,F,B,S" in command
    assert command[-2:] == ["--", "."]
    assert kwargs["cwd"] == py_project
    assert kwargs["timeout_seconds"] == 7
    assert kwargs["max_output_bytes"] == 99
    assert kwargs["capture_stdout"] is True
    assert "supersecret" not in kwargs["env"].values()


def test_timeout(py_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, RunSpy(error=ProcessTimeoutError()))

    report = analyze_with_ruff(py_project)

    assert report.status is RuffStatus.TIMEOUT
    assert report.complete is False
    assert report.error == "O Ruff excedeu o tempo limite."
    assert report.findings == []


def test_failure_to_start(py_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, RunSpy(error=OSError("exec format error")))

    report = analyze_with_ruff(py_project)

    assert report.status is RuffStatus.FAILED
    assert report.error == "Não foi possível iniciar o Ruff."


def test_ruff_not_available(py_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def missing() -> str:
        raise RuffNotAvailableError

    monkeypatch.setattr(ruff_analyzer, "_find_ruff", missing)
    monkeypatch.setattr(ruff_analyzer, "run_limited", fail_if_called)

    report = analyze_with_ruff(py_project)

    assert report.status is RuffStatus.FAILED
    assert "não está disponível" in (report.error or "")


def test_tool_error_exit_code(py_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(
        monkeypatch,
        RunSpy(simulated(b"", returncode=2, stderr=b"error: /srv/internal/path secret")),
    )

    report = analyze_with_ruff(py_project)

    assert report.status is RuffStatus.FAILED
    assert report.error == "O Ruff terminou com erro."
    assert "secret" not in report.model_dump_json()


def test_output_limit(py_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, RunSpy(simulated(b'[{"filename": "a', stdout_truncated=True)))

    report = analyze_with_ruff(py_project)

    assert report.status is RuffStatus.OUTPUT_LIMIT
    assert report.complete is False


@pytest.mark.parametrize(
    "stdout",
    [
        b"not json",
        b"\xff\xfe",
        b'{"filename": "a.py"}',
        b'[{"filename": "a.py"}]',
        b'[{"filename": "a.py", "message": "m", "location": {"row": "x", "column": 1}}]',
    ],
)
def test_unexpected_output(
    py_project: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    install(monkeypatch, RunSpy(simulated(stdout, returncode=1)))

    report = analyze_with_ruff(py_project)

    assert report.status is RuffStatus.FAILED
    assert report.error == "A saída do Ruff está em formato inesperado."


def test_simulated_response_is_sanitized(py_project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outside = "/srv/server/secret/file.py" if sys.platform != "win32" else r"C:\srv\secret\file.py"
    diagnostics = [
        {
            "filename": str(py_project / "mod.py"),
            "code": "F401",
            "message": "M" * 2000,
            "location": {"row": 3, "column": 5},
            "end_location": None,
            "fix": {"message": "Remove it", "applicability": "safe", "edits": []},
            "url": "javascript:alert(1)",
        },
        {
            "filename": outside,
            "code": None,
            "message": "outside",
            "location": {"row": 1, "column": 1},
            "fix": None,
            "url": None,
        },
    ]
    install(monkeypatch, RunSpy(simulated(json.dumps(diagnostics).encode(), returncode=1)))

    report = analyze_with_ruff(py_project)

    assert report.status is RuffStatus.COMPLETED
    first, second = report.findings
    assert first.file == "file.py"  # caminho fora da raiz: só o nome
    assert first.rule is None
    assert second.file == "mod.py"
    assert (second.line, second.column, second.end_line) == (3, 5, None)
    assert len(second.message) == 500
    assert second.suggestion == "Remove it"
    assert second.url is None


# --- Validação das configurações ---------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rules": ()},
        {"rules": ("--config=evil.toml",)},
        {"rules": ("E4,F",)},
        {"rules": ("e4",)},
        {"timeout_seconds": 0},
        {"max_output_bytes": 0},
        {"max_findings": 0},
    ],
)
def test_settings_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RuffSettings(**kwargs)
