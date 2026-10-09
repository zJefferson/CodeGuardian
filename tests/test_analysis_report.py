import json
import shutil
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app import __version__, analysis_report, structure_analyzer
from app.analysis_report import (
    AnalysisReport,
    CheckName,
    CheckStatus,
    OverallStatus,
    analyze_repository,
    build_report,
    git_version,
)
from app.dependency_audit import (
    AuditedPackage,
    AuditStatus,
    DependencyAuditReport,
    Vulnerability,
)
from app.dependency_files import DependencyFile, DependencyFileKind, UnauditedDependency
from app.repository_clone import CloneFailedError
from app.repository_url import parse_github_repository_url
from app.ruff_analyzer import RuffFinding, RuffReport, RuffStatus
from app.structure_analyzer import DocumentationInfo, StructureReport

REPO = parse_github_repository_url("https://github.com/psf/requests")
T0 = datetime(2026, 10, 9, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(seconds=12.3456)


# --- Fábricas de resultados das etapas ----------------------------------------


def structure_report(*, complete: bool = True, python_files: int = 2) -> StructureReport:
    return StructureReport(
        complete=complete,
        limitations=[] if complete else ["Limite de 10 arquivos atingido."],
        files_examined=10,
        python_files=[f"pkg/mod{i}.py" for i in range(python_files)],
        config_files=[],
        relevant_directories=[],
        # Acesso pelo módulo: o pytest tentaria coletar uma classe "Test*" importada.
        tests=structure_analyzer.TestsInfo(
            has_tests=True, test_file_count=1, test_directories=["tests"]
        ),
        documentation=DocumentationInfo(
            has_documentation=True, readme_files=["README.md"], docs_directories=[]
        ),
        ignored_directories=[".git"],
        skipped_links=0,
    )


def finding(rule: str = "F401", line: int = 1) -> RuffFinding:
    return RuffFinding(
        file="pkg/mod0.py",
        line=line,
        column=1,
        end_line=line,
        end_column=5,
        rule=rule,
        message="`os` imported but unused",
        suggestion="Remove unused import: `os`",
        url="https://docs.astral.sh/ruff/rules/unused-import",
    )


def ruff_report(
    status: RuffStatus = RuffStatus.COMPLETED,
    findings: list[RuffFinding] | None = None,
    finding_count: int | None = None,
    error: str | None = None,
) -> RuffReport:
    findings = findings or []
    count = len(findings) if finding_count is None else finding_count
    return RuffReport(
        status=status,
        tool_version="0.16.10",
        rules=["F"],
        findings=findings,
        finding_count=count,
        findings_truncated=count > len(findings),
        error=error,
    )


def audit_report(
    status: AuditStatus = AuditStatus.NO_VULNERABILITIES,
    *,
    vulnerable: bool = False,
    unaudited: int = 0,
    error: str | None = None,
) -> DependencyAuditReport:
    vulns = (
        [Vulnerability(id="PYSEC-2019-217", aliases=["CVE-2019-10906"], fix_versions=["2.10.1"])]
        if vulnerable
        else []
    )
    packages = []
    if status in {AuditStatus.NO_VULNERABILITIES, AuditStatus.VULNERABILITIES_FOUND}:
        packages.append(
            AuditedPackage(
                name="jinja2", version="2.4.1", sources=["requirements.txt"], vulnerabilities=vulns
            )
        )
    return DependencyAuditReport(
        status=status,
        tool_version="2.10.1",
        vulnerability_service="pypi",
        dependency_files=[
            DependencyFile(path="requirements.txt", kind=DependencyFileKind.REQUIREMENTS)
        ],
        packages=packages,
        unaudited=[
            UnauditedDependency(
                source="requirements.txt",
                line=i + 1,
                requirement="flask",
                reason="Versão não fixada.",
            )
            for i in range(unaudited)
        ],
        collection_errors=[],
        vulnerable_package_count=1 if vulnerable else 0,
        vulnerability_count=len(vulns),
        error=error,
    )


def build(**overrides: Any) -> AnalysisReport:
    params: dict[str, Any] = {
        "analysis_id": "analysis-1",
        "started_at": T0,
        "finished_at": T1,
        "duration_seconds": 12.3456,
        "repository": REPO,
        "structure": structure_report(),
        "ruff": ruff_report(),
        "dependencies": audit_report(),
        "git_version": "2.52.0",
    }
    params.update(overrides)
    return build_report(**params)


def statuses(report: AnalysisReport) -> dict[CheckName, CheckStatus]:
    return {check.name: check.status for check in report.checks}


# --- Relatórios completos ------------------------------------------------------


def test_complete_report_without_findings() -> None:
    report = build()

    assert report.overall_status is OverallStatus.NO_ISSUES_FOUND
    assert report.approved is True
    # Execução de testes desabilitada: aparece como skipped e não afeta o resultado.
    assert statuses(report)[CheckName.TESTS] is CheckStatus.SKIPPED
    assert {s for n, s in statuses(report).items() if n is not CheckName.TESTS} == {
        CheckStatus.COMPLETED
    }
    assert report.analysis_id == "analysis-1"
    assert report.repository is not None
    assert report.repository.url == "https://github.com/psf/requests"
    assert (report.started_at, report.finished_at) == (T0, T1)
    assert report.duration_seconds == 12.346
    assert report.tools.codeguardian == __version__
    assert (report.tools.git, report.tools.ruff, report.tools.pip_audit) == (
        "2.52.0",
        "0.16.10",
        "2.10.1",
    )
    counts = report.finding_counts
    assert (counts.ruff_findings, counts.vulnerabilities, counts.unaudited_dependencies) == (
        0,
        0,
        0,
    )
    assert report.warnings == []
    assert report.errors == []


def test_complete_report_with_findings() -> None:
    report = build(
        ruff=ruff_report(findings=[finding(), finding("S101", 2)]),
        dependencies=audit_report(AuditStatus.VULNERABILITIES_FOUND, vulnerable=True),
    )

    assert report.overall_status is OverallStatus.ISSUES_FOUND
    assert report.approved is False
    # Execução de testes desabilitada: aparece como skipped e não afeta o resultado.
    assert statuses(report)[CheckName.TESTS] is CheckStatus.SKIPPED
    assert {s for n, s in statuses(report).items() if n is not CheckName.TESTS} == {
        CheckStatus.COMPLETED
    }
    assert report.finding_counts.ruff_findings == 2
    assert report.finding_counts.vulnerabilities == 1
    assert report.finding_counts.vulnerable_packages == 1
    ruff_check = next(c for c in report.checks if c.name is CheckName.RUFF)
    assert (ruff_check.tool_status, ruff_check.finding_count) == ("completed", 2)
    assert report.ruff is not None and report.ruff.findings[0].rule == "F401"
    assert report.dependencies is not None
    assert report.dependencies.packages[0].vulnerabilities[0].id == "PYSEC-2019-217"


def test_only_ruff_findings_is_not_approved() -> None:
    report = build(ruff=ruff_report(findings=[finding()]))

    assert report.overall_status is OverallStatus.ISSUES_FOUND
    assert report.approved is False


# --- Relatórios parciais -------------------------------------------------------


def test_ruff_timeout_is_incomplete_not_approved() -> None:
    report = build(ruff=ruff_report(RuffStatus.TIMEOUT, error="O Ruff excedeu o tempo limite."))

    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.approved is False
    assert statuses(report)[CheckName.RUFF] is CheckStatus.FAILED
    # Sem resultado, a contagem é desconhecida (None), não zero.
    assert report.finding_counts.ruff_findings is None
    assert report.errors == ["O Ruff excedeu o tempo limite."]


def test_unaudited_dependencies_make_check_partial() -> None:
    report = build(dependencies=audit_report(unaudited=2))

    assert statuses(report)[CheckName.DEPENDENCIES] is CheckStatus.PARTIAL
    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.approved is False
    assert report.finding_counts.unaudited_dependencies == 2
    assert any("2 declaração(ões) não auditada(s)" in w for w in report.warnings)


def test_no_auditable_dependencies_is_partial() -> None:
    report = build(dependencies=audit_report(AuditStatus.NO_AUDITABLE_DEPENDENCIES, unaudited=1))

    assert statuses(report)[CheckName.DEPENDENCIES] is CheckStatus.PARTIAL
    assert report.finding_counts.vulnerabilities is None
    assert report.approved is False


def test_incomplete_structure_is_partial() -> None:
    report = build(structure=structure_report(complete=False))

    assert statuses(report)[CheckName.STRUCTURE] is CheckStatus.PARTIAL
    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.warnings == ["Estrutura: Limite de 10 arquivos atingido."]


def test_truncated_ruff_findings_warn_but_keep_count() -> None:
    report = build(ruff=ruff_report(findings=[finding()], finding_count=1500))

    assert report.finding_counts.ruff_findings == 1500
    assert report.warnings == ["Ruff: 1500 achados; apenas 1 detalhados."]
    assert statuses(report)[CheckName.RUFF] is CheckStatus.COMPLETED


def test_vulnerabilities_with_partial_check_are_reported_but_incomplete() -> None:
    report = build(
        dependencies=audit_report(AuditStatus.VULNERABILITIES_FOUND, vulnerable=True, unaudited=1)
    )

    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.finding_counts.vulnerabilities == 1


# --- Relatórios com falhas -----------------------------------------------------


def test_source_unavailable() -> None:
    message = "A fonte de vulnerabilidades está indisponível; tente novamente mais tarde."
    report = build(dependencies=audit_report(AuditStatus.SOURCE_UNAVAILABLE, error=message))

    assert statuses(report)[CheckName.DEPENDENCIES] is CheckStatus.FAILED
    assert report.finding_counts.vulnerabilities is None
    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.errors == [message]


def test_clone_failure_skips_analysis() -> None:
    report = build(
        repository_error="Repositório não encontrado ou inacessível.",
        structure=None,
        ruff=None,
        dependencies=None,
    )

    assert report.overall_status is OverallStatus.FAILED
    assert report.approved is False
    assert statuses(report) == {
        CheckName.REPOSITORY: CheckStatus.FAILED,
        CheckName.STRUCTURE: CheckStatus.SKIPPED,
        CheckName.RUFF: CheckStatus.SKIPPED,
        CheckName.DEPENDENCIES: CheckStatus.SKIPPED,
        CheckName.TESTS: CheckStatus.SKIPPED,
    }
    assert (report.structure, report.ruff, report.dependencies) == (None, None, None)
    assert report.finding_counts.ruff_findings is None
    assert report.tools.ruff is None
    assert report.errors == ["Repositório não encontrado ou inacessível."]


def test_invalid_url_has_no_repository() -> None:
    report = build(
        repository=None,
        repository_error="Apenas URLs HTTPS são permitidas.",
        structure=None,
        ruff=None,
        dependencies=None,
        git_version=None,
    )

    assert report.repository is None
    assert report.overall_status is OverallStatus.FAILED


def test_all_checks_failed() -> None:
    report = build(
        structure=None,
        structure_error="O diretório analisado não existe.",
        ruff=None,
        ruff_error="Erro interno na análise com Ruff.",
        dependencies=audit_report(AuditStatus.FAILED, error="O pip-audit terminou com erro."),
    )

    assert report.overall_status is OverallStatus.FAILED
    assert len(report.errors) == 3


# --- Sem achados / nada a analisar ---------------------------------------------


def test_nothing_to_analyze_is_not_approved() -> None:
    report = build(
        structure=structure_report(python_files=0),
        ruff=ruff_report(RuffStatus.NO_PYTHON_FILES),
        dependencies=audit_report(AuditStatus.NO_DEPENDENCY_FILES),
    )

    assert report.overall_status is OverallStatus.NOTHING_TO_ANALYZE
    assert report.approved is False
    assert statuses(report)[CheckName.RUFF] is CheckStatus.NOT_APPLICABLE
    assert statuses(report)[CheckName.DEPENDENCIES] is CheckStatus.NOT_APPLICABLE


def test_dependencies_only_project_without_findings() -> None:
    report = build(ruff=ruff_report(RuffStatus.NO_PYTHON_FILES))

    assert report.overall_status is OverallStatus.NO_ISSUES_FOUND
    assert report.approved is True


# --- Exportação ----------------------------------------------------------------


def test_json_export(tmp_path: Path) -> None:
    report = build(ruff=ruff_report(findings=[finding()]))

    path = report.export_json(tmp_path / "report.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["schema_version"] == "1.0"
    assert data["overall_status"] == "issues_found"
    assert data["started_at"] == "2026-10-09T12:00:00Z"
    assert data["checks"][2] == {
        "name": "ruff",
        "status": "completed",
        "tool_status": "completed",
        "finding_count": 1,
        "message": None,
    }
    assert data["ruff"]["findings"][0]["suggestion"] == "Remove unused import: `os`"
    # Apenas o resumo estrutural: sem a lista de arquivos.
    assert data["structure"]["python_file_count"] == 2
    assert "python_files" not in data["structure"]
    assert "ignored_directories" not in data["structure"]
    assert AnalysisReport.model_validate_json(report.to_json()) == report


def test_report_is_immutable() -> None:
    report = build()

    with pytest.raises(ValueError, match="frozen"):
        report.approved = False  # type: ignore[misc]


# --- Execução (etapas simuladas) -----------------------------------------------


class Pipeline:
    """Substitui clonagem e analisadores, registrando as chamadas."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.calls: list[str] = []
        self.clone_error: Exception | None = None
        self.structure: Any = structure_report()
        self.ruff: Any = ruff_report()
        self.audit: Any = audit_report()
        self.received_structure: list[Any] = []
        self.tmp_path = tmp_path
        for name, fake in {
            "cloned_repository": self.cloned_repository,
            "_analyze_structure": self.analyze_structure,
            "_analyze_with_ruff": self.analyze_with_ruff,
            "_audit_dependencies": self.audit_dependencies,
            "git_version": lambda: "2.52.0",
        }.items():
            monkeypatch.setattr(analysis_report, name, fake)

    @contextmanager
    def cloned_repository(self, repository: Any, **_kwargs: Any) -> Iterator[Path]:
        self.calls.append(f"clone:{repository.url}")
        if self.clone_error is not None:
            raise self.clone_error
        yield self.tmp_path

    def _result(self, value: Any) -> Any:
        if isinstance(value, Exception):
            raise value
        return value

    def analyze_structure(self, *_args: Any) -> Any:
        self.calls.append("structure")
        return self._result(self.structure)

    def analyze_with_ruff(self, *_args: Any, structure: Any = None, **_kwargs: Any) -> Any:
        self.calls.append("ruff")
        self.received_structure.append(structure)
        return self._result(self.ruff)

    def audit_dependencies(self, *_args: Any, structure: Any = None, **_kwargs: Any) -> Any:
        self.calls.append("audit")
        self.received_structure.append(structure)
        return self._result(self.audit)


@pytest.fixture
def pipeline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Pipeline:
    return Pipeline(monkeypatch, tmp_path)


def fake_clock() -> Any:
    times = iter([T0, T1])
    return lambda: next(times)


def test_analyze_repository_runs_all_steps(pipeline: Pipeline) -> None:
    report = analyze_repository("https://github.com/psf/requests.git", now=fake_clock())

    assert pipeline.calls == ["clone:https://github.com/psf/requests", "structure", "ruff", "audit"]
    assert pipeline.received_structure == [pipeline.structure, pipeline.structure]
    assert report.overall_status is OverallStatus.NO_ISSUES_FOUND
    assert uuid.UUID(report.analysis_id).version == 4
    assert (report.started_at, report.finished_at) == (T0, T1)
    assert report.duration_seconds == 12.346
    assert report.tools.git == "2.52.0"


def test_invalid_url_with_credentials_is_not_echoed(pipeline: Pipeline) -> None:
    report = analyze_repository("https://user:supersecret@github.com/psf/requests")

    assert pipeline.calls == []
    assert report.overall_status is OverallStatus.FAILED
    assert report.repository is None
    assert report.errors == ["A URL não pode conter credenciais."]
    assert "supersecret" not in report.to_json()


def test_clone_error_detail_is_not_exposed(pipeline: Pipeline) -> None:
    pipeline.clone_error = CloneFailedError(
        "Repositório não encontrado ou inacessível.",
        detail="fatal: could not read Username; token=supersecret; /srv/internal",
    )

    report = analyze_repository("https://github.com/psf/requests")

    assert pipeline.calls == ["clone:https://github.com/psf/requests"]
    assert report.overall_status is OverallStatus.FAILED
    assert report.errors == ["Repositório não encontrado ou inacessível."]
    payload = report.to_json()
    assert "supersecret" not in payload
    assert "/srv/internal" not in payload


def test_unexpected_step_error_does_not_stop_other_checks(pipeline: Pipeline) -> None:
    pipeline.ruff = RuntimeError("bug com detalhe interno supersecret")

    report = analyze_repository("https://github.com/psf/requests")

    assert pipeline.calls[-1] == "audit"
    assert statuses(report)[CheckName.RUFF] is CheckStatus.FAILED
    assert statuses(report)[CheckName.DEPENDENCIES] is CheckStatus.COMPLETED
    assert report.overall_status is OverallStatus.INCOMPLETE
    assert report.errors == ["Erro interno na análise com Ruff."]
    assert "supersecret" not in report.to_json()


def test_structure_error_still_runs_other_checks(pipeline: Pipeline) -> None:
    from app.structure_analyzer import StructureAnalysisError

    pipeline.structure = StructureAnalysisError("O diretório analisado não existe.")

    report = analyze_repository("https://github.com/psf/requests")

    assert pipeline.received_structure == [None, None]
    assert statuses(report)[CheckName.STRUCTURE] is CheckStatus.FAILED
    assert report.structure is None
    assert report.approved is False


@pytest.mark.skipif(shutil.which("git") is None, reason="Git não instalado.")
def test_git_version_reads_installed_git() -> None:
    version = git_version()

    assert version is not None
    assert version[0].isdigit()
