"""Relatório consolidado de uma análise.

``build_report`` apenas consolida os resultados que as etapas realmente
produziram: uma etapa que não executou aparece como ``skipped`` e nunca é
preenchida com valores presumidos. ``approved`` só é verdadeiro quando todas as
verificações aplicáveis foram concluídas por completo e sem achados.

A execução de testes é opcional: quando desabilitada, aparece como ``skipped``
e não altera ``overall_status``. Quando habilitada, falta de ambiente isolado ou
falhas de infraestrutura tornam a análise ``incomplete``, e testes reprovados
contam como achados.

``quality`` traz a pontuação explicável (``app/quality_score.py``), que é
independente de ``approved`` e não é uma medida absoluta de qualidade.

O relatório não inclui credenciais (a URL é a canônica, já validada), saídas
brutas das ferramentas nem trechos de código; da análise estrutural entra
apenas um resumo.
"""

import logging
import platform
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app import __version__
from app.dependency_audit import AuditSettings, AuditStatus, DependencyAuditReport
from app.dependency_audit import audit_dependencies as _audit_dependencies
from app.process_runner import ProcessTimeoutError, minimal_env, run_limited
from app.quality_score import QualityScore, compute_quality_score
from app.repository_clone import CloneError, CloneLimits, cloned_repository
from app.repository_url import (
    GitHubRepository,
    InvalidRepositoryURLError,
    parse_github_repository_url,
)
from app.ruff_analyzer import RuffReport, RuffSettings, RuffStatus
from app.ruff_analyzer import analyze_with_ruff as _analyze_with_ruff
from app.structure_analyzer import (
    ConfigFile,
    DocumentationInfo,
    RelevantDirectory,
    StructureAnalysisError,
    StructureLimits,
    StructureReport,
    TestsInfo,
)
from app.structure_analyzer import analyze_structure as _analyze_structure
from app.test_runner import TestExecutionSettings, TestRunReport, TestRunStatus
from app.test_runner import run_repository_tests as _run_repository_tests

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"


class CheckName(StrEnum):
    REPOSITORY = "repository"  # validação da URL e clonagem
    STRUCTURE = "structure"
    RUFF = "ruff"
    DEPENDENCIES = "dependencies"
    TESTS = "tests"  # execução opcional e isolada com pytest


class CheckStatus(StrEnum):
    COMPLETED = "completed"  # executou por completo
    PARTIAL = "partial"  # executou, mas parte não foi verificada
    FAILED = "failed"  # não produziu resultado utilizável
    SKIPPED = "skipped"  # não executou (etapa anterior falhou)
    NOT_APPLICABLE = "not_applicable"  # nada a verificar (ex.: sem arquivos Python)


class OverallStatus(StrEnum):
    NO_ISSUES_FOUND = "no_issues_found"
    ISSUES_FOUND = "issues_found"
    NOTHING_TO_ANALYZE = "nothing_to_analyze"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class CheckSummary(BaseModel):
    name: CheckName
    status: CheckStatus
    tool_status: str | None  # status original da etapa (ex.: "timeout")
    finding_count: int | None  # None quando a etapa não produziu contagem
    message: str | None = None


class FindingCounts(BaseModel):
    ruff_findings: int | None
    vulnerabilities: int | None
    vulnerable_packages: int | None
    unaudited_dependencies: int | None
    test_failures: int | None


class ToolVersions(BaseModel):
    codeguardian: str
    python: str
    git: str | None
    ruff: str | None
    pip_audit: str | None
    docker: str | None


class RepositoryInfo(BaseModel):
    url: str
    owner: str
    name: str


class StructureSummary(BaseModel):
    """Resumo da análise estrutural (sem a lista completa de arquivos)."""

    complete: bool
    limitations: list[str]
    files_examined: int
    python_file_count: int
    config_files: list[ConfigFile]
    relevant_directories: list[RelevantDirectory]
    tests: TestsInfo
    documentation: DocumentationInfo
    skipped_links: int


class AnalysisReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_VERSION
    analysis_id: str
    repository: RepositoryInfo | None
    started_at: datetime
    finished_at: datetime
    duration_seconds: float = Field(ge=0)
    tools: ToolVersions
    overall_status: OverallStatus
    approved: bool
    checks: list[CheckSummary]
    finding_counts: FindingCounts
    structure: StructureSummary | None
    ruff: RuffReport | None
    dependencies: DependencyAuditReport | None
    tests: TestRunReport | None
    warnings: list[str]
    errors: list[str]
    quality: QualityScore | None = None

    def to_json(self, *, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)

    def export_json(self, path: Path) -> Path:
        """Grava o relatório em ``path`` (UTF-8) e retorna o caminho."""
        path = Path(path)
        path.write_text(self.to_json(), encoding="utf-8")
        return path


class AnalysisSettings(BaseModel):
    model_config = ConfigDict(frozen=True)

    clone: CloneLimits = CloneLimits()
    structure: StructureLimits = StructureLimits()
    ruff: RuffSettings = RuffSettings()
    audit: AuditSettings = AuditSettings()
    tests: TestExecutionSettings = TestExecutionSettings()


# --- Consolidação ----------------------------------------------------------------


def build_report(
    *,
    analysis_id: str,
    started_at: datetime,
    finished_at: datetime,
    duration_seconds: float,
    repository: GitHubRepository | None,
    repository_error: str | None = None,
    structure: StructureReport | None = None,
    structure_error: str | None = None,
    ruff: RuffReport | None = None,
    ruff_error: str | None = None,
    dependencies: DependencyAuditReport | None = None,
    dependencies_error: str | None = None,
    tests: TestRunReport | None = None,
    tests_error: str | None = None,
    git_version: str | None = None,
) -> AnalysisReport:
    """Consolida os resultados produzidos pelas etapas da análise.

    ``*_error`` são mensagens seguras para etapas que falharam sem produzir
    relatório. Etapas sem relatório e sem erro são consideradas não executadas.
    """
    warnings: list[str] = []
    errors: list[str] = []

    repository_ok = repository is not None and repository_error is None
    checks = [
        CheckSummary(
            name=CheckName.REPOSITORY,
            status=CheckStatus.COMPLETED if repository_ok else CheckStatus.FAILED,
            tool_status=None,
            finding_count=None,
            message=repository_error,
        ),
        _structure_check(structure, structure_error, warnings),
        _ruff_check(ruff, ruff_error, warnings),
        _dependencies_check(dependencies, dependencies_error, warnings),
        _tests_check(tests, tests_error, warnings),
    ]
    errors += [c.message for c in checks if c.status is CheckStatus.FAILED and c.message]

    overall = _overall_status(checks, ruff, dependencies, tests, tests_error)
    report = AnalysisReport(
        analysis_id=analysis_id,
        repository=(
            RepositoryInfo(url=repository.url, owner=repository.owner, name=repository.name)
            if repository is not None
            else None
        ),
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=round(max(duration_seconds, 0.0), 3),
        tools=ToolVersions(
            codeguardian=__version__,
            python=platform.python_version(),
            git=git_version,
            ruff=ruff.tool_version if ruff else None,
            pip_audit=dependencies.tool_version if dependencies else None,
            docker=tests.docker_version if tests else None,
        ),
        overall_status=overall,
        approved=overall is OverallStatus.NO_ISSUES_FOUND,
        checks=checks,
        finding_counts=FindingCounts(
            ruff_findings=_ruff_count(ruff),
            vulnerabilities=_audit_count(dependencies, "vulnerability_count"),
            vulnerable_packages=_audit_count(dependencies, "vulnerable_package_count"),
            unaudited_dependencies=len(dependencies.unaudited) if dependencies else None,
            test_failures=_test_failures(tests),
        ),
        structure=_summarize_structure(structure),
        ruff=ruff,
        dependencies=dependencies,
        tests=tests,
        warnings=warnings,
        errors=errors,
    )
    return report.model_copy(update={"quality": compute_quality_score(report)})


def _structure_check(
    report: StructureReport | None, error: str | None, warnings: list[str]
) -> CheckSummary:
    if report is None:
        status = CheckStatus.FAILED if error else CheckStatus.SKIPPED
        return CheckSummary(
            name=CheckName.STRUCTURE,
            status=status,
            tool_status=None,
            finding_count=None,
            message=error,
        )
    warnings += [f"Estrutura: {item}" for item in report.limitations]
    return CheckSummary(
        name=CheckName.STRUCTURE,
        status=CheckStatus.COMPLETED if report.complete else CheckStatus.PARTIAL,
        tool_status="complete" if report.complete else "incomplete",
        finding_count=None,
    )


_RUFF_STATUS = {
    RuffStatus.COMPLETED: CheckStatus.COMPLETED,
    RuffStatus.NO_PYTHON_FILES: CheckStatus.NOT_APPLICABLE,
    RuffStatus.TIMEOUT: CheckStatus.FAILED,
    RuffStatus.OUTPUT_LIMIT: CheckStatus.FAILED,
    RuffStatus.FAILED: CheckStatus.FAILED,
}


def _ruff_check(report: RuffReport | None, error: str | None, warnings: list[str]) -> CheckSummary:
    if report is None:
        status = CheckStatus.FAILED if error else CheckStatus.SKIPPED
        return CheckSummary(
            name=CheckName.RUFF,
            status=status,
            tool_status=None,
            finding_count=None,
            message=error,
        )
    if report.findings_truncated:
        warnings.append(
            f"Ruff: {report.finding_count} achados; apenas {len(report.findings)} detalhados."
        )
    return CheckSummary(
        name=CheckName.RUFF,
        status=_RUFF_STATUS[report.status],
        tool_status=report.status.value,
        finding_count=_ruff_count(report),
        message=report.error,
    )


_AUDIT_STATUS = {
    AuditStatus.NO_VULNERABILITIES: CheckStatus.COMPLETED,
    AuditStatus.VULNERABILITIES_FOUND: CheckStatus.COMPLETED,
    AuditStatus.NO_DEPENDENCY_FILES: CheckStatus.NOT_APPLICABLE,
    AuditStatus.NO_AUDITABLE_DEPENDENCIES: CheckStatus.PARTIAL,
    AuditStatus.SOURCE_UNAVAILABLE: CheckStatus.FAILED,
    AuditStatus.TIMEOUT: CheckStatus.FAILED,
    AuditStatus.OUTPUT_LIMIT: CheckStatus.FAILED,
    AuditStatus.FAILED: CheckStatus.FAILED,
}


def _dependencies_check(
    report: DependencyAuditReport | None, error: str | None, warnings: list[str]
) -> CheckSummary:
    if report is None:
        status = CheckStatus.FAILED if error else CheckStatus.SKIPPED
        return CheckSummary(
            name=CheckName.DEPENDENCIES,
            status=status,
            tool_status=None,
            finding_count=None,
            message=error,
        )
    status = _AUDIT_STATUS[report.status]
    # Dependências não verificadas tornam a verificação parcial: não há como
    # afirmar que estão livres de vulnerabilidades conhecidas.
    if status is CheckStatus.COMPLETED and (report.unaudited or report.collection_errors):
        status = CheckStatus.PARTIAL
    if report.unaudited:
        warnings.append(
            f"Dependências: {len(report.unaudited)} declaração(ões) não auditada(s) "
            "(versão não fixada, origem fora do PyPI ou opção não suportada)."
        )
    warnings += [f"Dependências: {item}" for item in report.collection_errors]
    return CheckSummary(
        name=CheckName.DEPENDENCIES,
        status=status,
        tool_status=report.status.value,
        finding_count=_audit_count(report, "vulnerability_count"),
        message=report.error,
    )


_TEST_STATUS = {
    TestRunStatus.DISABLED: CheckStatus.SKIPPED,
    TestRunStatus.SKIPPED_UNAVAILABLE: CheckStatus.SKIPPED,
    TestRunStatus.NO_TESTS: CheckStatus.NOT_APPLICABLE,
    TestRunStatus.PASSED: CheckStatus.COMPLETED,
    TestRunStatus.FAILED: CheckStatus.COMPLETED,
    TestRunStatus.COLLECTION_ERROR: CheckStatus.FAILED,
    TestRunStatus.PYTEST_ERROR: CheckStatus.FAILED,
    TestRunStatus.TIMEOUT: CheckStatus.FAILED,
    TestRunStatus.RESOURCE_LIMIT: CheckStatus.FAILED,
    TestRunStatus.INFRASTRUCTURE_ERROR: CheckStatus.FAILED,
}


def _tests_check(
    report: TestRunReport | None, error: str | None, warnings: list[str]
) -> CheckSummary:
    if report is None:
        status = CheckStatus.FAILED if error else CheckStatus.SKIPPED
        return CheckSummary(
            name=CheckName.TESTS,
            status=status,
            tool_status=None,
            finding_count=None,
            message=error,
        )
    if report.status is TestRunStatus.SKIPPED_UNAVAILABLE and report.message:
        warnings.append(f"Testes: {report.message}")
    return CheckSummary(
        name=CheckName.TESTS,
        status=_TEST_STATUS[report.status],
        tool_status=report.status.value,
        finding_count=_test_failures(report),
        message=report.message,
    )


def _tests_requested(tests: TestRunReport | None, tests_error: str | None) -> bool:
    """A execução de testes só pesa no resultado quando foi habilitada."""
    if tests_error is not None:
        return True
    return tests is not None and tests.status is not TestRunStatus.DISABLED


def _test_failures(report: TestRunReport | None) -> int | None:
    if report is None or report.status not in {TestRunStatus.PASSED, TestRunStatus.FAILED}:
        return None
    if report.counts is None:
        return 0 if report.status is TestRunStatus.PASSED else None
    return report.counts.failed + report.counts.errors


def _overall_status(
    checks: list[CheckSummary],
    ruff: RuffReport | None,
    dependencies: DependencyAuditReport | None,
    tests: TestRunReport | None,
    tests_error: str | None,
) -> OverallStatus:
    by_name = {c.name: c for c in checks}
    if by_name[CheckName.REPOSITORY].status is not CheckStatus.COMPLETED:
        return OverallStatus.FAILED
    static = [by_name[n] for n in (CheckName.STRUCTURE, CheckName.RUFF, CheckName.DEPENDENCIES)]
    if all(c.status in {CheckStatus.FAILED, CheckStatus.SKIPPED} for c in static):
        return OverallStatus.FAILED
    considered = list(static)
    tests_requested = _tests_requested(tests, tests_error)
    if tests_requested:
        considered.append(by_name[CheckName.TESTS])
    if any(
        c.status in {CheckStatus.FAILED, CheckStatus.SKIPPED, CheckStatus.PARTIAL}
        for c in considered
    ):
        return OverallStatus.INCOMPLETE
    issues = (_ruff_count(ruff) or 0) + (_audit_count(dependencies, "vulnerability_count") or 0)
    if issues > 0 or (tests is not None and tests.status is TestRunStatus.FAILED):
        return OverallStatus.ISSUES_FOUND
    applicable = [CheckName.RUFF, CheckName.DEPENDENCIES]
    if tests_requested:
        applicable.append(CheckName.TESTS)
    if all(by_name[n].status is CheckStatus.NOT_APPLICABLE for n in applicable):
        return OverallStatus.NOTHING_TO_ANALYZE
    return OverallStatus.NO_ISSUES_FOUND


def _ruff_count(report: RuffReport | None) -> int | None:
    if report is None or report.status is not RuffStatus.COMPLETED:
        return None
    return report.finding_count


def _audit_count(report: DependencyAuditReport | None, field: str) -> int | None:
    if report is None or report.status not in {
        AuditStatus.NO_VULNERABILITIES,
        AuditStatus.VULNERABILITIES_FOUND,
    }:
        return None
    return getattr(report, field)


def _summarize_structure(report: StructureReport | None) -> StructureSummary | None:
    if report is None:
        return None
    return StructureSummary(
        complete=report.complete,
        limitations=report.limitations,
        files_examined=report.files_examined,
        python_file_count=len(report.python_files),
        config_files=report.config_files,
        relevant_directories=report.relevant_directories,
        tests=report.tests,
        documentation=report.documentation,
        skipped_links=report.skipped_links,
    )


# --- Execução ---------------------------------------------------------------------


@dataclass
class _StepResults:
    repository_error: str | None = None
    structure: StructureReport | None = None
    structure_error: str | None = None
    ruff: RuffReport | None = None
    ruff_error: str | None = None
    dependencies: DependencyAuditReport | None = None
    dependencies_error: str | None = None
    tests: TestRunReport | None = None
    tests_error: str | None = None


def analyze_repository(
    url: str,
    *,
    settings: AnalysisSettings | None = None,
    analysis_id: str | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> AnalysisReport:
    """Executa as etapas da análise sobre ``url`` e retorna o relatório consolidado.

    ``analysis_id`` permite usar um identificador já atribuído (ex.: pela API);
    se omitido, um UUID novo é gerado.
    """
    settings = settings or AnalysisSettings()
    analysis_id = analysis_id or str(uuid.uuid4())
    started_at = now()
    results = _StepResults()

    try:
        repository: GitHubRepository | None = parse_github_repository_url(url)
    except InvalidRepositoryURLError as exc:
        repository = None
        results.repository_error = exc.message

    if repository is not None:
        try:
            with cloned_repository(repository, limits=settings.clone) as path:
                _run_steps(path, settings, results)
        except CloneError as exc:
            # exc.detail (saída do Git) fica fora do relatório.
            logger.info("Falha de clonagem na análise %s: %s", analysis_id, exc.detail)
            results.repository_error = exc.message

    finished_at = now()
    return build_report(
        analysis_id=analysis_id,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=(finished_at - started_at).total_seconds(),
        repository=repository,
        repository_error=results.repository_error,
        structure=results.structure,
        structure_error=results.structure_error,
        ruff=results.ruff,
        ruff_error=results.ruff_error,
        dependencies=results.dependencies,
        dependencies_error=results.dependencies_error,
        tests=results.tests,
        tests_error=results.tests_error,
        git_version=git_version() if repository is not None else None,
    )


def _run_steps(path: Path, settings: AnalysisSettings, results: _StepResults) -> None:
    """Executa cada verificação isoladamente: a falha de uma não impede as demais.

    Exceções inesperadas (defeitos) viram falha da etapa, registrada em log,
    em vez de interromper a análise ou produzir um resultado presumido.
    """
    try:
        results.structure = _analyze_structure(path, settings.structure)
    except StructureAnalysisError as exc:
        results.structure_error = exc.message
    except Exception:
        logger.exception("Erro inesperado na análise estrutural.")
        results.structure_error = "Erro interno na análise estrutural."

    try:
        results.ruff = _analyze_with_ruff(path, settings=settings.ruff, structure=results.structure)
    except Exception:
        logger.exception("Erro inesperado na análise com Ruff.")
        results.ruff_error = "Erro interno na análise com Ruff."

    try:
        results.dependencies = _audit_dependencies(
            path, settings=settings.audit, structure=results.structure
        )
    except Exception:
        logger.exception("Erro inesperado na auditoria de dependências.")
        results.dependencies_error = "Erro interno na auditoria de dependências."

    try:
        results.tests = _run_repository_tests(path, settings.tests, structure=results.structure)
    except Exception:
        logger.exception("Erro inesperado na execução isolada de testes.")
        results.tests_error = "Erro interno na execução isolada de testes."


def git_version() -> str | None:
    """Versão do Git do servidor (ex.: ``2.52.0.windows.1``), ou None."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        result = run_limited(
            [git, "--version"],
            cwd=Path.cwd(),
            env=minimal_env(),
            timeout_seconds=10,
            max_output_bytes=256,
            capture_stdout=True,
        )
    except (OSError, ProcessTimeoutError):
        return None
    text = result.stdout.decode("utf-8", errors="replace").strip()
    prefix = "git version "
    if result.returncode != 0 or not text.startswith(prefix):
        return None
    return text[len(prefix) :][:64]
