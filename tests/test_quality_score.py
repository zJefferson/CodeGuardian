import json
from typing import Any

import pytest

from app.dependency_audit import AuditedPackage, AuditStatus, DependencyAuditReport, Vulnerability
from app.dependency_files import DependencyFile, DependencyFileKind, UnauditedDependency
from app.quality_score import DISCLAIMER, Dimension, QualityScore, ScoreStatus
from app.ruff_analyzer import RuffFinding, RuffReport, RuffStatus
from app.structure_analyzer import ConfigFile, ConfigKind, StructureReport
from app.test_runner import TestCounts, TestRunReport, TestRunStatus
from tests.test_analysis_report import build, structure_report

# --- Fábricas ------------------------------------------------------------------


def structure(
    *,
    python_files: int = 20,
    complete: bool = True,
    configs: tuple[ConfigKind, ...] = (ConfigKind.PYPROJECT, ConfigKind.LOCKFILE),
    has_tests: bool = True,
    readme: bool = True,
    docs: bool = False,
) -> StructureReport:
    base = structure_report(complete=complete, python_files=python_files)
    return base.model_copy(
        update={
            "config_files": [ConfigFile(path=f"cfg{i}", kind=k) for i, k in enumerate(configs)],
            "tests": base.tests.model_copy(update={"has_tests": has_tests}),
            "documentation": base.documentation.model_copy(
                update={
                    "readme_files": ["README.md"] if readme else [],
                    "docs_directories": ["docs"] if docs else [],
                }
            ),
        }
    )


def finding(rule: str | None, file: str = "pkg/mod.py", line: int = 1) -> RuffFinding:
    return RuffFinding(
        file=file,
        line=line,
        column=1,
        end_line=line,
        end_column=2,
        rule=rule,
        message="m",
        suggestion=None,
        url=None,
    )


def ruff(
    findings: list[RuffFinding] | None = None,
    status: RuffStatus = RuffStatus.COMPLETED,
    finding_count: int | None = None,
) -> RuffReport:
    findings = findings or []
    count = len(findings) if finding_count is None else finding_count
    return RuffReport(
        status=status,
        tool_version="0.16.10",
        rules=["E4", "E7", "E9", "F", "B", "S"],
        findings=findings,
        finding_count=count,
        findings_truncated=count > len(findings),
    )


EXAMPLE_FINDINGS = (
    [finding("F401", line=i) for i in range(4)]
    + [finding("S603", line=10 + i) for i in range(2)]
    + [finding("E711", line=20)]
)


def package(name: str, version: str, vulns: int = 0) -> AuditedPackage:
    return AuditedPackage(
        name=name,
        version=version,
        sources=["poetry.lock"],
        vulnerabilities=[
            Vulnerability(id=f"PYSEC-0000-{i}", aliases=[], fix_versions=[]) for i in range(vulns)
        ],
    )


def audit(
    status: AuditStatus = AuditStatus.VULNERABILITIES_FOUND,
    packages: list[AuditedPackage] | None = None,
    unaudited: list[str] | None = None,
) -> DependencyAuditReport:
    packages = (
        packages
        if packages is not None
        else [package("jinja2", "2.4.1", 3), package("flask", "3.1.0")]
    )
    return DependencyAuditReport(
        status=status,
        tool_version="2.10.1",
        vulnerability_service="pypi",
        dependency_files=[DependencyFile(path="poetry.lock", kind=DependencyFileKind.POETRY_LOCK)],
        packages=packages,
        unaudited=[
            UnauditedDependency(source="pyproject.toml", line=None, requirement=r, reason="x")
            for r in unaudited or []
        ],
        collection_errors=[],
        vulnerable_package_count=sum(1 for p in packages if p.vulnerabilities),
        vulnerability_count=sum(len(p.vulnerabilities) for p in packages),
    )


def make_tests_run(status: TestRunStatus, passed: int = 8, failed: int = 2) -> TestRunReport:
    counts = TestCounts(passed=passed, failed=failed)
    return TestRunReport(status=status, counts=counts, image="img", docker_version="29.8.2")


def score_of(**overrides: Any) -> QualityScore:
    params: dict[str, Any] = {
        "structure": structure(),
        "ruff": ruff(EXAMPLE_FINDINGS),
        "dependencies": audit(),
    }
    params.update(overrides)
    quality = build(**params).quality
    assert quality is not None
    return quality


def dimension(quality: QualityScore, name: Dimension) -> Any:
    return next(d for d in quality.dimensions if d.name is name)


# --- Cenários completos --------------------------------------------------------


def test_complete_example_matches_documented_formula() -> None:
    quality = score_of()

    static = dimension(quality, Dimension.STATIC_ANALYSIS)
    deps = dimension(quality, Dimension.DEPENDENCIES)
    practices = dimension(quality, Dimension.PRACTICES)
    tests = dimension(quality, Dimension.TESTS)

    # 4×F401 (3) + 2×S603 (5) + 1×E711 (1) = 23 pontos / 20 arquivos = 1,15
    assert static.score == 89.7  # 100 / (1 + 1.15 / 10)
    assert deps.score == 65.0  # 100 − 25 − 2×5
    assert practices.score == 90.0  # sem diretório de docs (−10)
    assert tests.status is ScoreStatus.NOT_APPLICABLE
    # (40×89,7 + 30×65 + 20×90) / 90
    assert quality.status is ScoreStatus.AVAILABLE
    assert quality.score == 81.5
    assert [static.effective_weight, deps.effective_weight, practices.effective_weight] == [
        0.4444,
        0.3333,
        0.2222,
    ]
    assert tests.effective_weight is None
    assert quality.disclaimer == DISCLAIMER
    assert quality.formula_version == "1.0"


def test_static_analysis_factors_explain_the_penalty() -> None:
    static = dimension(score_of(), Dimension.STATIC_ANALYSIS)

    impacts = {f.description.split(":")[0]: f.impact for f in static.factors}
    assert impacts["Erros prováveis (F, B)"] == -5.4
    assert impacts["Segurança (S)"] == -4.5
    assert impacts["Estilo e legibilidade"] == -0.4
    assert round(sum(impacts.values()), 1) == round(static.score - 100, 1)
    assert any("1.15 por arquivo" in f.description for f in static.factors)


def test_dependency_factors_list_each_vulnerable_package() -> None:
    deps = dimension(score_of(), Dimension.DEPENDENCIES)

    vulnerable = [f for f in deps.factors if f.impact < 0]
    assert len(vulnerable) == 1
    assert vulnerable[0].description.startswith("jinja2 2.4.1: 3 vulnerabilidade(s)")
    assert vulnerable[0].impact == -35.0
    assert any("Cobertura: 2 de 2" in f.description for f in deps.factors)
    assert any("CVSS" in f.description for f in deps.factors)


def test_practices_factors_show_each_item() -> None:
    practices = dimension(score_of(structure=structure(readme=False)), Dimension.PRACTICES)

    missing = {f.description: f.impact for f in practices.factors if f.impact < 0}
    assert missing == {
        "README na raiz: não (25 pontos)": -25.0,
        "Diretório de docs: não (10 pontos)": -10.0,
    }
    assert practices.score == 65.0


def test_complete_with_executed_tests() -> None:
    quality = score_of(tests=make_tests_run(TestRunStatus.FAILED, passed=8, failed=2))

    tests = dimension(quality, Dimension.TESTS)
    assert tests.score == 80.0
    assert tests.effective_weight == 0.1
    # (40×89,7 + 30×65 + 20×90 + 10×80) / 100
    assert quality.score == 81.4


def test_no_findings_and_clean_dependencies() -> None:
    quality = score_of(
        structure=structure(docs=True),
        ruff=ruff([]),
        dependencies=audit(AuditStatus.NO_VULNERABILITIES, [package("flask", "3.1.0")]),
    )

    assert [d.score for d in quality.dimensions[:3]] == [100.0, 100.0, 100.0]
    assert quality.score == 100.0


def test_assert_in_tests_is_not_penalized() -> None:
    findings = [finding("S101", file=f"tests/test_{i}.py") for i in range(5)]
    findings += [finding("S101", file="src/pkg/core.py"), finding("S101", file="conftest.py")]
    quality = score_of(structure=structure(python_files=10), ruff=ruff(findings))

    static = dimension(quality, Dimension.STATIC_ANALYSIS)
    assert static.score == 95.2  # apenas 1 S101 fora de testes: 5 / 10 = 0,5
    assert any("6 assert(s) (S101) em testes" in f.description for f in static.factors)


def test_syntax_errors_weigh_most() -> None:
    quality = score_of(structure=structure(python_files=1), ruff=ruff([finding("invalid-syntax")]))

    assert dimension(quality, Dimension.STATIC_ANALYSIS).score == 50.0  # D = 10


def test_dependency_score_floor_is_zero() -> None:
    quality = score_of(dependencies=audit(packages=[package(f"p{i}", "1.0", 2) for i in range(5)]))

    deps = dimension(quality, Dimension.DEPENDENCIES)
    assert deps.score == 0.0
    assert any("mínimo de 0" in f.description for f in deps.factors)


def test_ranges_covered_by_lockfile_do_not_reduce_coverage() -> None:
    quality = score_of(dependencies=audit(unaudited=["jinja2>=2", "Flask>=3"]))

    deps = dimension(quality, Dimension.DEPENDENCIES)
    assert deps.status is ScoreStatus.AVAILABLE
    assert any(
        "Cobertura: 2 de 2 pacote(s) auditado(s) (100%)" in f.description for f in deps.factors
    )


# --- Cenários parciais ---------------------------------------------------------


def test_without_dependency_files_weights_are_renormalized() -> None:
    quality = score_of(
        structure=structure(configs=(ConfigKind.PYPROJECT,)),
        dependencies=audit(AuditStatus.NO_DEPENDENCY_FILES, packages=[]),
    )

    deps = dimension(quality, Dimension.DEPENDENCIES)
    assert deps.status is ScoreStatus.NOT_APPLICABLE
    assert dimension(quality, Dimension.STATIC_ANALYSIS).effective_weight == 0.6667
    assert dimension(quality, Dimension.PRACTICES).effective_weight == 0.3333
    assert quality.status is ScoreStatus.AVAILABLE


def test_truncated_ruff_findings_make_score_unavailable() -> None:
    quality = score_of(ruff=ruff(EXAMPLE_FINDINGS, finding_count=9000))

    static = dimension(quality, Dimension.STATIC_ANALYSIS)
    assert static.status is ScoreStatus.UNAVAILABLE
    assert static.score is None
    assert "7 de 9000" in (static.reason or "")
    assert quality.status is ScoreStatus.UNAVAILABLE
    assert quality.score is None
    assert "static_analysis" in (quality.reason or "")
    # As demais dimensões continuam pontuadas.
    assert dimension(quality, Dimension.DEPENDENCIES).score == 65.0


def test_low_dependency_coverage_is_unavailable() -> None:
    quality = score_of(
        dependencies=audit(
            AuditStatus.NO_VULNERABILITIES,
            [package("flask", "3.1.0")],
            unaudited=["django", "requests>=2", "-r other.txt"],
        )
    )

    deps = dimension(quality, Dimension.DEPENDENCIES)
    assert deps.status is ScoreStatus.UNAVAILABLE
    assert any("Cobertura: 1 de 4" in f.description for f in deps.factors)
    assert quality.status is ScoreStatus.UNAVAILABLE


def test_incomplete_structure_makes_practices_unavailable() -> None:
    quality = score_of(structure=structure(complete=False))

    assert dimension(quality, Dimension.PRACTICES).status is ScoreStatus.UNAVAILABLE
    assert quality.score is None


def test_tests_without_counts_are_unavailable() -> None:
    run = TestRunReport(status=TestRunStatus.PASSED, counts=None)

    quality = score_of(tests=run)

    assert dimension(quality, Dimension.TESTS).status is ScoreStatus.UNAVAILABLE
    assert quality.score is None


def test_no_tests_found_is_not_applicable() -> None:
    quality = score_of(tests=TestRunReport(status=TestRunStatus.NO_TESTS))

    assert dimension(quality, Dimension.TESTS).status is ScoreStatus.NOT_APPLICABLE
    assert quality.score == 81.5


# --- Cenários com falhas -------------------------------------------------------


@pytest.mark.parametrize("status", [RuffStatus.TIMEOUT, RuffStatus.FAILED, RuffStatus.OUTPUT_LIMIT])
def test_failed_ruff_is_unavailable_not_zero(status: RuffStatus) -> None:
    quality = score_of(ruff=ruff(status=status))

    static = dimension(quality, Dimension.STATIC_ANALYSIS)
    assert (static.status, static.score) == (ScoreStatus.UNAVAILABLE, None)
    assert status.value in (static.reason or "")


@pytest.mark.parametrize(
    "status",
    [AuditStatus.SOURCE_UNAVAILABLE, AuditStatus.TIMEOUT, AuditStatus.FAILED],
)
def test_failed_audit_is_unavailable(status: AuditStatus) -> None:
    quality = score_of(dependencies=audit(status, packages=[]))

    assert dimension(quality, Dimension.DEPENDENCIES).status is ScoreStatus.UNAVAILABLE
    assert quality.status is ScoreStatus.UNAVAILABLE


@pytest.mark.parametrize(
    "status",
    [
        TestRunStatus.SKIPPED_UNAVAILABLE,
        TestRunStatus.COLLECTION_ERROR,
        TestRunStatus.TIMEOUT,
        TestRunStatus.INFRASTRUCTURE_ERROR,
    ],
)
def test_enabled_tests_that_did_not_run_block_overall(status: TestRunStatus) -> None:
    quality = score_of(tests=TestRunReport(status=status))

    assert dimension(quality, Dimension.TESTS).status is ScoreStatus.UNAVAILABLE
    assert quality.score is None


def test_steps_not_executed_are_unavailable() -> None:
    quality = score_of(structure=None, ruff=None, dependencies=None)

    statuses = {d.name: d.status for d in quality.dimensions}
    assert statuses[Dimension.STATIC_ANALYSIS] is ScoreStatus.UNAVAILABLE
    assert statuses[Dimension.DEPENDENCIES] is ScoreStatus.UNAVAILABLE
    assert statuses[Dimension.PRACTICES] is ScoreStatus.UNAVAILABLE
    assert quality.score is None


def test_clone_failure_has_no_score() -> None:
    quality = score_of(
        repository_error="Repositório não encontrado ou inacessível.",
        structure=None,
        ruff=None,
        dependencies=None,
    )

    assert quality.status is ScoreStatus.UNAVAILABLE
    assert quality.reason == "O repositório não foi analisado."
    assert all(d.status is ScoreStatus.UNAVAILABLE for d in quality.dimensions)


def test_nothing_to_analyze_has_no_score() -> None:
    quality = score_of(
        structure=structure(python_files=0, configs=()),
        ruff=ruff(status=RuffStatus.NO_PYTHON_FILES),
        dependencies=audit(AuditStatus.NO_DEPENDENCY_FILES, packages=[]),
    )

    assert quality.status is ScoreStatus.UNAVAILABLE
    assert "Não há código Python nem dependências" in (quality.reason or "")


# --- Exposição -----------------------------------------------------------------


def test_score_is_exported_in_report_json() -> None:
    data = json.loads(
        build(structure=structure(), ruff=ruff(EXAMPLE_FINDINGS), dependencies=audit()).to_json()
    )

    quality = data["quality"]
    assert quality["score"] == 81.5
    assert quality["status"] == "available"
    assert "Não é uma medida absoluta" in quality["disclaimer"]
    assert [d["name"] for d in quality["dimensions"]] == [
        "static_analysis",
        "dependencies",
        "practices",
        "tests",
    ]


def test_score_is_independent_from_approval() -> None:
    report = build(
        structure=structure(),
        ruff=ruff([]),
        dependencies=audit(AuditStatus.NO_VULNERABILITIES, [package("flask", "3.1.0")]),
    )

    assert report.approved is True
    assert (
        report.quality is not None and report.quality.score == 97.8
    )  # (40×100 + 30×100 + 20×90) / 90


def test_status_endpoint_exposes_score() -> None:
    from tests.test_api import api, start, wait_for

    def runner(url: str, analysis_id: str) -> Any:
        return build(
            analysis_id=analysis_id,
            structure=structure(),
            ruff=ruff(EXAMPLE_FINDINGS),
            dependencies=audit(),
        )

    with api(runner) as (client, _):
        accepted = start(client)
        status = wait_for(client, accepted["analysis_id"], "completed")

    assert status["quality_score"] == 81.5
