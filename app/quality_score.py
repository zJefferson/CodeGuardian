"""Pontuação explicável de qualidade (fórmula 1.0).

Calculada de forma determinística apenas a partir dos resultados estruturados
do relatório (Ruff, pip-audit, análise estrutural e execução de testes); não
usa IA nem lê o código analisado. Critérios, pesos e exemplos estão em
``docs/pontuacao.md``.

Cada dimensão termina como ``available`` (com nota), ``not_applicable`` (nada
a avaliar) ou ``unavailable`` (verificação falhou, não executou ou faltam
dados). Dimensões indisponíveis nunca valem 0 nem 100: a nota geral fica
indisponível se qualquer dimensão aplicável estiver indisponível.
"""

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from pydantic import BaseModel

from app.dependency_audit import AuditStatus, DependencyAuditReport
from app.ruff_analyzer import RuffReport, RuffStatus
from app.structure_analyzer import ConfigKind
from app.test_runner import TestRunReport, TestRunStatus

if TYPE_CHECKING:  # evita import circular: analysis_report usa este módulo
    from app.analysis_report import AnalysisReport, StructureSummary

FORMULA_VERSION = "1.0"
DISCLAIMER = (
    "Indicador relativo, baseado apenas nas verificações automatizadas executadas. "
    "Não é uma medida absoluta da qualidade do software."
)


class Dimension(StrEnum):
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCIES = "dependencies"
    PRACTICES = "practices"
    TESTS = "tests"


WEIGHTS = {
    Dimension.STATIC_ANALYSIS: 40,
    Dimension.DEPENDENCIES: 30,
    Dimension.PRACTICES: 20,
    Dimension.TESTS: 10,
}

# Análise estática: nota = 100 / (1 + D / HALF_SCORE_DENSITY), em que D é a soma
# dos pesos dos achados por arquivo Python. D = HALF_SCORE_DENSITY dá nota 50.
HALF_SCORE_DENSITY = 10.0

# Dependências.
VULNERABLE_PACKAGE_PENALTY = 25
EXTRA_VULNERABILITY_PENALTY = 5
MIN_DEPENDENCY_COVERAGE = 0.5

# Práticas do projeto (soma = 100).
PRACTICE_POINTS = {
    "tests": 40,
    "readme": 25,
    "declared_dependencies": 15,
    "pinned_versions": 10,
    "docs_directory": 10,
}


class ScoreStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class ScoreFactor(BaseModel):
    description: str
    impact: float  # pontos (de 0 a 100 na dimensão); negativo reduz a nota


class DimensionScore(BaseModel):
    name: Dimension
    weight: int
    effective_weight: float | None  # peso após renormalização (0 a 1)
    status: ScoreStatus
    score: float | None
    reason: str | None = None
    factors: list[ScoreFactor] = []


class QualityScore(BaseModel):
    formula_version: str = FORMULA_VERSION
    status: ScoreStatus
    score: float | None
    reason: str | None = None
    disclaimer: str = DISCLAIMER
    dimensions: list[DimensionScore]


def compute_quality_score(report: "AnalysisReport") -> QualityScore:
    """Calcula a pontuação a partir de um relatório consolidado."""
    if not _repository_analyzed(report):
        dimensions = [_unavailable(name, "O repositório não foi analisado.") for name in Dimension]
        return _overall(dimensions, forced_reason="O repositório não foi analisado.")

    dimensions = [
        _static_analysis(report.ruff, report.structure),
        _dependencies(report.dependencies),
        _practices(report.structure, report.dependencies),
        _tests(report.tests),
    ]
    applicable_code = [
        d
        for d in dimensions
        if d.name in {Dimension.STATIC_ANALYSIS, Dimension.DEPENDENCIES}
        and d.status is not ScoreStatus.NOT_APPLICABLE
    ]
    if not applicable_code:
        return _overall(
            dimensions, forced_reason="Não há código Python nem dependências para avaliar."
        )
    return _overall(dimensions)


# --- Dimensões ------------------------------------------------------------------


_SYNTAX = re.compile(r"invalid-syntax|E9\d*")
_SECURITY = re.compile(r"S\d+")
_LIKELY_BUG = re.compile(r"[FB]\d+")
_TEST_DIRS = frozenset({"tests", "test", "testing"})

# (descrição, peso) por categoria de regra.
_CATEGORIES = {
    "syntax": ("Código não analisável (sintaxe)", 10),
    "security": ("Segurança (S)", 5),
    "likely_bug": ("Erros prováveis (F, B)", 3),
    "style": ("Estilo e legibilidade", 1),
}


def _rule_category(rule: str | None, file: str) -> str | None:
    """Categoria do achado; None quando o achado não pesa na nota."""
    rule = rule or ""
    if _SYNTAX.fullmatch(rule):
        return "syntax"
    if _SECURITY.fullmatch(rule):
        # assert é o mecanismo normal do pytest: não penaliza em arquivos de teste.
        return None if rule == "S101" and _is_test_file(file) else "security"
    if _LIKELY_BUG.fullmatch(rule):
        return "likely_bug"
    return "style"


def _is_test_file(file: str) -> bool:
    path = PurePosixPath(file)
    name = path.name.lower()
    return (
        any(part.lower() in _TEST_DIRS for part in path.parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def _static_analysis(
    ruff: RuffReport | None, structure: "StructureSummary | None"
) -> DimensionScore:
    name = Dimension.STATIC_ANALYSIS
    if ruff is None:
        return _unavailable(name, "A análise com Ruff não foi executada.")
    if ruff.status is RuffStatus.NO_PYTHON_FILES:
        return _not_applicable(name, "Não há arquivos Python.")
    if ruff.status is not RuffStatus.COMPLETED:
        return _unavailable(name, f"A análise com Ruff não foi concluída ({ruff.status.value}).")
    if ruff.findings_truncated:
        return _unavailable(
            name,
            f"Somente {len(ruff.findings)} de {ruff.finding_count} achados foram detalhados; "
            "sem o detalhe por regra não é possível ponderá-los.",
        )
    if structure is None:
        return _unavailable(name, "Número de arquivos Python indisponível.")

    files_with_findings = {f.file for f in ruff.findings}
    file_count = max(structure.python_file_count, len(files_with_findings), 1)
    counts = dict.fromkeys(_CATEGORIES, 0)
    ignored_asserts = 0
    for finding in ruff.findings:
        category = _rule_category(finding.rule, finding.file)
        if category is None:
            ignored_asserts += 1
        else:
            counts[category] += 1

    points = {key: counts[key] * _CATEGORIES[key][1] for key in counts}
    total_points = sum(points.values())
    density = total_points / file_count
    score = 100 / (1 + density / HALF_SCORE_DENSITY)
    penalty = 100 - score

    factors = [
        ScoreFactor(
            description=(
                f"{label}: {counts[key]} achado(s) × peso {weight} = {points[key]} ponto(s)"
            ),
            impact=_round(-penalty * points[key] / total_points),
        )
        for key, (label, weight) in _CATEGORIES.items()
        if counts[key]
    ]
    factors.append(
        ScoreFactor(
            description=(
                f"Densidade: {total_points} ponto(s) em {file_count} arquivo(s) Python "
                f"= {density:.2f} por arquivo (densidade {HALF_SCORE_DENSITY:g} reduz a nota à "
                "metade)"
            ),
            impact=0.0,
        )
    )
    if ignored_asserts:
        factors.append(
            ScoreFactor(
                description=f"{ignored_asserts} assert(s) (S101) em testes desconsiderado(s)",
                impact=0.0,
            )
        )
    return _available(name, score, factors)


def _dependencies(audit: DependencyAuditReport | None) -> DimensionScore:
    name = Dimension.DEPENDENCIES
    if audit is None:
        return _unavailable(name, "A auditoria de dependências não foi executada.")
    if audit.status is AuditStatus.NO_DEPENDENCY_FILES:
        return _not_applicable(name, "Não há arquivos de dependências.")
    if audit.status is AuditStatus.NO_AUDITABLE_DEPENDENCIES:
        return _unavailable(name, "Nenhuma dependência com versão exata pôde ser auditada.")
    if audit.status not in {AuditStatus.NO_VULNERABILITIES, AuditStatus.VULNERABILITIES_FOUND}:
        return _unavailable(
            name, f"A auditoria de dependências não foi concluída ({audit.status.value})."
        )

    audited = {canonicalize_name(p.name) for p in audit.packages}
    unaudited = _unaudited_names(audit, audited)
    total = len(audited) + unaudited
    coverage = len(audited) / total if total else 0.0
    coverage_factor = ScoreFactor(
        description=(
            f"Cobertura: {len(audited)} de {total} pacote(s) auditado(s) ({coverage:.0%})"
        ),
        impact=0.0,
    )
    if coverage < MIN_DEPENDENCY_COVERAGE:
        result = _unavailable(
            name,
            f"Cobertura da auditoria abaixo de {MIN_DEPENDENCY_COVERAGE:.0%}; "
            "a nota não representaria as dependências.",
        )
        result.factors.append(coverage_factor)
        return result

    factors: list[ScoreFactor] = []
    for package in audit.packages:
        vulns = len(package.vulnerabilities)
        if not vulns:
            continue
        penalty = VULNERABLE_PACKAGE_PENALTY + EXTRA_VULNERABILITY_PENALTY * (vulns - 1)
        factors.append(
            ScoreFactor(
                description=(
                    f"{package.name} {package.version}: {vulns} vulnerabilidade(s) conhecida(s)"
                ),
                impact=-float(penalty),
            )
        )
    score = max(0.0, 100 + sum(f.impact for f in factors))
    if score == 0 and factors:
        factors.append(ScoreFactor(description="Nota limitada ao mínimo de 0", impact=0.0))
    factors.append(coverage_factor)
    factors.append(
        ScoreFactor(
            description="Gravidade não considerada: o pip-audit não informa CVSS", impact=0.0
        )
    )
    return _available(name, score, factors)


def _unaudited_names(audit: DependencyAuditReport, audited: set[str]) -> int:
    """Conta pacotes não auditados por nome, ignorando os auditados por outra fonte."""
    names: set[str] = set()
    unnamed = 0
    for entry in audit.unaudited:
        try:
            package = canonicalize_name(Requirement(entry.requirement).name)
        except InvalidRequirement:
            unnamed += 1  # opções (-r, -e...) e linhas inválidas: origem desconhecida
            continue
        if package not in audited:
            names.add(package)
    return len(names) + unnamed


def _practices(
    structure: "StructureSummary | None", audit: DependencyAuditReport | None
) -> DimensionScore:
    name = Dimension.PRACTICES
    if structure is None:
        return _unavailable(name, "A análise estrutural não foi executada.")
    if not structure.complete:
        return _unavailable(
            name, "A análise estrutural ficou incompleta; itens ausentes não podem ser afirmados."
        )

    kinds = {config.kind for config in structure.config_files}
    declared = bool(kinds & {ConfigKind.PYPROJECT, ConfigKind.REQUIREMENTS, ConfigKind.PIPFILE})
    pinned = _has_pinned_versions(kinds, audit)
    if pinned is None:
        return _unavailable(
            name, "Não foi possível determinar se há versões fixadas (auditoria não concluída)."
        )

    checks = {
        "tests": (structure.tests.has_tests, "Testes presentes"),
        "readme": (bool(structure.documentation.readme_files), "README na raiz"),
        "declared_dependencies": (declared, "Dependências declaradas"),
        "pinned_versions": (pinned, "Versões fixadas (lockfile ou ==)"),
        "docs_directory": (bool(structure.documentation.docs_directories), "Diretório de docs"),
    }
    factors = [
        ScoreFactor(
            description=f"{label}: {'sim' if ok else 'não'} ({PRACTICE_POINTS[key]} pontos)",
            impact=0.0 if ok else -float(PRACTICE_POINTS[key]),
        )
        for key, (ok, label) in checks.items()
    ]
    return _available(name, 100 + sum(f.impact for f in factors), factors)


def _has_pinned_versions(
    kinds: set[ConfigKind], audit: DependencyAuditReport | None
) -> bool | None:
    if ConfigKind.LOCKFILE in kinds:
        return True
    if audit is None:
        return None
    if audit.status in {AuditStatus.NO_DEPENDENCY_FILES, AuditStatus.NO_AUDITABLE_DEPENDENCIES}:
        return False
    if audit.status in {AuditStatus.NO_VULNERABILITIES, AuditStatus.VULNERABILITIES_FOUND}:
        return bool(audit.packages) or any("==" in entry.requirement for entry in audit.unaudited)
    return None


def _tests(tests: TestRunReport | None) -> DimensionScore:
    name = Dimension.TESTS
    if tests is None or tests.status is TestRunStatus.DISABLED:
        return _not_applicable(name, "Execução de testes desabilitada.")
    if tests.status is TestRunStatus.NO_TESTS:
        return _not_applicable(name, "Nenhum teste encontrado.")
    if tests.status not in {TestRunStatus.PASSED, TestRunStatus.FAILED}:
        return _unavailable(name, f"Os testes não puderam ser executados ({tests.status.value}).")
    counts = tests.counts
    if counts is None:
        return _unavailable(name, "Contagem de testes indisponível.")
    executed = counts.passed + counts.failed + counts.errors
    if executed == 0:
        return _unavailable(name, "Nenhum teste foi executado.")
    score = 100 * counts.passed / executed
    factors = [
        ScoreFactor(
            description=f"{counts.passed} de {executed} teste(s) aprovado(s)",
            impact=_round(score - 100),
        )
    ]
    if counts.failed or counts.errors:
        factors.append(
            ScoreFactor(
                description=f"{counts.failed} reprovado(s), {counts.errors} com erro",
                impact=0.0,
            )
        )
    return _available(name, score, factors)


# --- Consolidação ----------------------------------------------------------------


def _overall(dimensions: list[DimensionScore], forced_reason: str | None = None) -> QualityScore:
    applicable = [d for d in dimensions if d.status is not ScoreStatus.NOT_APPLICABLE]
    total_weight = sum(d.weight for d in applicable)
    for dimension in applicable:
        dimension.effective_weight = (
            round(dimension.weight / total_weight, 4) if total_weight else None
        )

    if forced_reason is not None:
        return QualityScore(
            status=ScoreStatus.UNAVAILABLE, score=None, reason=forced_reason, dimensions=dimensions
        )
    missing = [d for d in applicable if d.status is ScoreStatus.UNAVAILABLE]
    if missing:
        names = ", ".join(d.name.value for d in missing)
        return QualityScore(
            status=ScoreStatus.UNAVAILABLE,
            score=None,
            reason=f"Dados insuficientes nas dimensões: {names}.",
            dimensions=dimensions,
        )
    score = sum(d.weight * (d.score or 0.0) for d in applicable) / total_weight
    return QualityScore(status=ScoreStatus.AVAILABLE, score=_round(score), dimensions=dimensions)


def _available(name: Dimension, score: float, factors: list[ScoreFactor]) -> DimensionScore:
    return DimensionScore(
        name=name,
        weight=WEIGHTS[name],
        effective_weight=None,
        status=ScoreStatus.AVAILABLE,
        score=_round(score),
        factors=factors,
    )


def _unavailable(name: Dimension, reason: str) -> DimensionScore:
    return DimensionScore(
        name=name,
        weight=WEIGHTS[name],
        effective_weight=None,
        status=ScoreStatus.UNAVAILABLE,
        score=None,
        reason=reason,
    )


def _not_applicable(name: Dimension, reason: str) -> DimensionScore:
    return DimensionScore(
        name=name,
        weight=WEIGHTS[name],
        effective_weight=None,
        status=ScoreStatus.NOT_APPLICABLE,
        score=None,
        reason=reason,
    )


def _round(value: float) -> float:
    return round(value, 1)


def _repository_analyzed(report: "AnalysisReport") -> bool:
    return any(
        check.name == "repository" and check.status == "completed" for check in report.checks
    )
