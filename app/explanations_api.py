"""Endpoints opcionais de explicação de achados com IA local.

As explicações são geradas sob demanda para um achado de um relatório já
concluído e não alteram o relatório nem a pontuação. Resultados da IA
(desabilitada, indisponível, timeout, resposta inválida) são retornados com
``200`` e um ``status`` explícito; erros da requisição seguem o formato padrão.
"""

from typing import Annotated, Self
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.ai_explainer import Explainer, ExplanationResult, FindingKind
from app.analysis_report import AnalysisReport
from app.api import _ERRORS, APIError, JobManagerDep, _find
from app.jobs import JobStatus


class ExplanationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: FindingKind
    finding_index: int | None = Field(
        default=None, ge=0, le=100_000, description="Posição do achado em report.ruff.findings."
    )
    package: str | None = Field(default=None, min_length=1, max_length=200)
    vulnerability_id: str | None = Field(default=None, min_length=1, max_length=100)

    @model_validator(mode="after")
    def _required_fields(self) -> Self:
        if self.kind is FindingKind.RUFF_FINDING and self.finding_index is None:
            raise ValueError("Informe finding_index para achados do Ruff.")
        if self.kind is FindingKind.VULNERABILITY and (
            self.package is None or self.vulnerability_id is None
        ):
            raise ValueError("Informe package e vulnerability_id para vulnerabilidades.")
        return self


class AIStatusResponse(BaseModel):
    enabled: bool
    model: str | None
    local_only: bool = True


def get_explainer(request: Request) -> Explainer:
    return request.app.state.explainer


ExplainerDep = Annotated[Explainer, Depends(get_explainer)]

router = APIRouter(tags=["ai"])


@router.get("/ai/status", response_model=AIStatusResponse, summary="Status das explicações com IA")
def ai_status(explainer: ExplainerDep) -> AIStatusResponse:
    return AIStatusResponse(
        enabled=explainer.enabled,
        model=explainer.settings.model if explainer.enabled else None,
    )


@router.post(
    "/analyses/{analysis_id}/explanations",
    response_model=ExplanationResult,
    responses={code: _ERRORS[code] for code in (404, 409, 422)},
    summary="Explica um achado com IA local (opcional)",
)
def explain_finding(
    analysis_id: UUID,
    body: ExplanationRequest,
    jobs: JobManagerDep,
    explainer: ExplainerDep,
) -> ExplanationResult:
    report = _completed_report(jobs, analysis_id)
    if body.kind is FindingKind.RUFF_FINDING:
        findings = report.ruff.findings if report.ruff else []
        index = body.finding_index or 0
        if index >= len(findings):
            raise _finding_not_found()
        return explainer.explain_ruff_finding(findings[index])

    packages = report.dependencies.packages if report.dependencies else []
    for package in packages:
        if package.name != body.package:
            continue
        for vulnerability in package.vulnerabilities:
            if vulnerability.id == body.vulnerability_id:
                return explainer.explain_vulnerability(package, vulnerability)
    raise _finding_not_found()


def _completed_report(jobs: JobManagerDep, analysis_id: UUID) -> AnalysisReport:
    job = _find(jobs, analysis_id)
    if job.report is None:
        code = "analysis_failed" if job.status is JobStatus.FAILED else "analysis_not_ready"
        raise APIError(
            status.HTTP_409_CONFLICT, code, "O relatório da análise ainda não está disponível."
        )
    return job.report


def _finding_not_found() -> APIError:
    return APIError(
        status.HTTP_404_NOT_FOUND, "finding_not_found", "Achado não encontrado no relatório."
    )
