"""Endpoints REST de análise e tratamento consistente de erros.

Nenhuma requisição aguarda a análise: ``POST /analyses`` apenas valida e
enfileira (202); o andamento é consultado em ``GET /analyses/{id}`` e o
relatório em ``GET /analyses/{id}/report``.

Erros seguem sempre o formato ``{"error": {"code", "message", "details"}}``
e nunca reproduzem os valores enviados pelo cliente (que podem conter
credenciais).
"""

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.analysis_report import AnalysisReport, OverallStatus
from app.jobs import Job, JobManager, JobStatus, QueueFullError
from app.repository_url import InvalidRepositoryURLError, parse_github_repository_url

logger = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 8 * 1024
RETRY_AFTER_SECONDS = 30


# --- Modelos -----------------------------------------------------------------------


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository_url: str = Field(
        min_length=1,
        max_length=2048,
        description="URL HTTPS de um repositório público em github.com.",
        examples=["https://github.com/psf/requests"],
    )

    @field_validator("repository_url")
    @classmethod
    def _validate_repository_url(cls, value: str) -> str:
        try:
            return parse_github_repository_url(value).url
        except InvalidRepositoryURLError as exc:
            raise ValueError(exc.message) from None


class AnalysisAccepted(BaseModel):
    analysis_id: str
    status: JobStatus
    repository_url: str
    status_url: str
    report_url: str


class AnalysisStatusResponse(BaseModel):
    analysis_id: str
    status: JobStatus
    repository_url: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    overall_status: OverallStatus | None = Field(
        description="Resultado consolidado; disponível quando status = completed."
    )
    approved: bool | None
    quality_score: float | None = Field(
        description="Pontuação relativa (0 a 100) ou null se indisponível; detalhes no relatório."
    )
    report_url: str | None
    error: str | None


class ErrorDetail(BaseModel):
    field: str | None
    message: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[ErrorDetail] = []


class ErrorResponse(BaseModel):
    error: ErrorBody


class APIError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers


def _error_response(
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details or []))
    return JSONResponse(status_code=status_code, content=body.model_dump(), headers=headers)


# --- Rotas -------------------------------------------------------------------------


def get_job_manager(request: Request) -> JobManager:
    return request.app.state.job_manager


JobManagerDep = Annotated[JobManager, Depends(get_job_manager)]

router = APIRouter(prefix="/analyses", tags=["analyses"])

_ERRORS = {
    404: {"model": ErrorResponse, "description": "Análise não encontrada ou expirada."},
    409: {"model": ErrorResponse, "description": "Relatório ainda não disponível."},
    422: {"model": ErrorResponse, "description": "Entrada inválida."},
    503: {"model": ErrorResponse, "description": "Capacidade de análises esgotada."},
}


def _status_url(job_id: str) -> str:
    return f"/analyses/{job_id}"


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AnalysisAccepted,
    responses={code: _ERRORS[code] for code in (422, 503)},
    summary="Inicia uma análise",
)
def start_analysis(
    body: AnalysisRequest, response: Response, jobs: JobManagerDep
) -> AnalysisAccepted:
    try:
        job = jobs.submit(body.repository_url)
    except QueueFullError:
        raise APIError(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "capacity_exceeded",
            "Muitas análises em andamento; tente novamente mais tarde.",
            headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
        ) from None
    response.headers["Location"] = _status_url(job.id)
    return AnalysisAccepted(
        analysis_id=job.id,
        status=job.status,
        repository_url=job.repository_url,
        status_url=_status_url(job.id),
        report_url=f"{_status_url(job.id)}/report",
    )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisStatusResponse,
    responses={code: _ERRORS[code] for code in (404, 422)},
    summary="Consulta o status de uma análise",
)
def get_analysis_status(analysis_id: UUID, jobs: JobManagerDep) -> AnalysisStatusResponse:
    job = _find(jobs, analysis_id)
    report = job.report
    return AnalysisStatusResponse(
        analysis_id=job.id,
        status=job.status,
        repository_url=job.repository_url,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        overall_status=report.overall_status if report else None,
        approved=report.approved if report else None,
        quality_score=report.quality.score if report and report.quality else None,
        report_url=f"{_status_url(job.id)}/report" if report else None,
        error=job.error,
    )


@router.get(
    "/{analysis_id}/report",
    response_model=AnalysisReport,
    responses={code: _ERRORS[code] for code in (404, 409, 422)},
    summary="Consulta o relatório JSON de uma análise",
)
def get_analysis_report(analysis_id: UUID, jobs: JobManagerDep) -> AnalysisReport:
    job = _find(jobs, analysis_id)
    if job.report is not None:
        return job.report
    if job.status is JobStatus.FAILED:
        raise APIError(
            status.HTTP_409_CONFLICT,
            "analysis_failed",
            job.error or "A análise falhou e não produziu relatório.",
        )
    raise APIError(
        status.HTTP_409_CONFLICT,
        "analysis_not_ready",
        f"A análise ainda não terminou (status: {job.status.value}).",
    )


def _find(jobs: JobManager, analysis_id: UUID) -> Job:
    job = jobs.get(str(analysis_id))
    if job is None:
        raise APIError(
            status.HTTP_404_NOT_FOUND, "not_found", "Análise não encontrada ou expirada."
        )
    return job


# --- Tratamento de erros -------------------------------------------------------------


def register_error_handlers(app: FastAPI) -> None:
    """Registra os tratadores de erro e o limite de tamanho do corpo."""

    @app.exception_handler(APIError)
    async def _api_error(_request: Request, exc: APIError) -> JSONResponse:
        return _error_response(exc.status_code, exc.code, exc.message, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Somente local e mensagem: o padrão do FastAPI incluiria o valor enviado.
        details = [
            ErrorDetail(
                field=".".join(str(part) for part in error.get("loc", ()) if part != "body")
                or None,
                message=str(error.get("msg", "Valor inválido.")).removeprefix("Value error, "),
            )
            for error in exc.errors()
        ]
        return _error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "A requisição contém dados inválidos.",
            details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {404: "not_found", 405: "method_not_allowed", 413: "payload_too_large"}
        return _error_response(
            exc.status_code,
            codes.get(exc.status_code, "http_error"),
            str(exc.detail),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unexpected_error(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Erro inesperado na API.", exc_info=exc)
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "internal_error", "Erro interno do servidor."
        )

    @app.middleware("http")
    async def _limit_request_size(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_REQUEST_BYTES):
            return _error_response(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "payload_too_large",
                f"O corpo da requisição excede {MAX_REQUEST_BYTES} bytes.",
            )
        return await call_next(request)
