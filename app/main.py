"""Ponto de entrada da API CodeGuardian."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from app import __version__
from app.analysis_report import AnalysisReport, analyze_repository
from app.api import register_error_handlers, router
from app.jobs import JobManager


class HealthResponse(BaseModel):
    """Resposta do endpoint de verificação de saúde."""

    status: Literal["ok"]


def _run_analysis(repository_url: str, analysis_id: str) -> AnalysisReport:
    return analyze_repository(repository_url, analysis_id=analysis_id)


def create_app(job_manager: JobManager | None = None) -> FastAPI:
    """Cria a aplicação. ``job_manager`` permite injetar um gerenciador (testes)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        manager = job_manager or JobManager(_run_analysis)
        app.state.job_manager = manager
        try:
            yield
        finally:
            manager.shutdown()

    app = FastAPI(
        title="CodeGuardian",
        description="Análise de qualidade, dependências e segurança de repositórios Git públicos.",
        version=__version__,
        lifespan=lifespan,
    )
    register_error_handlers(app)
    app.include_router(router)

    @app.get("/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        """Indica que a API está em execução."""
        return HealthResponse(status="ok")

    return app


app = create_app()
