"""Ponto de entrada da API CodeGuardian."""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from app import __version__
from app.ai_explainer import AISettings, Explainer
from app.analysis_report import AnalysisReport, AnalysisSettings, analyze_repository
from app.api import register_error_handlers, router
from app.explanations_api import router as explanations_router
from app.jobs import JobManager
from app.test_runner import TestExecutionSettings
from app.web import register_web


class HealthResponse(BaseModel):
    """Resposta do endpoint de verificação de saúde."""

    status: Literal["ok"]


def _analysis_runner(settings: AnalysisSettings) -> Callable[[str, str], AnalysisReport]:
    def run(repository_url: str, analysis_id: str) -> AnalysisReport:
        return analyze_repository(repository_url, settings=settings, analysis_id=analysis_id)

    return run


def create_app(
    job_manager: JobManager | None = None, explainer: Explainer | None = None
) -> FastAPI:
    """Cria a aplicação. ``job_manager`` e ``explainer`` podem ser injetados (testes)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # A execução isolada de testes só é ativada por configuração explícita
        # (CODEGUARDIAN_TEST_EXECUTION=enabled e CODEGUARDIAN_TEST_IMAGE).
        settings = AnalysisSettings(tests=TestExecutionSettings.from_env())
        manager = job_manager or JobManager(_analysis_runner(settings))
        app.state.job_manager = manager
        # Explicações com IA local: opcionais, só com CODEGUARDIAN_AI_EXPLANATIONS=enabled.
        app.state.explainer = explainer or Explainer(AISettings.from_env())
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
    app.include_router(explanations_router)

    @app.get("/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        """Indica que a API está em execução."""
        return HealthResponse(status="ok")

    register_web(app)
    return app


app = create_app()
