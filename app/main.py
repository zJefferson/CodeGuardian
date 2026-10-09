"""Ponto de entrada da API CodeGuardian."""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

from app import __version__

app = FastAPI(
    title="CodeGuardian",
    description="Análise de qualidade, dependências e segurança de repositórios Git públicos.",
    version=__version__,
)


class HealthResponse(BaseModel):
    """Resposta do endpoint de verificação de saúde."""

    status: Literal["ok"]


@app.get("/health", response_model=HealthResponse, tags=["health"])
def health() -> HealthResponse:
    """Indica que a API está em execução."""
    return HealthResponse(status="ok")
