"""Interface web estática servida pela própria API (mesma origem).

A página consome apenas os endpoints REST existentes. Como o relatório contém
textos vindos de repositórios não confiáveis, a interface aplica uma política
de segurança de conteúdo restrita: nenhum script inline, apenas recursos da
própria origem. A política vale somente para a interface, não para ``/docs``.
"""

from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).parent / "static"

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    # Revalida a cada acesso (ETag), para que atualizações da interface cheguem
    # imediatamente ao navegador.
    "Cache-Control": "no-cache",
}


def _is_web_path(path: str) -> bool:
    return path == "/" or path.startswith("/static/")


def register_web(app: FastAPI) -> None:
    """Registra a página inicial, os arquivos estáticos e os cabeçalhos de segurança."""
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.middleware("http")
    async def _web_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if _is_web_path(request.url.path):
            response.headers.update(SECURITY_HEADERS)
        return response
