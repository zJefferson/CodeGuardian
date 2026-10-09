"""Interface web: entrega dos arquivos, cabeçalhos de segurança e salvaguardas."""

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.jobs import JobManager
from app.main import create_app
from app.web import CONTENT_SECURITY_POLICY, STATIC_DIR
from tests.test_analysis_report import build


@pytest.fixture
def client() -> Iterator[TestClient]:
    manager = JobManager(lambda url, aid: build(analysis_id=aid))
    with TestClient(create_app(manager)) as test_client:
        yield test_client


def test_index_page(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    for element_id in (
        'id="analysis-form"',
        'id="repository-url"',
        'id="submit-button"',
        'id="form-error"',
        'id="status-card"',
        'id="results"',
    ):
        assert element_id in html
    assert '<script src="/static/app.js" defer></script>' in html


def test_index_has_security_headers(client: TestClient) -> None:
    headers = client.get("/").headers

    assert headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in CONTENT_SECURITY_POLICY
    assert "unsafe-inline" not in CONTENT_SECURITY_POLICY
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-cache"


@pytest.mark.parametrize(
    ("path", "content_type"),
    [("/static/app.js", "javascript"), ("/static/styles.css", "text/css")],
)
def test_static_assets(client: TestClient, path: str, content_type: str) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert content_type in response.headers["content-type"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_missing_static_file_uses_error_format(client: TestClient) -> None:
    response = client.get("/static/nao-existe.js")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_static_path_traversal_is_blocked(client: TestClient) -> None:
    response = client.get("/static/../main.py")

    assert response.status_code == 404
    assert "create_app" not in response.text


def test_csp_is_not_applied_to_api_and_docs(client: TestClient) -> None:
    # /docs usa scripts externos do Swagger UI; a política vale só para a interface.
    assert "content-security-policy" not in client.get("/docs").headers
    assert "content-security-policy" not in client.get("/health").headers


def test_index_not_in_openapi(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]

    assert "/" not in paths
    assert set(paths) == {
        "/analyses",
        "/analyses/{analysis_id}",
        "/analyses/{analysis_id}/report",
        "/analyses/{analysis_id}/explanations",
        "/ai/status",
        "/health",
    }


# --- Salvaguardas do código da interface -----------------------------------------

APP_JS = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
INDEX_HTML = (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "pattern",
    [
        r"\.innerHTML\b",
        r"\.outerHTML\b",
        r"insertAdjacentHTML",
        r"document\.write",
        r"\beval\s*\(",
        r"new Function\s*\(",
        r"setAttribute\(\s*[\"']on",
        r"setAttribute\(\s*[\"']style",
    ],
)
def test_app_js_does_not_use_unsafe_dom_apis(pattern: str) -> None:
    # O relatório traz textos de repositórios não confiáveis: só textContent/nós de texto.
    assert not re.search(pattern, APP_JS)


def test_html_has_no_inline_scripts_or_handlers() -> None:
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", INDEX_HTML)
    assert not re.search(r"\son[a-z]+\s*=", INDEX_HTML)
    assert "style=" not in INDEX_HTML


def test_links_from_report_only_allow_https() -> None:
    assert 'url.startsWith("https://")' in APP_JS


def test_app_js_only_calls_existing_api_endpoints() -> None:
    called = set(re.findall(r'request\(\s*[`"](/[^`"$]*)', APP_JS))

    assert called == {"/analyses", "/analyses/", "/ai/status"}


def test_static_dir_contains_only_interface_files() -> None:
    assert sorted(p.name for p in Path(STATIC_DIR).iterdir()) == [
        "app.js",
        "index.html",
        "styles.css",
    ]
