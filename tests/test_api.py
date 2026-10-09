import json
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import analysis_report, dependency_audit
from app.analysis_report import AnalysisReport, analyze_repository
from app.jobs import JobManager, JobSettings
from app.main import create_app
from app.process_runner import ProcessResult
from tests.test_analysis_report import build

WAIT_SECONDS = 5


class FakeClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value


def report_for(analysis_id: str, **overrides: Any) -> AnalysisReport:
    return build(analysis_id=analysis_id, **overrides)


@contextmanager
def api(
    runner: Callable[[str, str], AnalysisReport],
    settings: JobSettings | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> Iterator[tuple[TestClient, JobManager]]:
    manager = JobManager(runner, settings, monotonic=monotonic)
    with TestClient(create_app(manager), raise_server_exceptions=False) as client:
        yield client, manager


def start(client: TestClient, url: str = "https://github.com/psf/requests") -> dict[str, Any]:
    response = client.post("/analyses", json={"repository_url": url})
    assert response.status_code == 202, response.text
    return response.json()


def wait_for(client: TestClient, analysis_id: str, *statuses: str) -> dict[str, Any]:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        body = client.get(f"/analyses/{analysis_id}").json()
        if body["status"] in statuses:
            return body
        time.sleep(0.01)
    pytest.fail(f"status {statuses} não alcançado; último: {body}")


def assert_error(response: Any, status_code: int, code: str) -> dict[str, Any]:
    assert response.status_code == status_code, response.text
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message", "details"}
    assert body["error"]["code"] == code
    return body["error"]


class Gate:
    """Runner que bloqueia até ser liberado, para observar estados intermediários."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.started = threading.Event()

    def __call__(self, url: str, analysis_id: str) -> AnalysisReport:
        self.started.set()
        self.release.wait(WAIT_SECONDS)
        return report_for(analysis_id)


# --- Fluxo principal -----------------------------------------------------------


def test_start_analysis_returns_202_with_location() -> None:
    with api(lambda url, aid: report_for(aid)) as (client, _):
        response = client.post(
            "/analyses", json={"repository_url": "https://GitHub.com/psf/requests.git"}
        )

    assert response.status_code == 202
    body = response.json()
    assert uuid.UUID(body["analysis_id"])
    assert body["repository_url"] == "https://github.com/psf/requests"
    assert body["status"] in {"queued", "running", "completed"}
    assert body["status_url"] == f"/analyses/{body['analysis_id']}"
    assert body["report_url"] == f"/analyses/{body['analysis_id']}/report"
    assert response.headers["location"] == body["status_url"]


def test_completed_analysis_status_and_report() -> None:
    received: list[tuple[str, str]] = []

    def runner(url: str, analysis_id: str) -> AnalysisReport:
        received.append((url, analysis_id))
        return report_for(analysis_id)

    with api(runner) as (client, _):
        accepted = start(client)
        status = wait_for(client, accepted["analysis_id"], "completed")
        report = client.get(status["report_url"])

    assert received == [("https://github.com/psf/requests", accepted["analysis_id"])]
    assert status["overall_status"] == "no_issues_found"
    assert status["approved"] is True
    assert status["error"] is None
    assert status["started_at"] is not None and status["finished_at"] is not None
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/json"
    data = report.json()
    assert data["analysis_id"] == accepted["analysis_id"]
    assert AnalysisReport.model_validate(data).approved is True


def test_failed_analysis_report_is_still_returned() -> None:
    def runner(url: str, analysis_id: str) -> AnalysisReport:
        return report_for(
            analysis_id,
            repository_error="Repositório não encontrado ou inacessível.",
            structure=None,
            ruff=None,
            dependencies=None,
        )

    with api(runner) as (client, _):
        accepted = start(client)
        status = wait_for(client, accepted["analysis_id"], "completed")
        report = client.get(f"/analyses/{accepted['analysis_id']}/report")

    assert status["overall_status"] == "failed"
    assert status["approved"] is False
    assert report.status_code == 200
    assert report.json()["errors"] == ["Repositório não encontrado ou inacessível."]


def test_report_not_ready_returns_409() -> None:
    gate = Gate()
    with api(gate) as (client, _):
        accepted = start(client)
        assert gate.started.wait(WAIT_SECONDS)
        status = client.get(f"/analyses/{accepted['analysis_id']}").json()
        response = client.get(f"/analyses/{accepted['analysis_id']}/report")
        gate.release.set()
        wait_for(client, accepted["analysis_id"], "completed")

    assert status["status"] == "running"
    assert status["overall_status"] is None and status["report_url"] is None
    error = assert_error(response, 409, "analysis_not_ready")
    assert "running" in error["message"]


def test_runner_crash_marks_analysis_failed() -> None:
    def runner(url: str, analysis_id: str) -> AnalysisReport:
        raise RuntimeError("detalhe interno supersecret")

    with api(runner) as (client, _):
        accepted = start(client)
        status = wait_for(client, accepted["analysis_id"], "failed")
        response = client.get(f"/analyses/{accepted['analysis_id']}/report")

    assert status["error"] == "Erro interno ao executar a análise."
    assert_error(response, 409, "analysis_failed")
    assert "supersecret" not in response.text + json.dumps(status)


# --- Validação de entrada ------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("https://user:supersecret@github.com/psf/requests", "A URL não pode conter credenciais."),
        ("http://github.com/psf/requests", "Apenas URLs HTTPS são permitidas."),
        ("https://localhost/psf/requests", "Endereços locais não são permitidos."),
        ("https://169.254.169.254/latest/meta-data", "Endereços IP não são permitidos"),
        ("https://gitlab.com/psf/requests", "Apenas repositórios hospedados em github.com"),
        ("https://github.com/psf", "O caminho deve seguir o formato"),
    ],
)
def test_invalid_repository_url(url: str, message: str) -> None:
    with api(lambda u, aid: report_for(aid)) as (client, manager):
        response = client.post("/analyses", json={"repository_url": url})

    error = assert_error(response, 422, "validation_error")
    assert error["details"][0]["field"] == "repository_url"
    assert error["details"][0]["message"].startswith(message)
    assert "supersecret" not in response.text
    assert url not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"repository_url": "https://github.com/psf/requests", "extra": "x"},
        {"repository_url": 123},
        {"repository_url": ""},
        {"repository_url": "https://github.com/" + "a" * 3000},
        ["https://github.com/psf/requests"],
    ],
)
def test_invalid_request_body(payload: Any) -> None:
    with api(lambda u, aid: report_for(aid)) as (client, _):
        response = client.post("/analyses", json=payload)

    error = assert_error(response, 422, "validation_error")
    assert error["details"]
    assert "a" * 100 not in response.text


def test_malformed_json() -> None:
    with api(lambda u, aid: report_for(aid)) as (client, _):
        response = client.post(
            "/analyses", content=b"{not json", headers={"content-type": "application/json"}
        )

    assert_error(response, 422, "validation_error")


def test_payload_too_large() -> None:
    with api(lambda u, aid: report_for(aid)) as (client, _):
        response = client.post(
            "/analyses",
            content=b'{"repository_url": "' + b"a" * 20_000 + b'"}',
            headers={"content-type": "application/json"},
        )

    assert_error(response, 413, "payload_too_large")


# --- Identificadores e rotas ---------------------------------------------------


def test_unknown_analysis_returns_404() -> None:
    unknown = uuid.uuid4()
    with api(lambda u, aid: report_for(aid)) as (client, _):
        status = client.get(f"/analyses/{unknown}")
        report = client.get(f"/analyses/{unknown}/report")

    assert_error(status, 404, "not_found")
    assert_error(report, 404, "not_found")


def test_invalid_analysis_id_returns_422() -> None:
    with api(lambda u, aid: report_for(aid)) as (client, _):
        response = client.get("/analyses/not-a-uuid")

    error = assert_error(response, 422, "validation_error")
    assert error["details"][0]["field"] == "path.analysis_id"


def test_unknown_route_and_method_use_error_format() -> None:
    with api(lambda u, aid: report_for(aid)) as (client, _):
        missing = client.get("/does-not-exist")
        method = client.delete("/analyses")

    assert_error(missing, 404, "not_found")
    assert_error(method, 405, "method_not_allowed")


def test_unexpected_error_returns_500(monkeypatch: pytest.MonkeyPatch) -> None:
    with api(lambda u, aid: report_for(aid)) as (client, manager):

        def broken_get(_job_id: str) -> None:
            raise RuntimeError("detalhe interno supersecret")

        monkeypatch.setattr(manager, "get", broken_get)
        response = client.get(f"/analyses/{uuid.uuid4()}")

    error = assert_error(response, 500, "internal_error")
    assert "supersecret" not in error["message"]


# --- Limites: nenhuma requisição fica bloqueada --------------------------------


def test_post_returns_immediately_while_analysis_runs() -> None:
    gate = Gate()
    with api(gate) as (client, _):
        started = time.monotonic()
        accepted = start(client)
        elapsed = time.monotonic() - started
        gate.release.set()
        wait_for(client, accepted["analysis_id"], "completed")

    assert elapsed < 1


def test_queue_full_returns_503() -> None:
    gate = Gate()
    settings = JobSettings(max_workers=1, max_pending=1)
    with api(gate, settings) as (client, _):
        start(client)
        start(client)
        response = client.post(
            "/analyses", json={"repository_url": "https://github.com/psf/requests"}
        )
        gate.release.set()

    assert_error(response, 503, "capacity_exceeded")
    assert response.headers["retry-after"] == "30"


def test_job_exceeding_max_duration_is_failed() -> None:
    clock = FakeClock()
    gate = Gate()
    settings = JobSettings(max_job_seconds=60)
    with api(gate, settings, monotonic=clock) as (client, _):
        accepted = start(client)
        assert gate.started.wait(WAIT_SECONDS)
        clock.value += 61
        status = client.get(f"/analyses/{accepted['analysis_id']}").json()
        gate.release.set()
        time.sleep(0.05)
        later = client.get(f"/analyses/{accepted['analysis_id']}").json()

    assert status["status"] == "failed"
    assert status["error"] == "A análise excedeu o tempo máximo permitido."
    # Um resultado que chega depois do prazo é descartado.
    assert later["status"] == "failed"


def test_finished_jobs_expire_after_ttl() -> None:
    clock = FakeClock()
    settings = JobSettings(ttl_seconds=60)
    with api(lambda u, aid: report_for(aid), settings, monotonic=clock) as (client, _):
        accepted = start(client)
        wait_for(client, accepted["analysis_id"], "completed")
        clock.value += 61
        response = client.get(f"/analyses/{accepted['analysis_id']}")

    assert_error(response, 404, "not_found")


# --- Integração com dependências externas simuladas ----------------------------


PIP_AUDIT_OUTPUT = {
    "dependencies": [
        {
            "name": "jinja2",
            "version": "2.4.1",
            "vulns": [
                {"id": "PYSEC-2019-217", "fix_versions": ["2.10.1"], "aliases": ["CVE-2019-10906"]}
            ],
        }
    ],
    "fixes": [],
}


def test_end_to_end_with_simulated_github_and_pypi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fluxo real (API → jobs → análise → Ruff), simulando apenas GitHub e PyPI."""
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "__init__.py").write_text("import os\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("jinja2==2.4.1\n", encoding="utf-8")
    cloned: list[str] = []

    @contextmanager
    def fake_clone(repository: Any, **_kwargs: Any) -> Iterator[Path]:
        cloned.append(repository.url)
        yield repo

    def fake_pip_audit(command: list[str], **_kwargs: Any) -> ProcessResult:
        return ProcessResult(
            returncode=1,
            stdout=json.dumps(PIP_AUDIT_OUTPUT).encode(),
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
        )

    monkeypatch.setattr(analysis_report, "cloned_repository", fake_clone)
    monkeypatch.setattr(dependency_audit, "run_limited", fake_pip_audit)

    def runner(url: str, analysis_id: str) -> AnalysisReport:
        return analyze_repository(url, analysis_id=analysis_id)

    with api(runner) as (client, _):
        accepted = start(client, "https://github.com/psf/requests")
        status = wait_for(client, accepted["analysis_id"], "completed", "failed")
        report = client.get(f"/analyses/{accepted['analysis_id']}/report").json()

    assert cloned == ["https://github.com/psf/requests"]
    assert status["status"] == "completed"
    assert status["overall_status"] == "issues_found"
    assert status["approved"] is False
    assert report["analysis_id"] == accepted["analysis_id"]
    checks = {c["name"]: c["status"] for c in report["checks"]}
    assert checks == {
        "repository": "completed",
        "structure": "completed",
        "ruff": "completed",
        "dependencies": "completed",
    }
    assert report["finding_counts"]["ruff_findings"] == 1
    assert report["ruff"]["findings"][0]["rule"] == "F401"
    assert report["finding_counts"]["vulnerabilities"] == 1
    assert report["dependencies"]["packages"][0]["vulnerabilities"][0]["id"] == "PYSEC-2019-217"


def test_openapi_documents_analysis_endpoints() -> None:
    with api(lambda u, aid: report_for(aid)) as (client, _):
        paths = client.get("/openapi.json").json()["paths"]

    assert set(paths["/analyses"]) == {"post"}
    assert "202" in paths["/analyses"]["post"]["responses"]
    assert "/analyses/{analysis_id}" in paths
    assert "409" in paths["/analyses/{analysis_id}/report"]["get"]["responses"]
