"""Execução de análises em segundo plano, limitada e em memória.

Não há infraestrutura persistente de tarefas (fila ou banco de dados) no
projeto. Este gerenciador é adequado apenas ao ambiente local:

- as análises rodam em um pool pequeno de threads do próprio processo da API;
- a fila tem tamanho máximo; quando cheia, novas análises são recusadas;
- resultados ficam em memória, expiram após ``ttl_seconds`` e são perdidos
  quando o processo reinicia;
- não há coordenação entre vários processos/workers do servidor.

As restrições e o que seria necessário para produção estão em ``docs/api.md``.
"""

import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.analysis_report import AnalysisReport

logger = logging.getLogger(__name__)

# (url canônica, analysis_id) -> relatório
AnalysisRunner = Callable[[str, str], AnalysisReport]


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"  # relatório disponível (o resultado pode indicar falha)
    FAILED = "failed"  # nenhum relatório foi produzido


_ACTIVE = frozenset({JobStatus.QUEUED, JobStatus.RUNNING})


class JobSettings(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_workers: int = Field(default=2, gt=0, le=16)
    max_pending: int = Field(default=10, ge=0, le=1000)
    max_stored_jobs: int = Field(default=200, gt=0)
    ttl_seconds: float = Field(default=3600.0, gt=0)
    # Tempo máximo de um job em execução. Cada etapa já tem timeout próprio;
    # este limite garante que nenhum job fique "running" indefinidamente.
    max_job_seconds: float = Field(default=900.0, gt=0)


@dataclass
class Job:
    id: str
    repository_url: str
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    report: AnalysisReport | None = None
    error: str | None = None
    _created_monotonic: float = 0.0
    _started_monotonic: float | None = None
    _finished_monotonic: float | None = None


class QueueFullError(Exception):
    """Capacidade de análises simultâneas esgotada."""


class JobManager:
    def __init__(
        self,
        runner: AnalysisRunner,
        settings: JobSettings | None = None,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._runner = runner
        self.settings = settings or JobSettings()
        self._now = now
        self._monotonic = monotonic
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=self.settings.max_workers, thread_name_prefix="codeguardian-analysis"
        )

    def submit(self, repository_url: str) -> Job:
        """Enfileira uma análise de ``repository_url`` (já validada e canônica).

        Raises:
            QueueFullError: se não houver capacidade para novas análises.
        """
        with self._lock:
            self._expire()
            active = sum(1 for job in self._jobs.values() if job.status in _ACTIVE)
            if active >= self.settings.max_workers + self.settings.max_pending:
                raise QueueFullError
            if len(self._jobs) >= self.settings.max_stored_jobs:
                self._evict_oldest_finished()
            if len(self._jobs) >= self.settings.max_stored_jobs:
                raise QueueFullError
            job = Job(
                id=str(uuid.uuid4()),
                repository_url=repository_url,
                status=JobStatus.QUEUED,
                created_at=self._now(),
                _created_monotonic=self._monotonic(),
            )
            self._jobs[job.id] = job
        self._executor.submit(self._run, job.id)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            self._expire()
            job = self._jobs.get(job_id)
            if job is not None:
                self._enforce_deadline(job)
            return job

    def shutdown(self) -> None:
        """Encerra o pool sem esperar análises em andamento."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    # --- Execução --------------------------------------------------------------

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status is not JobStatus.QUEUED:
                return
            job.status = JobStatus.RUNNING
            job.started_at = self._now()
            job._started_monotonic = self._monotonic()

        report: AnalysisReport | None = None
        error: str | None = None
        try:
            report = self._runner(job.repository_url, job.id)
        except Exception:
            logger.exception("Falha inesperada na análise %s.", job_id)
            error = "Erro interno ao executar a análise."

        with self._lock:
            if job.status is not JobStatus.RUNNING:
                return  # já encerrado por exceder o tempo máximo
            job.finished_at = self._now()
            job._finished_monotonic = self._monotonic()
            if report is not None:
                job.status, job.report = JobStatus.COMPLETED, report
            else:
                job.status, job.error = JobStatus.FAILED, error

    # --- Limites (chamados com o lock adquirido) ---------------------------------

    def _enforce_deadline(self, job: Job) -> None:
        if job.status is not JobStatus.RUNNING or job._started_monotonic is None:
            return
        if self._monotonic() - job._started_monotonic > self.settings.max_job_seconds:
            job.status = JobStatus.FAILED
            job.error = "A análise excedeu o tempo máximo permitido."
            job.finished_at = self._now()
            job._finished_monotonic = self._monotonic()

    def _expire(self) -> None:
        limit = self._monotonic() - self.settings.ttl_seconds
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job._finished_monotonic is not None and job._finished_monotonic < limit
        ]
        for job_id in expired:
            del self._jobs[job_id]

    def _evict_oldest_finished(self) -> None:
        finished = [job for job in self._jobs.values() if job.status not in _ACTIVE]
        if finished:
            oldest = min(finished, key=lambda job: job._finished_monotonic or 0.0)
            del self._jobs[oldest.id]
