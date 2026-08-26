"""
Background job runner.

`refresh_all` over a real inventory takes minutes — NVD alone paces requests at
6.5 s apiece without an API key — and holding an HTTP connection open that long
means the client, a reverse proxy, or a browser tab gives up long before the
work finishes, with no way to find out whether it succeeded.

Jobs run as asyncio tasks in the same process. That is a deliberate ceiling: the
app is a single uvicorn worker over SQLite, and pulling in Celery or a broker
would cost far more than it buys here. What that ceiling implies is handled
explicitly — a job holds its own database session rather than the request's, a
restart marks interrupted jobs failed instead of leaving them "running" forever,
and only one job of a given kind may be active at a time.
"""

import asyncio
import json
import logging
from datetime import datetime

from db.database import async_session
from db.models import Job, JobStatus
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

# Progress is committed at most this often; a refresh touching hundreds of
# components should not turn into hundreds of extra writes.
_PROGRESS_COMMIT_INTERVAL = 1.0

# Strong references to running tasks. asyncio only keeps weak ones, so without
# this a job can be garbage-collected mid-flight.
_running: dict[int, asyncio.Task] = {}

# A job outlives the request that started it, so it opens a session of its own
# rather than borrowing one. Overridable so tests can point jobs at the same
# engine their fixtures use.
_session_factory = async_session


def set_session_factory(factory) -> None:
    """Point background jobs at a different session maker. For tests."""
    global _session_factory
    _session_factory = factory


ACTIVE_STATUSES = (JobStatus.pending, JobStatus.running)


class JobAlreadyRunning(Exception):
    """Raised when a job of the same kind is already active."""

    def __init__(self, job: Job):
        self.job = job
        super().__init__(f"A {job.kind} job is already running (id={job.id})")


def serialize_job(job: Job) -> dict:
    result = None
    if job.result:
        try:
            result = json.loads(job.result)
        except ValueError:
            result = None

    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status.value if hasattr(job.status, "value") else job.status,
        "processed": job.processed,
        "total": job.total,
        "detail": job.detail,
        "result": result,
        "error": job.error,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
    }


class Progress:
    """
    Handle passed to a job body for reporting how far along it is.

    Writes are throttled — callers may report every item without thinking about
    the cost.
    """

    def __init__(self, db: AsyncSession, job: Job):
        self._db = db
        self._job = job
        self._last_commit = 0.0

    def set_total(self, total: int) -> None:
        self._job.total = total

    async def advance(self, detail: str | None = None, by: int = 1) -> None:
        self._job.processed += by
        if detail is not None:
            self._job.detail = detail

        now = asyncio.get_running_loop().time()
        if now - self._last_commit >= _PROGRESS_COMMIT_INTERVAL:
            self._last_commit = now
            await self._db.commit()

    async def flush(self) -> None:
        await self._db.commit()


async def get_job(db: AsyncSession, job_id: int) -> Job | None:
    result = await db.execute(select(Job).where(Job.id == job_id))
    return result.scalar_one_or_none()


async def list_jobs(db: AsyncSession, kind: str | None = None, limit: int = 20) -> list[Job]:
    stmt = select(Job).order_by(Job.id.desc()).limit(limit)
    if kind:
        stmt = stmt.where(Job.kind == kind)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_active_job(db: AsyncSession, kind: str) -> Job | None:
    result = await db.execute(
        select(Job).where(Job.kind == kind, Job.status.in_(ACTIVE_STATUSES))
    )
    return result.scalars().first()


async def start_job(db: AsyncSession, kind: str, body) -> Job:
    """
    Create a job row and run `body` in the background.

    `body` is `async def (db, progress) -> dict`; the dict it returns is stored
    as the job's result. It receives a session of its own, because the request
    that started the job is long gone by the time it runs.

    Raises JobAlreadyRunning if one of this kind is already active — two
    concurrent full refreshes would double the load on NVD for no benefit.
    """
    active = await get_active_job(db, kind)
    if active:
        raise JobAlreadyRunning(active)

    job = Job(kind=kind, status=JobStatus.pending, processed=0)
    db.add(job)
    await db.commit()
    await db.refresh(job)

    task = asyncio.create_task(_run(job.id, kind, body))
    _running[job.id] = task
    task.add_done_callback(lambda _: _running.pop(job.id, None))

    logger.info(f"Job {job.id} ({kind}) queued")
    return job


async def _run(job_id: int, kind: str, body) -> None:
    """Execute a job body against its own session and record the outcome."""
    async with _session_factory() as db:
        job = await get_job(db, job_id)
        if job is None:  # pragma: no cover — deleted between queue and start
            logger.error(f"Job {job_id} vanished before it started")
            return

        job.status = JobStatus.running
        job.started_at = datetime.now()
        await db.commit()

        progress = Progress(db, job)
        try:
            result = await body(db, progress)
            job.status = JobStatus.completed
            job.result = json.dumps(result) if result is not None else None
            job.detail = None
            logger.info(f"Job {job_id} ({kind}) completed")
        except asyncio.CancelledError:
            job.status = JobStatus.failed
            job.error = "Cancelled"
            await db.commit()
            raise
        except Exception as e:
            logger.exception(f"Job {job_id} ({kind}) failed")
            job.status = JobStatus.failed
            job.error = f"{type(e).__name__}: {e}"
        finally:
            job.finished_at = datetime.now()
            await db.commit()


async def wait_for_job(job_id: int, timeout: float = 30.0) -> None:
    """
    Block until a job's task finishes.

    Only meaningful in-process — used by tests and by any caller that genuinely
    wants the synchronous behaviour back. Returns immediately if the job has
    already finished.
    """
    task = _running.get(job_id)
    if task is None:
        return
    await asyncio.wait_for(asyncio.shield(task), timeout=timeout)


async def fail_interrupted_jobs(db: AsyncSession) -> int:
    """
    Mark jobs left active by a previous process as failed.

    Called on startup. Jobs live in this process, so anything still marked
    pending or running died with the restart; leaving those rows alone would
    both mislead the UI and block new jobs of the same kind forever.
    """
    result = await db.execute(select(Job).where(Job.status.in_(ACTIVE_STATUSES)))
    interrupted = list(result.scalars().all())
    now = datetime.now()

    for job in interrupted:
        job.status = JobStatus.failed
        job.error = "Interrupted by a restart"
        job.finished_at = now

    if interrupted:
        await db.commit()
        logger.warning(f"Marked {len(interrupted)} interrupted job(s) as failed")
    return len(interrupted)
