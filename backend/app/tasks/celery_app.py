import logging
import threading

from celery import Celery, signals
from celery.schedules import crontab

try:
    from prometheus_client import Counter, start_http_server
except ModuleNotFoundError:  # pragma: no cover - local dev fallback

    class _NoopCounter:
        def labels(self, **kwargs):  # noqa: ARG002
            return self

        def inc(self):
            return None

    def Counter(*args, **kwargs):  # type: ignore[misc] # noqa: N802, ARG001
        return _NoopCounter()

    def start_http_server(*args, **kwargs):  # noqa: ARG001
        return None


from app.core.config import settings
from app.core.logging_config import configure_logging

celery_app = Celery(
    "reconx",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.advanced_recon_tasks",
        "app.tasks.validation_tasks",
        "app.tasks.learning_tasks",
    ],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=1200,
    task_time_limit=1500,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "check-scheduled-scans": {
            "task": "app.tasks.scan_tasks.check_scheduled_scans",
            "schedule": crontab(minute=f"*/{settings.scheduled_scan_poll_minutes}"),
        },
    },
)
celery_app.autodiscover_tasks(["app.tasks"])

# ---------------------------------------------------------------------------
# Prometheus metrics for Celery tasks
# ---------------------------------------------------------------------------

celery_tasks_total = Counter(
    "celery_tasks_total",
    "Total Celery tasks by name and state",
    ["task_name", "state"],
)

# ---------------------------------------------------------------------------
# Structured JSON logging for Celery workers
# ---------------------------------------------------------------------------

# Thread-local storage so each worker thread can carry its own task_name.
_task_context: threading.local = threading.local()


@signals.after_setup_logger.connect
def _setup_json_logging(
    logger: logging.Logger, **kwargs: object
) -> None:  # noqa: ARG001
    """Apply JSON logging config to Celery's logger after it is set up."""
    configure_logging()


@signals.task_prerun.connect
def _inject_task_name(
    task_id: str,  # noqa: ARG001
    task: object,
    *args: object,
    **kwargs: object,
) -> None:
    """Inject the running task's name into the logging context."""
    task_name: str = getattr(task, "name", "unknown")
    _task_context.task_name = task_name

    # Attach a filter to the root logger that adds task_name to every record
    # emitted from this thread while the task is running.
    root = logging.getLogger()
    for f in root.filters:
        if isinstance(f, _TaskNameFilter):
            f.task_name = task_name
            return
    root.addFilter(_TaskNameFilter(task_name))


@signals.task_success.connect
def _on_task_success(sender: object, **kwargs: object) -> None:
    """Increment the success counter for the completed task."""
    task_name: str = getattr(sender, "name", "unknown")
    celery_tasks_total.labels(task_name=task_name, state="success").inc()


@signals.task_failure.connect
def _on_task_failure(sender: object, **kwargs: object) -> None:
    """Increment the failure counter for the failed task."""
    task_name: str = getattr(sender, "name", "unknown")
    celery_tasks_total.labels(task_name=task_name, state="failure").inc()


@signals.worker_ready.connect
def _start_metrics_server(**kwargs: object) -> None:
    """Start a Prometheus HTTP server on port 9540 when the worker is ready."""
    thread = threading.Thread(
        target=start_http_server,
        args=(9540,),
        daemon=True,
        name="prometheus-metrics-server",
    )
    thread.start()


class _TaskNameFilter(logging.Filter):
    """Injects ``task_name`` into log records for the current Celery task."""

    def __init__(self, task_name: str) -> None:
        super().__init__()
        self.task_name = task_name

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.task_name = getattr(_task_context, "task_name", self.task_name)
        return True
